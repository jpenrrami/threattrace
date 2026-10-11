from __future__ import annotations

import json
import ntpath
import re
import time
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from celery import shared_task
from sqlalchemy import select

from threattrace.cape.evidence_enrichment import (
    CapeReportCandidate,
    build_enriched_ioc_payload,
    persist_enrichment_result_in_session,
)
from threattrace.common.collections import dedupe_preserve
from threattrace.common.json_config import config_path, load_json_config
from threattrace.common.logging import configure_logging, get_logger
from threattrace.config.settings import get_settings
from threattrace.db.ioc_repository import upsert_ioc_report
from threattrace.db.models import AnalysisRun, Sample
from threattrace.db.repositories import get_status_id, store_cape_report
from threattrace.db.session import session_scope
from threattrace.etl.cape_evidence_extractor import (
    DEFAULT_EXTERNAL_ARCHIVE_ROOT,
    DEFAULT_LOCAL_ARCHIVE_ROOT,
    CapeEvidenceBundle,
    EvidenceSourceResolution,
    build_archive_name,
    extract_evidence_bundle,
)

PROCESS_REPORT_RULES_PATH = config_path("detection", "process_report_rules.json")
EVIDENCE_ENRICHMENT_RULES_PATH = config_path("cape", "evidence_enrichment_rules.json")


@lru_cache(maxsize=1)
def _process_report_rules() -> dict[str, Any]:
    return load_json_config(str(PROCESS_REPORT_RULES_PATH))


@lru_cache(maxsize=1)
def _default_campaign_features() -> dict[str, Any]:
    return dict(load_json_config(str(EVIDENCE_ENRICHMENT_RULES_PATH))["default_campaign_features"])


def _extract_process_chain(processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chain = []

    for proc in processes:
        chain.append(
            {
                "process_name": proc.get("process_name"),
                "pid": proc.get("process_id"),
                "parent_pid": proc.get("parent_id"),
                "command_line": proc.get("command_line"),
            }
        )

    return chain[:1000]


def _walk_process_tree(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    stack = list(nodes or [])
    while stack:
        node = stack.pop(0)
        if not isinstance(node, dict):
            continue
        items.append(node)
        children = node.get("children") or []
        if isinstance(children, list):
            stack.extend(child for child in children if isinstance(child, dict))
    return items


def _process_tree_commands(processtree: list[dict[str, Any]]) -> list[str]:
    commands: list[str] = []
    for node in _walk_process_tree(processtree):
        environ = node.get("environ") or {}
        if isinstance(environ, dict) and environ.get("CommandLine"):
            commands.append(str(environ["CommandLine"]))
        elif node.get("command_line"):
            commands.append(str(node["command_line"]))
        elif node.get("module_path"):
            commands.append(str(node["module_path"]))
    return dedupe_preserve(commands)


def _process_tree_chain(processtree: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    for node in _walk_process_tree(processtree):
        environ = node.get("environ") or {}
        command_line = environ.get("CommandLine") if isinstance(environ, dict) else None
        chain.append(
            {
                "process_name": node.get("name") or ntpath.basename(str(node.get("module_path") or "")) or None,
                "pid": node.get("pid"),
                "parent_pid": node.get("parent_id"),
                "command_line": command_line or node.get("command_line") or node.get("module_path"),
            }
        )
    return chain[:1000]


def _extract_resolved_apis(processes: list[dict[str, Any]]) -> list[str]:
    apis = []

    for proc in processes:
        for call in proc.get("calls", []) or []:
            api_name = call.get("api")
            if api_name:
                apis.append(api_name)

    deduped = dedupe_preserve(apis)
    return deduped[:5000]


def _extract_command_lines(processes: list[dict[str, Any]]) -> list[str]:
    commands = []

    for proc in processes:
        cmd = proc.get("command_line")
        if cmd:
            commands.append(cmd)

    return dedupe_preserve(commands)


def _extract_summary_commands(summary: dict[str, Any]) -> list[str]:
    return _merge_string_lists(
        summary.get("executed_commands", []),
        summary.get("commands", []),
        summary.get("cmdlines", []),
    )


def _extract_file_extensions(files: list[str]) -> list[str]:
    extensions = set()

    for path in files:
        if isinstance(path, str) and "." in path:
            ext = path.split(".")[-1].lower()
            if len(ext) <= 10:
                extensions.add(ext)

    return sorted(extensions)


def _merge_string_lists(*groups: list[Any]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()

    for group in groups:
        for item in group:
            if not isinstance(item, str):
                continue
            cleaned = item.strip()
            if not cleaned:
                continue
            marker = cleaned.lower()
            if marker in seen:
                continue
            seen.add(marker)
            merged.append(cleaned)

    return merged


def _merge_process_chain(
    existing: list[Any],
    process_names: list[Any],
    process_paths: list[Any],
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in existing:
        if not isinstance(item, dict):
            continue
        marker = json.dumps(item, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(item)

    for name in process_names:
        if not isinstance(name, str) or not name.strip():
            continue
        entry = {"process_name": name.strip(), "command_line": None}
        marker = json.dumps(entry, sort_keys=True)
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(entry)

    for path in process_paths:
        if not isinstance(path, str) or not path.strip():
            continue
        clean_path = path.strip()
        entry = {"process_name": ntpath.basename(clean_path) or clean_path, "command_line": clean_path}
        marker = json.dumps(entry, sort_keys=True)
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(entry)

    return merged


def _extract_attack_patterns(commands: list[str], summary: dict[str, Any], signatures: list[dict[str, Any]]) -> dict[str, bool]:
    command_blob = " ".join(commands).lower()
    signature_blob = " ".join(sig.get("name", "") for sig in signatures).lower()
    results: dict[str, bool] = {}
    for name, rule in _process_report_rules().get("attack_patterns", {}).items():
        source = str(rule.get("source"))
        if source == "summary_nonempty":
            results[str(name)] = bool(summary.get(rule.get("summary_key", "")))
            continue
        blob = command_blob if source == "command_blob" else signature_blob
        results[str(name)] = any(term in blob for term in rule.get("match_any", []))
    return results

logger = get_logger(__name__)

def _safe_stage_failure(
    report_path: Path,
    stage: str,
    error_message: str,
) -> None:
    logger.error(
        "Process report stage failure | stage=%s | report=%s | error=%s",
        stage,
        report_path,
        error_message,
    )
BASE_DIR = Path(__file__).resolve().parents[3]


def _runtime_reports_base_dir() -> Path:
    return get_settings().report_root


def _runtime_reports_dir() -> Path:
    return _runtime_reports_base_dir() / "raw"


def _processed_reports_dir() -> Path:
    return get_settings().storage_root / "processed_reports"


def ensure_directories() -> None:
    """Ensure required runtime directories exist."""
    runtime_reports_base_dir = _runtime_reports_base_dir()
    runtime_reports_dir = _runtime_reports_dir()
    processed_reports_dir = _processed_reports_dir()
    runtime_reports_base_dir.mkdir(parents=True, exist_ok=True)
    runtime_reports_dir.mkdir(parents=True, exist_ok=True)
    processed_reports_dir.mkdir(parents=True, exist_ok=True)
    (processed_reports_dir / "iocs").mkdir(parents=True, exist_ok=True)

    logger.info(
        "Verified runtime storage directories",
        extra={
            "stage": "etl",
            "service": "process_reports",
            "raw_reports_dir": str(_runtime_reports_dir()),
            "processed_reports_dir": str(processed_reports_dir),
        },
    )


def load_report(report_path: Path) -> dict[str, Any]:
    """Load a CAPE JSON report safely."""
    with report_path.open("r", encoding="utf-8", errors="ignore") as handle:
        raw_data = handle.read()
        raw_data = raw_data.replace("\x00", "")
        raw_data = raw_data.replace("\u0000", "")
        try:
            return json.loads(raw_data)
        except Exception as exc:
            logger.error(
                "JSON decode failure",
                extra={
                    "stage": "etl",
                    "service": "process_reports",
                    "error": str(exc),
                },
            )
            raise


def extract_relevant_fields(report: dict[str, Any]) -> dict[str, Any]:
    """Extract normalized high-value fields for downstream ETL."""
    target = report.get("target", {}).get("file", {})
    network = report.get("network", {}) or {}
    summary = report.get("behavior", {}).get("summary", {}) or {}
    processtree = report.get("behavior", {}).get("processtree", []) or []
    info = report.get("info", {}) or {}
    processes = report.get("behavior", {}).get("processes", []) or []
    signatures = report.get("signatures", []) or []

    command_lines = _merge_string_lists(
        _extract_command_lines(processes),
        _extract_summary_commands(summary),
        _process_tree_commands(processtree),
    )
    files_written = dedupe_preserve(summary.get("write_files", []))
    process_chain = dedupe_preserve(_extract_process_chain(processes) + _process_tree_chain(processtree))
    resolved_apis = _extract_resolved_apis(processes)

    scheduled_tasks = [
        cmd
        for cmd in command_lines
        if any(token in cmd.lower() for token in _process_report_rules().get("scheduled_task_tokens", []))
    ]
    services = [
        cmd
        for cmd in command_lines
        if any(cmd.lower().startswith(prefix) or f" {prefix}" in cmd.lower() for prefix in _process_report_rules().get("service_command_prefixes", []))
    ]
    lolbins = [
        cmd
        for cmd in command_lines
        if any(
            binary in cmd.lower()
            for binary in _process_report_rules().get("lolbin_tokens", [])
        )
    ]

    attack_patterns = _extract_attack_patterns(command_lines, summary, signatures)

    persistence_score = sum(
        [
            attack_patterns["registry_persistence"],
            attack_patterns["scheduled_tasks"],
            attack_patterns["service_creation"],
            attack_patterns["shadow_copy_deletion"],
            attack_patterns["defender_tampering"],
        ]
    )

    severity_score = sum(
        [
            attack_patterns["shadow_copy_deletion"],
            attack_patterns["defender_tampering"],
            attack_patterns["credential_access"],
            attack_patterns["ransomware_activity"],
            bool(lolbins),
            bool(services),
            bool(scheduled_tasks),
        ]
    )

    confidence_score = min(100, severity_score * 15 + persistence_score * 10)

    ransomware_indicators = [
        str(item["indicator"])
        for item in _process_report_rules().get("ransomware_indicator_mappings", [])
        if attack_patterns.get(str(item.get("pattern")))
    ]

    credential_access_indicators = [
        str(item["indicator"])
        for item in _process_report_rules().get("credential_indicator_mappings", [])
        if attack_patterns.get(str(item.get("pattern")))
    ]

    defense_evasion_indicators = []
    for item in _process_report_rules().get("defense_evasion_indicator_mappings", []):
        if item.get("condition") == "lolbins_nonempty" and lolbins or attack_patterns.get(str(item.get("pattern"))):
            defense_evasion_indicators.append(str(item["indicator"]))

    return {
        "sha256": (
            target.get("sha256")
            or info.get("sha256")
            or report.get("sha256")
        ),
        "md5": (
            target.get("md5")
            or info.get("md5")
            or report.get("md5")
        ),
        "sha1": (
            target.get("sha1")
            or info.get("sha1")
            or report.get("sha1")
        ),
        "file_name": target.get("name"),
        "file_size": target.get("size"),
        "file_type": target.get("type"),
        "cape_score": report.get("malscore"),
        "cape_status": report.get("malstatus"),
        "analysis_id": info.get("id"),
        "started": info.get("started"),
        "ended": info.get("ended"),
        "duration": info.get("duration"),
        "machine": info.get("machine", {}).get("name"),
        "signatures": signatures,
        "ttps": report.get("ttps", []),
        "domains": network.get("domains", []),
        "hosts": network.get("hosts", []),
        "http": network.get("http", []),
        "dns": network.get("dns", []),
        "tcp": network.get("tcp", []),
        "udp": network.get("udp", []),
        "smtp": network.get("smtp", []),
        "irc": network.get("irc", []),
        "files_written": files_written,
        "files_read": dedupe_preserve(summary.get("read_files", [])),
        "files_deleted": dedupe_preserve(summary.get("delete_files", [])),
        "keys_read": dedupe_preserve(summary.get("read_keys", [])),
        "keys_written": dedupe_preserve(summary.get("write_keys", [])),
        "keys_deleted": dedupe_preserve(summary.get("delete_keys", [])),
        "mutexes": dedupe_preserve(summary.get("mutexes", [])),
        "executed_commands": command_lines,
        "scheduled_tasks": dedupe_preserve(scheduled_tasks),
        "services": dedupe_preserve(services),
        "lolbins": dedupe_preserve(lolbins),
        "attack_patterns": attack_patterns,
        "persistence_score": persistence_score,
        "severity_score": severity_score,
        "confidence_score": confidence_score,
        "ransomware_indicators": dedupe_preserve(ransomware_indicators),
        "credential_access_indicators": dedupe_preserve(credential_access_indicators),
        "defense_evasion_indicators": dedupe_preserve(defense_evasion_indicators),
        "process_chain": process_chain,
        "resolved_apis": resolved_apis,
        "file_extensions_touched": _extract_file_extensions(files_written),
        "unified_ioc": {},
        "unified_ioc_normalized": {},
        "unified_ioc_threat_intel": {},
        "unified_ioc_scores": {},
        "sample_category": None,
        "family_hints": [],
        "campaign_features": _default_campaign_features(),
        "campaign_ready": False,
    }


def _resolve_analysis_dir(report_path: Path, original_report_ref: str | int) -> Path | None:
    try:
        if "analyses" in report_path.parts:
            analysis_idx = report_path.parts.index("analyses")
            return Path(*report_path.parts[: analysis_idx + 2])
    except (ValueError, OSError) as exc:
        logger.debug(
            "Could not infer CAPE analysis directory from report path",
            extra={"report_path": str(report_path), "error_message": str(exc)},
        )

    if isinstance(original_report_ref, int):
        return get_settings().cape_storage_path / "analyses" / str(original_report_ref)

    return None


def _build_normal_pipeline_resolution(
    *,
    sample_id: int,
    analysis_run_id: int,
    cape_task_id: int,
    analysis_dir: Path | None,
) -> EvidenceSourceResolution:
    settings = get_settings()
    expected_live_dir = settings.cape_storage_path / "analyses" / str(cape_task_id)
    archive_name = build_archive_name(sample_id, analysis_run_id, cape_task_id)
    expected_local_archive = DEFAULT_LOCAL_ARCHIVE_ROOT / archive_name
    expected_external_archive = DEFAULT_EXTERNAL_ARCHIVE_ROOT / archive_name

    if analysis_dir is not None and analysis_dir.is_dir():
        return EvidenceSourceResolution(
            mode="live_dir",
            status="found",
            path=analysis_dir,
            expected_live_dir=expected_live_dir,
            expected_local_archive=expected_local_archive,
            expected_external_archive=expected_external_archive,
        )

    return EvidenceSourceResolution(
        mode="missing_analysis_evidence",
        status="missing",
        reason="normal_pipeline_live_analysis_dir_missing_db_only_reprocessing",
        expected_live_dir=expected_live_dir,
        expected_local_archive=expected_local_archive,
        expected_external_archive=expected_external_archive,
    )


def save_processed_report(data: dict[str, Any], sha256: str) -> Path:
    """Persist normalized report."""
    processed_reports_dir = _processed_reports_dir()
    output_path = processed_reports_dir / f"{sha256}.json"
    processed_reports_dir.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(".json.tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
    temp_path.replace(output_path)
    return output_path



@shared_task(name="threattrace.workers.process_reports.process_single_report", bind=True)

def process_single_report(self, report_path: str | int):

    """Process one raw CAPE report into normalized structure."""

    original_report_ref = report_path

    if isinstance(report_path, int):
        report_path = get_settings().cape_storage_path / "analyses" / str(report_path) / "reports" / "report.json"
    else:
        report_path = Path(report_path)

    # Prevent recursive ingestion of already-generated IoC outputs
    if report_path.stem.endswith("_ioc"):
        logger.info(
            "Skipping derived IoC artifact during raw report processing: %s",
            report_path,
        )
        return None
    try:
        t0 = time.perf_counter()
        try:
            report = load_report(report_path)
        except Exception as load_exc:
            _safe_stage_failure(
                report_path,
                "load_report",
                str(load_exc),
            )
            raise
        logger.info(
            "Loaded CAPE report",
            extra={
                "stage": "etl",
                "service": "process_reports",
                "report_name": report_path.name,
                "report_path": str(report_path),
                "report_size": report_path.stat().st_size,
            },
        )

        try:
            processed = extract_relevant_fields(report)
        except Exception as extract_exc:
            _safe_stage_failure(
                report_path,
                "extract_relevant_fields",
                str(extract_exc),
            )
            raise

        analysis_dir = _resolve_analysis_dir(report_path, original_report_ref)
        if analysis_dir is not None:
            try:
                from threattrace.etl.ioc_engine.cape_artifacts import extract_cape_analysis_artifacts

                analysis_artifacts = extract_cape_analysis_artifacts(analysis_dir)
                processed.update(analysis_artifacts)
                artifact_payload = analysis_artifacts.get("analysis_artifacts", {})
                processed["files_written"] = _merge_string_lists(
                    processed.get("files_written", []),
                    artifact_payload.get("files_json_paths", []),
                    artifact_payload.get("reported_file_paths", []),
                    artifact_payload.get("config_file_paths", []),
                    artifact_payload.get("enhanced_file_write", []),
                    artifact_payload.get("enhanced_file_execute", []),
                    artifact_payload.get("enhanced_file_copy", []),
                    artifact_payload.get("enhanced_file_move", []),
                    artifact_payload.get("enhanced_libraries", []),
                    artifact_payload.get("enhanced_dir_create", []),
                    artifact_payload.get("bson_file_paths", []),
                )
                processed["files_read"] = _merge_string_lists(
                    processed.get("files_read", []),
                    artifact_payload.get("enhanced_file_read", []),
                )
                processed["files_deleted"] = _merge_string_lists(
                    processed.get("files_deleted", []),
                    artifact_payload.get("enhanced_file_delete", []),
                )
                processed["keys_read"] = _merge_string_lists(
                    processed.get("keys_read", []),
                    artifact_payload.get("enhanced_registry_read", []),
                    artifact_payload.get("config_registry_keys", []),
                    artifact_payload.get("bson_registry_keys", []),
                )
                processed["keys_written"] = _merge_string_lists(
                    processed.get("keys_written", []),
                    artifact_payload.get("enhanced_registry_write", []),
                    artifact_payload.get("config_registry_keys", []),
                    artifact_payload.get("bson_registry_keys", []),
                )
                processed["keys_deleted"] = _merge_string_lists(
                    processed.get("keys_deleted", []),
                    artifact_payload.get("enhanced_registry_delete", []),
                    artifact_payload.get("config_registry_keys", []),
                    artifact_payload.get("bson_registry_keys", []),
                )
                processed["executed_commands"] = _merge_string_lists(
                    processed.get("executed_commands", []),
                    artifact_payload.get("reported_process_paths", []),
                    artifact_payload.get("tree_command_lines", []),
                    artifact_payload.get("bson_command_lines", []),
                )
                processed["services"] = _merge_string_lists(
                    processed.get("services", []),
                    artifact_payload.get("enhanced_services", []),
                    artifact_payload.get("bson_services", []),
                )
                processed["process_chain"] = _merge_process_chain(
                    processed.get("process_chain", []),
                    _merge_string_lists(
                        artifact_payload.get("reported_process_names", []),
                        artifact_payload.get("tree_process_names", []),
                        artifact_payload.get("bson_process_names", []),
                    ),
                    _merge_string_lists(
                        artifact_payload.get("reported_process_paths", []),
                        artifact_payload.get("tree_process_paths", []),
                        artifact_payload.get("bson_process_paths", []),
                    ),
                )
                processed["urls"] = _merge_string_lists(
                    processed.get("urls", []),
                    artifact_payload.get("config_urls", []),
                    artifact_payload.get("bson_urls", []),
                )
                processed["domains"] = dedupe_preserve(
                    list(processed.get("domains", []))
                    + artifact_payload.get("config_domains", [])
                    + artifact_payload.get("bson_domains", [])
                )
                processed["hosts"] = dedupe_preserve(
                    list(processed.get("hosts", []))
                    + [{"ip": ip} for ip in artifact_payload.get("config_ips", []) if isinstance(ip, str)]
                    + [{"ip": ip} for ip in artifact_payload.get("bson_ips", []) if isinstance(ip, str)]
                )
                processed["user_agents"] = _merge_string_lists(
                    processed.get("user_agents", []),
                    artifact_payload.get("config_user_agents", []),
                    artifact_payload.get("bson_user_agents", []),
                )
                processed["file_extensions_touched"] = _extract_file_extensions(
                    processed.get("files_written", [])
                )
            except Exception as artifact_exc:
                logger.exception(
                    "CAPE analysis artifact enrichment failed",
                    extra={
                        "stage": "etl",
                        "service": "process_reports",
                        "analysis_dir": str(analysis_dir),
                        "error": str(artifact_exc),
                    },
                )

        # Unified modular IoC engine enrichment (non-destructive augmentation)
        try:
            from threattrace.etl.ioc_engine.orchestrator import extract_iocs, finalize_enriched_view
            from threattrace.etl.ioc_engine.processed import (
                extract_processed_report_iocs,
                merge_normalized_iocs,
            )

            unified_ioc = extract_iocs(report)
            processed_iocs = extract_processed_report_iocs(processed)

            if not isinstance(unified_ioc, dict):
                unified_ioc = {}

            unified_ioc["normalized"] = merge_normalized_iocs(
                unified_ioc.get("normalized", {}),
                processed_iocs,
            )
            threat_intel, scores = finalize_enriched_view(unified_ioc["normalized"])
            unified_ioc["threat_intel"] = threat_intel
            unified_ioc["scores"] = scores

            processed["unified_ioc"] = unified_ioc
            processed["unified_ioc_normalized"] = unified_ioc.get("normalized", {})
            processed["unified_ioc_threat_intel"] = unified_ioc.get("threat_intel", {})
            processed["unified_ioc_scores"] = unified_ioc.get("scores", {})

            # Promote enriched intelligence to top-level processed report for analytics readiness
            threat_intel = unified_ioc.get("threat_intel", {})
            processed["ttps"] = threat_intel.get("ttps", processed.get("ttps", []))
            processed["sample_category"] = threat_intel.get("sample_category")
            processed["family_hints"] = threat_intel.get("family_hints", [])
            processed["campaign_features"] = threat_intel.get("campaign_features", _default_campaign_features())
            processed["campaign_ready"] = threat_intel.get("campaign_ready", False)
        except Exception as ioc_exc:
            logger.exception(
                "Unified IoC extraction failed",
                extra={
                    "stage": "etl",
                    "service": "process_reports",
                    "report_path": str(report_path),
                    "error": str(ioc_exc),
                },
            )
            processed["unified_ioc"] = {}
            processed["unified_ioc_normalized"] = {}
            processed["unified_ioc_threat_intel"] = {}
            processed["unified_ioc_scores"] = {}

        sha256 = (
            processed.get("sha256")
            or report.get("target", {}).get("file", {}).get("sha256")
            or report.get("info", {}).get("sha256")
            or None
        )

        if not sha256:
            cape_task_id = None
            try:
                if isinstance(original_report_ref, int):
                    cape_task_id = original_report_ref
                elif "analyses" in report_path.parts:
                    analysis_idx = report_path.parts.index("analyses")
                    cape_task_id = int(report_path.parts[analysis_idx + 1])
            except Exception:
                cape_task_id = None

            if cape_task_id is not None:
                with session_scope() as session:
                    run = session.scalar(
                        select(AnalysisRun)
                        .where(AnalysisRun.cape_task_id == cape_task_id)
                        .order_by(AnalysisRun.id.desc())
                        .limit(1)
                    )
                    if run and run.sample and run.sample.sha256:
                        sha256 = run.sample.sha256

        if not sha256:
            stem = report_path.stem.lower()
            if re.fullmatch(r"[a-f0-9]{64}", stem):
                sha256 = stem

        if not sha256 or sha256 == "report":
            logger.warning(
                "Skipping report without valid sha256 fallback",
                extra={
                    "stage": "etl",
                    "service": "process_reports",
                    "report_path": str(report_path),
                },
            )
            return {

                "status": "skipped_no_sha256",

                "report_path": str(report_path),

            }

        processed["sha256"] = sha256

        enrichment_candidate: CapeReportCandidate | None = None
        enrichment_resolution: EvidenceSourceResolution | None = None
        enrichment_result = None

        try:
            with session_scope() as lookup_session:
                sample_for_enrichment = lookup_session.scalar(
                    select(Sample).where(Sample.sha256 == sha256)
                )
                latest_run_for_enrichment = None
                if sample_for_enrichment is not None:
                    latest_run_for_enrichment = lookup_session.scalar(
                        select(AnalysisRun)
                        .where(AnalysisRun.sample_id == sample_for_enrichment.id)
                        .order_by(AnalysisRun.id.desc())
                        .limit(1)
                    )

                if (
                    sample_for_enrichment is not None
                    and latest_run_for_enrichment is not None
                    and latest_run_for_enrichment.cape_task_id is not None
                ):
                    cape_task_id = int(latest_run_for_enrichment.cape_task_id)
                    enrichment_resolution = _build_normal_pipeline_resolution(
                        sample_id=sample_for_enrichment.id,
                        analysis_run_id=latest_run_for_enrichment.id,
                        cape_task_id=cape_task_id,
                        analysis_dir=analysis_dir,
                    )
                    enrichment_candidate = CapeReportCandidate(
                        sample_id=sample_for_enrichment.id,
                        analysis_run_id=latest_run_for_enrichment.id,
                        cape_task_id=cape_task_id,
                        sha256=sha256,
                        raw_json=report,
                        report_path=str(report_path),
                    )
                    enrichment_bundle = CapeEvidenceBundle(
                        sample_id=sample_for_enrichment.id,
                        analysis_run_id=latest_run_for_enrichment.id,
                        cape_task_id=cape_task_id,
                        raw_json=report,
                        source_mode=enrichment_resolution.mode,
                        source_path=enrichment_resolution.path,
                        analysis_dir=analysis_dir if analysis_dir is not None and analysis_dir.is_dir() else None,
                        sha256=sha256,
                    )
                    enrichment_result = extract_evidence_bundle(enrichment_bundle)
                    enriched_payload = build_enriched_ioc_payload(
                        enrichment_result,
                        enrichment_resolution,
                    )
                    processed = dict(enrichment_result.processed_fields)
                    processed["sha256"] = sha256
                    processed["unified_ioc"] = enriched_payload
                    processed["unified_ioc_normalized"] = enrichment_result.normalized_ioc
                    processed["unified_ioc_threat_intel"] = enriched_payload.get("threat_intel", {})
                    processed["unified_ioc_scores"] = enriched_payload.get("scores", {})
                    processed["sample_category"] = (
                        enrichment_result.normalized_ioc.get("sample_category")
                        or processed.get("sample_category")
                    )
                    processed["family_hints"] = (
                        enrichment_result.normalized_ioc.get("family_hints")
                        or processed.get("family_hints", [])
                    )
        except Exception as enrichment_exc:
            logger.exception(
                "Canonical CAPE evidence enrichment failed; falling back to base processed payload",
                extra={
                    "stage": "etl",
                    "service": "process_reports",
                    "sha256": sha256,
                    "report_path": str(report_path),
                    "error": str(enrichment_exc),
                },
            )

        try:
            from threattrace.detection.ttp_inference import infer_ttp_from_report, technique_ids

            ttp_inference = infer_ttp_from_report(processed)
            inferred_ttps = technique_ids(ttp_inference)
            processed["ttp_inference"] = ttp_inference
            processed["behavior_score"] = ttp_inference.get("behavior_score", 0)
            processed["ttps"] = sorted(set(processed.get("ttps", []) or []) | set(inferred_ttps))
            threat_intel = processed.get("unified_ioc_threat_intel")
            if isinstance(threat_intel, dict):
                threat_intel["ttps"] = sorted(set(threat_intel.get("ttps", []) or []) | set(inferred_ttps))
                threat_intel["ttp_inference_summary"] = ttp_inference.get("summary", {})
        except Exception as ttp_exc:
            logger.exception(
                "TTP inference failed",
                extra={
                    "stage": "etl",
                    "service": "process_reports",
                    "report_path": str(report_path),
                    "error": str(ttp_exc),
                },
            )

        existing_output = _processed_reports_dir() / f"{sha256}.json"
        if existing_output.exists():
            logger.info(
                "Processed report already exists, rewriting with current pipeline logic",
                extra={
                    "stage": "etl",
                    "service": "process_reports",
                    "sha256": sha256,
                },
            )

        processed = _sanitize_output(processed)

        # Defensive: avoid DB writes if processing failed partially
        if not processed or not processed.get("sha256"):
            return None

        try:
            output_path = save_processed_report(processed, sha256)
        except Exception as persist_exc:
            _safe_stage_failure(
                report_path,
                "save_processed_report",
                str(persist_exc),
            )
            raise

        try:
            with session_scope() as session:
                sample = session.scalar(
                    select(Sample).where(Sample.sha256 == sha256)
                )
                if sample:
                    sample.status_id = get_status_id(session, "etl_processing")

                if not sample:
                    raise ValueError(f"Sample not found for sha256={sha256}")

                # Always define latest_run after confirming sample
                latest_run = session.scalar(
                    select(AnalysisRun)
                    .where(AnalysisRun.sample_id == sample.id)
                    .order_by(AnalysisRun.id.desc())
                    .limit(1)
                )

                try:
                    store_cape_report(
                        session,
                        str(output_path),
                        sha256,
                        report,
                        analysis_run_id=latest_run.id if latest_run else None,
                        sha256=sha256,
                    )
                except Exception as cape_store_exc:
                    logger.exception(
                        "Failed storing cape_report for %s: %s",
                        sha256,
                        cape_store_exc,
                    )

                # Persist unified IoC intelligence through the shared enrichment path.
                try:
                    if enrichment_candidate and enrichment_resolution and enrichment_result:
                        enrichment_candidate = CapeReportCandidate(
                            sample_id=enrichment_candidate.sample_id,
                            analysis_run_id=enrichment_candidate.analysis_run_id,
                            cape_task_id=enrichment_candidate.cape_task_id,
                            sha256=enrichment_candidate.sha256,
                            raw_json=enrichment_candidate.raw_json,
                            report_path=str(output_path),
                        )
                        persist_enrichment_result_in_session(
                            session,
                            candidate=enrichment_candidate,
                            resolution=enrichment_resolution,
                            result=enrichment_result,
                        )
                    else:
                        upsert_ioc_report(
                            session=session,
                            sample_sha256=sha256,
                            processed_report_path=str(output_path),
                            ioc_payload=processed,
                        )
                except Exception as ioc_store_exc:
                    logger.exception(
                        "Failed storing IoC report for %s: %s",
                        sha256,
                        ioc_store_exc,
                    )

                if sample:
                    status_code = "done" if latest_run else "etl_completed"
                    sample.status_id = get_status_id(session, status_code)
                    sample.processed_report_path = str(output_path)
                    sample.analyzed = True

                if latest_run:
                    latest_run.state = "done"
                    latest_run.status_id = get_status_id(session, "done")
                    latest_run.error_stage = None
                    latest_run.error_message = None
                    latest_run.last_error = None
                    latest_run.locked = False
                    latest_run.locked_at = None

                    now_ts = datetime.now(UTC)

                    if hasattr(latest_run, "etl_completed_at"):
                        latest_run.etl_completed_at = now_ts

                    if hasattr(latest_run, "finished_at") and latest_run.finished_at is None:
                        latest_run.finished_at = now_ts
        except Exception as db_exc:
            logger.exception(
                "Failed updating ETL database state for %s: %s",
                sha256,
                db_exc,
            )
            if sha256:
                try:
                    with session_scope() as error_session:
                        sample = error_session.scalar(
                            select(Sample).where(Sample.sha256 == sha256)
                        )
                        if sample:
                            sample.status_id = get_status_id(error_session, "error")
                            sample.analyzed = False

                            latest_run = error_session.scalar(
                                select(AnalysisRun)
                                .where(AnalysisRun.sample_id == sample.id)
                                .order_by(AnalysisRun.id.desc())
                                .limit(1)
                            )
                            if latest_run:
                                latest_run.state = "error"
                                latest_run.status_id = get_status_id(error_session, "error")
                                latest_run.error_stage = "etl"
                                latest_run.error_message = str(db_exc)
                                latest_run.finished_at = datetime.now(UTC)
                                latest_run.locked = False
                                latest_run.locked_at = None
                except Exception:
                    logger.exception("Failed marking ETL DB exception as terminal error")
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        logger.info(
            "Processed report saved successfully",
            extra={
                "stage": "etl",
                "service": "process_reports",
                "sha256": sha256,
                "output_path": str(output_path),
                "elapsed_ms": elapsed_ms,
            },
        )
        return {
            "output_path": str(output_path),
            "sha256": str(sha256)
        }

    except Exception as exc:
        _safe_stage_failure(
            report_path,
            "process_single_report",
            str(exc),
        )
        logger.exception(
            "Failed processing report %s: %s",
            report_path,
            exc,
        )
        return None


def process_all_reports() -> list[str]:
    """Process all available raw CAPE reports from runtime_storage/reports/raw."""
    ensure_directories()

    runtime_reports_dir = _runtime_reports_dir()
    reports = sorted(runtime_reports_dir.glob("*.json"))

    logger.info(
        "Starting CAPE report ETL processing",
        extra={
            "stage": "etl",
            "service": "process_reports",
            "raw_reports_dir": str(_runtime_reports_dir()),
            "reports_detected": len(reports),
        },
    )

    enqueued: list[str] = []

    for report_path in reports:
        if report_path.stem.endswith("_ioc"):
            logger.debug(
                "Skipping recursive IoC file discovered in runtime reports: %s",
                report_path,
            )
            continue

        # mark as queued (logging only; DB status handled in worker)
        logger.info(
            "Queueing report for processing",
            extra={
                "stage": "etl",
                "service": "process_reports",
                "report_path": str(report_path),
                "status": "queued",
            },
        )

        # enqueue Celery task (async execution)
        process_single_report.apply_async(
            args=[str(report_path)],
            priority=5
        )
        enqueued.append(str(report_path))

    logger.info(
        "CAPE report ETL dispatch completed",
        extra={
            "stage": "etl",
            "service": "process_reports",
            "reports_enqueued": len(enqueued),
        },
    )

    return enqueued

def _sanitize_output(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: _sanitize_output(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_sanitize_output(v) for v in data]
    if isinstance(data, str):
        return data.replace("\x00", "")
    return data

@shared_task
def process_report_task(report_path: str):
    result = process_single_report(report_path)
    if isinstance(result, dict):
        # ensure no non-serializable values leak
        if "output_path" in result:
            result["output_path"] = str(result["output_path"])
        if "sha256" in result:
            result["sha256"] = str(result["sha256"])
        return result
    return str(result) if result is not None else None


if __name__ == "__main__":
    configure_logging()

    logger.info(
        "Launching CAPE report ETL processing module",
        extra={
            "stage": "etl",
            "service": "process_reports",
            "raw_reports_dir": str(_runtime_reports_dir()),
            "processed_reports_dir": str(_processed_reports_dir()),
        },
    )

    process_all_reports()
