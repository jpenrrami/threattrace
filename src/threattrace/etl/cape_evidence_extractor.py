from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

DEFAULT_ANALYSIS_ROOT = Path("runtime_storage/cape_storage/analyses")
DEFAULT_LOCAL_ARCHIVE_ROOT = Path("runtime_storage/archives")
DEFAULT_EXTERNAL_ARCHIVE_ROOT = Path("runtime_storage/external_archives")
DEFAULT_EXTRACT_TEMP_ROOT = Path(tempfile.gettempdir()) / "threattrace_cape_archive_enrichment"

PROCESSED_REPORT_EVIDENCE_KEYS = {
    "domains",
    "hosts",
    "http",
    "dns",
    "tcp",
    "udp",
    "files_written",
    "files_read",
    "files_deleted",
    "keys_read",
    "keys_written",
    "keys_deleted",
    "mutexes",
    "executed_commands",
    "scheduled_tasks",
    "services",
    "lolbins",
    "attack_patterns",
    "process_chain",
    "resolved_apis",
    "file_extensions_touched",
    "ransomware_indicators",
    "credential_access_indicators",
    "defense_evasion_indicators",
}


@dataclass(frozen=True)
class EvidenceSourceResolution:
    mode: str
    status: str
    path: Path | None = None
    reason: str | None = None
    expected_live_dir: Path | None = None
    expected_local_archive: Path | None = None
    expected_external_archive: Path | None = None
    external_archive_root_mounted: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for key, value in list(payload.items()):
            if isinstance(value, Path):
                payload[key] = str(value)
        return payload


@dataclass(frozen=True)
class CapeEvidenceBundle:
    sample_id: int
    analysis_run_id: int
    cape_task_id: int
    raw_json: dict[str, Any]
    source_mode: str
    source_path: Path | None
    analysis_dir: Path | None
    sha256: str | None = None


@dataclass
class EnrichmentResult:
    sample_id: int
    analysis_run_id: int
    cape_task_id: int
    source_mode: str
    processed_fields: dict[str, Any] = field(default_factory=dict)
    atomic_iocs: dict[str, list[str]] = field(default_factory=dict)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    behavior_patterns: list[str] = field(default_factory=list)
    detection_candidates: list[dict[str, Any]] = field(default_factory=list)
    endpoint_observability: dict[str, Any] = field(default_factory=dict)
    score_features: dict[str, Any] = field(default_factory=dict)
    normalized_ioc: dict[str, Any] = field(default_factory=dict)
    unified_ioc: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def build_archive_name(sample_id: int, analysis_run_id: int, cape_task_id: int) -> str:
    return f"{sample_id}_{analysis_run_id}_{cape_task_id}.tar.zst"


def is_external_archive_root_mounted(external_archive_root: Path) -> bool:
    mount_point = external_archive_root.parent if external_archive_root.name else external_archive_root
    try:
        return mount_point.exists() and mount_point.is_mount()
    except OSError:
        return False


def resolve_evidence_source(
    *,
    sample_id: int,
    analysis_run_id: int,
    cape_task_id: int,
    analysis_root: Path = DEFAULT_ANALYSIS_ROOT,
    local_archive_root: Path = DEFAULT_LOCAL_ARCHIVE_ROOT,
    external_archive_root: Path = DEFAULT_EXTERNAL_ARCHIVE_ROOT,
    external_mounted: bool | None = None,
) -> EvidenceSourceResolution:
    live_dir = analysis_root / str(cape_task_id)
    archive_name = build_archive_name(sample_id, analysis_run_id, cape_task_id)
    local_archive = local_archive_root / archive_name
    external_archive = external_archive_root / archive_name

    if live_dir.is_dir():
        return EvidenceSourceResolution(
            mode="live_dir",
            status="found",
            path=live_dir,
            expected_live_dir=live_dir,
            expected_local_archive=local_archive,
            expected_external_archive=external_archive,
            external_archive_root_mounted=external_mounted
            if external_mounted is not None
            else is_external_archive_root_mounted(external_archive_root),
        )

    if local_archive.is_file():
        return EvidenceSourceResolution(
            mode="local_archive",
            status="found",
            path=local_archive,
            expected_live_dir=live_dir,
            expected_local_archive=local_archive,
            expected_external_archive=external_archive,
            external_archive_root_mounted=external_mounted
            if external_mounted is not None
            else is_external_archive_root_mounted(external_archive_root),
        )

    mounted = (
        external_mounted
        if external_mounted is not None
        else is_external_archive_root_mounted(external_archive_root)
    )

    if mounted and external_archive.is_file():
        return EvidenceSourceResolution(
            mode="external_archive",
            status="found",
            path=external_archive,
            expected_live_dir=live_dir,
            expected_local_archive=local_archive,
            expected_external_archive=external_archive,
            external_archive_root_mounted=mounted,
        )

    reason = (
        "live_dir_missing_local_archive_missing_external_disk_not_mounted"
        if not mounted
        else "live_dir_missing_local_archive_missing_external_archive_missing"
    )
    return EvidenceSourceResolution(
        mode="missing_analysis_evidence",
        status="missing",
        path=None,
        reason=reason,
        expected_live_dir=live_dir,
        expected_local_archive=local_archive,
        expected_external_archive=external_archive,
        external_archive_root_mounted=mounted,
    )


def resolve_db_only_source() -> EvidenceSourceResolution:
    return EvidenceSourceResolution(mode="db_only", status="found")


def resolve_live_dir_source(
    *,
    cape_task_id: int,
    analysis_root: Path = DEFAULT_ANALYSIS_ROOT,
) -> EvidenceSourceResolution:
    live_dir = analysis_root / str(cape_task_id)
    if live_dir.is_dir():
        return EvidenceSourceResolution(
            mode="live_dir",
            status="found",
            path=live_dir,
            expected_live_dir=live_dir,
        )
    return EvidenceSourceResolution(
        mode="missing_analysis_dir",
        status="missing",
        reason="live_analysis_dir_missing",
        expected_live_dir=live_dir,
    )


def resolve_archive_source(
    *,
    sample_id: int,
    analysis_run_id: int,
    cape_task_id: int,
    archive_root: Path,
    source_mode: str,
    external_mounted: bool | None = None,
) -> EvidenceSourceResolution:
    archive = archive_root / build_archive_name(sample_id, analysis_run_id, cape_task_id)
    mounted = external_mounted
    if source_mode == "external_archive" and mounted is None:
        mounted = is_external_archive_root_mounted(archive_root)
    if source_mode == "external_archive" and not mounted:
        return EvidenceSourceResolution(
            mode="missing_archive",
            status="missing",
            reason="external_disk_not_mounted",
            expected_external_archive=archive,
            external_archive_root_mounted=False,
        )
    if archive.is_file():
        return EvidenceSourceResolution(
            mode=source_mode,
            status="found",
            path=archive,
            expected_local_archive=archive if source_mode == "local_archive" else None,
            expected_external_archive=archive if source_mode == "external_archive" else None,
            external_archive_root_mounted=mounted,
        )
    return EvidenceSourceResolution(
        mode="missing_archive",
        status="missing",
        reason="archive_missing",
        expected_local_archive=archive if source_mode == "local_archive" else None,
        expected_external_archive=archive if source_mode == "external_archive" else None,
        external_archive_root_mounted=mounted,
    )


def validate_archive_member_names(member_names: list[str]) -> None:
    for name in member_names:
        member_path = Path(name)
        if member_path.is_absolute():
            raise ValueError(f"Unsafe archive member uses absolute path: {name}")
        if any(part == ".." for part in member_path.parts):
            raise ValueError(f"Unsafe archive member uses traversal: {name}")
        if not str(member_path).strip() or str(member_path) == ".":
            raise ValueError(f"Unsafe empty archive member: {name!r}")


def _list_tar_zst_members(archive_path: Path) -> list[str]:
    result = subprocess.run(
        ["tar", "-I", "zstd --long=31", "-tf", str(archive_path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def safe_extract_tar_zst(
    *,
    archive_path: Path,
    extract_temp_root: Path = DEFAULT_EXTRACT_TEMP_ROOT,
    keep_temp: bool = False,
) -> Path:
    if not archive_path.is_file():
        raise FileNotFoundError(f"Archive not found: {archive_path}")
    if shutil.which("tar") is None:
        raise RuntimeError("Required tool not found in PATH: tar")
    if shutil.which("zstd") is None:
        raise RuntimeError("Required tool not found in PATH: zstd")

    member_names = _list_tar_zst_members(archive_path)
    validate_archive_member_names(member_names)

    extract_temp_root.mkdir(parents=True, exist_ok=True)
    destination = Path(
        tempfile.mkdtemp(
            prefix=f"{archive_path.stem}_{uuid4().hex[:8]}_",
            dir=str(extract_temp_root),
        )
    )
    try:
        subprocess.run(
            ["tar", "-I", "zstd --long=31", "-xf", str(archive_path), "-C", str(destination)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise

    if not keep_temp:
        return destination
    return destination


def cleanup_extracted_tree(path: Path | None) -> None:
    if path is not None:
        shutil.rmtree(path, ignore_errors=True)


def find_extracted_analysis_dir(extracted_root: Path, cape_task_id: int) -> Path:
    """Resolve the CAPE analysis directory inside a safely extracted archive."""
    direct_task_dir = extracted_root / str(cape_task_id)
    if direct_task_dir.is_dir():
        return direct_task_dir
    if (extracted_root / "reports" / "report.json").is_file():
        return extracted_root
    for child in sorted(extracted_root.iterdir()):
        if child.is_dir() and (child / "reports" / "report.json").is_file():
            return child
    return extracted_root


def _iter_strings(value: Any, *, limit: int = 5000) -> list[str]:
    results: list[str] = []

    def walk(item: Any) -> None:
        if len(results) >= limit:
            return
        if isinstance(item, str):
            cleaned = item.strip()
            if cleaned:
                results.append(cleaned)
            return
        if isinstance(item, dict):
            for child in item.values():
                walk(child)
            return
        if isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return results


def _malformed_url_warnings(value: Any, *, limit: int = 20) -> list[str]:
    warnings: list[str] = []
    seen: set[str] = set()
    for item in _iter_strings(value):
        lowered = item.lower()
        if "http://" not in lowered and "https://" not in lowered:
            continue
        try:
            parsed = urlparse(item)
            # Accessing hostname/port is where urllib raises for malformed IPv6
            # brackets or invalid port values.
            _ = parsed.hostname
            _ = parsed.port
        except ValueError:
            cleaned = item[:300]
            if cleaned not in seen:
                seen.add(cleaned)
                warnings.append(f"malformed_url_skipped: {cleaned}")
            if len(warnings) >= limit:
                break
    return warnings


def _safe_stage(stage: str, warnings: list[str], func, *args, fallback):
    try:
        return func(*args)
    except Exception as exc:
        warnings.append(f"{stage}_failed: {exc}")
        return fallback


def _is_processed_report_shape(report: dict[str, Any]) -> bool:
    if not isinstance(report, dict):
        return False
    if isinstance(report.get("behavior"), dict) or isinstance(report.get("network"), dict):
        return False
    return any(key in report for key in PROCESSED_REPORT_EVIDENCE_KEYS)


def _merge_processed_fields(*sources: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key, value in source.items():
            if value in (None, "", [], {}):
                continue
            existing = merged.get(key)
            if isinstance(existing, list) and isinstance(value, list):
                seen = {json.dumps(item, sort_keys=True, default=str) for item in existing}
                for item in value:
                    marker = json.dumps(item, sort_keys=True, default=str)
                    if marker not in seen:
                        seen.add(marker)
                        existing.append(item)
                continue
            if isinstance(existing, dict) and isinstance(value, dict):
                existing.update(value)
                continue
            if existing in (None, "", [], {}) or key not in merged:
                merged[key] = value
    return merged


def _extract_processed_fields(report: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    from threattrace.workers.process_reports import extract_relevant_fields

    extracted = _safe_stage(
        "extract_relevant_fields",
        warnings,
        extract_relevant_fields,
        report,
        fallback={},
    )
    if not _is_processed_report_shape(report):
        return extracted
    passthrough = {
        key: value
        for key, value in report.items()
        if key not in {"raw", "raw_iocs"} and not key.startswith("_")
    }
    return _merge_processed_fields(extracted, passthrough)


def extract_evidence_bundle(bundle: CapeEvidenceBundle) -> EnrichmentResult:
    """Build derived intelligence from raw JSON and optional analysis-dir evidence.

    This function is intentionally side-effect free. It does not write reports, update
    the database, call CAPE, or read external services.
    """
    from threattrace.etl.ioc_engine.orchestrator import extract_iocs, finalize_enriched_view
    from threattrace.etl.ioc_engine.processed import (
        extract_processed_report_iocs,
        merge_normalized_iocs,
    )
    warnings: list[str] = []
    processed = _extract_processed_fields(bundle.raw_json, warnings)

    if bundle.analysis_dir is not None:
        try:
            from threattrace.etl.ioc_engine.cape_artifacts import extract_cape_analysis_artifacts

            processed.update(extract_cape_analysis_artifacts(bundle.analysis_dir))
        except Exception as exc:  # pragma: no cover - defensive integration guard
            warnings.append(f"analysis_dir_artifact_extraction_failed: {exc}")

    warnings.extend(_malformed_url_warnings(processed))

    if _is_processed_report_shape(bundle.raw_json):
        unified_ioc = {
            "raw": {},
            "normalized": {},
            "threat_intel": {},
            "scores": {},
            "metrics": {"source": "processed_report_passthrough"},
        }
    else:
        unified_ioc = _safe_stage(
            "extract_iocs",
            warnings,
            extract_iocs,
            bundle.raw_json,
            fallback={},
        )
    processed_iocs = _safe_stage(
        "extract_processed_report_iocs",
        warnings,
        extract_processed_report_iocs,
        processed,
        fallback={},
    )
    normalized = _safe_stage(
        "merge_normalized_iocs",
        warnings,
        merge_normalized_iocs,
        unified_ioc.get("normalized", {}) if isinstance(unified_ioc, dict) else {},
        processed_iocs,
        fallback=unified_ioc.get("normalized", {}) if isinstance(unified_ioc, dict) else {},
    )
    if isinstance(unified_ioc, dict):
        unified_ioc["normalized"] = normalized
        threat_intel, scores = finalize_enriched_view(normalized)
        unified_ioc["threat_intel"] = threat_intel
        unified_ioc["scores"] = scores
        unified_ioc["detection_candidates"] = normalized.get("detection_candidates", [])
        unified_ioc["endpoint_observability"] = normalized.get("endpoint_observability", {})

    atomic_iocs = {
        "ip": normalized.get("ips", []),
        "domain": normalized.get("domains", []),
        "url": normalized.get("urls", []),
        "file": normalized.get("dropped_files", []),
        "registry": normalized.get("registry_keys", []),
        "mutex": normalized.get("mutexes", []),
        "process": normalized.get("process_chain", []),
    }
    scores = unified_ioc.get("scores", {}) if isinstance(unified_ioc, dict) else {}
    score_features = scores.get("features", {}) if isinstance(scores, dict) else {}

    return EnrichmentResult(
        sample_id=bundle.sample_id,
        analysis_run_id=bundle.analysis_run_id,
        cape_task_id=bundle.cape_task_id,
        source_mode=bundle.source_mode,
        processed_fields=processed,
        atomic_iocs=atomic_iocs,
        behavior_patterns=list((normalized.get("attack_patterns") or {}).keys())
        if isinstance(normalized.get("attack_patterns"), dict)
        else [],
        detection_candidates=normalized.get("detection_candidates", []),
        endpoint_observability=normalized.get("endpoint_observability", {}),
        score_features=score_features,
        normalized_ioc=normalized,
        unified_ioc=unified_ioc if isinstance(unified_ioc, dict) else {},
        warnings=warnings,
    )


def result_to_jsonable(result: EnrichmentResult) -> dict[str, Any]:
    return json.loads(json.dumps(asdict(result), default=str))
