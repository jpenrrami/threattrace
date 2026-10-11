from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select, text

from threattrace.common.collections import coerce_dict, coerce_list, dedupe_strings_preserve
from threattrace.common.json_config import config_path, load_json_config
from threattrace.common.logging import configure_logging
from threattrace.config.settings import get_settings
from threattrace.db.ioc_repository import (
    ATTACK_PATTERN_TO_TTP,
    BEHAVIOR_PATTERN_DETAILS,
    TTP_CATEGORY_MAP,
)
from threattrace.db.models import (
    BehaviorPattern,
    CapeReport,
    Domain,
    IOCReport,
    IPAddress,
    Sample,
    SampleArtifact,
    SampleAttackTechnique,
    SampleBehaviorScore,
    SampleIoC,
)
from threattrace.db.repositories import sanitize_json_strings
from threattrace.db.session import session_scope
from threattrace.detection.ttp_inference import infer_ttp_from_report
from threattrace.etl.cape_evidence_extractor import (
    DEFAULT_ANALYSIS_ROOT,
    DEFAULT_EXTERNAL_ARCHIVE_ROOT,
    DEFAULT_EXTRACT_TEMP_ROOT,
    DEFAULT_LOCAL_ARCHIVE_ROOT,
    CapeEvidenceBundle,
    EnrichmentResult,
    EvidenceSourceResolution,
    cleanup_extracted_tree,
    extract_evidence_bundle,
    find_extracted_analysis_dir,
    is_external_archive_root_mounted,
    resolve_archive_source,
    resolve_db_only_source,
    resolve_evidence_source,
    resolve_live_dir_source,
    safe_extract_tar_zst,
)
from threattrace.etl.ioc_engine.observability import ranking_score_for_ioc

MODE_AUTO = "auto_source_priority"
MODE_DB_ONLY = "db_only"
MODE_LIVE_DIR_ONLY = "live_dir_only"
MODE_ARCHIVE_ONLY = "archive_only"
MODE_CHOICES = (
    MODE_AUTO,
    MODE_DB_ONLY,
    MODE_LIVE_DIR_ONLY,
    MODE_ARCHIVE_ONLY,
)

CONFIG_PATH = config_path("cape", "evidence_enrichment_rules.json")


@lru_cache(maxsize=1)
def _evidence_enrichment_config() -> dict[str, Any]:
    return load_json_config(str(CONFIG_PATH))


DERIVED_UPDATE_TARGETS = list(_evidence_enrichment_config()["derived_update_targets"])

ALLOWED_IOC_TYPES = set(_evidence_enrichment_config()["allowed_ioc_types"])

ATOMIC_IOC_INSERT_LIMITS = {
    "ip": 500,
    "domain": 500,
    "url": 500,
    "file": 500,
    "registry": 500,
    "mutex": 250,
    "process": 300,
}

TTP_PROCESSED_FIELD_LIMITS = {
    "executed_commands": 500,
    "scheduled_tasks": 250,
    "services": 250,
    "lolbins": 250,
    "process_chain": 500,
    "files_written": 500,
    "files_deleted": 500,
    "keys_written": 500,
    "keys_deleted": 500,
    "mutexes": 250,
    "resolved_apis": 1000,
    "file_extensions_touched": 500,
    "ransomware_indicators": 500,
    "credential_access_indicators": 500,
    "defense_evasion_indicators": 500,
}

ANALYSIS_ARTIFACT_GROUP_LIMITS = {
    "config_domains": 100,
    "config_ips": 100,
    "config_urls": 100,
    "config_file_paths": 100,
    "config_registry_keys": 100,
    "reported_file_paths": 100,
    "reported_process_names": 100,
    "reported_process_paths": 100,
    "bson_process_names": 100,
    "bson_process_paths": 100,
    "bson_registry_keys": 100,
    "enhanced_file_write": 100,
    "enhanced_file_execute": 100,
    "enhanced_file_delete": 100,
    "enhanced_file_copy": 50,
    "enhanced_file_move": 50,
    "enhanced_libraries": 50,
}

NORMALIZED_ARTIFACT_GROUP_LIMITS = {
    "ransom_notes": 100,
    "suspicious_connections": 100,
    "network_indicators": 100,
    "high_signal_extensions": 100,
}


@dataclass(frozen=True)
class CapeReportCandidate:
    sample_id: int
    analysis_run_id: int
    cape_task_id: int
    sha256: str
    raw_json: dict[str, Any]
    report_path: str | None


def _candidate_from_mapping(row: Any) -> CapeReportCandidate:
    return CapeReportCandidate(
        sample_id=int(row["sample_id"]),
        analysis_run_id=int(row["analysis_run_id"]),
        cape_task_id=int(row["cape_task_id"]),
        sha256=str(row["sha256"]),
        raw_json=dict(row["raw_json"] or {}),
        report_path=row.get("report_path"),
    )


def fetch_candidates(
    *,
    limit: int,
    sample_id: int | None = None,
    analysis_run_id: int | None = None,
    cape_task_id: int | None = None,
    include_enriched: bool = False,
) -> list[CapeReportCandidate]:
    filters = ["cr.raw_json IS NOT NULL", "cr.raw_json <> '{}'::jsonb"]
    params: dict[str, Any] = {"limit": limit}
    if sample_id is not None:
        filters.append("s.id = :sample_id")
        params["sample_id"] = sample_id
    if analysis_run_id is not None:
        filters.append("ar.id = :analysis_run_id")
        params["analysis_run_id"] = analysis_run_id
    if cape_task_id is not None:
        filters.append("cr.cape_task_id = :cape_task_id")
        params["cape_task_id"] = cape_task_id
    if (
        not include_enriched
        and sample_id is None
        and analysis_run_id is None
        and cape_task_id is None
    ):
        filters.append(
            "NOT (cr.unified_ioc ? 'detection_candidates' "
            "AND cr.unified_ioc ? 'endpoint_observability')"
        )

    query = text(
        f"""
        SELECT
          s.id AS sample_id,
          ar.id AS analysis_run_id,
          cr.cape_task_id,
          s.sha256,
          cr.raw_json,
          cr.report_path
        FROM cape_reports cr
        JOIN analysis_runs ar ON ar.id = cr.analysis_run_id
        JOIN samples s ON s.id = ar.sample_id
        WHERE {' AND '.join(filters)}
        ORDER BY cr.fetched_at DESC, cr.id DESC
        LIMIT :limit
        """
    )
    with session_scope() as session:
        rows = session.execute(query, params).mappings().all()
        return [_candidate_from_mapping(row) for row in rows]


def _archive_source_mode(archive_root: Path, external_archive_root: Path) -> str:
    try:
        if archive_root.resolve() == external_archive_root.resolve():
            return "external_archive"
    except OSError:
        pass
    return "local_archive"


def resolve_candidate_source(
    candidate: CapeReportCandidate,
    *,
    mode: str,
    analysis_root: Path,
    local_archive_root: Path,
    external_archive_root: Path,
    archive_root: Path | None = None,
) -> EvidenceSourceResolution:
    if mode == MODE_DB_ONLY:
        return resolve_db_only_source()
    if mode == MODE_LIVE_DIR_ONLY:
        return resolve_live_dir_source(
            cape_task_id=candidate.cape_task_id,
            analysis_root=analysis_root,
        )
    if mode == MODE_ARCHIVE_ONLY:
        if archive_root is None:
            raise ValueError("archive_root is required for archive-only mode")
        source_mode = _archive_source_mode(archive_root, external_archive_root)
        return resolve_archive_source(
            sample_id=candidate.sample_id,
            analysis_run_id=candidate.analysis_run_id,
            cape_task_id=candidate.cape_task_id,
            archive_root=archive_root,
            source_mode=source_mode,
        )
    return resolve_evidence_source(
        sample_id=candidate.sample_id,
        analysis_run_id=candidate.analysis_run_id,
        cape_task_id=candidate.cape_task_id,
        analysis_root=analysis_root,
        local_archive_root=local_archive_root,
        external_archive_root=external_archive_root,
    )


def _empty_summary(
    *,
    mode: str,
    dry_run: bool,
    external_archive_root: Path,
    external_archive_root_mounted: bool,
) -> dict[str, Any]:
    return {
        "mode": mode,
        "dry_run": dry_run,
        "selected": 0,
        "would_process_from_live_dir": 0,
        "would_process_from_local_archive": 0,
        "would_process_from_external_archive": 0,
        "would_process_from_db_only": 0,
        "would_process_db_only_missing_filesystem": 0,
        "missing_analysis_evidence": 0,
        "missing_analysis_dir": 0,
        "missing_archive": 0,
        "external_archive_root_mounted": external_archive_root_mounted,
        "external_archive_root": str(external_archive_root),
        "errors": 0,
        "archive_extraction_performed": False,
        "planned_db_updates": DERIVED_UPDATE_TARGETS,
        "items": [],
    }


def build_dry_run_plan(
    candidates: Iterable[CapeReportCandidate],
    *,
    mode: str,
    analysis_root: Path,
    local_archive_root: Path,
    external_archive_root: Path,
    archive_root: Path | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    external_mounted = is_external_archive_root_mounted(external_archive_root)
    summary = _empty_summary(
        mode=mode,
        dry_run=True,
        external_archive_root=external_archive_root,
        external_archive_root_mounted=external_mounted,
    )

    for candidate in candidates:
        summary["selected"] += 1
        try:
            resolution = resolve_candidate_source(
                candidate,
                mode=mode,
                analysis_root=analysis_root,
                local_archive_root=local_archive_root,
                external_archive_root=external_archive_root,
                archive_root=archive_root,
            )
        except Exception as exc:
            summary["errors"] += 1
            resolution = EvidenceSourceResolution(
                mode="error",
                status="error",
                reason=str(exc),
            )

        if resolution.mode == "live_dir":
            summary["would_process_from_live_dir"] += 1
        elif resolution.mode == "local_archive":
            summary["would_process_from_local_archive"] += 1
        elif resolution.mode == "external_archive":
            summary["would_process_from_external_archive"] += 1
        elif resolution.mode == "db_only":
            summary["would_process_from_db_only"] += 1
        elif resolution.mode == "missing_analysis_evidence":
            summary["missing_analysis_evidence"] += 1
            summary["would_process_db_only_missing_filesystem"] += 1
        elif resolution.mode == "missing_analysis_dir":
            summary["missing_analysis_dir"] += 1
        elif resolution.mode == "missing_archive":
            summary["missing_archive"] += 1

        item = {
            "sample_id": candidate.sample_id,
            "analysis_run_id": candidate.analysis_run_id,
            "cape_task_id": candidate.cape_task_id,
            "sha256": candidate.sha256,
            "base_evidence": "cape_reports.raw_json",
            "raw_json_will_be_overwritten": False,
            "source": resolution.to_dict(),
        }
        if verbose or resolution.status != "found" or summary["selected"] <= 20:
            summary["items"].append(item)

    return summary


def _norm_str(value: Any, *, lowercase: bool = True) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return cleaned.lower() if lowercase else cleaned


def _score_int(value: Any) -> int:
    try:
        return max(0, min(100, int(round(float(value)))))
    except Exception:
        return 0


def _stable_entity_id(ioc_type: str, ioc_value: str) -> int:
    digest = hashlib.blake2b(
        f"{ioc_type}:{ioc_value}".encode(),
        digest_size=8,
    ).digest()
    return int.from_bytes(digest, "big") & ((1 << 63) - 1) or 1


def _humanize_pattern(pattern_code: str) -> str:
    return pattern_code.replace("_", " ").strip().capitalize()


def _iter_artifact_values(value: Any) -> Iterable[str]:
    if isinstance(value, list):
        for item in value:
            yield from _iter_artifact_values(item)
        return
    if isinstance(value, dict):
        yield json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
        return
    normalized = _norm_str(value, lowercase=False)
    if normalized:
        yield normalized


def _upsert_domain(session, domain_value: str) -> Domain | None:
    domain_value = domain_value.strip().lower()
    if not domain_value:
        return None
    existing = session.execute(
        select(Domain).where(Domain.domain == domain_value)
    ).scalar_one_or_none()
    if existing:
        return existing
    domain = Domain(domain=domain_value)
    session.add(domain)
    session.flush()
    return domain


def _upsert_ip(session, ip_value: str) -> IPAddress | None:
    try:
        parsed_ip = ipaddress.ip_address(ip_value.strip("[]"))
    except Exception:
        return None
    existing = session.execute(
        select(IPAddress).where(IPAddress.ip == str(parsed_ip))
    ).scalar_one_or_none()
    if existing:
        return existing
    ip_obj = IPAddress(
        ip=str(parsed_ip),
        ip_version=parsed_ip.version,
        is_private=parsed_ip.is_private,
    )
    session.add(ip_obj)
    session.flush()
    return ip_obj


def _upsert_behavior_pattern(session, pattern_code: str, *, severity: int | None = None) -> None:
    description, default_severity = BEHAVIOR_PATTERN_DETAILS.get(
        pattern_code,
        (_humanize_pattern(pattern_code), 3),
    )
    existing = session.execute(
        select(BehaviorPattern).where(BehaviorPattern.pattern_code == pattern_code)
    ).scalar_one_or_none()
    if existing:
        existing.description = description
        existing.severity = int(severity if severity is not None else default_severity)
        existing.rule_version = "cape_evidence_enrichment_v1"
        return
    session.add(
        BehaviorPattern(
            pattern_code=pattern_code,
            description=description,
            severity=int(severity if severity is not None else default_severity),
            rule_version="cape_evidence_enrichment_v1",
        )
    )


def _insert_sample_ioc(
    session,
    *,
    sample_id: int,
    ioc_type: str,
    value: str,
    entity_id: int,
    source: str,
) -> int:
    if ioc_type not in ALLOWED_IOC_TYPES:
        return 0
    cleaned = _norm_str(value, lowercase=ioc_type not in {"file", "registry", "process"})
    if not cleaned:
        return 0
    session.add(
        SampleIoC(
            sample_id=sample_id,
            type=ioc_type,
            value=cleaned,
            entity_id=entity_id,
            source=source,
            confidence=ranking_score_for_ioc(ioc_type, cleaned),
        )
    )
    return 1


def _insert_atomic_iocs(session, result: EnrichmentResult, *, source: str) -> int:
    rows: list[SampleIoC] = []
    for ioc_type, values in result.atomic_iocs.items():
        if ioc_type not in ALLOWED_IOC_TYPES:
            continue
        for value in _prioritized_atomic_iocs(ioc_type, coerce_list(values)):
            if ioc_type == "domain":
                domain = _upsert_domain(session, value)
                if domain:
                    cleaned = _norm_str(value, lowercase=True)
                    if cleaned:
                        rows.append(
                            SampleIoC(
                                sample_id=result.sample_id,
                                type=ioc_type,
                                value=cleaned,
                                entity_id=domain.id,
                                source=source,
                                confidence=ranking_score_for_ioc(ioc_type, cleaned),
                            )
                        )
            elif ioc_type == "ip":
                ip_obj = _upsert_ip(session, value)
                if ip_obj:
                    cleaned = str(ip_obj.ip)
                    rows.append(
                        SampleIoC(
                            sample_id=result.sample_id,
                            type=ioc_type,
                            value=cleaned,
                            entity_id=ip_obj.id,
                            source=source,
                            confidence=ranking_score_for_ioc(ioc_type, cleaned),
                        )
                    )
            else:
                cleaned = _norm_str(value, lowercase=ioc_type not in {"file", "registry", "process"})
                if cleaned:
                    rows.append(
                        SampleIoC(
                            sample_id=result.sample_id,
                            type=ioc_type,
                            value=cleaned,
                            entity_id=_stable_entity_id(ioc_type, cleaned),
                            source=source,
                            confidence=ranking_score_for_ioc(ioc_type, cleaned),
                        )
                    )
    if rows:
        session.bulk_save_objects(rows)
    return len(rows)


def _prioritized_atomic_iocs(ioc_type: str, values: list[Any]) -> list[str]:
    lowercase = ioc_type not in {"file", "registry", "process"}
    deduped = dedupe_strings_preserve(values, lowercase=lowercase)
    limit = int(ATOMIC_IOC_INSERT_LIMITS.get(ioc_type, 500))
    if len(deduped) <= limit:
        return deduped

    def rank(value: str) -> tuple[float, int, int, str]:
        confidence = ranking_score_for_ioc(ioc_type, value)
        observable = 1 if confidence >= 0.8 else 0
        return (-confidence, -observable, min(len(value), 240), value)

    return sorted(deduped, key=rank)[:limit]


def _artifact_groups(result: EnrichmentResult) -> dict[str, list[str]]:
    processed = coerce_dict(result.processed_fields)
    analysis_artifacts = coerce_dict(processed.get("analysis_artifacts"))
    groups: dict[str, list[str]] = {
        "evidence_source_mode": [result.source_mode],
    }

    for key, value in analysis_artifacts.items():
        limit = ANALYSIS_ARTIFACT_GROUP_LIMITS.get(str(key))
        if limit is None:
            continue
        values = dedupe_strings_preserve(list(_iter_artifact_values(value)), lowercase=True)
        if values:
            groups[f"cape_{key}"] = values[:limit]

    normalized = coerce_dict(result.normalized_ioc)
    for key, limit in NORMALIZED_ARTIFACT_GROUP_LIMITS.items():
        values = dedupe_strings_preserve(coerce_list(normalized.get(key)), lowercase=True)
        if values:
            groups[key] = values[:limit]

    for pattern in result.behavior_patterns:
        normalized_pattern = _norm_str(pattern)
        if normalized_pattern:
            groups.setdefault("behavior_pattern", []).append(normalized_pattern)

    if result.warnings:
        groups["enrichment_warning"] = result.warnings[:100]
    if result.errors:
        groups["enrichment_error"] = result.errors[:100]

    return groups


def _insert_sample_artifacts(session, result: EnrichmentResult, *, source: str) -> int:
    rows: list[SampleArtifact] = []
    for artifact_type, values in _artifact_groups(result).items():
        for value in dedupe_strings_preserve(values, lowercase=True):
            rows.append(
                SampleArtifact(
                    sample_id=result.sample_id,
                    artifact_type=artifact_type,
                    artifact_value=value,
                    source=source,
                    confidence=0.20 if artifact_type in {"enrichment_warning", "enrichment_error"} else 1.0,
                )
            )
    if rows:
        session.bulk_save_objects(rows)
    return len(rows)


def _ttp_inference_for_result(result: EnrichmentResult, threat_intel: dict[str, Any] | None = None) -> dict[str, Any]:
    return infer_ttp_from_report(
        {
            **_bounded_ttp_processed_fields(result.processed_fields),
            "normalized": coerce_dict(result.normalized_ioc),
            "threat_intel": coerce_dict(threat_intel),
        }
    )


def _bounded_ttp_processed_fields(processed_fields: dict[str, Any]) -> dict[str, Any]:
    processed = coerce_dict(processed_fields)
    bounded: dict[str, Any] = {}
    for key, limit in TTP_PROCESSED_FIELD_LIMITS.items():
        value = processed.get(key)
        if isinstance(value, list):
            bounded[key] = value[:limit]
        elif value not in (None, "", [], {}):
            bounded[key] = value
    if isinstance(processed.get("attack_patterns"), dict):
        bounded["attack_patterns"] = processed["attack_patterns"]
    if isinstance(processed.get("signatures"), list):
        bounded["signatures"] = processed["signatures"][:250]
    return bounded


def _insert_attack_techniques(session, result: EnrichmentResult) -> int:
    normalized = coerce_dict(result.normalized_ioc)
    threat_intel = coerce_dict(result.unified_ioc.get("threat_intel"))
    attack_patterns = coerce_dict(normalized.get("attack_patterns"))
    ttps = set(dedupe_strings_preserve(coerce_list(threat_intel.get("ttps")) + coerce_list(normalized.get("ttps"))))
    ttp_inference = _ttp_inference_for_result(result, threat_intel)
    ttp_details = [
        item
        for item in coerce_list(ttp_inference.get("ttps"))
        if isinstance(item, dict) and item.get("ttp_id")
    ]
    ttps.update(str(item["ttp_id"]).lower() for item in ttp_details)
    for pattern, enabled in attack_patterns.items():
        if enabled and pattern in ATTACK_PATTERN_TO_TTP:
            ttps.add(ATTACK_PATTERN_TO_TTP[pattern].lower())
            _upsert_behavior_pattern(session, pattern)

    rows: list[SampleAttackTechnique] = []
    for technique in sorted(ttps):
        technique_upper = technique.upper()
        detail = next(
            (
                item
                for item in ttp_details
                if str(item.get("ttp_id") or "").upper() == technique_upper
            ),
            {},
        )
        rows.append(
            SampleAttackTechnique(
                sample_id=result.sample_id,
                technique=technique_upper,
                category=TTP_CATEGORY_MAP.get(technique_upper, "unknown"),
                confidence=float(detail.get("confidence") or 1.0),
            )
        )
    if rows:
        session.bulk_save_objects(rows)
    return len(rows)


def _scores_for_result(result: EnrichmentResult) -> dict[str, int]:
    normalized = coerce_dict(result.normalized_ioc)
    scores = coerce_dict(result.unified_ioc.get("scores"))
    defaults = _evidence_enrichment_config()["score_defaults"]
    return {
        "persistence_score": _score_int(normalized.get("persistence_score") or result.processed_fields.get("persistence_score")),
        "severity_score": _score_int(scores.get("severity_score") or normalized.get("severity_score") or result.processed_fields.get("severity_score")),
        "confidence_score": _score_int(scores.get("confidence_score") or normalized.get("confidence_score") or result.processed_fields.get("confidence_score")),
        "ransomware_score": _score_int(scores.get("threat_score") or normalized.get("ransomware_score") or normalized.get("severity_score")),
        "credential_score": int(defaults["credential_indicator_score"]) if coerce_list(normalized.get("credential_access_indicators")) else 0,
        "defense_evasion_score": int(defaults["defense_evasion_indicator_score"]) if coerce_list(normalized.get("defense_evasion_indicators")) else 0,
    }


def _replace_derived_sample_rows(session, result: EnrichmentResult) -> dict[str, int]:
    sample_id = result.sample_id
    session.execute(delete(SampleIoC).where(SampleIoC.sample_id == sample_id))
    session.execute(delete(SampleArtifact).where(SampleArtifact.sample_id == sample_id))
    session.execute(delete(SampleAttackTechnique).where(SampleAttackTechnique.sample_id == sample_id))
    session.execute(delete(SampleBehaviorScore).where(SampleBehaviorScore.sample_id == sample_id))
    session.flush()

    source = f"cape_evidence_enrichment:{result.source_mode}"
    iocs = _insert_atomic_iocs(session, result, source=source)
    artifacts = _insert_sample_artifacts(session, result, source=source)
    techniques = _insert_attack_techniques(session, result)
    score_values = _scores_for_result(result)
    now = datetime.now(UTC)
    session.add(
        SampleBehaviorScore(
            sample_id=sample_id,
            created_at=now,
            updated_at=now,
            **score_values,
        )
    )
    return {
        "sample_iocs": iocs,
        "sample_artifacts": artifacts,
        "sample_attack_techniques": techniques,
        "sample_behavior_scores": 1,
    }


def _enriched_ioc_payload(result: EnrichmentResult, resolution: EvidenceSourceResolution) -> dict[str, Any]:
    payload = dict(coerce_dict(result.unified_ioc))
    payload["normalized"] = coerce_dict(result.normalized_ioc)
    ttp_inference = _ttp_inference_for_result(result, coerce_dict(payload.get("threat_intel")))
    inferred_ttps = [
        str(item.get("ttp_id"))
        for item in coerce_list(ttp_inference.get("ttps"))
        if isinstance(item, dict) and item.get("ttp_id")
    ]
    threat_intel = coerce_dict(payload.get("threat_intel"))
    threat_intel["ttps"] = sorted(set(coerce_list(threat_intel.get("ttps"))) | set(inferred_ttps))
    threat_intel["ttp_inference_summary"] = ttp_inference.get("summary", {})
    payload["threat_intel"] = threat_intel
    payload["ttp_inference"] = ttp_inference
    payload["behavior_score"] = ttp_inference.get("behavior_score", 0)
    payload["detection_candidates"] = coerce_list(
        payload.get("detection_candidates")
        or result.detection_candidates
        or result.normalized_ioc.get("detection_candidates")
    )
    payload["endpoint_observability"] = coerce_dict(
        payload.get("endpoint_observability")
        or result.endpoint_observability
        or result.normalized_ioc.get("endpoint_observability")
    )
    payload["evidence_source"] = resolution.to_dict()
    payload["base_evidence"] = "cape_reports.raw_json"
    payload["raw_json_overwritten"] = False
    payload["missing_analysis_evidence"] = resolution.mode in {
        "missing_analysis_evidence",
        "missing_analysis_dir",
        "missing_archive",
    }
    if result.warnings:
        payload["warnings"] = result.warnings
    if result.errors:
        payload["errors"] = result.errors
    return sanitize_json_strings(payload)


def _update_cape_report_fields(report: CapeReport, result: EnrichmentResult, resolution: EvidenceSourceResolution) -> None:
    processed = coerce_dict(result.processed_fields)
    normalized = coerce_dict(result.normalized_ioc)
    payload = _enriched_ioc_payload(result, resolution)
    threat_intel = coerce_dict(payload.get("threat_intel"))
    scores = coerce_dict(payload.get("scores"))

    report.scheduled_tasks = normalized.get("scheduled_tasks") or processed.get("scheduled_tasks") or []
    report.services = normalized.get("services") or processed.get("services") or []
    report.lolbins = normalized.get("lolbins") or processed.get("lolbins") or []
    report.attack_patterns = normalized.get("attack_patterns") or processed.get("attack_patterns") or {}
    report.persistence_score = _score_int(normalized.get("persistence_score") or processed.get("persistence_score"))
    report.severity_score = _score_int(scores.get("severity_score") or normalized.get("severity_score") or processed.get("severity_score"))
    report.confidence_score = _score_int(scores.get("confidence_score") or normalized.get("confidence_score") or processed.get("confidence_score"))
    report.ransomware_indicators = normalized.get("ransomware_indicators") or processed.get("ransomware_indicators") or []
    report.credential_access_indicators = normalized.get("credential_access_indicators") or processed.get("credential_access_indicators") or []
    report.defense_evasion_indicators = normalized.get("defense_evasion_indicators") or processed.get("defense_evasion_indicators") or []
    report.process_chain = normalized.get("process_chain") or processed.get("process_chain") or []
    report.resolved_apis = normalized.get("resolved_apis") or processed.get("resolved_apis") or []
    report.file_extensions_touched = normalized.get("file_extensions_touched") or processed.get("file_extensions_touched") or []
    report.unified_ioc = payload
    report.unified_ioc_normalized = normalized
    report.unified_ioc_threat_intel = threat_intel
    report.unified_ioc_scores = scores
    report.sample_category = normalized.get("sample_category") or threat_intel.get("sample_category")
    report.family_hints = normalized.get("family_hints") or threat_intel.get("family_hints") or []
    report.campaign_features = threat_intel.get("campaign_features") or dict(_evidence_enrichment_config()["default_campaign_features"])
    report.campaign_ready = bool(threat_intel.get("campaign_ready"))
    report.etl_processed = True


def _upsert_ioc_report(
    session,
    *,
    result: EnrichmentResult,
    resolution: EvidenceSourceResolution,
    processed_report_path: str,
) -> None:
    payload = _enriched_ioc_payload(result, resolution)
    normalized = coerce_dict(result.normalized_ioc)
    threat_intel = coerce_dict(payload.get("threat_intel"))
    scores = coerce_dict(payload.get("scores"))
    now = datetime.now(UTC)
    existing = session.get(IOCReport, result.analysis_run_id)
    if existing:
        existing.processed_report_path = processed_report_path
        existing.sample_category = normalized.get("sample_category") or threat_intel.get("sample_category")
        existing.family_hints = normalized.get("family_hints") or threat_intel.get("family_hints") or []
        existing.campaign_features = threat_intel.get("campaign_features") or dict(_evidence_enrichment_config()["default_campaign_features"])
        existing.unified_ioc = payload
        existing.normalized_ioc = normalized
        existing.threat_intel = threat_intel
        existing.scores = scores
        existing.updated_at = now
        return
    session.add(
        IOCReport(
            analysis_run_id=result.analysis_run_id,
            processed_report_path=processed_report_path,
            sample_category=normalized.get("sample_category") or threat_intel.get("sample_category"),
            family_hints=normalized.get("family_hints") or threat_intel.get("family_hints") or [],
            campaign_features=threat_intel.get("campaign_features") or dict(_evidence_enrichment_config()["default_campaign_features"]),
            unified_ioc=payload,
            normalized_ioc=normalized,
            threat_intel=threat_intel,
            scores=scores,
            created_at=now,
            updated_at=now,
        )
    )


def _persist_enrichment_result_in_session(
    session,
    *,
    candidate: CapeReportCandidate,
    resolution: EvidenceSourceResolution,
    result: EnrichmentResult,
) -> dict[str, Any]:
    report = session.execute(
        select(CapeReport)
        .where(CapeReport.analysis_run_id == candidate.analysis_run_id)
        .with_for_update()
    ).scalar_one()
    sample = session.execute(
        select(Sample)
        .where(Sample.id == candidate.sample_id)
        .with_for_update()
    ).scalar_one()

    existing_ioc_report = session.get(IOCReport, candidate.analysis_run_id)
    processed_report_path = (
        existing_ioc_report.processed_report_path
        if existing_ioc_report is not None and existing_ioc_report.processed_report_path
        else report.report_path
    )
    if not processed_report_path:
        processed_report_path = f"cape_reports.raw_json:{candidate.analysis_run_id}"

    _update_cape_report_fields(report, result, resolution)
    _upsert_ioc_report(
        session,
        result=result,
        resolution=resolution,
        processed_report_path=processed_report_path,
    )
    row_counts = _replace_derived_sample_rows(session, result)
    sample.ioc_report_path = processed_report_path

    return {
        "processed_report_path": processed_report_path,
        "row_counts": row_counts,
        "raw_json_overwritten": False,
        "cape_report_id": report.id,
    }


def persist_enrichment_result_in_session(
    session,
    *,
    candidate: CapeReportCandidate,
    resolution: EvidenceSourceResolution,
    result: EnrichmentResult,
) -> dict[str, Any]:
    """Persist derived enrichment data using an existing transaction.

    This is the shared write path for CAPE report enrichment. It intentionally
    does not modify ``cape_reports.raw_json``.
    """
    return _persist_enrichment_result_in_session(
        session,
        candidate=candidate,
        resolution=resolution,
        result=result,
    )


def _persist_enrichment_result(
    *,
    candidate: CapeReportCandidate,
    resolution: EvidenceSourceResolution,
    result: EnrichmentResult,
) -> dict[str, Any]:
    with session_scope() as session:
        return _persist_enrichment_result_in_session(
            session,
            candidate=candidate,
            resolution=resolution,
            result=result,
        )


def build_enriched_ioc_payload(
    result: EnrichmentResult,
    resolution: EvidenceSourceResolution,
) -> dict[str, Any]:
    """Return the canonical enriched IoC payload without writing to the DB."""
    return _enriched_ioc_payload(result, resolution)


def _bundle_for_candidate(
    candidate: CapeReportCandidate,
    resolution: EvidenceSourceResolution,
    *,
    analysis_dir: Path | None,
) -> CapeEvidenceBundle:
    return CapeEvidenceBundle(
        sample_id=candidate.sample_id,
        analysis_run_id=candidate.analysis_run_id,
        cape_task_id=candidate.cape_task_id,
        raw_json=candidate.raw_json,
        source_mode=resolution.mode,
        source_path=resolution.path,
        analysis_dir=analysis_dir,
        sha256=candidate.sha256,
    )


def _analysis_dir_for_resolution(
    candidate: CapeReportCandidate,
    resolution: EvidenceSourceResolution,
    *,
    extract_temp_root: Path,
    keep_temp: bool,
) -> tuple[Path | None, Path | None]:
    if resolution.mode == "live_dir" and resolution.path is not None:
        return resolution.path, None
    if resolution.mode in {"local_archive", "external_archive"} and resolution.path is not None:
        extracted_root = safe_extract_tar_zst(
            archive_path=resolution.path,
            extract_temp_root=extract_temp_root,
            keep_temp=keep_temp,
        )
        return find_extracted_analysis_dir(extracted_root, candidate.cape_task_id), extracted_root
    return None, None


def _add_source_count(summary: dict[str, Any], resolution: EvidenceSourceResolution) -> None:
    if resolution.mode == "live_dir":
        summary["processed_from_live_dir"] += 1
    elif resolution.mode == "local_archive":
        summary["processed_from_local_archive"] += 1
    elif resolution.mode == "external_archive":
        summary["processed_from_external_archive"] += 1
    elif resolution.mode == "db_only":
        summary["processed_from_db_only"] += 1
    elif resolution.mode == "missing_analysis_evidence":
        summary["missing_analysis_evidence"] += 1
        summary["processed_db_only_missing_filesystem"] += 1
    elif resolution.mode == "missing_analysis_dir":
        summary["missing_analysis_dir"] += 1
        summary["processed_db_only_missing_filesystem"] += 1
    elif resolution.mode == "missing_archive":
        summary["missing_archive"] += 1
        summary["processed_db_only_missing_filesystem"] += 1


def execute_enrichment(
    candidates: Iterable[CapeReportCandidate],
    *,
    mode: str,
    analysis_root: Path,
    local_archive_root: Path,
    external_archive_root: Path,
    extract_temp_root: Path,
    keep_temp: bool,
    archive_root: Path | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    external_mounted = is_external_archive_root_mounted(external_archive_root)
    summary = {
        "mode": mode,
        "dry_run": False,
        "selected": 0,
        "processed": 0,
        "processed_from_live_dir": 0,
        "processed_from_local_archive": 0,
        "processed_from_external_archive": 0,
        "processed_from_db_only": 0,
        "processed_db_only_missing_filesystem": 0,
        "missing_analysis_evidence": 0,
        "missing_analysis_dir": 0,
        "missing_archive": 0,
        "external_archive_root_mounted": external_mounted,
        "external_archive_root": str(external_archive_root),
        "archive_extraction_performed": False,
        "raw_json_overwrites": 0,
        "updated_targets": DERIVED_UPDATE_TARGETS[:-1],
        "row_counts": {key: 0 for key in _evidence_enrichment_config()["row_count_keys"]},
        "errors": 0,
        "items": [],
    }

    for candidate in candidates:
        summary["selected"] += 1
        extracted_root: Path | None = None
        item: dict[str, Any] = {
            "sample_id": candidate.sample_id,
            "analysis_run_id": candidate.analysis_run_id,
            "cape_task_id": candidate.cape_task_id,
            "sha256": candidate.sha256,
            "base_evidence": "cape_reports.raw_json",
            "raw_json_will_be_overwritten": False,
        }
        try:
            resolution = resolve_candidate_source(
                candidate,
                mode=mode,
                analysis_root=analysis_root,
                local_archive_root=local_archive_root,
                external_archive_root=external_archive_root,
                archive_root=archive_root,
            )
            _add_source_count(summary, resolution)
            analysis_dir, extracted_root = _analysis_dir_for_resolution(
                candidate,
                resolution,
                extract_temp_root=extract_temp_root,
                keep_temp=keep_temp,
            )
            if extracted_root is not None:
                summary["archive_extraction_performed"] = True
                if keep_temp:
                    item["kept_temp_dir"] = str(extracted_root)

            bundle = _bundle_for_candidate(
                candidate,
                resolution,
                analysis_dir=analysis_dir,
            )
            result = extract_evidence_bundle(bundle)
            persist_info = _persist_enrichment_result(
                candidate=candidate,
                resolution=resolution,
                result=result,
            )
            summary["processed"] += 1
            summary["raw_json_overwrites"] += int(bool(persist_info["raw_json_overwritten"]))
            for key, value in persist_info["row_counts"].items():
                summary["row_counts"][key] += int(value)
            item.update(
                {
                    "status": "processed",
                    "source": resolution.to_dict(),
                    "result_counts": {
                        "iocs": sum(len(v) for v in result.atomic_iocs.values()),
                        "behavior_patterns": len(result.behavior_patterns),
                        "detection_candidates": len(result.detection_candidates),
                    },
                    "db": persist_info,
                }
            )
        except Exception as exc:
            summary["errors"] += 1
            item.update({"status": "error", "error": str(exc)})
        finally:
            if extracted_root is not None and not keep_temp:
                cleanup_extracted_tree(extracted_root)

        if verbose or item.get("status") != "processed" or summary["selected"] <= 20:
            summary["items"].append(item)

    return summary


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed


def _archive_root_arg(mode: str) -> bool:
    return mode == MODE_ARCHIVE_ONLY


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan CAPE raw-report reprocessing and evidence enrichment safely"
    )
    parser.add_argument("--dry-run", action="store_true", help="Plan only; do not update DB or extract archives")
    parser.add_argument("--limit", type=_positive_int, default=10)
    parser.add_argument("--sample-id", type=_positive_int)
    parser.add_argument("--analysis-run-id", type=_positive_int)
    parser.add_argument("--cape-task-id", type=_positive_int)
    parser.add_argument("--mode", choices=MODE_CHOICES)
    parser.add_argument("--analysis-root", type=Path, default=DEFAULT_ANALYSIS_ROOT)
    parser.add_argument("--local-archive-root", type=Path, default=DEFAULT_LOCAL_ARCHIVE_ROOT)
    parser.add_argument("--external-archive-root", type=Path, default=DEFAULT_EXTERNAL_ARCHIVE_ROOT)
    parser.add_argument("--extract-temp-root", type=Path, default=DEFAULT_EXTRACT_TEMP_ROOT)
    parser.add_argument("--keep-temp", action="store_true")
    parser.add_argument("--regenerate-reports", dest="regenerate_reports", action="store_true", default=False)
    parser.add_argument("--no-regenerate-reports", dest="regenerate_reports", action="store_false")
    parser.add_argument(
        "--include-enriched",
        action="store_true",
        help="Also select reports that already have top-level detection enrichment",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--archive-root", type=Path)
    return parser


def _mode_for_args(args: argparse.Namespace) -> str:
    return str(getattr(args, "mode", None) or MODE_AUTO)


def _optional_archive_root(args: argparse.Namespace) -> Path | None:
    return getattr(args, "archive_root", None)


def _finalize_payload(payload: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    payload["regenerate_reports"] = bool(args.regenerate_reports)
    payload["extract_temp_root"] = str(args.extract_temp_root)
    payload["keep_temp"] = bool(args.keep_temp)
    return payload


def run(args: argparse.Namespace) -> dict[str, Any]:
    mode = _mode_for_args(args)
    archive_root = _optional_archive_root(args)
    if _archive_root_arg(mode) and archive_root is None:
        raise SystemExit("--archive-root is required when --mode archive_only")
    candidates = fetch_candidates(
        limit=args.limit,
        sample_id=args.sample_id,
        analysis_run_id=args.analysis_run_id,
        cape_task_id=args.cape_task_id,
        include_enriched=bool(args.include_enriched),
    )
    if not args.dry_run:
        payload = execute_enrichment(
            candidates,
            mode=mode,
            analysis_root=args.analysis_root,
            local_archive_root=args.local_archive_root,
            external_archive_root=args.external_archive_root,
            extract_temp_root=args.extract_temp_root,
            keep_temp=bool(args.keep_temp),
            archive_root=archive_root,
            verbose=args.verbose,
        )
        return _finalize_payload(payload, args)

    payload = build_dry_run_plan(
        candidates,
        mode=mode,
        analysis_root=args.analysis_root,
        local_archive_root=args.local_archive_root,
        external_archive_root=args.external_archive_root,
        archive_root=archive_root,
        verbose=args.verbose,
    )
    return _finalize_payload(payload, args)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    settings = get_settings()
    configure_logging(settings.log_level)
    try:
        payload = run(args)
    except Exception as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
