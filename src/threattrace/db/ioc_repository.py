from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from threattrace.common.collections import coerce_dict, coerce_list
from threattrace.common.json_config import config_path, load_json_config
from threattrace.common.logging import get_logger
from threattrace.db.models import (
    AnalysisRun,
    BehaviorPattern,
    Domain,
    IOCReport,
    IPAddress,
    Sample,
    SampleArtifact,
    SampleAttackTechnique,
    SampleBehaviorScore,
    SampleIoC,
)
from threattrace.db.repositories import get_status_id
from threattrace.db.session import session_scope
from threattrace.etl.ioc_engine.observability import ranking_score_for_ioc

logger = get_logger(__name__)


IOC_REPOSITORY_CONFIG_PATH = config_path("cape", "evidence_enrichment_rules.json")


ALLOWED_IOC_TYPES = set(load_json_config(str(IOC_REPOSITORY_CONFIG_PATH))["allowed_ioc_types"])

TTP_CATEGORY_MAP = {
    "T1490": "impact",
    "T1547": "persistence",
    "T1547.001": "persistence",
    "T1053": "execution",
    "T1053.005": "execution",
    "T1003": "credential_access",
    "T1562": "defense_evasion",
    "T1486": "impact",
    "T1021": "lateral_movement",
    "T1055": "defense_evasion",
    "T1543": "persistence",
    "T1543.003": "persistence",
    "T1546": "persistence",
    "T1112": "defense_evasion",
    "T1059": "execution",
    "T1218": "defense_evasion",
    "T1105": "command_and_control",
    "T1070": "defense_evasion",
    "T1083": "discovery",
    "T1057": "discovery",
    "T1016": "discovery",
    "TTP0001": "impact",
    "TTP0002": "impact",
    "TTP0003": "defense_evasion",
    "TTP0004": "defense_evasion",
    "TTP0005": "persistence",
    "TTP0006": "persistence",
    "TTP0007": "execution",
    "TTP0008": "execution",
    "TTP0009": "defense_evasion",
    "TTP0010": "command_and_control",
    "TTP0011": "defense_evasion",
    "TTP0012": "discovery",
    "TTP0013": "discovery",
    "TTP0014": "discovery",
    "TTP0015": "custom",
}

ATTACK_PATTERN_TO_TTP = {
    "shadow_copy_deletion": "T1490",
    "registry_persistence": "T1547",
    "scheduled_tasks": "T1053",
    "credential_access": "T1003",
    "defender_tampering": "T1562",
    "crypto_activity": "T1486",
    "lateral_movement": "T1021",
    "process_injection": "T1055",
    "service_creation": "T1543",
    "backup_tampering": "T1490",
    "wmi_persistence": "T1546",
    "process_hollowing": "T1055",
}

BEHAVIOR_PATTERN_DETAILS = {
    "shadow_copy_deletion": ("Deletes shadow copies to block recovery", 5),
    "registry_persistence": ("Uses registry persistence mechanisms", 4),
    "scheduled_tasks": ("Creates or abuses scheduled tasks", 3),
    "credential_access": ("Accesses credential material or LSASS-like targets", 5),
    "defender_tampering": ("Attempts to tamper with Defender or EDR controls", 5),
    "crypto_activity": ("Exhibits crypto or encryption-like activity", 5),
    "lateral_movement": ("Shows lateral movement indicators", 4),
    "process_injection": ("Performs process injection style behavior", 5),
    "service_creation": ("Creates or abuses Windows services", 4),
    "backup_tampering": ("Tampers with backup or restore mechanisms", 5),
    "wmi_persistence": ("Uses WMI persistence style behavior", 4),
    "process_hollowing": ("Performs process hollowing or similar stealth execution", 5),
    "ransomware_extension_activity": ("Touches suspicious encrypted extension patterns", 4),
    "ransom_note_creation": ("Creates ransom note like artifacts", 4),
    "mass_file_modification": ("Modifies large numbers of files", 4),
    "lolbins_usage": ("Abuses living-off-the-land binaries", 3),
    "persistence_api_usage": ("Uses APIs commonly associated with persistence", 3),
    "defense_evasion": ("Uses APIs commonly associated with defense evasion", 4),
}


def _norm_str(x: Any) -> str | None:
    if not isinstance(x, str):
        return None
    v = x.strip().lower()
    return v or None


def _stable_entity_id(ioc_type: str, ioc_value: str) -> int:
    digest = hashlib.blake2b(
        f"{ioc_type}:{ioc_value}".encode(),
        digest_size=8,
    ).digest()
    entity_id = int.from_bytes(digest, "big") & ((1 << 63) - 1)
    return entity_id or 1


def _normalized_values(payload: dict[str, Any], *keys: str) -> list[str]:
    normalized = coerce_dict(
        payload.get("normalized")
        or payload.get("unified_ioc_normalized")
        or payload.get("normalized_ioc")
        or {}
    )

    values: list[str] = []
    for key in keys:
        for item in coerce_list(normalized.get(key)):
            value = _norm_str(item)
            if value:
                values.append(value)

    return sorted(set(values))


def _top_level_values(payload: dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        for item in coerce_list(payload.get(key)):
            value = _norm_str(item)
            if value:
                values.append(value)
    return sorted(set(values))


def _process_values(payload: dict[str, Any]) -> list[str]:
    values = _normalized_values(payload, "process_chain")

    if values:
        return values

    extracted: list[str] = []
    for item in coerce_list(payload.get("process_chain")):
        if not isinstance(item, dict):
            continue
        value = _norm_str(item.get("command_line") or item.get("process_name"))
        if value:
            extracted.append(value)

    extracted.extend(_top_level_values(payload, "executed_commands"))
    return sorted(set(extracted))


def _upsert_domain(session, domain_value: str):
    existing = session.execute(
        select(Domain).where(Domain.domain == domain_value)
    ).scalar_one_or_none()

    if existing:
        return existing

    domain = Domain(domain=domain_value)
    session.add(domain)
    session.flush()
    return domain


def _upsert_ip(session, ip_value: str):
    existing = session.execute(
        select(IPAddress).where(IPAddress.ip == ip_value)
    ).scalar_one_or_none()

    if existing:
        return existing

    try:
        parsed_ip = ipaddress.ip_address(ip_value)
    except Exception:
        return None

    ip_obj = IPAddress(
        ip=ip_value,
        ip_version=parsed_ip.version,
        is_private=parsed_ip.is_private,
    )
    session.add(ip_obj)
    session.flush()
    return ip_obj


def _link_sample_ioc(
    session,
    sample_id: int,
    ioc_type: str,
    ioc_value: str,
    entity_id: int | None = None,
    source: str = "ioc_engine",
    confidence: float | None = None,
):
    if ioc_type not in ALLOWED_IOC_TYPES:
        return

    if confidence is None:
        confidence = ranking_score_for_ioc(ioc_type, ioc_value)

    existing = session.execute(
        select(SampleIoC).where(
            SampleIoC.sample_id == sample_id,
            SampleIoC.type == ioc_type,
            SampleIoC.entity_id == entity_id,
            SampleIoC.value == ioc_value,
        )
    ).scalar_one_or_none()

    if existing:
        existing.source = source
        existing.confidence = max(float(existing.confidence or 0), float(confidence))
        return

    session.add(
        SampleIoC(
            sample_id=sample_id,
            type=ioc_type,
            value=ioc_value,
            entity_id=entity_id,
            source=source,
            confidence=confidence,
        )
    )


def _link_sample_artifact(
    session,
    sample_id: int,
    artifact_type: str,
    artifact_value: str,
    source: str = "cape_analysis",
):
    existing = session.execute(
        select(SampleArtifact).where(
            SampleArtifact.sample_id == sample_id,
            SampleArtifact.artifact_type == artifact_type,
            SampleArtifact.artifact_value == artifact_value,
        )
    ).scalar_one_or_none()

    if existing:
        return

    session.add(
        SampleArtifact(
            sample_id=sample_id,
            artifact_type=artifact_type,
            artifact_value=artifact_value,
            source=source,
            confidence=1.0,
        )
    )


def _to_score_int(value: Any) -> int:
    try:
        return max(0, min(100, int(round(float(value)))))
    except Exception:
        return 0


def _humanize_pattern(pattern_code: str) -> str:
    return pattern_code.replace("_", " ").strip().capitalize()


def _upsert_behavior_pattern(
    session,
    pattern_code: str,
    description: str,
    severity: int,
    rule_version: str = "ioc_engine_v1",
):
    existing = session.execute(
        select(BehaviorPattern).where(BehaviorPattern.pattern_code == pattern_code)
    ).scalar_one_or_none()

    if existing:
        existing.description = description
        existing.severity = severity
        existing.rule_version = rule_version
        return existing

    pattern = BehaviorPattern(
        pattern_code=pattern_code,
        description=description,
        severity=severity,
        rule_version=rule_version,
    )
    session.add(pattern)
    session.flush()
    return pattern


def _link_sample_attack_technique(
    session,
    sample_id: int,
    technique: str,
    category: str,
    confidence: float = 1.0,
):
    existing = session.execute(
        select(SampleAttackTechnique).where(
            SampleAttackTechnique.sample_id == sample_id,
            SampleAttackTechnique.technique == technique,
        )
    ).scalar_one_or_none()

    if existing:
        existing.category = category
        existing.confidence = confidence
        return

    session.add(
        SampleAttackTechnique(
            sample_id=sample_id,
            technique=technique,
            category=category,
            confidence=confidence,
        )
    )


def _upsert_sample_behavior_score(
    session,
    sample_id: int,
    scores: dict[str, Any],
):
    existing = session.execute(
        select(SampleBehaviorScore).where(SampleBehaviorScore.sample_id == sample_id)
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    values = {
        "persistence_score": _to_score_int(scores.get("persistence_score")),
        "severity_score": _to_score_int(scores.get("severity_score")),
        "confidence_score": _to_score_int(scores.get("confidence_score")),
        "ransomware_score": _to_score_int(scores.get("ransomware_score")),
        "credential_score": _to_score_int(scores.get("credential_score")),
        "defense_evasion_score": _to_score_int(scores.get("defense_evasion_score")),
    }

    if existing:
        existing.persistence_score = values["persistence_score"]
        existing.severity_score = values["severity_score"]
        existing.confidence_score = values["confidence_score"]
        existing.ransomware_score = values["ransomware_score"]
        existing.credential_score = values["credential_score"]
        existing.defense_evasion_score = values["defense_evasion_score"]
        existing.updated_at = now
        return

    session.add(
        SampleBehaviorScore(
            sample_id=sample_id,
            persistence_score=values["persistence_score"],
            severity_score=values["severity_score"],
            confidence_score=values["confidence_score"],
            ransomware_score=values["ransomware_score"],
            credential_score=values["credential_score"],
            defense_evasion_score=values["defense_evasion_score"],
            created_at=now,
            updated_at=now,
        )
    )


def upsert_ioc_report(
    processed_report_path: str,
    ioc_payload: dict[str, Any],
    sha256: str | None = None,
    sample_sha256: str | None = None,
    session=None,
    **kwargs,
) -> None:
    """
    Persist advanced IoC intelligence into PostgreSQL.

    Stores:
    - unified_ioc raw extraction
    - normalized IoCs
    - threat intel enrichment
    - scoring
    - family hints
    - sample category
    """

    if sha256 is None:
        sha256 = sample_sha256

    if sha256 is None:
        raise ValueError("sha256/sample_sha256 is required")

    if session is None:
        with session_scope() as managed_session:
            return upsert_ioc_report(
                processed_report_path=processed_report_path,
                ioc_payload=ioc_payload,
                sha256=sha256,
                session=managed_session,
            )

    # Resolve sample and latest analysis run for this sample
    sample = session.scalar(
        select(Sample).where(Sample.sha256 == sha256)
    )

    if not sample:
        logger.warning("No Sample found for sha256=%s", sha256)
        return None

    latest_run = session.scalar(
        select(AnalysisRun)
        .where(AnalysisRun.sample_id == sample.id)
        .order_by(AnalysisRun.id.desc())
        .limit(1)
    )

    if latest_run is None:
        logger.warning(
            "No AnalysisRun found for sample sha256=%s (IOCReport will be skipped, but IoC links will still be stored)",
            sha256,
        )
        latest_run = None

    # IOCReport is keyed by analysis_run_id (only if analysis_run exists)
    existing = None
    if latest_run is not None:
        existing = session.get(IOCReport, latest_run.id)

    payload = coerce_dict(ioc_payload)

    normalized = coerce_dict(
        payload.get("normalized")
        or payload.get("unified_ioc_normalized")
        or payload.get("normalized_ioc")
        or {}
    )
    normalized_domains = coerce_list(normalized.get("domains"))
    normalized_ips = coerce_list(normalized.get("ips"))
    normalized_urls = _normalized_values(payload, "urls")
    normalized_files = _normalized_values(payload, "dropped_files")
    normalized_registry = _normalized_values(payload, "registry_keys")
    normalized_mutexes = _normalized_values(payload, "mutexes")
    normalized_processes = _process_values(payload)

    normalized_domains = sorted({d.strip().lower() for d in normalized_domains if isinstance(d, str) and d.strip()})
    normalized_ips = sorted({i.strip() for i in normalized_ips if isinstance(i, str) and i.strip()})
    if not normalized_files:
        normalized_files = _top_level_values(payload, "files_written", "files_read", "files_deleted")
    if not normalized_registry:
        normalized_registry = _top_level_values(payload, "keys_written", "keys_read", "keys_deleted")
    if not normalized_mutexes:
        normalized_mutexes = _top_level_values(payload, "mutexes")
    if not normalized_urls:
        normalized_urls = _top_level_values(payload, "urls")

    threat_intel = coerce_dict(
        payload.get("threat_intel")
        or payload.get("unified_ioc_threat_intel")
        or {}
    )
    scores = coerce_dict(payload.get("scores") or payload.get("unified_ioc_scores"))
    family_hints = payload.get("family_hints")
    if not isinstance(family_hints, list):
        family_hints = []
    campaign_features = coerce_dict(payload.get("campaign_features"))
    analysis_artifacts = coerce_dict(payload.get("analysis_artifacts"))
    attack_patterns = coerce_dict(
        normalized.get("attack_patterns")
        or threat_intel.get("attack_patterns")
        or payload.get("attack_patterns")
        or {}
    )
    ttps = coerce_list(
        threat_intel.get("ttps")
        or normalized.get("ttps")
        or payload.get("ttps")
        or []
    )
    ttp_inference = coerce_dict(payload.get("ttp_inference"))
    ttp_details = [
        item
        for item in coerce_list(ttp_inference.get("ttps"))
        if isinstance(item, dict) and item.get("ttp_id")
    ]
    ttps = sorted(
        {
            str(item)
            for item in ttps
            if item
        }
        | {
            str(item["ttp_id"])
            for item in ttp_details
        }
    )
    if not ttps:
        ttps = sorted(
            {
                technique
                for pattern, technique in ATTACK_PATTERN_TO_TTP.items()
                if attack_patterns.get(pattern)
            }
        )
    sample_mb = coerce_dict(sample.malwarebazaar_data) if sample else {}
    artifact_groups = {
        "cape_payload_sha256": coerce_list(analysis_artifacts.get("cape_payload_hashes")),
        "analysis_file_sha256": coerce_list(analysis_artifacts.get("files_hashes")),
        "procdump_sha256": coerce_list(analysis_artifacts.get("procdump_hashes")),
        "selfextracted_sha256": coerce_list(analysis_artifacts.get("selfextracted_hashes")),
        "digisig_signer": coerce_list(analysis_artifacts.get("digisig_signers")),
        "pcap_sha256": [analysis_artifacts.get("pcap_sha256")] if analysis_artifacts.get("pcap_sha256") else [],
        "decrypted_pcap_sha256": [analysis_artifacts.get("decrypted_pcap_sha256")] if analysis_artifacts.get("decrypted_pcap_sha256") else [],
        "mixed_pcap_sha256": [analysis_artifacts.get("mixed_pcap_sha256")] if analysis_artifacts.get("mixed_pcap_sha256") else [],
        "cape_process_name": coerce_list(analysis_artifacts.get("reported_process_names")),
        "cape_process_path": coerce_list(analysis_artifacts.get("reported_process_paths")),
        "cape_config_family": coerce_list(analysis_artifacts.get("cape_config_families")),
        "loaded_library": coerce_list(analysis_artifacts.get("enhanced_libraries")),
        "service_name": coerce_list(analysis_artifacts.get("enhanced_services")),
        "bson_api_name": coerce_list(analysis_artifacts.get("bson_api_names")),
        "bson_user_agent": coerce_list(analysis_artifacts.get("bson_user_agents")),
        "ttp": ttps,
        "family_hint": coerce_list(family_hints),
        "campaign_protocol": coerce_list(campaign_features.get("protocols")),
        "campaign_dns_activity": coerce_list(campaign_features.get("dns_activity")),
        "campaign_suspicious_connection": coerce_list(campaign_features.get("suspicious_connections")),
        "suspicious_domain": coerce_list(threat_intel.get("suspicious_domains")),
        "sample_md5": [payload.get("md5")] if payload.get("md5") else [],
        "sample_sha1": [payload.get("sha1")] if payload.get("sha1") else [],
        "sample_sha256": [payload.get("sha256")] if payload.get("sha256") else [],
        "malwarebazaar_tag": coerce_list(sample_mb.get("tags")),
        "malware_family": [sample_mb.get("signature")] if sample_mb.get("signature") else [],
        "malware_file_type": [sample_mb.get("file_type")] if sample_mb.get("file_type") else [],
        "malware_reporter": [sample_mb.get("reporter")] if sample_mb.get("reporter") else [],
        "malware_origin_country": [sample_mb.get("origin_country")] if sample_mb.get("origin_country") else [],
    }

    sample_category = payload.get("sample_category")
    if not isinstance(sample_category, str):
        sample_category = None

    now = datetime.now(UTC)

    if latest_run is not None:
        if existing:
            existing.processed_report_path = processed_report_path
            existing.sample_category = sample_category
            existing.family_hints = family_hints
            existing.campaign_features = campaign_features
            existing.unified_ioc = payload
            existing.normalized_ioc = normalized
            existing.threat_intel = threat_intel
            existing.scores = scores
            existing.updated_at = now
        else:
            existing = IOCReport(
                analysis_run_id=latest_run.id,
                processed_report_path=processed_report_path,
                sample_category=sample_category,
                family_hints=family_hints,
                campaign_features=campaign_features,
                unified_ioc=payload,
                normalized_ioc=normalized,
                threat_intel=threat_intel,
                scores=scores,
                created_at=now,
                updated_at=now,
            )
            session.add(existing)

    sample = session.scalar(
        select(Sample).where(Sample.sha256 == sha256)
    )
    if sample:
        sample.ioc_report_path = processed_report_path

    if latest_run:
        latest_run.status_id = get_status_id(session, "etl_completed")
        latest_run.error_stage = None
        latest_run.error_message = None

        now_ts = datetime.now(UTC)

        if hasattr(latest_run, "etl_completed_at"):
            latest_run.etl_completed_at = now_ts

        # ensure pipeline is fully closed
        if hasattr(latest_run, "finished_at") and latest_run.finished_at is None:
            latest_run.finished_at = now_ts

    if sample:
        _upsert_sample_behavior_score(session, sample.id, scores)

        for pattern_code, enabled in attack_patterns.items():
            if not enabled:
                continue
            description, severity = BEHAVIOR_PATTERN_DETAILS.get(
                pattern_code,
                (_humanize_pattern(pattern_code), 3),
            )
            _upsert_behavior_pattern(
                session,
                pattern_code=pattern_code,
                description=description,
                severity=severity,
            )

        for technique in ttps:
            normalized_technique = _norm_str(technique)
            if not normalized_technique:
                continue
            detail = next(
                (
                    item
                    for item in ttp_details
                    if str(item.get("ttp_id") or "").upper() == normalized_technique.upper()
                ),
                {},
            )
            _link_sample_attack_technique(
                session,
                sample_id=sample.id,
                technique=normalized_technique.upper(),
                category=TTP_CATEGORY_MAP.get(normalized_technique.upper(), "unknown"),
                confidence=float(detail.get("confidence") or 1.0),
            )

        for domain_value in normalized_domains:
            domain_obj = _upsert_domain(session, domain_value)
            if not domain_obj:
                continue
            _link_sample_ioc(
                session,
                sample_id=sample.id,
                ioc_type="domain",
                ioc_value=domain_value,
                entity_id=domain_obj.id,
            )

        for ip_value in normalized_ips:
            ip_obj = _upsert_ip(session, ip_value)
            if not ip_obj:
                continue
            _link_sample_ioc(
                session,
                sample_id=sample.id,
                ioc_type="ip",
                ioc_value=ip_value,
                entity_id=ip_obj.id,
            )

        for ioc_type, values in (
            ("url", normalized_urls),
            ("file", normalized_files),
            ("registry", normalized_registry),
            ("mutex", normalized_mutexes),
            ("process", normalized_processes),
        ):
            for value in values:
                _link_sample_ioc(
                    session,
                    sample_id=sample.id,
                    ioc_type=ioc_type,
                    ioc_value=value,
                    entity_id=_stable_entity_id(ioc_type, value),
                )

        for artifact_type, values in artifact_groups.items():
            for item in values:
                value = _norm_str(item)
                if not value:
                    continue
                _link_sample_artifact(
                    session,
                    sample_id=sample.id,
                    artifact_type=artifact_type,
                    artifact_value=value,
                )
