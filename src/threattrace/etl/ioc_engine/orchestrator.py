from __future__ import annotations

import time
from functools import lru_cache
from pathlib import Path
from typing import Any

from threattrace.common import get_logger
from threattrace.common.collections import coerce_dict, coerce_list, dedupe_preserve
from threattrace.common.json_config import load_json_config

from .api import extract_api_iocs
from .filesystem import extract_filesystem_iocs
from .network import extract_network_iocs
from .normalizer import normalize_iocs
from .process import extract_process_iocs
from .registry import extract_registry_iocs
from .scoring import calculate_threat_score, determine_risk_level
from .threat_intel import default_family_hints, enrich_threat_intelligence

logger = get_logger(__name__)
ROOT_DIR = Path(__file__).resolve().parents[4]
ORCHESTRATOR_CONFIG_PATH = ROOT_DIR / "config" / "detection" / "orchestrator_rules.json"


@lru_cache(maxsize=1)
def _orchestrator_config() -> dict[str, Any]:
    return load_json_config(str(ORCHESTRATOR_CONFIG_PATH))


# Harden: Extractor wrapper to preserve partial outputs on extractor failure
def _run_extractor_safe(
    name: str,
    extractor,
    report: dict[str, Any],
) -> dict[str, Any] | list[Any]:
    try:
        result = extractor(report)

        if isinstance(result, dict):
            return coerce_dict(result)

        if isinstance(result, list):
            return coerce_list(result)

        logger.warning(
            "IoC extractor '%s' returned unexpected type=%s",
            name,
            type(result).__name__,
        )
        return {}

    except Exception as exc:
        logger.exception(
            "IoC extractor '%s' failed: %s",
            name,
            exc,
        )
        return {}


def _truncate(value: list[Any], limit: int | None = None) -> list[Any]:
    limit = int(limit or _orchestrator_config()["max_ioc_items_per_category"])
    return value[:limit]


def _sanitize_extractor_output(raw_iocs: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}

    for category, payload in coerce_dict(raw_iocs).items():
        try:
            if isinstance(payload, dict):
                cleaned_payload: dict[str, Any] = {}

                for key, values in payload.items():
                    try:
                        cleaned_payload[str(key)] = _truncate(
                            dedupe_preserve(coerce_list(values))
                        )
                    except Exception:
                        cleaned_payload[str(key)] = []

                sanitized[str(category)] = cleaned_payload

            elif isinstance(payload, list):
                sanitized[str(category)] = _truncate(
                    dedupe_preserve(coerce_list(payload))
                )

            else:
                sanitized[str(category)] = payload

        except Exception:
            logger.exception(
                "IoC sanitization failure for category '%s'",
                category,
            )
            sanitized[str(category)] = {}

    return sanitized


def _validate_scores(scores: dict[str, Any]) -> dict[str, Any]:
    validated = dict(scores or {})

    for key in (
        "threat_score",
        "severity_score",
        "confidence_score",
    ):
        value = validated.get(key, 0)

        try:
            value = float(value)
        except Exception:
            value = 0

        value = max(0, min(100, value))
        validated[key] = value

    validated["risk_level"] = determine_risk_level(validated["threat_score"])

    return validated


def _validate_threat_intel(threat_intel: dict[str, Any]) -> dict[str, Any]:
    validated = dict(threat_intel or {})
    default_threat_intel = _orchestrator_config()["default_threat_intel"]

    validated["ttps"] = dedupe_preserve(coerce_list(validated.get("ttps", [])))
    validated["family_hints"] = dedupe_preserve(
        coerce_list(validated.get("family_hints", []))
    )
    validated["suspicious_domains"] = dedupe_preserve(
        coerce_list(validated.get("suspicious_domains", []))
    )
    validated["ransom_notes"] = dedupe_preserve(
        coerce_list(validated.get("ransom_notes", []))
    )

    if not isinstance(validated.get("campaign_features"), dict):
        validated["campaign_features"] = dict(default_threat_intel.get("campaign_features", {}))

    if validated.get("sample_category") is None:
        validated["sample_category"] = default_threat_intel.get("sample_category", "unknown")

    validated["campaign_ready"] = bool(
        validated.get("campaign_ready", False)
    )

    if not validated["family_hints"]:
        validated["family_hints"] = dedupe_preserve(
            default_family_hints(
                sample_category=validated.get("sample_category"),
                suspicious_domains=coerce_list(validated.get("suspicious_domains", [])),
                ransom_notes=coerce_list(validated.get("ransom_notes", [])),
            )
        )

    return validated


def finalize_enriched_view(normalized: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized = coerce_dict(normalized)
    threat_intel = enrich_threat_intelligence(normalized)
    threat_intel = _validate_threat_intel(threat_intel)

    threat_intel.setdefault(
        "suspicious_domains",
        coerce_list(normalized.get("suspicious_domains", [])),
    )
    threat_intel.setdefault(
        "ransom_notes",
        coerce_list(normalized.get("ransom_notes", [])),
    )
    threat_intel.setdefault(
        "suspicious_connections",
        coerce_list(normalized.get("suspicious_connections", [])),
    )

    scoring_input = dict(normalized)
    scoring_input.update(threat_intel)
    scoring_input.setdefault(
        "suspicious_connections",
        coerce_list(normalized.get("suspicious_connections", [])),
    )
    scores = _validate_scores(calculate_threat_score(scoring_input))
    return threat_intel, scores


def extract_iocs(report: dict[str, Any]) -> dict[str, Any]:
    """
    Unified IoC Engine entrypoint.

    Hardened pipeline:
        RAW CAPE Report
            ↓
        Specialized extractors
            ↓
        Sanitization / dedupe / truncation
            ↓
        Normalization
            ↓
        Threat intelligence enrichment
            ↓
        Score validation
            ↓
        Final unified intelligence object
    """
    t0 = time.perf_counter()

    try:
        raw_iocs = {
            "network": _run_extractor_safe(
                "network",
                extract_network_iocs,
                report,
            ),
            "filesystem": _run_extractor_safe(
                "filesystem",
                extract_filesystem_iocs,
                report,
            ),
            "registry": _run_extractor_safe(
                "registry",
                extract_registry_iocs,
                report,
            ),
            "process": _run_extractor_safe(
                "process",
                extract_process_iocs,
                report,
            ),
            "api": _run_extractor_safe(
                "api",
                extract_api_iocs,
                report,
            ),
        }

    except Exception as exc:
        logger.exception(
            "IoC raw extraction failure: %s",
            exc,
        )

        return {
            "raw": {},
            "normalized": {},
            "threat_intel": dict(_orchestrator_config()["default_threat_intel"]),
            "scores": dict(_orchestrator_config()["default_scores"]),
        }

    try:
        sanitized_raw = _sanitize_extractor_output(raw_iocs)
        t_sanitize = time.perf_counter()
    except Exception as exc:
        logger.exception(
            "IoC sanitization global failure: %s",
            exc,
        )
        sanitized_raw = {}

    try:
        normalized = normalize_iocs(sanitized_raw)
        t_normalize = time.perf_counter()
        for key in _orchestrator_config()["truncate_normalized_keys"]:
            if isinstance(normalized.get(key), list):
                normalized[key] = _truncate(normalized[key])
    except Exception as exc:
        logger.exception(
            "IoC normalization failure: %s",
            exc,
        )
        normalized = {}

    try:
        threat_intel, scores = finalize_enriched_view(normalized)
        t_ti = time.perf_counter()

    except Exception as exc:
        logger.exception(
            "Threat intelligence enrichment failure: %s",
            exc,
        )
        threat_intel = dict(_orchestrator_config()["default_threat_intel"])
        scores = dict(_orchestrator_config()["default_scores"])

    try:
        t_score = time.perf_counter()
    except Exception as exc:
        logger.exception(
            "Threat scoring failure: %s",
            exc,
        )
        scores = dict(_orchestrator_config()["default_scores"])

    metrics = {
        "timings_ms": {
            "sanitize": int((t_sanitize - t0) * 1000) if 't_sanitize' in locals() else 0,
            "normalize": int((t_normalize - t_sanitize) * 1000) if 't_normalize' in locals() and 't_sanitize' in locals() else 0,
            "threat_intel": int((t_ti - t_normalize) * 1000) if 't_ti' in locals() and 't_normalize' in locals() else 0,
            "scoring": int((t_score - t_ti) * 1000) if 't_score' in locals() and 't_ti' in locals() else 0,
            "total": int((time.perf_counter() - t0) * 1000),
        },
        "sizes": {
            "raw_categories": len(coerce_dict(sanitized_raw)),
            "normalized_keys": len(coerce_dict(normalized)),
        },
    }

    return {
        "raw": sanitized_raw,
        "normalized": coerce_dict(normalized),
        "threat_intel": _validate_threat_intel(threat_intel),
        "scores": coerce_dict(scores),
        "metrics": metrics,
    }
