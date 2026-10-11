from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from threattrace.common.json_config import load_json_config

ROOT_DIR = Path(__file__).resolve().parents[4]
CONFIG_PATH = ROOT_DIR / "config" / "detection" / "observability_rules.json"


@lru_cache(maxsize=1)
def _observability_config() -> dict[str, Any]:
    payload = load_json_config(str(CONFIG_PATH))
    return {
        "regex": {
            str(name): re.compile(str(pattern), re.IGNORECASE)
            for name, pattern in payload.get("regex", {}).items()
        },
        "registry_hive_aliases": {
            str(key): str(value)
            for key, value in payload.get("registry_hive_aliases", {}).items()
        },
        "prioritized_behaviors": {
            str(item) for item in payload.get("prioritized_behaviors", [])
        },
        "behavior_categories": {
            str(item) for item in payload.get("behavior_categories", [])
        }
        | {str(item) for item in payload.get("prioritized_behaviors", [])},
        "atomic_ioc_categories": {
            str(item) for item in payload.get("atomic_ioc_categories", [])
        },
        "ioc_type_rules": payload.get("ioc_type_rules", {}),
        "behavior_rules": payload.get("behavior_rules", {}),
        "ranking_score_by_risk": {
            str(key): float(value)
            for key, value in payload.get("ranking_score_by_risk", {}).items()
        },
        "behavior_ranking_score": float(payload.get("behavior_ranking_score", 0.95)),
    }


def _regex(name: str) -> re.Pattern[str]:
    return _observability_config()["regex"][name]


def clean_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = _regex("control_chars").sub("", value).strip()
    return cleaned or None


def normalize_ip(value: Any, *, public_only: bool = False) -> str | None:
    cleaned = clean_string(value)
    if not cleaned:
        return None
    try:
        addr = ipaddress.ip_address(cleaned.strip("[]"))
    except ValueError:
        return None
    if public_only and (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_link_local
    ):
        return None
    return str(addr)


def normalize_domain(value: Any) -> str | None:
    cleaned = clean_string(value)
    if not cleaned:
        return None
    try:
        parsed = urlparse(cleaned)
        host = parsed.hostname if parsed.scheme and parsed.netloc else cleaned
    except ValueError:
        return None
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    if normalize_ip(host):
        return None
    if not _regex("domain").match(host):
        return None
    return host


def normalize_url(value: Any) -> str | None:
    cleaned = clean_string(value)
    if not cleaned:
        return None
    try:
        parsed = urlparse(cleaned)
    except ValueError:
        return None
    if parsed.scheme and parsed.netloc:
        try:
            host = (parsed.hostname or "").lower()
            port_value = parsed.port
        except ValueError:
            return None
        if not host:
            return None
        port = f":{port_value}" if port_value else ""
        path = parsed.path or ""
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{parsed.scheme.lower()}://{host}{port}{path}{query}".rstrip("/")
    return cleaned.lower().rstrip("/") or None


def normalize_windows_path(value: Any) -> str | None:
    cleaned = clean_string(value)
    if not cleaned:
        return None
    normalized = cleaned.replace("/", "\\").strip().strip('"').lower()
    if normalized.startswith("\\\\?\\unc\\"):
        normalized = "\\\\" + normalized[len("\\\\?\\unc\\"):]
    for prefix in ("\\\\??\\\\", "\\??\\", "\\\\?\\", "\\?\\"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    while "\\\\" in normalized and not normalized.startswith("\\\\"):
        normalized = normalized.replace("\\\\", "\\")
    return normalized or None


def normalize_registry_key(value: Any) -> str | None:
    normalized = normalize_windows_path(value)
    if not normalized:
        return None
    for alias, full_name in _observability_config()["registry_hive_aliases"].items():
        if normalized == alias or normalized.startswith(alias + "\\"):
            return full_name + normalized[len(alias):]
    if normalized.startswith("\\registry\\machine\\"):
        return "hkey_local_machine\\" + normalized[len("\\registry\\machine\\"):]
    if normalized.startswith("\\registry\\user\\"):
        return "hkey_users\\" + normalized[len("\\registry\\user\\"):]
    return normalized


def classify_ioc_observability(ioc_type: str, value: str) -> dict[str, Any]:
    ioc_type = (ioc_type or "").lower()
    value_l = (value or "").lower()
    rules = _observability_config()["ioc_type_rules"]
    if ioc_type in {"ip", "domain", "url"}:
        rule = rules["network"]
        return {
            "endpoint_observable": bool(rule["endpoint_observable"]),
            "observability": list(rule["observability"]),
            "suggested_detector": str(rule["suggested_detector"]),
            "false_positive_risk": str(rule["false_positive_risk"]),
            "generalization_value": str(rule["generalization_value"]),
        }
    rule = rules.get(ioc_type, rules["default"])
    if "match_mode" not in rule:
        return {
            "endpoint_observable": bool(rule["endpoint_observable"]),
            "observability": list(rule["observability"]),
            "suggested_detector": str(rule["suggested_detector"]),
            "false_positive_risk": str(rule["false_positive_risk"]),
            "generalization_value": str(rule["generalization_value"]),
        }
    matched = False
    if rule["match_mode"] == "regex":
        matched = bool(_regex(str(rule["match_regex"])).search(value_l))
    elif rule["match_mode"] == "contains_any":
        matched = any(str(item) in value_l for item in rule.get("match_values", []))
    return {
        "endpoint_observable": bool(rule["endpoint_observable"]),
        "observability": list(rule["observability"]),
        "suggested_detector": str(rule["suggested_detector"]),
        "false_positive_risk": str(rule["risk_if_match"] if matched else rule["risk_else"]),
        "generalization_value": str(rule["generalization_if_match"] if matched else rule["generalization_else"]),
    }


def classify_behavior_observability(pattern: str) -> dict[str, Any]:
    pattern = (pattern or "").lower()
    behavior_rules = _observability_config()["behavior_rules"]
    if pattern in _observability_config()["prioritized_behaviors"]:
        rule = behavior_rules["prioritized"]
        risk = "low" if pattern in set(behavior_rules.get("prioritized_low_risk_patterns", [])) else str(rule["false_positive_risk"])
        return {
            "endpoint_observable": bool(rule["endpoint_observable"]),
            "observability": list(rule["observability"]),
            "suggested_detector": str(rule["suggested_detector"]),
            "false_positive_risk": risk,
            "generalization_value": str(rule["generalization_value"]),
        }
    rule = behavior_rules["default"]
    return {
        "endpoint_observable": bool(rule["endpoint_observable"]),
        "observability": list(rule["observability"]),
        "suggested_detector": str(rule["suggested_detector"]),
        "false_positive_risk": str(rule["false_positive_risk"]),
        "generalization_value": str(rule["generalization_value"]),
    }


def ranking_score_for_ioc(ioc_type: str, value: str) -> float:
    metadata = classify_ioc_observability(ioc_type, value)
    risk = str(metadata["false_positive_risk"])
    scores = _observability_config()["ranking_score_by_risk"]
    return float(scores.get(risk, scores["unknown"]))


def build_detection_candidate(
    *,
    category: str,
    value: str,
    source: str,
    sample_refs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    config = _observability_config()
    if category in config["behavior_categories"]:
        metadata = classify_behavior_observability(category)
        if category in config["prioritized_behaviors"]:
            ranking_score = config["behavior_ranking_score"]
        else:
            risk = str(metadata["false_positive_risk"])
            ranking_score = config["ranking_score_by_risk"].get(
                risk, config["ranking_score_by_risk"]["unknown"]
            )
        candidate_type = "behavioral_candidate"
    elif category in config["atomic_ioc_categories"]:
        metadata = classify_ioc_observability(category, value)
        ranking_score = ranking_score_for_ioc(category, value)
        candidate_type = "atomic_candidate"
    else:
        metadata = classify_ioc_observability(category, value)
        ranking_score = ranking_score_for_ioc(category, value)
        candidate_type = "context_candidate"
    return {
        "type": candidate_type,
        "category": category,
        "value": value,
        "source": source,
        "ranking_score": ranking_score,
        "sample_refs": sample_refs or [],
        **metadata,
    }
