from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from threattrace.common.json_config import config_path, load_json_config

ROOT_DIR = Path(__file__).resolve().parents[4]
CONFIG_PATH = config_path("detection", "threat_intel_rules.json")


@lru_cache(maxsize=1)
def _threat_intel_config() -> dict[str, Any]:
    return load_json_config(str(CONFIG_PATH))


def _has_attack_patterns(normalized: dict[str, Any], patterns: list[str], *, mode: str) -> bool:
    attack_patterns = normalized.get("attack_patterns", {}) or {}
    if mode == "all":
        return all(bool(attack_patterns.get(pattern)) for pattern in patterns)
    if mode == "any":
        return any(bool(attack_patterns.get(pattern)) for pattern in patterns)
    if mode == "none":
        return not any(bool(attack_patterns.get(pattern)) for pattern in patterns)
    return False


def _has_nonempty_lists(normalized: dict[str, Any], keys: list[str], *, mode: str) -> bool:
    if mode == "all":
        return all(bool(normalized.get(key)) for key in keys)
    if mode == "any":
        return any(bool(normalized.get(key)) for key in keys)
    return False


def default_family_hints(*, sample_category: str | None, suspicious_domains: list[Any], ransom_notes: list[Any]) -> list[str]:
    hints: list[str] = []
    if ransom_notes:
        hints.append("Ransom-note-artifact")
    if suspicious_domains:
        hints.append("Suspicious-C2-Infrastructure")
    if sample_category in {"ransomware_locker", "ransomware_extortion", "ransomware_worm"}:
        hints.append("Generic-modern-ransomware")
    return sorted(set(hints))


def map_ttps(normalized: dict[str, Any]) -> list[str]:
    attack_patterns = normalized.get("attack_patterns", {}) or {}
    config = _threat_intel_config()
    ttps: list[str] = []

    for pattern, technique in config["attack_ttps"].items():
        if attack_patterns.get(pattern):
            ttps.append(str(technique))

    for extra in config.get("extra_ttp_sources", []):
        if normalized.get(extra["normalized_key"]):
            ttps.append(str(extra["ttp"]))

    return sorted(set(ttps))


def classify_sample(normalized: dict[str, Any]) -> str:
    for rule in _threat_intel_config().get("sample_classification_rules", []):
        if rule.get("all_attack_patterns") and not _has_attack_patterns(normalized, list(rule["all_attack_patterns"]), mode="all"):
            continue
        if rule.get("any_attack_patterns") and not _has_attack_patterns(normalized, list(rule["any_attack_patterns"]), mode="any"):
            continue
        if rule.get("none_attack_patterns") and not _has_attack_patterns(normalized, list(rule["none_attack_patterns"]), mode="none"):
            continue
        if rule.get("any_normalized_nonempty") and not _has_nonempty_lists(normalized, list(rule["any_normalized_nonempty"]), mode="any"):
            continue
        return str(rule["category"])

    return "unknown"


def detect_family_hints(normalized: dict[str, Any]) -> list[str]:
    config = _threat_intel_config()
    hints: list[str] = []

    extensions = [str(e).lower() for e in (normalized.get("file_extensions_touched", []) or [])]
    suspicious_domains = [str(d).lower() for d in (normalized.get("suspicious_domains", []) or [])]
    ransom_notes = [str(r).lower() for r in (normalized.get("ransom_notes", []) or [])]
    mutexes = [str(m).lower() for m in (normalized.get("mutexes", []) or [])]
    lower_lists = {
        "file_extensions_touched": extensions,
        "suspicious_domains": suspicious_domains,
        "ransom_notes": ransom_notes,
        "mutexes": mutexes,
        "suspicious_connections": [str(c).lower() for c in (normalized.get("suspicious_connections", []) or [])],
    }

    for rule in config.get("family_hint_rules", []):
        if rule.get("hint_source") == "ransom_extensions":
            families = config["ransom_extensions"]
            key = str(rule["normalized_list"])
            if any(any(ext in item for item in lower_lists.get(key, [])) for ext in families):
                for ext, family in families.items():
                    if any(ext in item for item in lower_lists.get(key, [])):
                        hints.append(str(family))
            continue
        if rule.get("all_attack_patterns") and not _has_attack_patterns(normalized, list(rule["all_attack_patterns"]), mode="all"):
            continue
        if rule.get("any_normalized_nonempty") and not _has_nonempty_lists(normalized, list(rule["any_normalized_nonempty"]), mode="any"):
            continue
        match_mode = rule.get("match_mode")
        if match_mode == "nonempty":
            if not lower_lists.get(str(rule["normalized_list"]), []):
                continue
        elif match_mode == "contains_any_fragment":
            values = lower_lists.get(str(rule["normalized_list"]), [])
            fragments = [str(item) for item in rule.get("fragments", [])] or [str(item) for item in config.get(str(rule.get("fragments_source")), [])]
            if not any(any(fragment in value for fragment in fragments) for value in values):
                continue
        hints.append(str(rule["hint"]))

    return sorted(set(hints))


def enrich_threat_intelligence(normalized: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(normalized)

    ttps = map_ttps(normalized)
    sample_category = classify_sample(normalized)
    family_hints = detect_family_hints(normalized)

    campaign_features: dict[str, bool] = {}
    for key, source in _threat_intel_config().get("campaign_features", {}).items():
        if "." in source:
            left, right = str(source).split(".", 1)
            if left == "attack_patterns":
                campaign_features[str(key)] = bool((normalized.get("attack_patterns", {}) or {}).get(right))
            else:
                campaign_features[str(key)] = False
        else:
            campaign_features[str(key)] = bool(normalized.get(source))

    campaign_risk_score = sum(int(v) for v in campaign_features.values()) * int(_threat_intel_config().get("campaign_feature_weight", 10))

    enriched.update(
        {
            "ttps": ttps,
            "sample_category": sample_category,
            "family_hints": family_hints,
            "campaign_features": campaign_features,
            "campaign_ready": any(campaign_features.values()),
            "campaign_risk_score": campaign_risk_score,
        }
    )

    return enriched
