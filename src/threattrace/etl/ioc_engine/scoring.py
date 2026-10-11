from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from threattrace.common.json_config import load_json_config


def _feature(
    name: str,
    weight: int,
    evidence: Any,
    source: str,
) -> dict[str, Any] | None:
    if isinstance(evidence, list):
        evidence_items = [str(item) for item in evidence[:10] if item]
        if not evidence_items:
            return None
        evidence_value: Any = evidence_items
    elif evidence:
        evidence_value = str(evidence)
    else:
        return None
    return {
        "name": name,
        "weight": weight,
        "evidence": evidence_value,
        "source": source,
    }


def _sum_features(features: list[dict[str, Any]]) -> int:
    return min(100, sum(int(feature.get("weight", 0)) for feature in features))


ROOT_DIR = Path(__file__).resolve().parents[4]
CONFIG_PATH = ROOT_DIR / "config" / "detection" / "scoring_rules.json"


@lru_cache(maxsize=1)
def _scoring_config() -> dict[str, Any]:
    return load_json_config(str(CONFIG_PATH))


def _resolve_source(normalized: dict[str, Any], source: str, attack_patterns: dict[str, Any]) -> Any:
    if source.startswith("normalized."):
        return normalized.get(source.split(".", 1)[1])
    if source.startswith("attack_patterns."):
        return attack_patterns.get(source.split(".", 1)[1])
    return None


def determine_risk_level(threat_score: float) -> str:
    for level in _scoring_config()["risk_levels"]:
        if float(threat_score) >= float(level["min"]):
            return str(level["name"])
    return "low"


def _build_group_features(
    normalized: dict[str, Any],
    attack_patterns: dict[str, Any],
    definitions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    features: list[dict[str, Any]] = []
    for definition in definitions:
        evidence = _resolve_source(normalized, str(definition["source"]), attack_patterns)
        mode = str(definition["mode"])
        if mode == "list_count":
            weight = min(int(definition["max"]), len(evidence or []) * int(definition["per_item"]))
        else:
            weight = int(definition["weight"])
        feature = _feature(
            str(definition["name"]),
            weight,
            evidence,
            str(definition["source"]),
        )
        if feature:
            features.append(feature)
    return features


def calculate_threat_score(normalized: dict[str, Any]) -> dict[str, Any]:
    """
    Central behavioral scoring engine.

    Calculates:
    - Persistence
    - Severity
    - Confidence
    - Ransomware
    - Credential access
    - Defense evasion
    - Composite threat score
    """

    attack_patterns = normalized.get("attack_patterns", {}) or {}
    config = _scoring_config()
    group_definitions = config["feature_groups"]
    persistence_features = _build_group_features(normalized, attack_patterns, group_definitions["persistence"])
    ransomware_features = _build_group_features(normalized, attack_patterns, group_definitions["ransomware"])
    credential_features = _build_group_features(normalized, attack_patterns, group_definitions["credential_access"])
    defense_features = _build_group_features(normalized, attack_patterns, group_definitions["defense_evasion"])
    c2_features = _build_group_features(normalized, attack_patterns, group_definitions["c2"])

    persistence_score = _sum_features(persistence_features)
    ransomware_score = _sum_features(ransomware_features)
    credential_score = _sum_features(credential_features)
    defense_evasion_score = _sum_features(defense_features)
    c2_score = _sum_features(c2_features)

    # Severity score
    severity_weights = config["severity_weights"]
    severity_score = min(
        100,
        (
            ransomware_score * float(severity_weights["ransomware"])
            + credential_score * float(severity_weights["credential_access"])
            + defense_evasion_score * float(severity_weights["defense_evasion"])
            + persistence_score * float(severity_weights["persistence"])
            + c2_score * float(severity_weights["c2"])
        ),
    )

    confidence_score = min(
        int(config["confidence_score_cap"]),
        sum(
            len(_resolve_source(normalized, str(item["source"]), attack_patterns) or []) * int(item["per_item"])
            for item in config["confidence_inputs"]
        ),
    )

    threat_weights = config["threat_score_weights"]
    threat_score = round(
        (
            severity_score * float(threat_weights["severity_score"])
            + confidence_score * float(threat_weights["confidence_score"])
            + ransomware_score * float(threat_weights["ransomware_score"])
            + defense_evasion_score * float(threat_weights["defense_evasion_score"])
            + credential_score * float(threat_weights["credential_score"])
            + c2_score * float(threat_weights["c2_score"])
        ),
        2,
    )

    risk_level = determine_risk_level(threat_score)

    return {
        "persistence_score": round(persistence_score, 2),
        "ransomware_score": round(ransomware_score, 2),
        "credential_score": round(credential_score, 2),
        "defense_evasion_score": round(defense_evasion_score, 2),
        "c2_score": round(c2_score, 2),
        "severity_score": round(severity_score, 2),
        "confidence_score": round(confidence_score, 2),
        "threat_score": threat_score,
        "risk_level": risk_level,
        "features": {
            "persistence": persistence_features,
            "ransomware": ransomware_features,
            "credential_access": credential_features,
            "defense_evasion": defense_features,
            "c2": c2_features,
        },
    }
