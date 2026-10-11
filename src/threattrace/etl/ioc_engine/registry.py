from __future__ import annotations

from typing import Any

from threattrace.common.collections import dedupe_strings_lower_sorted as _dedupe
from threattrace.etl.ioc_engine.observability import normalize_registry_key

PERSISTENCE_KEYS = [
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"software\microsoft\windows\currentversion\policies\explorer\run",
    r"system\currentcontrolset\services",
    r"software\microsoft\windows nt\currentversion\winlogon",
    r"software\microsoft\windows\currentversion\shellserviceobjectdelayload",
    r"software\\microsoft\\windows\\currentversion\\runservices",
    r"software\\microsoft\\windows\\currentversion\\runservicesonce",
    r"software\\microsoft\\windows nt\\currentversion\\image file execution options",
    r"software\\microsoft\\windows\\currentversion\\policies\\system",
]


DEFENDER_TAMPERING_KEYS = [
    "disableantispyware",
    "disableantivirus",
    "tamperprotection",
    "real-time protection",
    "windefend",
]

WMI_PERSISTENCE_KEYS = [
    "__eventfilter",
    "commandlineeventconsumer",
    "filtertoconsumerbinding",
]

def _norm_key(value: Any) -> str | None:
    return normalize_registry_key(value)


def extract_registry_iocs(report: dict[str, Any]) -> dict[str, Any]:
    """
    Extract registry and persistence IoCs from CAPE report.

    Coverage:
    - Registry modifications
    - Autoruns
    - Persistence
    - Services
    - Defender tampering
    - Security policy changes
    """

    summary = report.get("behavior", {}).get("summary", {}) or {}
    processes = report.get("behavior", {}).get("processes", []) or []

    raw_registry_keys: list[str] = []
    registry_keys: list[str] = []
    persistence_keys: list[str] = []
    defender_tampering: list[str] = []
    scheduled_tasks: list[str] = []
    services: list[str] = []
    wmi_persistence: list[str] = []

    # Aggregate registry activity
    for field in ("keys", "read_keys", "write_keys", "delete_keys"):
        raw_registry_keys.extend(summary.get(field, []) or [])

    # Analyze registry persistence
    for key in raw_registry_keys:
        normalized_key = _norm_key(key)
        if not normalized_key:
            continue
        lower_key = normalized_key.lower()
        registry_keys.append(normalized_key)

        if any(pattern in lower_key for pattern in PERSISTENCE_KEYS):
            persistence_keys.append(normalized_key)

        if any(pattern in lower_key for pattern in DEFENDER_TAMPERING_KEYS):
            defender_tampering.append(normalized_key)

        if any(pattern in lower_key for pattern in WMI_PERSISTENCE_KEYS):
            wmi_persistence.append(normalized_key)

    # Process command line analysis
    for proc in processes:
        cmd = proc.get("command_line", "")
        if not cmd:
            continue

        lower_cmd = cmd.lower()

        if "schtasks" in lower_cmd:
            scheduled_tasks.append(cmd)

        if lower_cmd.startswith("sc ") and " create " in lower_cmd:
            services.append(cmd)

    attack_patterns = {
        "registry_persistence": bool(persistence_keys),
        "wmi_persistence": bool(wmi_persistence),
        "scheduled_tasks": bool(scheduled_tasks),
        "service_creation": bool(services),
        "defender_tampering": bool(defender_tampering),
    }

    persistence_indicators: list[str] = []

    if attack_patterns["registry_persistence"]:
        persistence_indicators.append("registry_persistence")

    if attack_patterns["scheduled_tasks"]:
        persistence_indicators.append("scheduled_tasks")

    if attack_patterns["service_creation"]:
        persistence_indicators.append("service_creation")

    if attack_patterns["wmi_persistence"]:
        persistence_indicators.append("wmi_persistence")

    defense_evasion_indicators: list[str] = []

    if attack_patterns["defender_tampering"]:
        defense_evasion_indicators.append("defender_tampering")

    persistence_score = sum(
        [
            attack_patterns["registry_persistence"],
            attack_patterns["scheduled_tasks"],
            attack_patterns["service_creation"],
            attack_patterns["wmi_persistence"] * 2,
        ]
    )

    registry_d = _dedupe(registry_keys)
    persistence_d = _dedupe(persistence_keys)
    scheduled_d = _dedupe(scheduled_tasks)
    services_d = _dedupe(services)
    defender_d = _dedupe(defender_tampering)
    wmi_d = _dedupe(wmi_persistence)

    return {
        "registry_keys": registry_d,
        "persistence_keys": persistence_d,
        "scheduled_tasks": scheduled_d,
        "services": services_d,
        "defender_tampering": defender_d,
        "wmi_persistence": wmi_d,
        "attack_patterns": attack_patterns,
        "persistence_indicators": _dedupe(persistence_indicators),
        "defense_evasion_indicators": _dedupe(defense_evasion_indicators),
        "persistence_score": persistence_score,
        "counts": {
            "registry_keys": len(registry_d),
            "persistence_keys": len(persistence_d),
            "scheduled_tasks": len(scheduled_d),
            "services": len(services_d),
            "defender_tampering": len(defender_d),
            "wmi_persistence": len(wmi_d),
        },
    }
