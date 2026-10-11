from __future__ import annotations

from typing import Any

from threattrace.common.collections import dedupe_strings_lower_sorted as _dedupe

CRYPTO_APIS = [
    "cryptencrypt",
    "cryptdecrypt",
    "cryptacquirecontext",
    "bcryptencrypt",
    "bcryptdecrypt",
    "bcryptgenrandom",
]


CREDENTIAL_APIS = [
    "credsenumerate",
    "lsaopenpolicy",
    "lsaretrieveprivatedata",
    "samopenuser",
    "logonuser",
    "readprocessmemory",
    "lsass",
]


DEFENSE_EVASION_APIS = [
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "zwqueryinformationprocess",
    "virtualprotect",
    "writeprocessmemory",
    "createremotethread",
]

INJECTION_APIS = [
    "createremotethread",
    "ntcreatethreadex",
    "queueuserapc",
    "setthreadcontext",
]


PERSISTENCE_APIS = [
    "regsetvalue",
    "createservice",
    "openservice",
    "schtasks",
]

def extract_api_iocs(report: dict[str, Any]) -> dict[str, Any]:
    """
    Extract behavioral API IoCs from CAPE report.

    Coverage:
    - Crypto APIs
    - Credential theft APIs
    - Defense evasion APIs
    - Persistence APIs
    - Injection APIs
    """

    processes = report.get("behavior", {}).get("processes", []) or []

    resolved_apis: list[str] = []
    crypto_activity: list[str] = []
    credential_activity: list[str] = []
    defense_evasion_activity: list[str] = []
    persistence_activity: list[str] = []
    injection_activity: list[str] = []

    for proc in processes:
        calls = proc.get("calls", []) or []

        for call in calls:
            api = call.get("api")
            if not api:
                continue

            lower_api = api.lower()
            resolved_apis.append(api)

            if any(pattern in lower_api for pattern in CRYPTO_APIS):
                crypto_activity.append(api)

            if any(pattern in lower_api for pattern in CREDENTIAL_APIS):
                credential_activity.append(api)

            if any(pattern in lower_api for pattern in DEFENSE_EVASION_APIS):
                defense_evasion_activity.append(api)

            if any(pattern in lower_api for pattern in PERSISTENCE_APIS):
                persistence_activity.append(api)

            if any(pattern in lower_api for pattern in INJECTION_APIS):
                injection_activity.append(api)

    attack_patterns = {
        "crypto_activity": bool(crypto_activity),
        "credential_access": bool(credential_activity),
        "defense_evasion": bool(defense_evasion_activity),
        "persistence_api_usage": bool(persistence_activity),
        "process_injection": bool(injection_activity),
    }

    ransomware_indicators: list[str] = []
    if attack_patterns["crypto_activity"]:
        ransomware_indicators.append("crypto_api_usage")

    credential_access_indicators: list[str] = []
    if attack_patterns["credential_access"]:
        credential_access_indicators.append("credential_api_usage")

    defense_evasion_indicators: list[str] = []
    if attack_patterns["defense_evasion"]:
        defense_evasion_indicators.append("defense_evasion_api_usage")

    persistence_indicators: list[str] = []
    if attack_patterns["persistence_api_usage"]:
        persistence_indicators.append("persistence_api_usage")

    injection_indicators: list[str] = []
    if attack_patterns["process_injection"]:
        injection_indicators.append("process_injection_api_usage")

    resolved_apis_d = _dedupe(resolved_apis)
    crypto_d = _dedupe(crypto_activity)
    credential_d = _dedupe(credential_activity)
    defense_d = _dedupe(defense_evasion_activity)
    persistence_d = _dedupe(persistence_activity)
    injection_d = _dedupe(injection_activity)

    return {
        "resolved_apis": resolved_apis_d,
        "crypto_activity": crypto_d,
        "credential_activity": credential_d,
        "defense_evasion_activity": defense_d,
        "persistence_activity": persistence_d,
        "injection_activity": injection_d,
        "attack_patterns": attack_patterns,
        "ransomware_indicators": _dedupe(ransomware_indicators),
        "credential_access_indicators": _dedupe(credential_access_indicators),
        "defense_evasion_indicators": _dedupe(defense_evasion_indicators),
        "persistence_indicators": _dedupe(persistence_indicators),
        "injection_indicators": _dedupe(injection_indicators),
        "counts": {
            "resolved_apis": len(resolved_apis_d),
            "crypto_activity": len(crypto_d),
            "credential_activity": len(credential_d),
            "defense_evasion_activity": len(defense_d),
            "persistence_activity": len(persistence_d),
            "injection_activity": len(injection_d),
        },
    }
