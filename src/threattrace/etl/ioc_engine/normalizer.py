from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from threattrace.common.collections import dedupe_strings_lower_sorted as _dedupe
from threattrace.etl.ioc_engine.observability import build_detection_candidate

_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)

_BENIGN_DOMAIN_KEYWORDS = (
    "microsoft",
    "azure",
    "office",
    "windows",
    "google",
    "gstatic",
    "cloudflare",
    "onenote",
    "live.com",
    "office365",
    "sharepoint",
    "m365",
    "windowsupdate",
    "akadns",
)

_SUSPICIOUS_URL_RE = re.compile(
    r"(?i)(https?://[^\s]+(\.(exe|dll|ps1|vbs|js|jse|hta|zip|rar|7z|tmp|dat|bin)|/(gate|panel|payload|locker|decrypt|download)(/|$)|\?.*(cmd|id|key|token)=))"
)

_SUSPICIOUS_PROCESS_RE = re.compile(
    r"(?i)(\b(vssadmin|wbadmin|bcdedit|reagentc|wevtutil|cipher|rundll32|regsvr32|mshta|wscript|cscript|powershell|pwsh|cmd|schtasks|sc)\b|\\appdata\\|\\programdata\\|\\users\\public\\|\\windows\\temp\\|\\vr-malware-test\\| -enc\b|/create\b|create service|delete shadows)"
)

_SUSPICIOUS_REGISTRY_RE = re.compile(
    r"(?i)(\\run(once|services|servicesonce)?\\|currentversion\\run|\\winlogon\\|\\services\\[^\\]+\\(imagepath|servicedll|start)\b|__eventfilter|commandlineeventconsumer|filtertoconsumerbinding|defender|windefend|disableantispyware|disableantivirus|tamperprotection)"
)

_SUSPICIOUS_FILE_RE = re.compile(
    r"(?i)(\\vr-malware-test\\|\\appdata\\local\\temp\\|\\appdata\\roaming\\|\\users\\public\\|\\programdata\\|\\windows\\temp\\|\\desktop\\|\\documents\\|\\downloads\\).*(readme|decrypt|recover|restore|how_to|ransom|akira|locked|encrypted|crypted|crypt|enc|\.exe$|\.dll$|\.scr$|\.com$|\.bat$|\.cmd$|\.ps1$|\.vbs$|\.js$|\.jse$|\.wsf$|\.wsh$|\.hta$|\.lnk$|\.tmp$|\.dat$|\.bin$)"
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_valid_domain(value: str) -> bool:
    if not value or _is_ip(value):
        return False
    return bool(_DOMAIN_REGEX.match(value.strip().lower()))


def _filter_domains(values: list[str]) -> list[str]:
    return sorted(
        {
            v.strip().lower()
            for v in values
            if isinstance(v, str)
            and _is_valid_domain(v)
        }
    )


def _normalize_url(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    try:
        parsed = urlparse(cleaned)
    except ValueError:
        return None
    if parsed.scheme and parsed.netloc:
        path = parsed.path or ""
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}{query}".rstrip("/")
    return cleaned.lower().rstrip("/") or None


def _extract_malicious_domains(values: list[str]) -> list[str]:
    return sorted(
        {
            v for v in values
            if not any(v.endswith(keyword) or f".{keyword}" in v for keyword in _BENIGN_DOMAIN_KEYWORDS)
        }
    )


def _extract_ransom_notes(process: dict[str, Any], filesystem: dict[str, Any]) -> list[str]:
    return _dedupe(
        process.get("ransom_notes", [])
        + filesystem.get("ransom_notes", [])
    )


def _extract_high_signal_extensions(values: list[str]) -> list[str]:
    suspicious = {
        "lockbit",
        "blackcat",
        "alphv",
        "akira",
        "hive",
        "royal",
        "medusa",
        "conti",
        "clop",
        "play",
        "rhysida",
        "ryuk",
        "wncry",
        "encrypted",
        "crypted",
    }
    return sorted({v for v in values if v.lower() in suspicious})


def _is_high_signal_url(value: str) -> bool:
    return bool(_SUSPICIOUS_URL_RE.search(value or ""))


def _is_suspicious_process_candidate(value: str) -> bool:
    text = (value or "").strip().lower()
    if text in {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        return False
    return bool(_SUSPICIOUS_PROCESS_RE.search(text))


def _is_suspicious_registry_candidate(value: str) -> bool:
    return bool(_SUSPICIOUS_REGISTRY_RE.search(value or ""))


def _is_suspicious_file_candidate(value: str) -> bool:
    return bool(_SUSPICIOUS_FILE_RE.search(value or ""))


def _merge_attack_patterns(*sources: dict[str, Any]) -> dict[str, bool]:
    merged: dict[str, bool] = {}
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key, value in source.items():
            merged[str(key)] = bool(merged.get(str(key))) or bool(value)
    return merged


def normalize_iocs(raw_iocs: dict[str, Any]) -> dict[str, Any]:
    """
    Unified normalization layer for all IoC extraction modules.

    Input:
        raw_iocs = {
            "network": ...,
            "filesystem": ...,
            "registry": ...,
            "process": ...,
            "api": ...
        }

    Output:
        Single DB-ready normalized schema
    """

    network = raw_iocs.get("network", {}) or {}
    filesystem = raw_iocs.get("filesystem", {}) or {}
    registry = raw_iocs.get("registry", {}) or {}
    process = raw_iocs.get("process", {}) or {}
    api = raw_iocs.get("api", {}) or {}

    # Core IoCs
    raw_domains = _dedupe(network.get("domains", []))
    raw_ips = _dedupe(network.get("ips", []) + network.get("private_ips", []))

    promoted_ips = [v for v in raw_domains if _is_ip(v)]
    domains = _filter_domains(raw_domains)
    suspicious_domains = _extract_malicious_domains(
        _dedupe(
            domains
            + network.get("suspicious_domains", [])
        )
    )
    ips = _dedupe(raw_ips + promoted_ips)

    raw_urls = network.get("urls", [])
    urls = _dedupe([
        normalized
        for u in raw_urls
        if isinstance(u, str)
        for normalized in [_normalize_url(u)]
        if normalized
    ])

    suspicious_connections = _dedupe(network.get("suspicious_connections", []))

    registry_keys = _dedupe(registry.get("registry_keys", []))
    dropped_files = _dedupe(filesystem.get("dropped_files", []))
    mutexes = _dedupe(
        process.get("mutexes", [])
        + registry.get("mutexes", [])
        + filesystem.get("mutexes", [])
    )

    # Behavioral categories
    scheduled_tasks = _dedupe(registry.get("scheduled_tasks", []))
    services = _dedupe(registry.get("services", []))
    lolbins = _dedupe(process.get("lolbins", []))

    # Process intelligence
    process_chain = _dedupe(
        process.get("command_lines", [])
        + process.get("process_names", [])
    )
    suspicious_processes = _dedupe(process.get("suspicious_processes", []))
    lateral_movement = _dedupe(process.get("lateral_movement", []))
    injection_indicators = _dedupe(process.get("injection_indicators", []))

    # API intelligence
    resolved_apis = _dedupe(api.get("resolved_apis", []))

    # File extensions
    file_extensions_touched = []
    for file_path in dropped_files:
        if "." in file_path:
            ext = file_path.split(".")[-1].lower()
            if len(ext) <= 15:
                file_extensions_touched.append(ext)

    file_extensions_touched = _dedupe(file_extensions_touched)

    high_signal_extensions = _extract_high_signal_extensions(file_extensions_touched)
    if any(len(ext) > 10 for ext in file_extensions_touched):
        high_signal_extensions.append("generic_high_entropy_extension")
    ransom_notes = _extract_ransom_notes(process, filesystem)

    # Merge attack patterns
    attack_patterns = _merge_attack_patterns(
        filesystem.get("attack_patterns", {}),
        registry.get("attack_patterns", {}),
        process.get("attack_patterns", {}),
        api.get("attack_patterns", {}),
    )

    # Future threat intelligence enrichment placeholders
    ttps: list[str] = []
    sample_category: str | None = None
    family_hints: list[str] = []

    # Initial lightweight behavioral classification
    if attack_patterns.get("crypto_activity") and attack_patterns.get("shadow_copy_deletion"):
        if lateral_movement:
            sample_category = "ransomware_worm"
        elif ransom_notes:
            sample_category = "ransomware_extortion"
        else:
            sample_category = "ransomware_locker"
    elif attack_patterns.get("credential_access") and suspicious_domains:
        sample_category = "trojan_stealer"
    elif attack_patterns.get("credential_access"):
        sample_category = "credential_theft"
    elif suspicious_domains and attack_patterns.get("defender_tampering"):
        sample_category = "trojan_loader"
    elif lateral_movement:
        sample_category = "worm_like"
    else:
        sample_category = "unknown"

    # Initial family heuristics
    for ext in high_signal_extensions:
        if ext in {"ryuk"}:
            family_hints.append("Ryuk-like")
        elif ext in {"wncry"}:
            family_hints.append("WannaCry-like")
        elif ext in {"lockbit"}:
            family_hints.append("LockBit-like")
        elif ext in {"blackcat", "alphv"}:
            family_hints.append("BlackCat/ALPHV-like")
        elif ext in {"akira"}:
            family_hints.append("Akira-like")
        elif ext in {"hive"}:
            family_hints.append("Hive-like")
        elif ext in {"royal"}:
            family_hints.append("Royal-like")
        elif ext in {"medusa"}:
            family_hints.append("MedusaLocker-like")
        elif ext in {"conti"}:
            family_hints.append("Conti-like")
        elif ext in {"clop"}:
            family_hints.append("Cl0p-like")
        elif ext in {"play"}:
            family_hints.append("Play-like")
        elif ext in {"rhysida"}:
            family_hints.append("Rhysida-like")

    if ransom_notes:
        family_hints.append("Ransom-note-artifact")

    if attack_patterns.get("shadow_copy_deletion") and attack_patterns.get("crypto_activity"):
        family_hints.append("Generic-modern-ransomware")

    if attack_patterns.get("defender_tampering"):
        family_hints.append("EDR-evasion")

    if suspicious_domains:
        family_hints.append("Suspicious-C2-Infrastructure")

    if lateral_movement and attack_patterns.get("credential_access"):
        family_hints.append("Enterprise-spread")

    # Consolidated indicators
    ransomware_indicators = _dedupe(
        filesystem.get("ransomware_indicators", [])
        + api.get("ransomware_indicators", [])
    )

    credential_access_indicators = _dedupe(
        process.get("credential_access_indicators", [])
        + api.get("credential_access_indicators", [])
    )

    defense_evasion_indicators = _dedupe(
        registry.get("defense_evasion_indicators", [])
        + process.get("defense_evasion_indicators", [])
        + api.get("defense_evasion_indicators", [])
    )

    persistence_indicators = _dedupe(
        registry.get("persistence_indicators", [])
        + api.get("persistence_indicators", [])
    )

    # Scores
    raw_persistence_score = registry.get("persistence_score", 0)
    if isinstance(raw_persistence_score, list):
        persistence_score = len(raw_persistence_score)
    elif isinstance(raw_persistence_score, bool) or isinstance(raw_persistence_score, (int, float)):
        persistence_score = int(raw_persistence_score)
    else:
        persistence_score = 0

    severity_score = sum(
        [
            attack_patterns.get("shadow_copy_deletion", False) * 2,
            attack_patterns.get("defender_tampering", False) * 2,
            attack_patterns.get("credential_access", False) * 2,
            attack_patterns.get("ransomware_extension_activity", False) * 2,
            attack_patterns.get("crypto_activity", False) * 3,
            bool(lolbins),
            bool(services),
            bool(scheduled_tasks),
            bool(lateral_movement) * 2,
            bool(injection_indicators) * 3,
            bool(ransom_notes) * 2,
            bool(suspicious_domains),
        ]
    )

    confidence_score = min(
        100,
        int(severity_score * 8)
        + int(persistence_score * 10)
        + int(len(ransomware_indicators) * 5)
        + int(len(defense_evasion_indicators) * 5)
        + int(len(ransom_notes) * 4)
        + int(len(suspicious_domains) * 4)
        + int(len(injection_indicators) * 6)
        + int(len(suspicious_connections) * 3),
    )

    suspicious_urls = _dedupe([value for value in urls if _is_high_signal_url(value)])
    suspicious_registry = _dedupe(
        registry.get("persistence_keys", [])
        + registry.get("defender_tampering", [])
        + registry.get("wmi_persistence", [])
        + [value for value in registry_keys if _is_suspicious_registry_candidate(value)]
    )
    suspicious_files_for_detection = _dedupe(
        filesystem.get("ransom_notes", [])
        + filesystem.get("ransomware_files", [])
        + filesystem.get("suspicious_files", [])
        + [value for value in dropped_files if _is_suspicious_file_candidate(value)]
    )
    suspicious_process_candidates = _dedupe(
        suspicious_processes
        + lolbins
        + lateral_movement
        + process.get("ransomware_activity", [])
        + process.get("defender_tampering", [])
        + [value for value in process_chain if _is_suspicious_process_candidate(value)]
        + scheduled_tasks
        + services
    )

    network_indicators = _dedupe(
        suspicious_domains
        + suspicious_urls
        + suspicious_connections
        + [value for value in ips if value]
    )

    detection_candidates: list[dict[str, Any]] = []
    for category, values in (
        ("domain", suspicious_domains),
        ("ip", ips if suspicious_domains or suspicious_urls or suspicious_connections else []),
        ("url", suspicious_urls),
        ("file", suspicious_files_for_detection),
        ("registry", suspicious_registry),
        ("mutex", mutexes),
        ("process", suspicious_process_candidates),
    ):
        for value in values[:500]:
            detection_candidates.append(
                build_detection_candidate(
                    category=category,
                    value=value,
                    source="ioc_engine.normalized",
                )
            )

    for pattern, enabled in attack_patterns.items():
        if enabled:
            detection_candidates.append(
                build_detection_candidate(
                    category=pattern,
                    value=pattern,
                    source="ioc_engine.attack_patterns",
                )
            )

    endpoint_observability = {
        "high_value": [
            candidate
            for candidate in detection_candidates
            if candidate.get("generalization_value") == "high"
            and candidate.get("false_positive_risk") in {"low", "medium"}
        ][:500],
        "medium_value": [
            candidate
            for candidate in detection_candidates
            if candidate.get("generalization_value") == "medium"
        ][:500],
        "low_value": [
            candidate
            for candidate in detection_candidates
            if candidate.get("false_positive_risk") == "high"
        ][:500],
        "cape_only": [
            candidate
            for candidate in detection_candidates
            if candidate.get("observability") == ["cape_only_or_high_cost"]
        ][:500],
    }

    return {
        "domains": domains,
        "suspicious_domains": suspicious_domains,
        "ips": ips,
        "urls": urls,
        "mutexes": mutexes,
        "ttps": ttps,
        "sample_category": sample_category,
        "family_hints": _dedupe(family_hints),
        "registry_keys": registry_keys,
        "dropped_files": dropped_files,
        "network_indicators": network_indicators,
        "scheduled_tasks": scheduled_tasks,
        "services": services,
        "lolbins": lolbins,
        "resolved_apis": resolved_apis,
        "process_chain": process_chain,
        "suspicious_processes": suspicious_processes,
        "lateral_movement": lateral_movement,
        "injection_indicators": injection_indicators,
        "file_extensions_touched": file_extensions_touched,
        "high_signal_extensions": high_signal_extensions,
        "ransom_notes": ransom_notes,
        "attack_patterns": attack_patterns,
        "persistence_indicators": persistence_indicators,
        "ransomware_indicators": ransomware_indicators,
        "credential_access_indicators": credential_access_indicators,
        "defense_evasion_indicators": defense_evasion_indicators,
        "persistence_score": persistence_score,
        "severity_score": severity_score,
        "confidence_score": confidence_score,
        "suspicious_connections": suspicious_connections,
        "detection_candidates": detection_candidates[:2000],
        "endpoint_observability": endpoint_observability,
        "counts": {
            "domains": len(domains),
            "suspicious_domains": len(suspicious_domains),
            "ips": len(ips),
            "urls": len(urls),
            "mutexes": len(mutexes),
            "registry_keys": len(registry_keys),
            "dropped_files": len(dropped_files),
            "lolbins": len(lolbins),
            "scheduled_tasks": len(scheduled_tasks),
            "services": len(services),
            "lateral_movement": len(lateral_movement),
            "injection_indicators": len(injection_indicators),
            "resolved_apis": len(resolved_apis),
            "ransomware_indicators": len(ransomware_indicators),
            "credential_access_indicators": len(credential_access_indicators),
            "defense_evasion_indicators": len(defense_evasion_indicators),
            "ransom_notes": len(ransom_notes),
            "high_signal_extensions": len(high_signal_extensions),
            "suspicious_connections": len(suspicious_connections),
            "detection_candidates": len(detection_candidates),
        },
    }
