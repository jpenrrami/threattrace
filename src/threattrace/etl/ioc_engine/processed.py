from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from threattrace.common.collections import coerce_dict, coerce_list, dedupe_strings_lower_preserve
from threattrace.etl.ioc_engine.observability import (
    clean_string,
    normalize_domain,
    normalize_ip,
    normalize_registry_key,
    normalize_url,
    normalize_windows_path,
)

NORMALIZED_LIST_LIMITS = {
    "domains": 500,
    "suspicious_domains": 500,
    "ips": 500,
    "urls": 500,
    "dropped_files": 1000,
    "ransom_notes": 500,
    "suspicious_files": 500,
    "ransomware_files": 500,
    "registry_keys": 1000,
    "persistence_keys": 500,
    "defender_tampering": 500,
    "wmi_persistence": 500,
    "mutexes": 250,
    "process_chain": 500,
    "suspicious_processes": 500,
    "scheduled_tasks": 500,
    "services": 500,
    "lolbins": 500,
    "lateral_movement": 500,
    "injection_indicators": 500,
    "suspicious_connections": 500,
    "ransomware_indicators": 500,
    "credential_access_indicators": 500,
    "defense_evasion_indicators": 500,
    "persistence_indicators": 500,
    "resolved_apis": 1500,
    "file_extensions_touched": 500,
    "high_signal_extensions": 500,
    "network_indicators": 1000,
}

REGISTRY_PRIORITY_RE = re.compile(
    r"(\\run(once)?\\|\\services\\|\\winlogon\\|defender|windefend|disableantispyware|tamperprotection|__eventfilter|commandlineeventconsumer)",
    re.IGNORECASE,
)
FILE_PRIORITY_RE = re.compile(
    r"(readme|decrypt|recover|restore|ransom|locked|encrypted|crypted|\\users\\public\\|\\appdata\\|\\programdata\\|\\windows\\temp\\|\\vr-malware-test\\)",
    re.IGNORECASE,
)
PROCESS_PRIORITY_RE = re.compile(
    r"\b(vssadmin|wbadmin|bcdedit|wevtutil|cipher|rundll32|regsvr32|mshta|wscript|cscript|powershell|cmd|schtasks|sc)\b",
    re.IGNORECASE,
)


def _priority_score(key: str, value: str) -> tuple[int, int, str]:
    score = 0
    if key.startswith("registry") or key in {"persistence_keys", "defender_tampering", "wmi_persistence"}:
        score = 1 if REGISTRY_PRIORITY_RE.search(value) else 0
    elif key in {"dropped_files", "ransom_notes", "suspicious_files", "ransomware_files"}:
        score = 1 if FILE_PRIORITY_RE.search(value) else 0
    elif key in {"process_chain", "suspicious_processes", "lolbins", "scheduled_tasks", "services"}:
        score = 1 if PROCESS_PRIORITY_RE.search(value) else 0
    return (-score, min(len(value), 240), value)


def _cap_normalized_lists(payload: dict[str, Any]) -> dict[str, Any]:
    capped = dict(payload)
    for key, limit in NORMALIZED_LIST_LIMITS.items():
        values = coerce_list(capped.get(key))
        if len(values) > limit:
            capped[key] = sorted(values, key=lambda item: _priority_score(key, str(item)))[:limit]
    counts = dict(capped.get("counts") or {})
    for key in NORMALIZED_LIST_LIMITS:
        if isinstance(capped.get(key), list):
            counts[key] = len(capped[key])
    capped["counts"] = counts
    return capped


def _normalize_url(value: Any) -> str | None:
    return normalize_url(value)


def _normalize_string(value: Any) -> str | None:
    cleaned = clean_string(value)
    if cleaned:
        cleaned = cleaned.lower()
    return cleaned or None


DOMAIN_RE = re.compile(r"\b[a-z0-9][a-z0-9.-]{1,253}\.[a-z]{2,63}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _is_ip(value: str) -> bool:
    return normalize_ip(value) is not None


def _iter_strings(value: Any) -> list[str]:
    results: list[str] = []
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            results.append(cleaned)
        return results
    if isinstance(value, dict):
        for item in value.values():
            results.extend(_iter_strings(item))
        return results
    if isinstance(value, list):
        for item in value:
            results.extend(_iter_strings(item))
    return results


def _extract_domains_from_strings(values: list[str]) -> list[str]:
    domains: list[str] = []
    for value in values:
        normalized_url = _normalize_url(value)
        if normalized_url and "://" in normalized_url:
            try:
                parsed = urlparse(normalized_url)
            except ValueError:
                parsed = None
            if parsed is None:
                continue
            host = normalize_domain(parsed.hostname or "")
            if host:
                domains.append(host)
        for match in DOMAIN_RE.findall(value):
            cleaned = normalize_domain(match)
            if cleaned:
                domains.append(cleaned)
    return dedupe_strings_lower_preserve(domains)


def _extract_ips_from_strings(values: list[str]) -> list[str]:
    ips: list[str] = []
    for value in values:
        normalized_url = _normalize_url(value)
        if normalized_url and "://" in normalized_url:
            try:
                parsed = urlparse(normalized_url)
            except ValueError:
                parsed = None
            if parsed is None:
                continue
            host_ip = normalize_ip(parsed.hostname or "")
            if host_ip:
                ips.append(host_ip)
        for match in IPV4_RE.findall(value):
            normalized_ip = normalize_ip(match)
            if normalized_ip:
                ips.append(normalized_ip)
    return dedupe_strings_lower_preserve(ips)


def _extract_domains(processed_report: dict[str, Any]) -> list[str]:
    domains: list[str] = []

    for entry in coerce_list(processed_report.get("domains")):
        if isinstance(entry, dict):
            value = entry.get("domain") or entry.get("host")
        else:
            value = entry
        normalized = normalize_domain(value)
        if normalized:
            domains.append(normalized)

    for entry in coerce_list(processed_report.get("dns")):
        if not isinstance(entry, dict):
            continue
        normalized = normalize_domain(entry.get("request"))
        if normalized:
            domains.append(normalized)
        domains.extend(_extract_domains_from_strings(_iter_strings(entry.get("answers"))))

    for entry in coerce_list(processed_report.get("http")):
        if not isinstance(entry, dict):
            continue
        for field in ("host", "hostname", "server"):
            normalized = _normalize_string(entry.get(field))
            normalized = normalize_domain(normalized)
            if normalized:
                domains.append(normalized)
        uri = _normalize_url(entry.get("uri") or entry.get("url"))
        if uri and "://" in uri:
            try:
                parsed = urlparse(uri)
            except ValueError:
                parsed = None
            if parsed is None:
                continue
            host = (parsed.hostname or "").lower().strip()
            host = normalize_domain(host)
            if host:
                domains.append(host)

    for key in ("smtp", "irc", "suspicious_connections", "dns_activity"):
        domains.extend(_extract_domains_from_strings(_iter_strings(processed_report.get(key))))

    for entry in coerce_list(processed_report.get("analysis_artifacts", {}).get("config_domains")):
        normalized = _normalize_string(entry)
        if normalized:
            domains.append(normalized)

    return dedupe_strings_lower_preserve(domains)


def _extract_ips(processed_report: dict[str, Any]) -> list[str]:
    ips: list[str] = []

    for entry in coerce_list(processed_report.get("hosts")):
        if isinstance(entry, dict):
            value = entry.get("ip")
        else:
            value = entry
        normalized = normalize_ip(value)
        if normalized:
            ips.append(normalized)

    for protocol in ("tcp", "udp"):
        for entry in coerce_list(processed_report.get(protocol)):
            if not isinstance(entry, dict):
                continue
            for field in ("dst", "src"):
                normalized = normalize_ip(entry.get(field))
                if normalized:
                    ips.append(normalized)

    for entry in coerce_list(processed_report.get("dns")):
        if not isinstance(entry, dict):
            continue
        ips.extend(_extract_ips_from_strings(_iter_strings(entry.get("answers"))))

    for key in ("smtp", "irc", "suspicious_connections"):
        ips.extend(_extract_ips_from_strings(_iter_strings(processed_report.get(key))))

    for entry in coerce_list(processed_report.get("analysis_artifacts", {}).get("config_ips")):
        normalized = _normalize_string(entry)
        if normalized:
            ips.append(normalized)

    return dedupe_strings_lower_preserve(ips)


def _extract_urls(processed_report: dict[str, Any]) -> list[str]:
    urls: list[str] = []

    for entry in coerce_list(processed_report.get("http")):
        if not isinstance(entry, dict):
            continue
        normalized = _normalize_url(entry.get("uri") or entry.get("url") or entry.get("path"))
        if normalized:
            urls.append(normalized)
        if entry.get("host") and entry.get("path"):
            normalized = _normalize_url(f"http://{entry.get('host')}{entry.get('path')}")
            if normalized:
                urls.append(normalized)

    for entry in coerce_list(processed_report.get("urls")):
        normalized = _normalize_url(entry)
        if normalized:
            urls.append(normalized)

    for entry in coerce_list(processed_report.get("analysis_artifacts", {}).get("config_urls")):
        normalized = _normalize_url(entry)
        if normalized:
            urls.append(normalized)

    return dedupe_strings_lower_preserve(urls)


def _extract_files(processed_report: dict[str, Any]) -> list[str]:
    files: list[str] = []
    for key in ("files_written", "files_read", "files_deleted"):
        for entry in coerce_list(processed_report.get(key)):
            normalized = normalize_windows_path(entry) or _normalize_string(entry)
            if normalized:
                files.append(normalized)
    for key in ("ransom_notes", "reported_file_paths", "reported_process_paths", "enhanced_libraries"):
        for entry in coerce_list(processed_report.get(key)):
            normalized = _normalize_string(entry)
            if normalized:
                files.append(normalized)
    for entry in coerce_list(processed_report.get("analysis_artifacts", {}).get("reported_file_paths")):
        normalized = normalize_windows_path(entry) or _normalize_string(entry)
        if normalized:
            files.append(normalized)
    file_name = normalize_windows_path(processed_report.get("file_name")) or _normalize_string(processed_report.get("file_name"))
    if file_name:
        files.append(file_name)
    return dedupe_strings_lower_preserve(files)


def _extract_registry_keys(processed_report: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    for key in ("keys_read", "keys_written", "keys_deleted"):
        for entry in coerce_list(processed_report.get(key)):
            normalized = normalize_registry_key(entry)
            if normalized:
                keys.append(normalized)
    for key in ("registry_keys", "persistence_keys", "wmi_persistence", "defender_tampering"):
        for entry in coerce_list(processed_report.get(key)):
            normalized = normalize_registry_key(entry)
            if normalized:
                keys.append(normalized)
    for entry in coerce_list(processed_report.get("analysis_artifacts", {}).get("bson_registry_keys")):
        normalized = normalize_registry_key(entry)
        if normalized:
            keys.append(normalized)
    return dedupe_strings_lower_preserve(keys)


def _extract_mutexes(processed_report: dict[str, Any]) -> list[str]:
    mutexes: list[str] = []
    for entry in coerce_list(processed_report.get("mutexes")):
        normalized = _normalize_string(entry)
        if normalized:
            mutexes.append(normalized)
    return dedupe_strings_lower_preserve(mutexes)


def _extract_processes(processed_report: dict[str, Any]) -> list[str]:
    processes: list[str] = []

    for entry in coerce_list(processed_report.get("process_chain")):
        if not isinstance(entry, dict):
            continue
        normalized = _normalize_string(entry.get("command_line") or entry.get("process_name"))
        if normalized:
            processes.append(normalized)

    for entry in coerce_list(processed_report.get("executed_commands")):
        normalized = _normalize_string(entry)
        if normalized:
            processes.append(normalized)

    for key in (
        "services",
        "lolbins",
        "reported_process_names",
        "reported_process_paths",
        "bson_process_names",
        "bson_process_paths",
        "scheduled_tasks",
    ):
        for entry in coerce_list(processed_report.get(key)):
            normalized = _normalize_string(entry)
            if normalized:
                processes.append(normalized)

    for entry in coerce_list(processed_report.get("analysis_artifacts", {}).get("reported_process_names")):
        normalized = _normalize_string(entry)
        if normalized:
            processes.append(normalized)

    for entry in coerce_list(processed_report.get("analysis_artifacts", {}).get("reported_process_paths")):
        normalized = _normalize_string(entry)
        if normalized:
            processes.append(normalized)

    return dedupe_strings_lower_preserve(processes)


def extract_processed_report_iocs(processed_report: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "domains": _extract_domains(processed_report),
        "ips": _extract_ips(processed_report),
        "urls": _extract_urls(processed_report),
        "dropped_files": _extract_files(processed_report),
        "registry_keys": _extract_registry_keys(processed_report),
        "mutexes": _extract_mutexes(processed_report),
        "process_chain": _extract_processes(processed_report),
        "scheduled_tasks": dedupe_strings_lower_preserve(coerce_list(processed_report.get("scheduled_tasks"))),
        "services": dedupe_strings_lower_preserve(coerce_list(processed_report.get("services"))),
        "lolbins": dedupe_strings_lower_preserve(coerce_list(processed_report.get("lolbins"))),
        "resolved_apis": dedupe_strings_lower_preserve(coerce_list(processed_report.get("resolved_apis"))),
        "file_extensions_touched": dedupe_strings_lower_preserve(coerce_list(processed_report.get("file_extensions_touched"))),
        "attack_patterns": {
            str(key): bool(value)
            for key, value in coerce_dict(processed_report.get("attack_patterns")).items()
        },
    }

    normalized["counts"] = {
        "domains": len(normalized["domains"]),
        "ips": len(normalized["ips"]),
        "urls": len(normalized["urls"]),
        "dropped_files": len(normalized["dropped_files"]),
        "registry_keys": len(normalized["registry_keys"]),
        "mutexes": len(normalized["mutexes"]),
        "process_chain": len(normalized["process_chain"]),
    }

    return normalized


def merge_normalized_iocs(
    base_normalized: dict[str, Any],
    processed_normalized: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(base_normalized or {})

    for key in (
        "domains",
        "suspicious_domains",
        "ips",
        "urls",
        "dropped_files",
        "ransom_notes",
        "suspicious_files",
        "ransomware_files",
        "registry_keys",
        "persistence_keys",
        "defender_tampering",
        "wmi_persistence",
        "mutexes",
        "process_chain",
        "suspicious_processes",
        "scheduled_tasks",
        "services",
        "lolbins",
        "lateral_movement",
        "injection_indicators",
        "suspicious_connections",
        "ransomware_indicators",
        "credential_access_indicators",
        "defense_evasion_indicators",
        "persistence_indicators",
        "resolved_apis",
        "file_extensions_touched",
    ):
        merged[key] = dedupe_strings_lower_preserve(
            coerce_list(merged.get(key)) + coerce_list(processed_normalized.get(key))
        )

    merged["attack_patterns"] = {
        str(key): bool((merged.get("attack_patterns") or {}).get(key)) or bool(value)
        for key, value in {
            **coerce_dict(merged.get("attack_patterns")),
            **coerce_dict(processed_normalized.get("attack_patterns")),
        }.items()
    }

    counts = dict(merged.get("counts") or {})
    counts.update(processed_normalized.get("counts") or {})

    for key in (
        "domains",
        "ips",
        "urls",
        "dropped_files",
        "registry_keys",
        "mutexes",
        "process_chain",
    ):
        counts[key] = len(coerce_list(merged.get(key)))

    merged["counts"] = counts
    return _refresh_detection_view(merged)


def _refresh_detection_view(merged: dict[str, Any]) -> dict[str, Any]:
    from threattrace.etl.ioc_engine.normalizer import normalize_iocs

    raw_iocs = {
        "network": {
            "domains": coerce_list(merged.get("domains")) + coerce_list(merged.get("suspicious_domains")),
            "ips": coerce_list(merged.get("ips")),
            "urls": coerce_list(merged.get("urls")),
            "suspicious_domains": coerce_list(merged.get("suspicious_domains")),
            "suspicious_connections": coerce_list(merged.get("suspicious_connections")),
        },
        "filesystem": {
            "dropped_files": coerce_list(merged.get("dropped_files")),
            "ransom_notes": coerce_list(merged.get("ransom_notes")),
            "suspicious_files": coerce_list(merged.get("suspicious_files")),
            "ransomware_files": coerce_list(merged.get("ransomware_files")),
            "ransomware_indicators": coerce_list(merged.get("ransomware_indicators")),
            "attack_patterns": coerce_dict(merged.get("attack_patterns")),
        },
        "registry": {
            "registry_keys": coerce_list(merged.get("registry_keys")),
            "persistence_keys": coerce_list(merged.get("persistence_keys")),
            "defender_tampering": coerce_list(merged.get("defender_tampering")),
            "wmi_persistence": coerce_list(merged.get("wmi_persistence")),
            "mutexes": coerce_list(merged.get("mutexes")),
            "scheduled_tasks": coerce_list(merged.get("scheduled_tasks")),
            "services": coerce_list(merged.get("services")),
            "persistence_indicators": coerce_list(merged.get("persistence_indicators")),
            "defense_evasion_indicators": coerce_list(merged.get("defense_evasion_indicators")),
            "attack_patterns": coerce_dict(merged.get("attack_patterns")),
        },
        "process": {
            "mutexes": coerce_list(merged.get("mutexes")),
            "command_lines": coerce_list(merged.get("process_chain")),
            "process_names": coerce_list(merged.get("suspicious_processes")),
            "suspicious_processes": coerce_list(merged.get("suspicious_processes")),
            "lolbins": coerce_list(merged.get("lolbins")),
            "lateral_movement": coerce_list(merged.get("lateral_movement")),
            "injection_indicators": coerce_list(merged.get("injection_indicators")),
            "ransomware_activity": coerce_list(merged.get("ransomware_indicators")),
            "defender_tampering": coerce_list(merged.get("defense_evasion_indicators")),
            "credential_access_indicators": coerce_list(merged.get("credential_access_indicators")),
            "defense_evasion_indicators": coerce_list(merged.get("defense_evasion_indicators")),
            "ransom_notes": coerce_list(merged.get("ransom_notes")),
            "attack_patterns": coerce_dict(merged.get("attack_patterns")),
        },
        "api": {
            "resolved_apis": coerce_list(merged.get("resolved_apis")),
            "ransomware_indicators": coerce_list(merged.get("ransomware_indicators")),
            "credential_access_indicators": coerce_list(merged.get("credential_access_indicators")),
            "defense_evasion_indicators": coerce_list(merged.get("defense_evasion_indicators")),
            "persistence_indicators": coerce_list(merged.get("persistence_indicators")),
            "attack_patterns": coerce_dict(merged.get("attack_patterns")),
        },
    }
    refreshed = normalize_iocs(raw_iocs)
    refreshed["attack_patterns"] = {
        str(key): bool((coerce_dict(refreshed.get("attack_patterns"))).get(key)) or bool(value)
        for key, value in {
            **coerce_dict(merged.get("attack_patterns")),
            **coerce_dict(refreshed.get("attack_patterns")),
        }.items()
    }
    for key in ("ttps", "sample_category", "family_hints"):
        if merged.get(key) and not refreshed.get(key):
            refreshed[key] = merged[key]
    return _cap_normalized_lists(refreshed)
