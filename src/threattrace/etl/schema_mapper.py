from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class NormalizedReport:
    """Normalized subset of CAPE report data for DB ingestion."""

    sha256: str
    md5: str | None
    sha1: str | None
    file_name: str | None
    file_size: int | None
    file_type: str | None
    score: float | int | None
    family: str | None
    platform: str | None
    architecture: str | None
    signatures: list[dict[str, Any]]
    processes: list[dict[str, Any]]
    network: dict[str, Any]
    mutexes: list[str]
    files_written: list[str]
    files_deleted: list[str]
    registry_keys: list[str]
    scheduled_tasks: list[str]
    services: list[str]
    lolbins: list[str]
    attack_patterns: dict[str, Any]
    persistence_score: int
    process_chain: list[dict[str, Any]]
    resolved_apis: list[str]
    file_extensions_touched: list[str]
    domains: list[str]
    hosts: list[str]
    http_requests: list[dict[str, Any]]
    dns_requests: list[dict[str, Any]]
    ttps: list[str]
    sample_category: str | None
    family_hints: list[str]
    campaign_features: dict[str, Any]
    campaign_ready: bool
    threat_score: float | int | None
    severity_score: float | int | None
    confidence_score: float | int | None
    risk_level: str | None
    raw_report: dict[str, Any]


def _safe_get(data: dict[str, Any], *path: str, default: Any = None) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def _dedupe_list(items: list[Any]) -> list[Any]:
    seen = set()
    result = []

    for item in items:
        marker = json.dumps(item, sort_keys=True, default=str) if isinstance(item, (dict, list)) else str(item)
        if marker not in seen:
            seen.add(marker)
            result.append(item)

    return result


def _sanitize_string(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "").strip()


def _detect_architecture(raw_sample: dict[str, Any]) -> str:

    tags = raw_sample.get("tags") or []

    if isinstance(tags, str):
        tags = [t.strip().lower() for t in tags.split(",") if t.strip()]
    else:
        tags = [str(t).strip().lower() for t in tags]

    architecture = str(
        raw_sample.get("architecture")
        or raw_sample.get("cpu_architecture")
        or raw_sample.get("file_arch")
        or ""
    ).strip().lower()

    file_type = str(
        raw_sample.get("file_type")
        or raw_sample.get("file_type_mime")
        or ""
    ).lower()

    trid = " ".join(
        [str(x).lower() for x in (raw_sample.get("trid") or [])]
    )

    # Nivel 1: campo explícito
    if architecture in ("x86", "32-bit", "win32", "i386"):
        return "x86"

    if architecture in ("x64", "64-bit", "win64", "amd64", "x86_64"):
        return "x64"

    # Nivel 2: tags
    if "x64" in tags:
        return "x64"

    if "x86" in tags:
        return "x86"

    # Nivel 3: TRiD
    if any(term in trid for term in ["win64", "64 executable", "pe32+"]):
        return "x64"

    if any(term in trid for term in ["win32", "32 executable", "pe32"]):
        return "x86"

    # Nivel 4: MIME / tipo
    if any(term in file_type for term in ["pe32+", "64-bit", "win64"]):
        return "x64"

    if any(term in file_type for term in ["pe32", "32-bit", "win32", "dos-exec", "x-dosexec"]):
        return "x86"

    # Nivel 5: EXE genérico
    if "exe" in file_type or "dll" in file_type:
        if "64" in file_type:
            return "x64"
        return "x86"

    return "unknown"


def map_cape_report(report: dict[str, Any]) -> NormalizedReport:
    """Transform raw CAPE JSON into normalized structure for ETL/database layers."""

    target_file = _safe_get(report, "target", "file", default={}) or {}
    pe_data = target_file.get("pe", {}) or {}
    summary = _safe_get(report, "behavior", "summary", default={}) or {}

    behavior = report.get("behavior", {}) or {}
    processes = behavior.get("processes", []) or []

    command_lines = []
    process_chain = []
    resolved_apis = []
    file_extensions = set()

    for proc in processes:
        process_chain.append(
            {
                "process_name": proc.get("process_name"),
                "pid": proc.get("process_id"),
                "parent_pid": proc.get("parent_id"),
                "command_line": proc.get("command_line"),
            }
        )

        if proc.get("command_line"):
            command_lines.append(proc.get("command_line"))

        for call in proc.get("calls", []) or []:
            api_name = call.get("api")
            if api_name:
                resolved_apis.append(api_name)

        for path in proc.get("file_activities", []) or []:
            if isinstance(path, str) and "." in path:
                ext = path.split(".")[-1].lower()
                if len(ext) <= 10:
                    file_extensions.add(ext)

    scheduled_tasks = [cmd for cmd in command_lines if "schtasks" in cmd.lower()]
    services = [cmd for cmd in command_lines if cmd.lower().startswith("sc ") and " create " in cmd.lower()]
    lolbins = [
        cmd
        for cmd in command_lines
        if any(
            re.search(rf"\b{re.escape(binary)}\b", cmd.lower())
            for binary in [
                "powershell",
                "cmd.exe",
                "rundll32",
                "regsvr32",
                "mshta",
                "wmic",
                "certutil",
                "bitsadmin",
            ]
        )
    ]

    command_blob = " ".join(command_lines).lower()

    attack_patterns = {
        "shadow_copy_deletion": any(term in command_blob for term in ["vssadmin delete", "wmic shadowcopy delete", "bcdedit"]),
        "backup_tampering": any(term in command_blob for term in ["wbadmin delete", "catalog", "bcdedit"]),
        "defender_tampering": any(term in command_blob for term in ["defender", "mpcmdrun", "disableantispyware"]),
        "scheduled_tasks": bool(scheduled_tasks),
        "service_creation": bool(services),
        "registry_persistence": bool(summary.get("write_keys", [])),
        "credential_access": any(term in command_blob for term in ["mimikatz", "lsass"]),
        "process_injection": any(term in command_blob for term in ["createremotethread", "writeprocessmemory"]),
        "process_hollowing": any(term in command_blob for term in ["ntunmapviewofsection", "resume thread"]),
        "wmi_persistence": any(term in command_blob for term in ["__eventfilter", "commandlineeventconsumer"]),
    }

    persistence_score = sum(
        [
            bool(summary.get("write_keys", [])),
            bool(scheduled_tasks),
            bool(services),
            attack_patterns.get("wmi_persistence", False) * 2,
            attack_patterns.get("shadow_copy_deletion", False),
            attack_patterns.get("backup_tampering", False),
        ]
    )

    network = report.get("network", {}) or {}

    domains = _dedupe_list(
        [
            _sanitize_string(entry.get("domain") if isinstance(entry, dict) else entry).lower()
            for entry in (network.get("domains", []) or [])
            if entry
        ]
    )

    hosts = _dedupe_list(
        [
            _sanitize_string(entry.get("ip") if isinstance(entry, dict) else entry)
            for entry in (network.get("hosts", []) or [])
            if entry
        ]
    )

    suspicious_connections = []
    for proto in ("tcp", "udp"):
        for entry in network.get(proto, []) or []:
            ip = entry.get("dst") or entry.get("src")
            port = entry.get("dport") or entry.get("sport")
            if ip and port and str(port).isdigit() and int(port) in {4444, 1337, 6666, 6667, 9001, 8081}:
                suspicious_connections.append(f"{ip}:{port}")

    unified_scores = report.get("unified_ioc_scores", {}) or {}
    unified_threat_intel = report.get("unified_ioc_threat_intel", {}) or {}

    return NormalizedReport(
        sha256=target_file.get("sha256") or "",
        md5=target_file.get("md5"),
        sha1=target_file.get("sha1"),
        file_name=target_file.get("name"),
        file_size=target_file.get("size"),
        file_type=target_file.get("type"),
        score=report.get("malscore"),
        family=report.get("malfamily") or report.get("malstatus"),
        platform=_safe_get(report, "info", "machine", "platform"),
        architecture=_detect_architecture(
            {
                "architecture": pe_data.get("architecture"),
                "file_type": target_file.get("type"),
                "tags": [],
            }
        ),
        signatures=report.get("signatures", []) or [],
        processes=processes,
        network=network,
        mutexes=_dedupe_list(summary.get("mutexes", []) or []),
        files_written=_dedupe_list(summary.get("write_files", []) or []),
        files_deleted=_dedupe_list(summary.get("delete_files", []) or []),
        registry_keys=_dedupe_list(
            (summary.get("keys", []) or []) + (summary.get("write_keys", []) or [])
        ),
        scheduled_tasks=_dedupe_list(scheduled_tasks),
        services=_dedupe_list(services),
        lolbins=_dedupe_list(lolbins),
        attack_patterns=attack_patterns,
        persistence_score=persistence_score,
        process_chain=_dedupe_list(process_chain),
        resolved_apis=resolved_apis[:10000],
        file_extensions_touched=sorted(file_extensions),
        domains=domains,
        hosts=hosts,
        http_requests=network.get("http", []) or [],
        dns_requests=network.get("dns", []) or [],
        ttps=unified_threat_intel.get("ttps", []),
        sample_category=unified_threat_intel.get("sample_category"),
        family_hints=unified_threat_intel.get("family_hints", []),
        campaign_features={
            **unified_threat_intel.get("campaign_features", {}),
            "suspicious_connections": list(set(suspicious_connections)),
        },
        campaign_ready=unified_threat_intel.get("campaign_ready", False),
        threat_score=unified_scores.get("threat_score"),
        severity_score=unified_scores.get("severity_score"),
        confidence_score=unified_scores.get("confidence_score"),
        risk_level=unified_scores.get("risk_level"),
        raw_report=report,
    )


def normalized_report_to_dict(normalized: NormalizedReport) -> dict[str, Any]:
    """Convert dataclass object into serializable dictionary."""

    return {
        "sha256": normalized.sha256,
        "md5": normalized.md5,
        "sha1": normalized.sha1,
        "file_name": normalized.file_name,
        "file_size": normalized.file_size,
        "file_type": normalized.file_type,
        "score": normalized.score,
        "family": normalized.family,
        "platform": normalized.platform,
        "architecture": normalized.architecture,
        "signatures": normalized.signatures,
        "processes": normalized.processes,
        "network": normalized.network,
        "mutexes": normalized.mutexes,
        "files_written": normalized.files_written,
        "files_deleted": normalized.files_deleted,
        "registry_keys": normalized.registry_keys,
        "scheduled_tasks": normalized.scheduled_tasks,
        "services": normalized.services,
        "lolbins": normalized.lolbins,
        "attack_patterns": normalized.attack_patterns,
        "persistence_score": normalized.persistence_score,
        "process_chain": normalized.process_chain,
        "resolved_apis": normalized.resolved_apis,
        "file_extensions_touched": normalized.file_extensions_touched,
        "ttps": normalized.ttps,
        "sample_category": normalized.sample_category,
        "family_hints": normalized.family_hints,
        "campaign_features": normalized.campaign_features,
        "campaign_ready": normalized.campaign_ready,
        "threat_score": normalized.threat_score,
        "severity_score": normalized.severity_score,
        "confidence_score": normalized.confidence_score,
        "risk_level": normalized.risk_level,
        "domains": normalized.domains,
        "hosts": normalized.hosts,
        "http_requests": normalized.http_requests,
        "dns_requests": normalized.dns_requests,
        "raw_report": normalized.raw_report,
    }
