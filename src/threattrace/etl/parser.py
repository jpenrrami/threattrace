from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _safe_get(summary: dict[str, Any], *keys: str) -> list[Any]:
    """Safely merge multiple summary keys into a deduplicated list."""
    results: list[Any] = []
    seen = set()

    for key in keys:
        for item in summary.get(key, []) or []:
            marker = str(item)
            if marker not in seen:
                seen.add(marker)
                results.append(item)

    return results


def _extract_attack_patterns(summary: dict[str, Any], commands: list[str], signatures: list[dict[str, Any]]) -> dict[str, bool]:
    """Derive high-value ransomware and ATT&CK-style behavioral heuristics."""
    command_blob = " ".join(commands).lower()
    signature_blob = " ".join(sig.get("name", "") for sig in signatures).lower()

    return {
        "shadow_copy_deletion": any(term in command_blob for term in ["vssadmin delete", "wmic shadowcopy delete", "bcdedit"]),
        "backup_tampering": any(term in command_blob for term in ["wbadmin delete", "catalog", "bcdedit"]),
        "defender_tampering": any(term in command_blob for term in ["defender", "mpcmdrun", "disableantispyware"]),
        "persistence_registry": bool(summary.get("write_keys", [])),
        "scheduled_tasks": "schtasks" in command_blob,
        "service_creation": any(term in command_blob for term in ["sc create", "net start"]),
        "credential_access": any(term in command_blob for term in ["mimikatz", "lsass"]),
        "process_injection": any(term in command_blob for term in ["createremotethread", "writeprocessmemory"]),
        "process_hollowing": any(term in command_blob for term in ["ntunmapviewofsection", "resume thread"]),
        "wmi_persistence": any(term in command_blob for term in ["__eventfilter", "commandlineeventconsumer"]),
        "ransomware_notes": any(term in signature_blob for term in ["ransom", "encrypt", "locker"]),
    }


def load_report(report_path: str | Path) -> dict[str, Any]:
    """Load a CAPE/Cuckoo JSON report from disk."""
    path = Path(report_path)

    if not path.exists():
        raise FileNotFoundError(f"Report not found: {path}")

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return json.load(handle)


def extract_static_features(report: dict[str, Any]) -> dict[str, Any]:
    """Extract core static sample metadata."""
    target = report.get("target", {}).get("file", {})
    pe = target.get("pe", {})

    return {
        "sha256": target.get("sha256"),
        "sha1": target.get("sha1"),
        "md5": target.get("md5"),
        "size": target.get("size"),
        "file_type": target.get("type"),
        "imphash": pe.get("imphash"),
        "entrypoint": pe.get("entrypoint"),
        "machine_type": pe.get("machine_type"),
        "timestamp": pe.get("timestamp"),
        "sections": pe.get("sections", []),
        "imports": pe.get("imports", {}),
        "exports": pe.get("exports", []),
        "strings_sample": target.get("strings", [])[:500],
    }


def extract_behavioral_features(report: dict[str, Any]) -> dict[str, Any]:
    """Extract behavioral, persistence, execution-chain, and advanced runtime indicators."""
    behavior = report.get("behavior", {})
    summary = behavior.get("summary", {})
    processes = behavior.get("processes", [])
    signatures = report.get("signatures", [])

    resolved_apis = []
    command_lines = []
    process_chain = []
    file_extensions_written = set()

    for proc in processes:
        proc_name = proc.get("process_name")
        pid = proc.get("process_id")
        ppid = proc.get("parent_id")

        process_chain.append(
            {
                "process_name": proc_name,
                "pid": pid,
                "parent_pid": ppid,
                "command_line": proc.get("command_line"),
            }
        )

        if proc.get("command_line"):
            command_lines.append(proc.get("command_line"))

        for call in proc.get("calls", []):
            api_name = call.get("api")
            if api_name:
                resolved_apis.append(api_name)

        for path in proc.get("file_activities", []) or []:
            if isinstance(path, str) and "." in path:
                ext = path.split(".")[-1].lower()
                if len(ext) <= 10:
                    file_extensions_written.add(ext)

    persistence_keys = _safe_get(
        summary,
        "write_keys",
        "write_registry",
    )

    scheduled_tasks = [cmd for cmd in command_lines if "schtasks" in cmd.lower()]
    services = [cmd for cmd in command_lines if cmd.lower().startswith("sc ") and " create " in cmd.lower()]
    import re

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

    attack_patterns = _extract_attack_patterns(summary, command_lines, signatures)

    return {
        "process_count": len(processes),
        "process_tree": behavior.get("processtree", []),
        "process_chain": process_chain,
        "files_created": _safe_get(summary, "write_files", "created_files"),
        "files_deleted": _safe_get(summary, "delete_files", "deleted_files"),
        "files_modified": _safe_get(summary, "modify_files"),
        "registry_read": _safe_get(summary, "read_keys"),
        "registry_write": persistence_keys,
        "registry_delete": _safe_get(summary, "delete_keys"),
        "mutexes": _safe_get(summary, "mutexes"),
        "commands": command_lines,
        "scheduled_tasks": scheduled_tasks,
        "services": services,
        "lolbins": lolbins,
        "resolved_apis": resolved_apis[:10000],
        "signature_names": [sig.get("name") for sig in signatures],
        "attack_patterns": attack_patterns,
        "file_extensions_touched": sorted(file_extensions_written),
        "persistence_score": sum(
            [
                bool(persistence_keys),
                bool(scheduled_tasks),
                bool(services),
                attack_patterns.get("wmi_persistence", False) * 2,
                attack_patterns.get("shadow_copy_deletion", False),
                attack_patterns.get("backup_tampering", False),
            ]
        ),
    }


def extract_network_features(report: dict[str, Any]) -> dict[str, Any]:
    """Extract expanded network IoCs, protocols, and communication metadata."""
    network = report.get("network", {})

    urls = []
    user_agents = []

    for http_entry in network.get("http", []):
        if http_entry.get("uri"):
            uri = http_entry.get("uri")
            urls.append(uri.replace("http://", "").replace("https://", "").rstrip("/"))
        if http_entry.get("user-agent"):
            user_agents.append(http_entry.get("user-agent"))

    suspicious_connections = []
    for proto in ("tcp", "udp"):
        for entry in network.get(proto, []) or []:
            ip = entry.get("dst") or entry.get("src")
            port = entry.get("dport") or entry.get("sport")
            if ip and port and str(port).isdigit() and int(port) in {4444, 1337, 6666, 6667, 9001, 8081}:
                suspicious_connections.append(f"{ip}:{port}")

    return {
        "domains": network.get("domains", []),
        "hosts": network.get("hosts", []),
        "dns": network.get("dns", []),
        "http": network.get("http", []),
        "tcp": network.get("tcp", []),
        "udp": network.get("udp", []),
        "icmp": network.get("icmp", []),
        "smtp": network.get("smtp", []),
        "irc": network.get("irc", []),
        "urls": urls,
        "user_agents": user_agents,
        "dead_hosts": network.get("dead_hosts", []),
        "pcap_sha256": network.get("pcap_sha256"),
        "suspicious_connections": list(set(suspicious_connections)),
    }


def extract_iocs(report: dict[str, Any]) -> dict[str, Any]:
    """Generate normalized IoC bundle for downstream DB insertion."""
    static = extract_static_features(report)
    behavior = extract_behavioral_features(report)
    network = extract_network_features(report)

    return {
        "sample": static,
        "behavior": behavior,
        "network": network,
        "malfamily": report.get("malfamily"),
        "malscore": report.get("malscore"),
        "malstatus": report.get("malstatus"),
        "analysis_info": report.get("info", {}),
    }


def parse_report(report_path: str | Path) -> dict[str, Any]:
    """Main parser entrypoint."""
    report = load_report(report_path)
    return extract_iocs(report)
