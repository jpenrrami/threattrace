from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from threattrace.common.collections import coerce_list


@dataclass(frozen=True)
class EvidenceItem:
    source: str
    value: str
    normalized: str
    context: str


@dataclass(frozen=True)
class Signal:
    code: str
    weight: float
    reason: str
    evidence: EvidenceItem


@dataclass(frozen=True)
class TTPDefinition:
    ttp_id: str
    name: str
    kind: str
    mitre_attack_id: str | None = None
    mitre_name: str | None = None


@dataclass(frozen=True)
class TechniqueRule:
    ttp_id: str
    required_any: tuple[str, ...]
    strong_any: tuple[str, ...] = ()
    weak_any: tuple[str, ...] = ()
    min_confidence: float = 0.45


MICROSOFT_DOMAIN_RE = re.compile(
    r"(?i)(^|\.)("
    r"microsoft|windowsupdate|update\.microsoft|download\.microsoft|msftconnecttest|"
    r"msftncsi|office|office365|live|bing|azure|akadns|msedge|edgesuite"
    r")\.(com|net)$"
)
PATTERNS = {
    "ransom_note": re.compile(r"(?i)(readme|restore|recover|decrypt|how_to|recover_files|ransom).*\.(txt|html|hta|md)$"),
    "impact_noise": re.compile(r"(?i)(too many files open|\\avg\\|avg\\av\\|avast|antivirus|security product|cfgall\\fixcfg\.lock|\.log\.lock$|\.lck$)"),
    "encrypted_ext": re.compile(r"(?i)\.(locked|lock|crypted|crypt|enc|encrypted|akira|bianlian)$"),
    "mass_impact": re.compile(r"(?i)(mass_file|many files|file_extensions_touched|encrypted_extensions|ransomware_indicators)"),
    "recovery_tool": re.compile(r"(?i)\b(vssadmin|wbadmin|bcdedit|shadow|recovery|backup)\b"),
    "destructive": re.compile(r"(?i)\b(delete|remove|resize|disable|off|clear|purge|catalog)\b"),
    "defense": re.compile(r"(?i)\b(defender|windefend|securityhealthservice|set-mppreference|amsi|tamper|firewall|edr)\b"),
    "disable": re.compile(r"(?i)\b(disable|stop|kill|off|bypass|exclude|exclusion|disablerealtimemonitoring)\b"),
    "registry": re.compile(r"(?i)(^|\\|\.)(registry|keys_written|keys_deleted|keys_read)|\\software\\|hkey_|hkcu\\|hklm\\"),
    "registry_write": re.compile(r"(?i)(keys_written|keys_deleted|reg\s+(add|delete)|setvalue|deletevalue|RegSetValue|RegDeleteValue)"),
    "meaningful_registry": re.compile(r"(?i)\\(run|runonce|startup)\\|currentversion\\run|\\services\\[^\\]+\\(imagepath|servicedll|start)\b|\\policies\\|\\defender\\|\\security center\\|\\windows defender\\|ransom|decrypt|recover"),
    "run_key": re.compile(r"(?i)\\(run|runonce)\\|currentversion\\run|\\startup\\(?!desktop\.ini\b)"),
    "startup_payload": re.compile(r"(?i)\.(exe|dll|bat|cmd|ps1|vbs|js|jse|lnk|py|hta|scr)(\b|$)"),
    "service": re.compile(r"(?i)(^|\.)(services?|service_name)|\\services\\|\bsc\.exe\s+create\b|\bsc\s+create\b"),
    "source_string": re.compile(r"(?i)(https?://|gitlab\.|github\.|golang\.org|/src/|/pkg/|svc/mgr|\.go\b|self\.|::|function |class )"),
    "strong_service": re.compile(r"(?i)\bcreateservice\b|\bsc(\.exe)?\s+(create|config)\b|\\services\\[^\\]+\\(imagepath|servicedll|start)\b|(^|\.)services?\[\d+\]\.(name|binary|imagepath|servicedll)"),
    "scheduled_task": re.compile(r"(?i)scheduled_tasks?|taskcache\\tasks|schtasks(\.exe)?\s+/(create|change|run)"),
    "command_ctx": re.compile(r"(?i)(command|cmdline|process_chain|executed_commands|processes|\b/c\b|\s-enc(odedcommand)?\b)"),
    "script_host": re.compile(r"(?i)\b(cmd|powershell|pwsh|wscript|cscript)(\.exe)?\b"),
    "proxy_exec": re.compile(r"(?i)\b(rundll32|regsvr32|mshta)(\.exe)?\b"),
    "proxy_suspicious": re.compile(r"(?i)(\\temp\\|\\appdata\\|\\programdata\\|\\users\\public\\|[a-z]:\\(?!windows\\|program files(?: \(x86\))?\\)|https?://|javascript:|script:|scrobj\.dll|\.sct|\.hta|\.dat|\.tmp|\.bin|\.crypted|\.locked| -enc|\.(dll|cpl|ocx)\b[^\r\n,]*,\s*(#[0-9]+|[A-Za-z_@$?][A-Za-z0-9_@$?]*))"),
    "transfer_api": re.compile(r"(?i)\b(urldownloadtofile|internetopenurl|winhttpopenrequest|winhttpreceiveresponse|http(send|open)request|connect|recv|send)\b"),
    "payload_file": re.compile(r"(?i)(https?://|payload|download|stage|drop|/gate|/file|/bin|/payload|\.exe|\.dll|\.ps1|\.vbs|\.js|\.hta|\.zip|\.rar|\.7z)$"),
    "cleanup": re.compile(r"(?i)\bwevtutil\b.*\b(cl|clear-log)\b|\bclear-eventlog\b|\b(del|erase|remove-item|rmdir|rd)\b.*\b(log|temp|tmp|prefetch|event|recycle|trace)\b|\b(cleanup|clear traces?)\b"),
    "file_discovery": re.compile(r"(?i)(\b(cmd|powershell|pwsh)\b.*\b(dir|tree|where|findstr)\b|\bget-childitem\b|recursive (file|directory) enumeration|find(first|next)file.*(users|desktop|documents|downloads|\\\\\*|c:\\\\|[a-z]:\\\\))"),
    "process_discovery": re.compile(r"(?i)\b(tasklist|pslist|get-process)\b"),
    "network_discovery": re.compile(r"(?i)(\b(cmd|powershell|pwsh)\b.*\b(ipconfig|netstat|arp|route\s+print|nltest)\b|\bget-net(ipconfiguration|route)\b)"),
    "mutex": re.compile(r"(?i)(mutex|mutant|global\\|local\\)"),
    "mutex_noise": re.compile(r"(?i)(zonescachecountermutex|zoneslockedcachecountermutex|adap_wmi_entry|refreshra_mutex|wilstaging|(^|\\)sm0$)"),
    "mutex_suspicious": re.compile(r"(?i)(ransom|crypt|locker|payload|malware|[a-f0-9]{16,}|[A-Za-z0-9+/]{24,}={0,2})"),
}
NETWORK_KEYS = ("url", "domain", "ip", "http", "dns", "download", "network", "connect")
STRONG_NETWORK_KEYS = ("url", "domain", "ip", "http", "dns", "download", "connection", "remote")

TTP_REGISTRY = {
    item.ttp_id: item
    for item in (
        TTPDefinition("TTP0001", "Ransomware File Impact", "mapped", "T1486", "Data Encrypted for Impact"),
        TTPDefinition("TTP0002", "Recovery Inhibition", "mapped", "T1490", "Inhibit System Recovery"),
        TTPDefinition("TTP0003", "Security Control Impairment", "mapped", "T1562", "Impair Defenses"),
        TTPDefinition("TTP0004", "Registry Modification", "mapped", "T1112", "Modify Registry"),
        TTPDefinition("TTP0005", "Run Key Persistence", "mapped", "T1547.001", "Registry Run Keys / Startup Folder"),
        TTPDefinition("TTP0006", "Windows Service Persistence", "mapped", "T1543.003", "Windows Service"),
        TTPDefinition("TTP0007", "Scheduled Task Persistence", "mapped", "T1053.005", "Scheduled Task"),
        TTPDefinition("TTP0008", "Script Interpreter Execution", "mapped", "T1059", "Command and Scripting Interpreter"),
        TTPDefinition("TTP0009", "Proxy Binary Execution", "mapped", "T1218", "System Binary Proxy Execution"),
        TTPDefinition("TTP0010", "External Payload Transfer", "mapped", "T1105", "Ingress Tool Transfer"),
        TTPDefinition("TTP0011", "Trace Removal", "mapped", "T1070", "Indicator Removal"),
        TTPDefinition("TTP0012", "File System Discovery", "mapped", "T1083", "File and Directory Discovery"),
        TTPDefinition("TTP0013", "Process Discovery", "mapped", "T1057", "Process Discovery"),
        TTPDefinition("TTP0014", "Network Configuration Discovery", "mapped", "T1016", "System Network Configuration Discovery"),
        TTPDefinition("TTP0015", "Project-Specific Mutex Artifact", "custom"),
    )
}

TECHNIQUES = (
    TechniqueRule("TTP0001", ("ransom_note", "encrypted_ext", "ransomware_indicator", "mass_impact"), ("ransom_note", "encrypted_ext", "mass_impact"), min_confidence=0.55),
    TechniqueRule("TTP0002", ("recovery_destructive",), min_confidence=0.75),
    TechniqueRule("TTP0003", ("defense_tamper",), min_confidence=0.65),
    TechniqueRule("TTP0004", ("registry_modification",), min_confidence=0.55),
    TechniqueRule("TTP0005", ("run_key",), min_confidence=0.75),
    TechniqueRule("TTP0006", ("service_persistence",), min_confidence=0.7),
    TechniqueRule("TTP0007", ("scheduled_task",), min_confidence=0.7),
    TechniqueRule("TTP0008", ("script_execution",), min_confidence=0.65),
    TechniqueRule("TTP0009", ("proxy_execution",), min_confidence=0.7),
    TechniqueRule("TTP0010", ("external_payload_transfer",), min_confidence=0.65),
    TechniqueRule("TTP0011", ("cleanup",), min_confidence=0.65),
    TechniqueRule("TTP0012", ("file_discovery",), min_confidence=0.5),
    TechniqueRule("TTP0013", ("process_discovery",), min_confidence=0.5),
    TechniqueRule("TTP0014", ("network_discovery",), min_confidence=0.5),
    TechniqueRule("TTP0015", ("mutex_artifact",), min_confidence=0.75),
)


def _iter_leaf(value: Any, source: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_leaf(child, f"{source}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_leaf(child, f"{source}[{index}]")
    elif value not in (None, ""):
        yield source, str(value)


def _compact(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())[:220]


def _extract_evidence(payload: dict[str, Any]) -> list[EvidenceItem]:
    seen: set[tuple[str, str]] = set()
    out: list[EvidenceItem] = []
    for source, raw in _iter_leaf(payload):
        value = _compact(raw)
        if not value or value.startswith("{"):
            continue
        normalized = value.lower().replace("/", "\\")
        key = (source, normalized)
        if key in seen:
            continue
        seen.add(key)
        out.append(EvidenceItem(source=source, value=value, normalized=normalized, context=f"{source.lower()} {normalized}"))
    return out


def _host(value: str) -> str:
    parsed = urlparse(value.strip().lower())
    return parsed.hostname or value.strip().lower()


def _external(value: str) -> bool:
    host = _host(value)
    if not host or host in {"localhost", "localdomain"}:
        return False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return not MICROSOFT_DOMAIN_RE.search(host)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def _network_transfer_source(item: EvidenceItem) -> bool:
    source = item.source.lower()
    value = item.value.lower()
    if value.endswith((".dll", ".sys", ".ocx")) and not value.startswith(("http://", "https://")):
        return False
    return value.startswith(("http://", "https://")) or any(key in source for key in STRONG_NETWORK_KEYS)


def _mutex_key(value: str) -> str:
    normalized = value.lower().replace("\\\\", "\\").replace("/", "\\")
    normalized = re.sub(r"^(local|global)\\+", "", normalized)
    return normalized


def _signals_for(item: EvidenceItem) -> list[Signal]:
    c = item.context
    signals: list[Signal] = []
    add = signals.append
    if PATTERNS["ransom_note"].search(item.value) and not PATTERNS["impact_noise"].search(c):
        add(Signal("ransom_note", 0.55, "ransom-note artifact", item))
    if PATTERNS["encrypted_ext"].search(item.value) and not PATTERNS["impact_noise"].search(c):
        add(Signal("encrypted_ext", 0.45, "encrypted extension mutation", item))
    if ("ransomware_indicators" in item.source.lower() or PATTERNS["mass_impact"].search(c)) and not PATTERNS["impact_noise"].search(c):
        add(Signal("ransomware_indicator", 0.35, "ransomware impact indicator", item))
    if PATTERNS["mass_impact"].search(c) and not PATTERNS["impact_noise"].search(c):
        add(Signal("mass_impact", 0.35, "mass file impact signal", item))
    if PATTERNS["recovery_tool"].search(c) and PATTERNS["destructive"].search(c):
        add(Signal("recovery_destructive", 0.85, "recovery artifact destructive intent", item))
    if PATTERNS["defense"].search(c) and PATTERNS["disable"].search(c):
        add(Signal("defense_tamper", 0.75, "security control disable/tamper intent", item))
    if PATTERNS["registry"].search(c):
        add(Signal("weak_registry", 0.15, "registry context", item))
    if PATTERNS["registry_write"].search(c) and PATTERNS["meaningful_registry"].search(c):
        add(Signal("registry_modification", 0.65, "meaningful registry write/delete", item))
    if PATTERNS["run_key"].search(c) and PATTERNS["startup_payload"].search(c):
        add(Signal("run_key", 0.85, "Run/RunOnce/Startup persistence key", item))
    if PATTERNS["service"].search(c):
        add(Signal("weak_service", 0.2, "service registry/API context", item))
    if PATTERNS["strong_service"].search(c) and not PATTERNS["source_string"].search(c):
        add(Signal("service_persistence", 0.75, "Windows service persistence artifact", item))
    if PATTERNS["scheduled_task"].search(c):
        add(Signal("scheduled_task", 0.75, "scheduled task artifact", item))
    if PATTERNS["script_host"].search(c) and PATTERNS["command_ctx"].search(c):
        add(Signal("script_execution", 0.75, "script interpreter execution context", item))
    if PATTERNS["proxy_exec"].search(c) and PATTERNS["command_ctx"].search(c) and PATTERNS["proxy_suspicious"].search(c):
        add(Signal("proxy_execution", 0.8, "proxy execution binary in command context", item))
    if _network_transfer_source(item) and _external(item.value) and (PATTERNS["payload_file"].search(c) or PATTERNS["transfer_api"].search(c)):
        add(Signal("external_payload_transfer", 0.75, "external payload transfer indicator", item))
    if PATTERNS["cleanup"].search(c):
        add(Signal("cleanup", 0.75, "trace/log/temp cleanup intent", item))
    if PATTERNS["file_discovery"].search(c) and PATTERNS["command_ctx"].search(c):
        add(Signal("file_discovery", 0.6, "file discovery command", item))
    if PATTERNS["process_discovery"].search(c) and PATTERNS["command_ctx"].search(c):
        add(Signal("process_discovery", 0.6, "process discovery command", item))
    if PATTERNS["network_discovery"].search(c) and PATTERNS["command_ctx"].search(c):
        add(Signal("network_discovery", 0.6, "network config discovery command", item))
    mutex_value = _mutex_key(item.value)
    if (
        "mutex" in item.source.lower()
        and PATTERNS["mutex"].search(c)
        and len(item.value) >= 8
        and not PATTERNS["mutex_noise"].search(mutex_value)
        and PATTERNS["mutex_suspicious"].search(item.value)
    ):
        add(Signal("mutex_artifact", 0.75, "project-specific malware mutex artifact", item))
    return signals


def _confidence(signals: list[Signal], rule: TechniqueRule) -> float:
    codes = {signal.code for signal in signals}
    if not codes.intersection(rule.required_any):
        return 0.0
    score = sum(signal.weight for signal in signals if signal.code in set(rule.required_any + rule.strong_any + rule.weak_any))
    support_bonus = min(0.2, 0.05 * max(0, len(codes) - 1))
    return min(0.99, max(rule.min_confidence, score + support_bonus))


def _technique(rule: TechniqueRule, signals: list[Signal]) -> dict[str, Any] | None:
    conf = _confidence(signals, rule)
    if conf <= 0:
        return None
    definition = TTP_REGISTRY[rule.ttp_id]
    picked = signals[:8]
    evidence = []
    sources = []
    reasons = []
    seen_ev: set[str] = set()
    for signal in picked:
        text = signal.evidence.value
        if text not in seen_ev:
            seen_ev.add(text)
            evidence.append(text)
        if signal.evidence.source not in sources:
            sources.append(signal.evidence.source)
        if signal.reason not in reasons:
            reasons.append(signal.reason)
    return {
        "ttp_id": definition.ttp_id,
        "name": definition.name,
        "kind": definition.kind,
        "mitre_attack_id": definition.mitre_attack_id,
        "mitre_name": definition.mitre_name,
        "confidence": round(conf, 2),
        "evidence": evidence,
        "sources": sources,
        "reason": "; ".join(reasons[:3]),
    }


def infer_ttp_from_report(payload: dict[str, Any]) -> dict[str, Any]:
    evidence = _extract_evidence(payload)
    by_code: dict[str, list[Signal]] = defaultdict(list)
    for item in evidence:
        for signal in _signals_for(item):
            by_code[signal.code].append(signal)

    techniques = []
    for rule in TECHNIQUES:
        signals = [signal for code in set(rule.required_any + rule.strong_any + rule.weak_any) for signal in by_code.get(code, [])]
        technique = _technique(rule, signals)
        if technique:
            techniques.append(technique)
    techniques.sort(key=lambda item: item["ttp_id"])
    score = min(100, round(sum(float(item["confidence"]) for item in techniques) * 10))
    return {
        "ttps": techniques,
        "behavior_score": score,
        "summary": {
            "technique_count": len(techniques),
            "signal_count": sum(len(items) for items in by_code.values()),
            "sources": sorted({source for item in techniques for source in item["sources"]}),
            "has_ransomware_behavior": any(item.get("mitre_attack_id") in {"T1486", "T1490"} for item in techniques),
            "text_items_scanned": len(evidence),
            "matched": bool(techniques),
        },
    }


def technique_ids(inference: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(item.get("ttp_id"))
            for item in coerce_list(inference.get("ttps"))
            if isinstance(item, dict) and item.get("ttp_id")
        }
    )
