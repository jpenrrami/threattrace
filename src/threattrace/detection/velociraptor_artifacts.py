from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from threattrace.common.json_config import load_json_config
from threattrace.detection.noise import classify_noise, has_suspicious_context


def _artifact_name(stem: str) -> str:
    return f"ThreatTrace.Detection.{stem.replace('-', '_').replace(' ', '_')}"

ROOT_DIR = Path(__file__).resolve().parents[3]
CONFIG_DIR = ROOT_DIR / "config" / "velociraptor"
_FALLBACK_FILE_GLOBS = (
    "C:/Users/*/AppData/Local/Temp/**,"
    "C:/Users/*/AppData/Roaming/**,"
    "C:/Users/*/Desktop/**,"
    "C:/Users/*/Documents/**,"
    "C:/Users/*/Downloads/**,"
    "C:/Users/Public/**,"
    "C:/ProgramData/**,"
    "C:/vr-malware-test/**,"
    "C:/Windows/Temp/**"
)
_FALLBACK_RANSOM_NOTE_GLOBS = (
    "C:/*.txt,"
    "C:/*.html,"
    "C:/*.hta,"
    "C:/*.md,"
    f"{_FALLBACK_FILE_GLOBS},"
    "C:/Program Files/**,"
    "C:/Program Files (x86)/**,"
    "C:/PerfLogs/**,"
    "C:/Documents and Settings/**"
)
_REQUIRED_VALIDATION_GLOBS = (
    "C:/vr-malware-test/**",
    "C:/Users/*/AppData/Local/Temp/**",
    "C:/Users/*/AppData/Roaming/**",
    "C:/Users/*/Desktop/**",
    "C:/Users/*/Documents/**",
    "C:/ProgramData/**",
    "C:/Windows/Temp/**",
)
_TTP_EVIDENCE_PATTERNS = {
    "TTP0001": re.compile(r"(?i)(readme|restore|recover|decrypt|ransom|\.akira\b|\.bianlian\b|\.locked\b|\.encrypted\b|mass.*(rename|write|delete)|encrypt)"),
    "TTP0005": re.compile(r"(?i)(\\run\\|\\runonce\\|\\startup\\).*\.(exe|dll|bat|cmd|ps1|vbs|js|jse|lnk|py|hta|scr)\b"),
    "TTP0006": re.compile(r"(?i)(createservice|sc(\.exe)?\s+(create|config)|\\services\\[^\\]+\\(imagepath|servicedll|start)\b)"),
    "TTP0007": re.compile(r"(?i)(schtasks(\.exe)?\s+/(create|change|run)|scheduled_tasks?|taskcache\\tasks)"),
    "TTP0009": re.compile(
        r"(?i)\b(rundll32|regsvr32|mshta|wscript|cscript)(?:\.exe)?\b.*("
        r"\\temp\\|\\appdata\\|\\programdata\\|\\users\\public\\|"
        r"[a-z]:\\(?!windows\\|program files(?: \(x86\))?\\)|"
        r"https?://|javascript:|vbscript:|script:|scrobj\.dll|"
        r"\.(sct|hta|tmp|dat|bin|js|jse|vbs|vbe|wsf|wsh)\b|"
        r"\.(dll|cpl|ocx)\b[^\\r\\n,]*,\s*(#[0-9]+|[A-Za-z_@$?][A-Za-z0-9_@$?]*)"
        r")"
    ),
    "TTP0010": re.compile(r"(?i)(https?://.*\.(exe|dll|ps1|vbs|js|hta|zip|rar|7z)|urldownloadtofile|wininet|winhttp|download.*payload)"),
    "TTP0015": re.compile(r"(?i)(global\\.*(payload|ransom|crypt|locker)|[a-f0-9]{16,})"),
}
_TTP_ARTIFACTS = {
    "TTP0001": {
        "name": "Windows.ThreatTrace.Ransomware.TTP0001.RansomwareImpact",
        "intent": "Find strong ransomware impact files such as ransom notes and encrypted extensions",
        "observable": "Ransom note paths, ransomware extensions, mass rename/write/delete markers",
        "template": "file_glob_regex",
        "min_confidence": 0.65,
    },
    "TTP0005": {
        "name": "Windows.ThreatTrace.Ransomware.TTP0005.RunKeyPersistence",
        "intent": "Find Run/RunOnce/Startup payload persistence",
        "observable": "Run key or Startup executable/script/link payload entries",
        "template": "registry_regex",
        "min_confidence": 0.70,
    },
    "TTP0006": {
        "name": "Windows.ThreatTrace.Ransomware.TTP0006.ServicePersistence",
        "intent": "Find suspicious service persistence",
        "observable": "Service ImagePath/ServiceDll/Start writes or service creation commands",
        "template": "registry_regex",
        "min_confidence": 0.70,
    },
    "TTP0007": {
        "name": "Windows.ThreatTrace.Ransomware.TTP0007.ScheduledTaskPersistence",
        "intent": "Find suspicious scheduled task persistence",
        "observable": "Scheduled task creation or TaskCache artifacts",
        "template": "registry_regex",
        "min_confidence": 0.70,
    },
    "TTP0009": {
        "name": "Windows.ThreatTrace.Ransomware.TTP0009.ProxyExecution",
        "intent": "Find suspicious LOLBin/proxy execution",
        "observable": "proxy execution via rundll32/regsvr32/mshta/wscript/cscript using DLL exports, scriptlets, URLs, or proxy-binary child-process execution",
        "template": "process_regex",
        "min_confidence": 0.70,
    },
    "TTP0010": {
        "name": "Windows.ThreatTrace.Ransomware.TTP0010.PayloadTransfer",
        "intent": "Find external payload transfer indicators",
        "observable": "Payload URL, download API, WinINet/WinHTTP transfer evidence",
        "template": "network_regex",
        "min_confidence": 0.70,
    },
    "TTP0015": {
        "name": "Windows.ThreatTrace.Ransomware.TTP0015.MalwareMutex",
        "intent": "Find malware-like mutexes after noise filtering",
        "observable": "Unique high-entropy or family-like mutex names",
        "template": "mutex_regex",
        "min_confidence": 0.70,
    },
}
_SUSPICIOUS_NETWORK_URL_RE = re.compile(
    r"(?i)\.(exe|dll|ps1|bat|cmd|js|jse|vbs|vbe|wsf|wsh|hta|zip|rar|7z|cab|msi|iso|img|lnk|scr|tmp|dat|bin)(?:$|[?#])"
)
_MAX_NETWORK_CANDIDATES = 250
_MAX_NATIVE_CANDIDATES_BY_ARTIFACT = {
    "Windows.ThreatTrace.Ransomware.RansomNotes": 300,
    "Windows.ThreatTrace.Ransomware.SuspiciousDroppedFiles": 300,
    "Windows.ThreatTrace.Ransomware.NetworkIndicators": _MAX_NETWORK_CANDIDATES,
}
_MAX_NATIVE_CANDIDATES_DEFAULT = 500
_PARAMETER_BUNDLE_SIZE = 100


def _generalized_ttp_pattern(ttp_id: str, evidence: list[str]) -> tuple[str, str]:
    if ttp_id == "TTP0001":
        return (
            r"(?i)(^|\\|/)(readme|.*_readme|recover[^\\/]*|decrypt[^\\/]*|restore[^\\/]*|how_to[^\\/]*|help[^\\/]*)"
            r"\.(txt|html|hta|md)\b|"
            r"\.(akira|bianlian|locked|encrypted|crypted|crypt|enc)\b",
            "ransom note naming or ransomware encrypted extension",
        )
    if ttp_id == "TTP0005":
        return (
            r"(?i)(\\startup\\[^\\]+\.(exe|bat|cmd|ps1|vbs|js|jse|lnk|py|hta|scr)\b|"
            r"\\(run|runonce)\\[^\\]+\.(exe|bat|cmd|ps1|vbs|js|jse|lnk|py|hta|scr)\b|"
            r"currentversion\\run.*\.(exe|bat|cmd|ps1|vbs|js|jse|lnk|py|hta|scr)\b)",
            "Run/RunOnce/Startup payload persistence",
        )
    if ttp_id == "TTP0009":
        return (
            r"(?i)("
            r"\b(rundll32)(?:\.exe)?\b.*((%temp%|%appdata%|\\users\\[^\\]+\\appdata\\|\\users\\public\\|\\programdata\\|[a-z]:\\(?!windows\\|program files(?: \(x86\))?\\)).*\.(dll|cpl|ocx)\b[^\\r\\n,]*,\s*(#[0-9]+|[A-Za-z_@$?][A-Za-z0-9_@$?]*)|https?://)|"
            r"\b(regsvr32)(?:\.exe)?\b.*((%temp%|%appdata%|\\users\\[^\\]+\\appdata\\|\\users\\public\\|\\programdata\\|[a-z]:\\(?!windows\\|program files(?: \(x86\))?\\)).*\.(dll|ocx|sct)\b|/i:\s*(https?://|scrobj\.dll)|https?://|scrobj\.dll)|"
            r"\b(mshta)(?:\.exe)?\b.*((%temp%|%appdata%|\\users\\[^\\]+\\appdata\\|\\users\\public\\|\\programdata\\|[a-z]:\\(?!windows\\|program files(?: \(x86\))?\\)).*\.(hta|js|jse|vbs|vbe|wsf)\b|https?://|javascript:|vbscript:)|"
            r"\b(wscript|cscript)(?:\.exe)?\b.*(%temp%|%appdata%|\\users\\[^\\]+\\appdata\\|\\users\\public\\|\\programdata\\|[a-z]:\\(?!windows\\|program files(?: \(x86\))?\\)).*\.(js|jse|vbs|vbe|wsf|wsh)\b|"
            r"\b(parentprocessname|creatorprocessname)\b.{0,64}\b(rundll32|regsvr32|mshta|wscript|cscript)(?:\.exe)?\b"
            r")",
            "proxy execution via non-system DLL export, scriptlet/URL, script payload, or proxy-binary child-process ancestry",
        )
    if ttp_id == "TTP0015":
        return (
            r"(?i)(global\\.*(payload|ransom|crypt|locker|mutex)|"
            r"(global\\)?[a-z0-9_./-]*[a-f0-9]{16,}[a-z0-9_./-]*|"
            r"(global\\)?[A-Za-z0-9+/]{24,}={0,2})",
            "malware-like global or high-entropy mutex",
        )
    return "|".join(re.escape(value) for value in evidence), "literal strong evidence"


def _config_path(filename: str) -> Path:
    return CONFIG_DIR / filename


def _ttp_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get("ttps"), list):
        return [item for item in payload["ttps"] if isinstance(item, dict)]
    inference = payload.get("ttp_inference")
    if isinstance(inference, dict) and isinstance(inference.get("ttps"), list):
        return [item for item in inference["ttps"] if isinstance(item, dict)]
    return []


def _ttp_evidence(item: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    values: list[str] = []
    for value in item.get("evidence", []) or []:
        text = str(value or "").strip()
        if not text or text.lower() in seen:
            continue
        seen.add(text.lower())
        values.append(text[:240])
    return values


def _strong_ttp_evidence(ttp_id: str, evidence: list[str]) -> list[str]:
    pattern = _TTP_EVIDENCE_PATTERNS.get(ttp_id)
    if pattern is None:
        return []
    return [item for item in evidence if pattern.search(item.replace("/", "\\"))]


def build_ttp_velociraptor_artifact_plan(payload: dict[str, Any]) -> dict[str, Any]:
    generated_at = datetime.now(UTC).isoformat()
    selected: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for item in _ttp_items(payload):
        ttp_id = str(item.get("ttp_id") or "")
        mapping = _TTP_ARTIFACTS.get(ttp_id)
        evidence = _ttp_evidence(item)
        confidence = float(item.get("confidence") or 0)
        if mapping is None:
            skipped.append({"ttp_id": ttp_id, "reason": "no_artifact_mapping", "evidence": evidence[:3]})
            continue
        if confidence < float(str(mapping["min_confidence"])):
            skipped.append({"ttp_id": ttp_id, "reason": "below_required_evidence_strength", "evidence": evidence[:3]})
            continue
        strong = _strong_ttp_evidence(ttp_id, evidence)
        if not strong:
            skipped.append({"ttp_id": ttp_id, "reason": "no_strong_observable_evidence", "evidence": evidence[:3]})
            continue
        selected.append({"ttp_id": ttp_id, "name": item.get("name"), "confidence": confidence, "evidence": strong})
        candidate_regex, normalized_observable = _generalized_ttp_pattern(ttp_id, strong)
        artifacts.append(
            {
                "name": str(mapping["name"]),
                "type": "velociraptor_ttp_artifact_plan",
                "generated_at": generated_at,
                "ttp_id": ttp_id,
                "ttp_name": item.get("name"),
                "mitre_attack_id": item.get("mitre_attack_id"),
                "artifact_intent": str(mapping["intent"]),
                "expected_observable_evidence": str(mapping["observable"]),
                "required_evidence_strength": "strong",
                "query_template": str(mapping["template"]),
                "evidence": strong,
                "raw_evidence": strong,
                "generalized_pattern": candidate_regex,
                "normalized_observable": normalized_observable,
                "sources": item.get("sources", []),
                "candidate_regex": candidate_regex,
            }
        )
    return {
        "dry_run": True,
        "generated_at": generated_at,
        "selected_ttps": selected,
        "generated_artifacts": artifacts,
        "skipped_ttps": skipped,
        "summary": {
            "selected_ttp_count": len(selected),
            "generated_artifact_count": len(artifacts),
            "skipped_ttp_count": len(skipped),
        },
    }


@lru_cache(maxsize=1)
def _artifact_configs() -> dict[str, Any]:
    group_payload = load_json_config(str(_config_path("artifact_groups.json")))
    rule_payload = load_json_config(str(_config_path("classification_rules.json")))
    query_payload = load_json_config(str(_config_path("native_vql_templates.json")))
    glob_payload = load_json_config(str(_config_path("default_globs.json")))
    groups = {str(item["name"]): item for item in group_payload["groups"]}
    rules = []
    for item in rule_payload["rules"]:
        rule = dict(item)
        if "value_regex" in rule:
            rule["value_pattern"] = re.compile(str(rule["value_regex"]), re.IGNORECASE)
        if "context_regex" in rule:
            rule["context_pattern"] = re.compile(str(rule["context_regex"]), re.IGNORECASE)
        if "category" in rule:
            rule["category"] = str(rule["category"]).lower()
        if "category_in" in rule:
            rule["category_in"] = {str(value).lower() for value in rule["category_in"]}
        rules.append(rule)
    return {
        "groups": groups,
        "rules": rules,
        "default_group": str(rule_payload["default_group"]),
        "high_confidence_groups": {str(item) for item in group_payload.get("high_confidence_groups", [])},
        "exact_ioc_policy": dict(group_payload.get("exact_ioc_policy", {})),
        "query_profiles": {
            str(key): {
                "query": str(value["query"]),
                "regex_mode": str(value.get("regex_mode") or "substring"),
            }
            for key, value in query_payload["profiles"].items()
        },
        "description_lines": [str(item) for item in query_payload["description_lines"]],
        "glob_profiles": {
            str(key): {
                "parameter_name": str(value["parameter_name"]),
                "default": str(value["default"]),
            }
            for key, value in glob_payload["profiles"].items()
        },
    }


def _group_config(name: str) -> dict[str, Any]:
    return _artifact_configs()["groups"].get(
        name,
        {
            "name": name,
            "description": name,
            "query_profile": "file_glob",
            "glob_profile": "file_glob",
        },
    )


def _normalize_native_query(profile: str, query: str) -> str:
    return query


def _network_eventlog_query() -> str:
    return """LET Regex <= CandidateRegex
LET TimeWindowHoursInt <= atoi(string=TimeWindowHours)
LET Cutoff <= now() - TimeWindowHoursInt * 3600
LET MaxRowsInt <= atoi(string=MaxRows)
LET PowerShellExe <= 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe'
LET DnsClientScript <= format(format="$ErrorActionPreference='SilentlyContinue'; $start=(Get-Date).AddHours(-%v); Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; StartTime=$start} -ErrorAction SilentlyContinue | Select-Object -First %v | ForEach-Object { $xml=[xml]$_.ToXml(); $data=@{}; foreach ($d in $xml.Event.EventData.Data) { $name=[string]$d.Name; if ($name) { $data[$name]=[string]$d.'#text' } }; [PSCustomObject]@{ EventTime=$_.TimeCreated.ToUniversalTime().ToString('o'); Channel=$_.LogName; Provider=$_.ProviderName; EventID=$_.Id; RecordID=$_.RecordId; Message=$_.Message; MessageFlat=($_.Message -replace '\\s+', ' '); EventDataJson=($data | ConvertTo-Json -Compress -Depth 6) } | ConvertTo-Json -Compress -Depth 6 }", args=[TimeWindowHoursInt, MaxRowsInt])
LET SysmonNetScript <= format(format="$ErrorActionPreference='SilentlyContinue'; $start=(Get-Date).AddHours(-%v); Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$start} -ErrorAction SilentlyContinue | Select-Object -First %v | ForEach-Object { $xml=[xml]$_.ToXml(); $data=@{}; foreach ($d in $xml.Event.EventData.Data) { $name=[string]$d.Name; if ($name) { $data[$name]=[string]$d.'#text' } }; [PSCustomObject]@{ EventTime=$_.TimeCreated.ToUniversalTime().ToString('o'); Channel=$_.LogName; Provider=$_.ProviderName; EventID=$_.Id; RecordID=$_.RecordId; Message=$_.Message; MessageFlat=($_.Message -replace '\\s+', ' '); EventDataJson=($data | ConvertTo-Json -Compress -Depth 6) } | ConvertTo-Json -Compress -Depth 6 }", args=[TimeWindowHoursInt, MaxRowsInt])
LET FirewallScript <= format(format="$ErrorActionPreference='SilentlyContinue'; $start=(Get-Date).AddHours(-%v); Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; StartTime=$start} -ErrorAction SilentlyContinue | Select-Object -First %v | ForEach-Object { $xml=[xml]$_.ToXml(); $data=@{}; foreach ($d in $xml.Event.EventData.Data) { $name=[string]$d.Name; if ($name) { $data[$name]=[string]$d.'#text' } }; [PSCustomObject]@{ EventTime=$_.TimeCreated.ToUniversalTime().ToString('o'); Channel=$_.LogName; Provider=$_.ProviderName; EventID=$_.Id; RecordID=$_.RecordId; Message=$_.Message; MessageFlat=($_.Message -replace '\\s+', ' '); EventDataJson=($data | ConvertTo-Json -Compress -Depth 6) } | ConvertTo-Json -Compress -Depth 6 }", args=[TimeWindowHoursInt, MaxRowsInt])
LET DnsClientPowerShell <= SELECT *
FROM foreach(
  row={ SELECT parse_json(data=Stdout) AS Row FROM execve(argv=[PowerShellExe, '-ExecutionPolicy', 'Unrestricted', '-encodedCommand', base64encode(string=utf16_encode(string=DnsClientScript))], sep='\\n', length=10000000) WHERE Stdout },
  query={ SELECT Row.EventTime AS EventTime, Row.Channel AS Channel, Row.Provider AS Provider, Row.EventID AS EventID, Row.RecordID AS RecordID, Row.Message AS Message, Row.MessageFlat AS MessageFlat, Row.EventDataJson AS EventDataJson, 'dns_client_powershell' AS source, 'Get-WinEvent:Microsoft-Windows-DNS-Client/Operational' AS _Source FROM scope() })
WHERE Message =~ Regex OR MessageFlat =~ Regex OR EventDataJson =~ Regex
LET SysmonNetPowerShell <= SELECT *
FROM foreach(
  row={ SELECT parse_json(data=Stdout) AS Row FROM execve(argv=[PowerShellExe, '-ExecutionPolicy', 'Unrestricted', '-encodedCommand', base64encode(string=utf16_encode(string=SysmonNetScript))], sep='\\n', length=10000000) WHERE Stdout },
  query={ SELECT Row.EventTime AS EventTime, Row.Channel AS Channel, Row.Provider AS Provider, Row.EventID AS EventID, Row.RecordID AS RecordID, Row.Message AS Message, Row.MessageFlat AS MessageFlat, Row.EventDataJson AS EventDataJson, 'sysmon_network_powershell' AS source, 'Get-WinEvent:Microsoft-Windows-Sysmon/Operational' AS _Source FROM scope() })
WHERE Message =~ Regex OR MessageFlat =~ Regex OR EventDataJson =~ Regex
LET FirewallPowerShell <= SELECT *
FROM foreach(
  row={ SELECT parse_json(data=Stdout) AS Row FROM execve(argv=[PowerShellExe, '-ExecutionPolicy', 'Unrestricted', '-encodedCommand', base64encode(string=utf16_encode(string=FirewallScript))], sep='\\n', length=10000000) WHERE Stdout },
  query={ SELECT Row.EventTime AS EventTime, Row.Channel AS Channel, Row.Provider AS Provider, Row.EventID AS EventID, Row.RecordID AS RecordID, Row.Message AS Message, Row.MessageFlat AS MessageFlat, Row.EventDataJson AS EventDataJson, 'firewall_powershell' AS source, 'Get-WinEvent:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' AS _Source FROM scope() })
WHERE Message =~ Regex OR MessageFlat =~ Regex OR EventDataJson =~ Regex
LET DnsClientEvtxHunter <= SELECT System.TimeCreated.SystemTime AS EventTime,
       Channel,
       Provider,
       System.EventID.Value AS EventID,
       Message,
       _Source,
       'dns_client_evtxhunter' AS source
FROM Artifact.Windows.EventLogs.EvtxHunter(EvtxGlob='C:/Windows/System32/winevt/Logs/Microsoft-Windows-DNS-Client%4Operational.evtx')
WHERE Message =~ Regex AND System.TimeCreated.SystemTime > Cutoff
LET SysmonNetEvtxHunter <= SELECT System.TimeCreated.SystemTime AS EventTime,
       Channel,
       Provider,
       System.EventID.Value AS EventID,
       Message,
       _Source,
       'sysmon_network_evtxhunter' AS source
FROM Artifact.Windows.EventLogs.EvtxHunter(EvtxGlob='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
WHERE Message =~ Regex AND System.TimeCreated.SystemTime > Cutoff
LET FirewallEvtxHunter <= SELECT System.TimeCreated.SystemTime AS EventTime,
       Channel,
       Provider,
       System.EventID.Value AS EventID,
       Message,
       _Source,
       'firewall_evtxhunter' AS source
FROM Artifact.Windows.EventLogs.EvtxHunter(EvtxGlob='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx')
WHERE Message =~ Regex AND System.TimeCreated.SystemTime > Cutoff
SELECT *, 'eventlog_network' AS match_type,
       ArtifactName AS source_artifact,
       format(format='%v:%v:%v', args=[ArtifactName, source, if(condition=_Source, then=_Source, else=source)]) AS candidate_id
FROM chain(a=DnsClientPowerShell, b=SysmonNetPowerShell, c=FirewallPowerShell, d=DnsClientEvtxHunter, e=SysmonNetEvtxHunter, f=FirewallEvtxHunter)
LIMIT 1001"""


def _process_trace_query() -> str:
    return """LET Regex <= CandidateRegex
LET ProcessPathRegex <= CandidateProcessPathRegex
LET ProcessNameRegex <= CandidateProcessNameRegex
LET CommandLineRegex <= CandidateCommandLineRegex
LET TimeWindowHoursInt <= atoi(string=TimeWindowHours)
LET Cutoff <= now() - TimeWindowHoursInt * 3600
LET MaxRowsInt <= atoi(string=MaxRows)
LET PowerShellExe <= 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe'
LET IsProxyExecutionCandidate <= CandidateRegex =~ '(?i)(rundll32|regsvr32|mshta|wscript|cscript)'
LET ProxyBinaryRegex <= '(?i)\\b(rundll32|regsvr32|mshta|wscript|cscript)(?:\\.exe)?\\b'
LET ProxyDirectRegex <= '(?i)(https?://|javascript:|vbscript:|script:|scrobj\\.dll|/i:\\s*(https?://|scrobj\\.dll)|(%temp%|%appdata%|\\\\users\\\\[^\\\\]+\\\\appdata\\\\|\\\\users\\\\public\\\\|\\\\programdata\\\\|[a-z]:\\\\(?!windows\\\\|program files(?: \\(x86\\))?\\\\)).*\\.(dll|cpl|ocx|sct|hta|js|jse|vbs|vbe|wsf|wsh|tmp|dat|bin)\\b([^\\r\\n,]*,\\s*(#[0-9]+|[A-Za-z_@$?][A-Za-z0-9_@$?]*))?)'
LET ProxyChildRegex <= '(?i)\\.(exe|dll|cpl|ocx|js|jse|vbs|vbe|wsf|wsh|hta|tmp|dat|bin)\\b'
LET Security4688Script <= format(format="$ErrorActionPreference='SilentlyContinue'; $start=(Get-Date).AddHours(-%v); Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$start} -ErrorAction SilentlyContinue | Select-Object -First %v | ForEach-Object { $xml=[xml]$_.ToXml(); $data=@{}; foreach ($d in $xml.Event.EventData.Data) { $name=[string]$d.Name; if ($name) { $data[$name]=[string]$d.'#text' } }; [PSCustomObject]@{ EventTime=$_.TimeCreated.ToUniversalTime().ToString('o'); Channel=$_.LogName; Provider=$_.ProviderName; EventID=$_.Id; RecordID=$_.RecordId; Message=$_.Message; MessageFlat=($_.Message -replace '\\s+', ' '); NewProcessName=$data['NewProcessName']; CommandLine=$(if ($data.ContainsKey('CommandLine')) { $data['CommandLine'] } else { $data['ProcessCommandLine'] }); ParentProcessName=$(if ($data.ContainsKey('ParentProcessName')) { $data['ParentProcessName'] } else { $data['CreatorProcessName'] }); CreatorProcessName=$data['CreatorProcessName']; SubjectUserName=$data['SubjectUserName']; EventDataJson=($data | ConvertTo-Json -Compress -Depth 6) } | ConvertTo-Json -Compress -Depth 6 }", args=[TimeWindowHoursInt, MaxRowsInt])
LET PowerShellOperationalScript <= format(format="$ErrorActionPreference='SilentlyContinue'; $start=(Get-Date).AddHours(-%v); Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$start} -ErrorAction SilentlyContinue | Select-Object -First %v | ForEach-Object { $xml=[xml]$_.ToXml(); $data=@{}; foreach ($d in $xml.Event.EventData.Data) { $name=[string]$d.Name; if ($name) { $data[$name]=[string]$d.'#text' } }; [PSCustomObject]@{ EventTime=$_.TimeCreated.ToUniversalTime().ToString('o'); Channel=$_.LogName; Provider=$_.ProviderName; EventID=$_.Id; RecordID=$_.RecordId; Message=$_.Message; MessageFlat=($_.Message -replace '\\s+', ' '); EventDataJson=($data | ConvertTo-Json -Compress -Depth 6) } | ConvertTo-Json -Compress -Depth 6 }", args=[TimeWindowHoursInt, MaxRowsInt])
LET SysmonProcessScript <= format(format="$ErrorActionPreference='SilentlyContinue'; $start=(Get-Date).AddHours(-%v); Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$start} -ErrorAction SilentlyContinue | Select-Object -First %v | ForEach-Object { $xml=[xml]$_.ToXml(); $data=@{}; foreach ($d in $xml.Event.EventData.Data) { $name=[string]$d.Name; if ($name) { $data[$name]=[string]$d.'#text' } }; [PSCustomObject]@{ EventTime=$_.TimeCreated.ToUniversalTime().ToString('o'); Channel=$_.LogName; Provider=$_.ProviderName; EventID=$_.Id; RecordID=$_.RecordId; Message=$_.Message; MessageFlat=($_.Message -replace '\\s+', ' '); NewProcessName=$data['Image']; CommandLine=$data['CommandLine']; ParentProcessName=$data['ParentImage']; CreatorProcessName=''; EventDataJson=($data | ConvertTo-Json -Compress -Depth 6) } | ConvertTo-Json -Compress -Depth 6 }", args=[TimeWindowHoursInt, MaxRowsInt])
LET LiveProcess <= SELECT Pid, Name, Exe, Exe AS OSPath, Exe AS NewProcessName, CommandLine,
       '' AS ParentProcessName,
       '' AS CreatorProcessName,
       CreateTime AS EventTime,
       'pslist' AS source,
       'pslist' AS _Source
  FROM pslist()
  WHERE ((Name =~ ProcessNameRegex OR Exe =~ ProcessPathRegex OR CommandLine =~ CommandLineRegex)
     OR (IsProxyExecutionCandidate AND ((Name =~ ProxyBinaryRegex OR Exe =~ ProxyBinaryRegex) AND CommandLine =~ ProxyDirectRegex)))
    AND CreateTime > Cutoff
LET Security4688PowerShell <= SELECT *
FROM foreach(
  row={ SELECT parse_json(data=Stdout) AS Row FROM execve(argv=[PowerShellExe, '-ExecutionPolicy', 'Unrestricted', '-encodedCommand', base64encode(string=utf16_encode(string=Security4688Script))], sep='\\n', length=10000000) WHERE Stdout },
  query={ SELECT Row.EventTime AS EventTime, Row.Channel AS Channel, Row.Provider AS Provider, Row.EventID AS EventID, Row.RecordID AS RecordID, Row.Message AS Message, Row.MessageFlat AS MessageFlat, if(condition=Row.NewProcessName, then=Row.NewProcessName, else='Get-WinEvent:Security/4688') AS OSPath, Row.NewProcessName AS NewProcessName, Row.CommandLine AS CommandLine, Row.ParentProcessName AS ParentProcessName, Row.CreatorProcessName AS CreatorProcessName, Row.SubjectUserName AS SubjectUserName, Row.EventDataJson AS EventDataJson, 'security_4688_powershell' AS source, 'Get-WinEvent:Security/4688' AS _Source FROM scope() })
WHERE NewProcessName =~ ProcessPathRegex OR (NewProcessName AND basename(path=NewProcessName, path_type='windows') =~ ProcessNameRegex) OR CommandLine =~ CommandLineRegex OR ParentProcessName =~ ProcessPathRegex OR CreatorProcessName =~ ProcessPathRegex OR EventDataJson =~ Regex OR Message =~ Regex OR MessageFlat =~ Regex
   OR (IsProxyExecutionCandidate AND ((NewProcessName =~ ProxyBinaryRegex AND CommandLine =~ ProxyDirectRegex)
       OR ((ParentProcessName =~ ProxyBinaryRegex OR CreatorProcessName =~ ProxyBinaryRegex) AND (NewProcessName =~ ProxyChildRegex OR CommandLine =~ ProxyDirectRegex))))
LET PowerShellOperationalPowerShell <= SELECT *
FROM foreach(
  row={ SELECT parse_json(data=Stdout) AS Row FROM execve(argv=[PowerShellExe, '-ExecutionPolicy', 'Unrestricted', '-encodedCommand', base64encode(string=utf16_encode(string=PowerShellOperationalScript))], sep='\\n', length=10000000) WHERE Stdout },
  query={ SELECT Row.EventTime AS EventTime, Row.Channel AS Channel, Row.Provider AS Provider, Row.EventID AS EventID, Row.RecordID AS RecordID, Row.Message AS Message, Row.MessageFlat AS MessageFlat, Row.EventDataJson AS EventDataJson, 'powershell_operational_powershell' AS source, 'Get-WinEvent:Microsoft-Windows-PowerShell/Operational' AS _Source FROM scope() })
WHERE Message =~ Regex OR MessageFlat =~ Regex OR EventDataJson =~ Regex
   OR (IsProxyExecutionCandidate AND (Message =~ ProxyDirectRegex OR MessageFlat =~ ProxyDirectRegex))
LET SysmonProcessPowerShell <= SELECT *
FROM foreach(
  row={ SELECT parse_json(data=Stdout) AS Row FROM execve(argv=[PowerShellExe, '-ExecutionPolicy', 'Unrestricted', '-encodedCommand', base64encode(string=utf16_encode(string=SysmonProcessScript))], sep='\\n', length=10000000) WHERE Stdout },
  query={ SELECT Row.EventTime AS EventTime, Row.Channel AS Channel, Row.Provider AS Provider, Row.EventID AS EventID, Row.RecordID AS RecordID, Row.Message AS Message, Row.MessageFlat AS MessageFlat, if(condition=Row.NewProcessName, then=Row.NewProcessName, else='Get-WinEvent:Microsoft-Windows-Sysmon/Operational') AS OSPath, Row.NewProcessName AS NewProcessName, Row.CommandLine AS CommandLine, Row.ParentProcessName AS ParentProcessName, Row.CreatorProcessName AS CreatorProcessName, Row.EventDataJson AS EventDataJson, 'sysmon_process_powershell' AS source, 'Get-WinEvent:Microsoft-Windows-Sysmon/Operational' AS _Source FROM scope() })
WHERE NewProcessName =~ ProcessPathRegex OR (NewProcessName AND basename(path=NewProcessName, path_type='windows') =~ ProcessNameRegex) OR CommandLine =~ CommandLineRegex OR ParentProcessName =~ ProcessPathRegex OR CreatorProcessName =~ ProcessPathRegex OR EventDataJson =~ Regex OR Message =~ Regex OR MessageFlat =~ Regex
   OR (IsProxyExecutionCandidate AND ((NewProcessName =~ ProxyBinaryRegex AND CommandLine =~ ProxyDirectRegex)
       OR ((ParentProcessName =~ ProxyBinaryRegex OR CreatorProcessName =~ ProxyBinaryRegex) AND (NewProcessName =~ ProxyChildRegex OR CommandLine =~ ProxyDirectRegex))))
LET Security4688EvtxHunter <= SELECT System.TimeCreated.SystemTime AS EventTime,
       Channel,
       Provider,
       System.EventID.Value AS EventID,
       if(condition=_Source, then=_Source, else='Security.evtx') AS OSPath,
       Message,
       _Source,
       'security_4688_evtxhunter' AS source
  FROM Artifact.Windows.EventLogs.EvtxHunter(EvtxGlob='%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx', IdRegex='^4688$')
  WHERE (Message =~ Regex OR (IsProxyExecutionCandidate AND (Message =~ ProxyDirectRegex OR Message =~ ProxyBinaryRegex)))
    AND System.TimeCreated.SystemTime > Cutoff
LET PowerShellOperationalEvtxHunter <= SELECT System.TimeCreated.SystemTime AS EventTime,
       Channel,
       Provider,
       System.EventID.Value AS EventID,
       if(condition=_Source, then=_Source, else='Microsoft-Windows-PowerShell%4Operational.evtx') AS OSPath,
       Message,
       _Source,
       'powershell_operational_evtxhunter' AS source
  FROM Artifact.Windows.EventLogs.EvtxHunter(EvtxGlob='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx')
  WHERE (Message =~ Regex OR (IsProxyExecutionCandidate AND Message =~ ProxyDirectRegex))
    AND System.TimeCreated.SystemTime > Cutoff
LET SysmonProcessEvtxHunter <= SELECT System.TimeCreated.SystemTime AS EventTime,
       Channel,
       Provider,
       System.EventID.Value AS EventID,
       if(condition=_Source, then=_Source, else='Microsoft-Windows-Sysmon%4Operational.evtx') AS OSPath,
       Message,
       _Source,
       'sysmon_process_evtxhunter' AS source
  FROM Artifact.Windows.EventLogs.EvtxHunter(EvtxGlob='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx')
  WHERE (Message =~ Regex OR (IsProxyExecutionCandidate AND (Message =~ ProxyDirectRegex OR Message =~ ProxyBinaryRegex)))
    AND System.TimeCreated.SystemTime > Cutoff
LET PrefetchProcess <= SELECT get(field='OSPath', default=get(field='source')) AS OSPath,
       get(field='ExecutablePath', default=get(field='file_name')) AS ExecutablePath,
       get(field='ExecutablePath', default=get(field='file_name')) AS NewProcessName,
       if(condition=get(field='event_time'), then=get(field='event_time'), else=get(member='0', item=get(field='LastRunTimes'))) AS EventTime,
       'prefetch' AS source,
       'Windows.Timeline.Prefetch' AS _Source
  FROM Artifact.Windows.Timeline.Prefetch()
  WHERE ((get(field='OSPath', default=get(field='source')) =~ ProcessPathRegex OR get(field='ExecutablePath', default=get(field='file_name')) =~ ProcessPathRegex OR get(field='file_name') =~ ProcessNameRegex)
      OR (IsProxyExecutionCandidate AND get(field='ExecutablePath', default=get(field='file_name')) =~ ProxyBinaryRegex))
    AND if(condition=get(field='event_time'), then=get(field='event_time'), else=get(member='0', item=get(field='LastRunTimes'))) > Cutoff
LET AmcacheEvidence <= SELECT OSPath, Name, Name AS NewProcessName,
       Mtime AS EventTime,
       'amcache_hive' AS source,
       'C:/Windows/AppCompat/Programs/Amcache.hve' AS _Source
  FROM glob(globs='C:/Windows/AppCompat/Programs/Amcache.hve')
  WHERE (OSPath =~ ProcessPathRegex OR Name =~ ProcessNameRegex) AND Mtime > Cutoff
LET ShimcacheEvidence <= SELECT OSPath, Name, Name AS NewProcessName,
       Mtime AS EventTime,
       'shimcache_hive' AS source,
       'C:/Windows/System32/config/SYSTEM' AS _Source
  FROM glob(globs='C:/Windows/System32/config/SYSTEM')
  WHERE (OSPath =~ ProcessPathRegex OR Name =~ ProcessNameRegex) AND Mtime > Cutoff
SELECT *, 'process_trace' AS match_type,
       ArtifactName AS source_artifact,
       format(format='%v:%v:%v', args=[ArtifactName, source, get(field='OSPath', default=get(field='_Source', default=source))]) AS candidate_id
FROM chain(a=LiveProcess, b=Security4688PowerShell, c=PowerShellOperationalPowerShell, d=SysmonProcessPowerShell, e=Security4688EvtxHunter, f=PowerShellOperationalEvtxHunter, g=SysmonProcessEvtxHunter, h=PrefetchProcess, i=AmcacheEvidence, j=ShimcacheEvidence)
LIMIT 1001"""


def _service_persistence_query() -> str:
    return """LET Regex <= CandidateRegex
LET TimeWindowHoursInt <= atoi(string=TimeWindowHours)
LET Cutoff <= now() - TimeWindowHoursInt * 3600
LET MaxRowsInt <= atoi(string=MaxRows)
LET PowerShellExe <= 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe'
LET ServiceControlRegex <= '(?i)(^|[\\\\/\\s])(sc|sc\\.exe)\\s+(create|config|start|failure|sdset)(\\s|$)|(^|[\\\\/\\s])net(\\.exe)?\\s+start(\\s|$)|New-Service|Set-Service|Start-Service'
LET ServiceWritableBinaryRegex <= '(?i)(users\\\\[^\\\\]+\\\\appdata\\\\|users\\\\public\\\\|programdata\\\\|windows\\\\temp\\\\|temp\\\\|vr-malware-test\\\\).+\\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jse|wsf|hta)\\b'
LET RegistryServiceGlobs <= split(string=RegistryGlobs, sep=",")
LET Security4688Script <= format(format="$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'; $start=(Get-Date).AddHours(-%v); Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$start} -ErrorAction SilentlyContinue | Select-Object -First %v | ForEach-Object { $xml=[xml]$_.ToXml(); $data=@{}; foreach ($d in $xml.Event.EventData.Data) { $name=[string]$d.Name; if ($name) { $data[$name]=[string]$d.'#text' } }; [PSCustomObject]@{ EventTime=$_.TimeCreated.ToUniversalTime().ToString('o'); Channel=$_.LogName; Provider=$_.ProviderName; EventID=$_.Id; RecordID=$_.RecordId; Message=$_.Message; MessageFlat=($_.Message -replace '\\s+', ' '); NewProcessName=$data['NewProcessName']; CommandLine=$(if ($data.ContainsKey('CommandLine')) { $data['CommandLine'] } else { $data['ProcessCommandLine'] }); ParentProcessName=$(if ($data.ContainsKey('ParentProcessName')) { $data['ParentProcessName'] } else { $data['CreatorProcessName'] }); CreatorProcessName=$data['CreatorProcessName']; SubjectUserName=$data['SubjectUserName']; EventDataJson=($data | ConvertTo-Json -Compress -Depth 6) } | ConvertTo-Json -Compress -Depth 6 }", args=[TimeWindowHoursInt, MaxRowsInt])
LET RegistryHits <= SELECT OSPath, Data, Mtime,
       Mtime AS EventTime,
       'exact_service_registry' AS match_type,
       ArtifactName AS source_artifact,
       format(format="%v:%v", args=[ArtifactName, OSPath]) AS candidate_id
FROM glob(globs=RegistryServiceGlobs, accessor="registry")
WHERE OSPath =~ Regex OR Data =~ Regex
LET LiveServiceControl <= SELECT Pid, Name, Exe AS OSPath, CommandLine,
       CreateTime AS EventTime,
       'live_service_control_process' AS match_type,
       ArtifactName AS source_artifact,
       format(format="%v:%v", args=[ArtifactName, Exe]) AS candidate_id
FROM pslist()
WHERE CreateTime > Cutoff
  AND (
    Name =~ Regex OR Exe =~ Regex OR CommandLine =~ Regex OR
    CommandLine =~ ServiceControlRegex OR CommandLine =~ ServiceWritableBinaryRegex
  )
LET Security4688ServiceControl <= SELECT *
FROM foreach(
  row={ SELECT parse_json(data=Stdout) AS Row FROM execve(argv=[PowerShellExe, '-ExecutionPolicy', 'Unrestricted', '-encodedCommand', base64encode(string=utf16_encode(string=Security4688Script))], sep='\\n', length=10000000) WHERE Stdout },
  query={ SELECT Row.EventTime AS EventTime, Row.Channel AS Channel, Row.Provider AS Provider, Row.EventID AS EventID, Row.RecordID AS RecordID, Row.Message AS Message, Row.MessageFlat AS MessageFlat, if(condition=Row.NewProcessName, then=Row.NewProcessName, else='Get-WinEvent:Security/4688') AS OSPath, Row.NewProcessName AS NewProcessName, Row.CommandLine AS CommandLine, Row.ParentProcessName AS ParentProcessName, Row.CreatorProcessName AS CreatorProcessName, Row.SubjectUserName AS SubjectUserName, Row.EventDataJson AS EventDataJson, 'service_control_process' AS match_type, ArtifactName AS source_artifact, format(format='%v:%v:%v', args=[ArtifactName, 'security_4688_powershell', if(condition=Row.NewProcessName, then=Row.NewProcessName, else=Row.RecordID)]) AS candidate_id FROM scope() })
WHERE NewProcessName =~ Regex OR CommandLine =~ Regex OR ParentProcessName =~ Regex OR CreatorProcessName =~ Regex OR EventDataJson =~ Regex OR Message =~ Regex OR MessageFlat =~ Regex
   OR CommandLine =~ ServiceControlRegex OR MessageFlat =~ ServiceControlRegex OR EventDataJson =~ ServiceControlRegex
   OR CommandLine =~ ServiceWritableBinaryRegex OR MessageFlat =~ ServiceWritableBinaryRegex OR EventDataJson =~ ServiceWritableBinaryRegex
SELECT *
FROM chain(a=RegistryHits, b=LiveServiceControl, c=Security4688ServiceControl)
LIMIT 1001"""


def _scheduled_task_persistence_query() -> str:
    return """LET Regex <= CandidateRegex
LET TimeWindowHoursInt <= atoi(string=TimeWindowHours)
LET Cutoff <= now() - TimeWindowHoursInt * 3600
LET MaxRowsInt <= atoi(string=MaxRows)
LET PowerShellExe <= 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe'
LET ScheduledTaskBinaryRegex <= '(?i)schtasks\\.exe'
LET ScheduledTaskActionRegex <= '(?i)(-create|-change|-run|-delete|/create|/change|/run|/delete|Register-ScheduledTask|Start-ScheduledTask|Unregister-ScheduledTask)'
LET RegistryTaskGlobs <= split(string=RegistryGlobs, sep=",")
LET Security4688Script <= format(format="$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'; $start=(Get-Date).AddHours(-%v); Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$start} -ErrorAction SilentlyContinue | Select-Object -First %v | ForEach-Object { $xml=[xml]$_.ToXml(); $data=@{}; foreach ($d in $xml.Event.EventData.Data) { $name=[string]$d.Name; if ($name) { $data[$name]=[string]$d.'#text' } }; [PSCustomObject]@{ EventTime=$_.TimeCreated.ToUniversalTime().ToString('o'); Channel=$_.LogName; Provider=$_.ProviderName; EventID=$_.Id; RecordID=$_.RecordId; Message=$_.Message; MessageFlat=($_.Message -replace '\\s+', ' '); NewProcessName=$data['NewProcessName']; CommandLine=$(if ($data.ContainsKey('CommandLine')) { $data['CommandLine'] } else { $data['ProcessCommandLine'] }); ParentProcessName=$(if ($data.ContainsKey('ParentProcessName')) { $data['ParentProcessName'] } else { $data['CreatorProcessName'] }); CreatorProcessName=$data['CreatorProcessName']; SubjectUserName=$data['SubjectUserName']; EventDataJson=($data | ConvertTo-Json -Compress -Depth 6) } | ConvertTo-Json -Compress -Depth 6 }", args=[TimeWindowHoursInt, MaxRowsInt])
LET RegistryHits <= SELECT OSPath, Data, Mtime,
       Mtime AS EventTime,
       'exact_scheduled_task_registry' AS match_type,
       ArtifactName AS source_artifact,
       format(format="%v:%v", args=[ArtifactName, OSPath]) AS candidate_id
FROM glob(globs=RegistryTaskGlobs, accessor="registry")
WHERE OSPath =~ Regex OR Data =~ Regex
LET LiveScheduledTask <= SELECT Pid, Name, Exe AS OSPath, CommandLine,
       CreateTime AS EventTime,
       'live_scheduled_task_process' AS match_type,
       ArtifactName AS source_artifact,
       format(format="%v:%v", args=[ArtifactName, Exe]) AS candidate_id
FROM pslist()
WHERE CreateTime > Cutoff
  AND (
    Name =~ Regex OR Exe =~ Regex OR CommandLine =~ Regex OR
    (Exe =~ ScheduledTaskBinaryRegex AND CommandLine =~ ScheduledTaskActionRegex)
  )
LET Security4688ScheduledTask <= SELECT *
FROM foreach(
  row={ SELECT parse_json(data=Stdout) AS Row FROM execve(argv=[PowerShellExe, '-ExecutionPolicy', 'Unrestricted', '-encodedCommand', base64encode(string=utf16_encode(string=Security4688Script))], sep='\\n', length=10000000) WHERE Stdout },
  query={ SELECT Row.EventTime AS EventTime, Row.Channel AS Channel, Row.Provider AS Provider, Row.EventID AS EventID, Row.RecordID AS RecordID, Row.Message AS Message, Row.MessageFlat AS MessageFlat, if(condition=Row.NewProcessName, then=Row.NewProcessName, else='Get-WinEvent:Security/4688') AS OSPath, Row.NewProcessName AS NewProcessName, Row.CommandLine AS CommandLine, Row.ParentProcessName AS ParentProcessName, Row.CreatorProcessName AS CreatorProcessName, Row.SubjectUserName AS SubjectUserName, Row.EventDataJson AS EventDataJson, 'scheduled_task_process' AS match_type, ArtifactName AS source_artifact, format(format='%v:%v:%v', args=[ArtifactName, 'security_4688_powershell', if(condition=Row.NewProcessName, then=Row.NewProcessName, else=Row.RecordID)]) AS candidate_id FROM scope() })
WHERE NewProcessName =~ Regex OR CommandLine =~ Regex OR ParentProcessName =~ Regex OR CreatorProcessName =~ Regex OR EventDataJson =~ Regex OR Message =~ Regex OR MessageFlat =~ Regex
   OR (
      (NewProcessName =~ ScheduledTaskBinaryRegex OR CommandLine =~ ScheduledTaskBinaryRegex OR EventDataJson =~ ScheduledTaskBinaryRegex)
      AND (CommandLine =~ ScheduledTaskActionRegex OR MessageFlat =~ ScheduledTaskActionRegex OR EventDataJson =~ ScheduledTaskActionRegex)
   )
SELECT *
FROM chain(a=RegistryHits, b=LiveScheduledTask, c=Security4688ScheduledTask)
LIMIT 1001"""


def _behavioral_composite_query(glob_name: str) -> str:
    return f"""LET TimeWindowHoursInt <= atoi(string=TimeWindowHours)
LET MaxRowsInt <= atoi(string=MaxRows)
LET Cutoff <= now() - TimeWindowHoursInt * 3600
LET PowerShellExe <= 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe'
LET NoteGlobs <= split(string={glob_name}, sep=",")
LET SuspiciousNoteRegex <= '(?i)(^|[\\\\/])[^\\\\/]*(readme|recover|restore|decrypt|how[_ -]?to|help|ransom|payment|bitcoin|unlock|encrypted|instructions?)[^\\\\/]*\\.(txt|hta|md|rtf|html|url)$'
LET DeployableWritableProcessRegex <= '(?i)([\\\\/]users[\\\\/][^\\\\/]+[\\\\/]appdata[\\\\/]|[\\\\/]users[\\\\/]public[\\\\/]|[\\\\/]programdata[\\\\/]|[\\\\/]windows[\\\\/]temp|[\\\\/]temp[\\\\/]).*\\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jse|hta)'
LET LabExecutionRegex <= '(?i)[\\\\/](vr-malware-test|threattrace-bait)[\\\\/]'
LET BaitRegex <= '(?i)[\\\\/]threattrace-bait[\\\\/]'
LET EncryptedExtensionRegex <= '(?i)[\\\\/](threattrace-bait|desktop|documents|downloads|programdata)[\\\\/].*\\.(akira|bianlian|ava|locked|lockbit|encrypted|crypted|crypt|enc|pay|pay2key|conti|hive|royal|revil|ryuk|blackcat|alphv|blackbasta|ransomhub|qilin)$'
LET ExcludeRegex <= '(?i)(post_execution_triage\\.ps1|execute_sample\\.ps1)$'
LET Security4688Script <= format(format="$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'; $start=(Get-Date).AddHours(-%v); Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4688; StartTime=$start}} -ErrorAction SilentlyContinue | Select-Object -First %v | ForEach-Object {{ $xml=[xml]$_.ToXml(); $data=@{{}}; foreach ($d in $xml.Event.EventData.Data) {{ $n=[string]$d.Name; if ($n) {{ $data[$n]=[string]$d.'#text' }} }}; [PSCustomObject]@{{ EventTime=$_.TimeCreated.ToUniversalTime().ToString('o'); RecordID=$_.RecordId; EventID=$_.Id; Provider=$_.ProviderName; NewProcessName=$data['NewProcessName']; CommandLine=$(if ($data.ContainsKey('CommandLine')) {{ $data['CommandLine'] }} else {{ $data['ProcessCommandLine'] }}); ParentProcessName=$(if ($data.ContainsKey('ParentProcessName')) {{ $data['ParentProcessName'] }} else {{ $data['CreatorProcessName'] }}); CreatorProcessName=$data['CreatorProcessName']; SubjectUserName=$data['SubjectUserName']; EventDataJson=($data | ConvertTo-Json -Compress -Depth 6) }} | ConvertTo-Json -Compress -Depth 6 }}", args=[TimeWindowHoursInt, MaxRowsInt])
LET LiveProcessScript <= "$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'; Get-CimInstance Win32_Process | ForEach-Object {{ $gp=Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue; [PSCustomObject]@{{ Pid=$_.ProcessId; Name=$_.Name; Exe=$_.ExecutablePath; CommandLine=$_.CommandLine; ParentProcessId=$_.ParentProcessId; CreateTime=$_.CreationDate; WorkingSet64=$(if ($gp) {{ $gp.WorkingSet64 }} else {{ $null }}); PrivateMemorySize64=$(if ($gp) {{ $gp.PrivateMemorySize64 }} else {{ $null }}); HandleCount=$(if ($gp) {{ $gp.HandleCount }} else {{ $null }}); ThreadCount=$(if ($gp) {{ $gp.Threads.Count }} else {{ $null }}) }} }} | ConvertTo-Json -Compress -Depth 5"
LET Notes <= SELECT OSPath, Size, Mtime, Btime,
       if(condition=Mtime > Cutoff, then=Mtime, else=Btime) AS EventTime
  FROM glob(globs=NoteGlobs)
  WHERE (Mtime > Cutoff OR Btime > Cutoff)
    AND OSPath =~ SuspiciousNoteRegex
    AND NOT OSPath =~ ExcludeRegex
LET BaitChanges <= SELECT OSPath, Size, Mtime, Btime,
       if(condition=Mtime > Cutoff, then=Mtime, else=Btime) AS EventTime
  FROM glob(globs=NoteGlobs)
  WHERE (Mtime > Cutoff OR Btime > Cutoff)
    AND OSPath =~ BaitRegex
    AND NOT OSPath =~ ExcludeRegex
LET EncryptedFiles <= SELECT OSPath, Size, Mtime, Btime,
       if(condition=Mtime > Cutoff, then=Mtime, else=Btime) AS EventTime
  FROM glob(globs=NoteGlobs)
  WHERE (Mtime > Cutoff OR Btime > Cutoff)
    AND OSPath =~ EncryptedExtensionRegex
    AND NOT OSPath =~ ExcludeRegex
LET LiveSuspiciousProcess <= SELECT Row.Pid AS Pid,
       Row.Name AS Name,
       Row.Exe AS Exe,
       Row.CommandLine AS CommandLine,
       Row.ParentProcessId AS ParentProcessId,
       Row.CreateTime AS CreateTime,
       Row.WorkingSet64 AS WorkingSet64,
       Row.PrivateMemorySize64 AS PrivateMemorySize64,
       Row.HandleCount AS HandleCount,
       Row.ThreadCount AS ThreadCount,
       Row.Exe AS OSPath,
       now() AS EventTime
  FROM foreach(
    row={{ SELECT parse_json(data=Stdout) AS Row FROM execve(argv=[PowerShellExe, '-NoProfile', '-ExecutionPolicy', 'Unrestricted', '-encodedCommand', base64encode(string=utf16_encode(string=LiveProcessScript))], sep='\\n', length=10000000) WHERE Stdout AND NOT Stdout =~ '^(#< CLIXML|<Objs)' }},
    query={{ SELECT Row FROM scope() }})
  WHERE Row.Exe =~ DeployableWritableProcessRegex OR Row.CommandLine =~ DeployableWritableProcessRegex
LET ProcessEvents <= SELECT *
FROM foreach(
  row={{ SELECT parse_json(data=Stdout) AS Row FROM execve(argv=[PowerShellExe, '-NoProfile', '-ExecutionPolicy', 'Unrestricted', '-encodedCommand', base64encode(string=utf16_encode(string=Security4688Script))], sep='\\n', length=10000000) WHERE Stdout AND NOT Stdout =~ '^(#< CLIXML|<Objs)' }},
  query={{ SELECT Row.EventTime AS EventTime,
       Row.EventID AS EventID,
       Row.Provider AS Provider,
       Row.RecordID AS RecordID,
       Row.NewProcessName AS NewProcessName,
       Row.CommandLine AS CommandLine,
       Row.ParentProcessName AS ParentProcessName,
       Row.CreatorProcessName AS CreatorProcessName,
       Row.SubjectUserName AS SubjectUserName,
       Row.EventDataJson AS EventDataJson,
       Row.NewProcessName AS OSPath
  FROM scope() }})
WHERE NewProcessName =~ DeployableWritableProcessRegex OR CommandLine =~ DeployableWritableProcessRegex OR ParentProcessName =~ DeployableWritableProcessRegex OR CommandLine =~ LabExecutionRegex
LET ProcessEventSignal <= SELECT EventTime,
       if(condition=CommandLine =~ LabExecutionRegex, then='lab_controlled_execution_4688', else='deployable_writable_process_execution_4688') AS BehaviorType,
       if(condition=CommandLine =~ LabExecutionRegex, then='medium', else='high') AS Severity,
       if(condition=CommandLine =~ LabExecutionRegex, then=0.60, else=0.86) AS Confidence,
       if(condition=CommandLine =~ LabExecutionRegex, then=4, else=18) AS Score,
       if(condition=CommandLine =~ LabExecutionRegex, then='Lab controlled execution marker from validation staging path', else='Security 4688 process execution from writable user/application location') AS Message,
       NewProcessName AS EvidenceJson,
       format(format='record=%v parent=%v child=%v cmd=%v user=%v', args=[RecordID, ParentProcessName, NewProcessName, CommandLine, SubjectUserName]) AS ProcessEvidenceJson,
       '' AS MemoryEvidenceJson,
       '' AS NetworkEvidenceJson,
       CommandLine AS CommandLine,
       ParentProcessName AS ParentProcessName,
       NewProcessName AS NewProcessName,
       RecordID AS RecordID,
       SubjectUserName AS SubjectUserName,
       EventDataJson AS EventDataJson,
       0 AS BaitModifiedCount,
       0 AS BaitDirsTouched,
       0 AS RansomNoteCount,
       0 AS BroadRansomNoteCount,
       1 AS ProcessEventCount,
       0 AS ImpactEventCount,
       0 AS ProxyEventCount,
       0 AS LiveSuspiciousProcessCount,
       0 AS ExternalConnectionCount,
       NewProcessName AS OSPath,
       'behavioral_composite' AS match_type,
       ArtifactName AS source_artifact,
       format(format='%v:%v:%v', args=[ArtifactName, if(condition=CommandLine =~ LabExecutionRegex, then='lab_controlled_execution_4688', else='deployable_writable_process_execution_4688'), NewProcessName]) AS candidate_id
FROM ProcessEvents
LET NoteWithLiveProcess <= SELECT * FROM foreach(
  row={{ SELECT OSPath AS NotePath, EventTime AS NoteTime FROM Notes LIMIT 250 }},
  query={{ SELECT NoteTime AS EventTime,
       'ransom_note_spread_correlated' AS BehaviorType,
       'high' AS Severity,
       0.90 AS Confidence,
       22 AS Score,
       'ransom-note-like file creation correlated with live writable/staged process' AS Message,
       NotePath AS EvidenceJson,
       format(format='%v %v %v', args=[Pid, Exe, CommandLine]) AS ProcessEvidenceJson,
       '' AS MemoryEvidenceJson,
       '' AS NetworkEvidenceJson,
       0 AS BaitModifiedCount,
       0 AS BaitDirsTouched,
       1 AS RansomNoteCount,
       1 AS BroadRansomNoteCount,
       1 AS ProcessEventCount,
       0 AS ImpactEventCount,
       0 AS ProxyEventCount,
       1 AS LiveSuspiciousProcessCount,
       0 AS ExternalConnectionCount,
       NotePath AS OSPath,
       'behavioral_composite' AS match_type,
       ArtifactName AS source_artifact,
       format(format='%v:%v:%v', args=[ArtifactName, 'ransom_note_spread_correlated', NotePath]) AS candidate_id
  FROM LiveSuspiciousProcess LIMIT 1 }})
LET NoteWithProcessEvent <= SELECT * FROM foreach(
  row={{ SELECT OSPath AS NotePath, EventTime AS NoteTime FROM Notes LIMIT 250 }},
  query={{ SELECT NoteTime AS EventTime,
       'ransom_note_spread_correlated' AS BehaviorType,
       'high' AS Severity,
       0.88 AS Confidence,
       22 AS Score,
       'ransom-note-like file creation correlated with Security 4688 writable/staged process execution' AS Message,
       NotePath AS EvidenceJson,
       format(format='record=%v parent=%v child=%v cmd=%v user=%v', args=[RecordID, ParentProcessName, NewProcessName, CommandLine, SubjectUserName]) AS ProcessEvidenceJson,
       '' AS MemoryEvidenceJson,
       '' AS NetworkEvidenceJson,
       CommandLine AS CommandLine,
       ParentProcessName AS ParentProcessName,
       NewProcessName AS NewProcessName,
       RecordID AS RecordID,
       SubjectUserName AS SubjectUserName,
       EventDataJson AS EventDataJson,
       0 AS BaitModifiedCount,
       0 AS BaitDirsTouched,
       1 AS RansomNoteCount,
       1 AS BroadRansomNoteCount,
       1 AS ProcessEventCount,
       0 AS ImpactEventCount,
       0 AS ProxyEventCount,
       0 AS LiveSuspiciousProcessCount,
       0 AS ExternalConnectionCount,
       NotePath AS OSPath,
       'behavioral_composite' AS match_type,
       ArtifactName AS source_artifact,
       format(format='%v:%v:%v', args=[ArtifactName, 'ransom_note_spread_4688', NotePath]) AS candidate_id
  FROM ProcessEvents LIMIT 1 }})
LET BaitWithLiveProcess <= SELECT * FROM foreach(
  row={{ SELECT OSPath AS ChangedPath, EventTime AS ChangedTime FROM BaitChanges LIMIT 250 }},
  query={{ SELECT ChangedTime AS EventTime,
       'bait_file_churn' AS BehaviorType,
       'high' AS Severity,
       0.95 AS Confidence,
       25 AS Score,
       'bait/staging file changed after execution and live writable/staged process exists' AS Message,
       ChangedPath AS EvidenceJson,
       format(format='%v %v %v', args=[Pid, Exe, CommandLine]) AS ProcessEvidenceJson,
       '' AS MemoryEvidenceJson,
       '' AS NetworkEvidenceJson,
       1 AS BaitModifiedCount,
       1 AS BaitDirsTouched,
       0 AS RansomNoteCount,
       0 AS BroadRansomNoteCount,
       1 AS ProcessEventCount,
       0 AS ImpactEventCount,
       0 AS ProxyEventCount,
       1 AS LiveSuspiciousProcessCount,
       0 AS ExternalConnectionCount,
       ChangedPath AS OSPath,
       'behavioral_composite' AS match_type,
       ArtifactName AS source_artifact,
       format(format='%v:%v:%v', args=[ArtifactName, 'bait_file_churn', ChangedPath]) AS candidate_id
  FROM LiveSuspiciousProcess LIMIT 1 }})
LET BaitWithProcessEvent <= SELECT * FROM foreach(
  row={{ SELECT OSPath AS ChangedPath, EventTime AS ChangedTime FROM BaitChanges LIMIT 250 }},
  query={{ SELECT ChangedTime AS EventTime,
       'bait_file_churn' AS BehaviorType,
       'high' AS Severity,
       0.90 AS Confidence,
       23 AS Score,
       'bait/staging file changed after execution and Security 4688 writable/staged process exists' AS Message,
       ChangedPath AS EvidenceJson,
       format(format='record=%v parent=%v child=%v cmd=%v user=%v', args=[RecordID, ParentProcessName, NewProcessName, CommandLine, SubjectUserName]) AS ProcessEvidenceJson,
       '' AS MemoryEvidenceJson,
       '' AS NetworkEvidenceJson,
       CommandLine AS CommandLine,
       ParentProcessName AS ParentProcessName,
       NewProcessName AS NewProcessName,
       RecordID AS RecordID,
       SubjectUserName AS SubjectUserName,
       EventDataJson AS EventDataJson,
       1 AS BaitModifiedCount,
       1 AS BaitDirsTouched,
       0 AS RansomNoteCount,
       0 AS BroadRansomNoteCount,
       1 AS ProcessEventCount,
       0 AS ImpactEventCount,
       0 AS ProxyEventCount,
       0 AS LiveSuspiciousProcessCount,
       0 AS ExternalConnectionCount,
       ChangedPath AS OSPath,
       'behavioral_composite' AS match_type,
       ArtifactName AS source_artifact,
       format(format='%v:%v:%v', args=[ArtifactName, 'bait_file_churn_4688', ChangedPath]) AS candidate_id
  FROM ProcessEvents LIMIT 1 }})
LET EncryptedWithProcessEvent <= SELECT * FROM foreach(
  row={{ SELECT OSPath AS EncryptedPath, EventTime AS EncryptedTime FROM EncryptedFiles LIMIT 250 }},
  query={{ SELECT EncryptedTime AS EventTime,
       'encrypted_extension_correlated' AS BehaviorType,
       'high' AS Severity,
       0.88 AS Confidence,
       22 AS Score,
       'ransomware-like encrypted extension correlated with Security 4688 writable/staged process execution' AS Message,
       EncryptedPath AS EvidenceJson,
       format(format='record=%v parent=%v child=%v cmd=%v user=%v', args=[RecordID, ParentProcessName, NewProcessName, CommandLine, SubjectUserName]) AS ProcessEvidenceJson,
       '' AS MemoryEvidenceJson,
       '' AS NetworkEvidenceJson,
       CommandLine AS CommandLine,
       ParentProcessName AS ParentProcessName,
       NewProcessName AS NewProcessName,
       RecordID AS RecordID,
       SubjectUserName AS SubjectUserName,
       EventDataJson AS EventDataJson,
       0 AS BaitModifiedCount,
       0 AS BaitDirsTouched,
       0 AS RansomNoteCount,
       0 AS BroadRansomNoteCount,
       1 AS ProcessEventCount,
       0 AS ImpactEventCount,
       0 AS ProxyEventCount,
       0 AS LiveSuspiciousProcessCount,
       0 AS ExternalConnectionCount,
       EncryptedPath AS OSPath,
       'behavioral_composite' AS match_type,
       ArtifactName AS source_artifact,
       format(format='%v:%v:%v', args=[ArtifactName, 'encrypted_extension_4688', EncryptedPath]) AS candidate_id
  FROM ProcessEvents LIMIT 1 }})
LET LiveProcessSignal <= SELECT CreateTime AS EventTime,
       if(condition=WorkingSet64 OR PrivateMemorySize64 OR HandleCount OR ThreadCount, then='writable_live_process_memory', else='writable_live_process_context') AS BehaviorType,
       if(condition=WorkingSet64 OR PrivateMemorySize64 OR HandleCount OR ThreadCount, then='high', else='medium') AS Severity,
       if(condition=WorkingSet64 OR PrivateMemorySize64 OR HandleCount OR ThreadCount, then=0.88, else=0.72) AS Confidence,
       if(condition=WorkingSet64 OR PrivateMemorySize64 OR HandleCount OR ThreadCount, then=20, else=10) AS Score,
       'live executable from writable/staged location with process context' AS Message,
       Exe AS EvidenceJson,
       CommandLine AS ProcessEvidenceJson,
       format(format='pid=%v ws=%v private=%v handles=%v threads=%v', args=[Pid, WorkingSet64, PrivateMemorySize64, HandleCount, ThreadCount]) AS MemoryEvidenceJson,
       '' AS NetworkEvidenceJson,
       0 AS BaitModifiedCount,
       0 AS BaitDirsTouched,
       0 AS RansomNoteCount,
       0 AS BroadRansomNoteCount,
       1 AS ProcessEventCount,
       0 AS ImpactEventCount,
       0 AS ProxyEventCount,
       1 AS LiveSuspiciousProcessCount,
       0 AS ExternalConnectionCount,
       Exe AS OSPath,
       'behavioral_composite' AS match_type,
       ArtifactName AS source_artifact,
       format(format='%v:%v:%v', args=[ArtifactName, 'writable_live_process_context', Exe]) AS candidate_id
FROM LiveSuspiciousProcess
SELECT *
FROM chain(a=ProcessEventSignal, b=NoteWithLiveProcess, c=NoteWithProcessEvent, d=BaitWithLiveProcess, e=BaitWithProcessEvent, f=EncryptedWithProcessEvent, g=LiveProcessSignal)
LIMIT 1001"""


def _candidate_text(candidate: dict[str, Any]) -> str:
    return str(candidate.get("value") or "").lower().replace("/", "\\")


def _context_text(candidate: dict[str, Any]) -> str:
    return " ".join(str(candidate.get(key) or "") for key in ("value", "source", "category", "suggested_detector")).lower()


def _confidence_level(candidate: dict[str, Any]) -> str:
    confidence = float(candidate.get("confidence") or 0)
    if confidence >= 0.9:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


def _candidate_group(candidate: dict[str, Any]) -> str:
    category = str(candidate.get("category") or "").lower()
    value = _candidate_text(candidate)
    context = _context_text(candidate)
    for rule in _artifact_configs()["rules"]:
        if "category" in rule and category != rule["category"]:
            continue
        if "category_in" in rule and category not in rule["category_in"]:
            continue
        if "value_pattern" in rule and not rule["value_pattern"].search(value):
            continue
        if "context_pattern" in rule and not rule["context_pattern"].search(context):
            continue
        return str(rule["group"])
    return str(_artifact_configs()["default_group"])


def _is_high_confidence(candidate: dict[str, Any], group_name: str) -> bool:
    sample_count = int(candidate.get("sample_count") or 0)
    source = str(candidate.get("source") or "")
    category = str(candidate.get("category") or "").lower()
    value = _candidate_text(candidate)
    note_only_groups = {"Windows.ThreatTrace.Ransomware.RansomNotes"}
    if group_name in note_only_groups:
        return False
    if group_name == "Windows.ThreatTrace.Ransomware.EncryptedExtensions":
        return sample_count >= 2 or _confidence_level(candidate) == "high"
    if group_name == "Windows.ThreatTrace.Ransomware.RansomwareBinaries":
        return category in {"hash", "process"} or re.search(r"\\[^\\]+\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js|jse|wsf|hta)$", value) is not None
    if source.startswith("sample_artifacts:") and sample_count < 2:
        return False
    if group_name in _artifact_configs()["high_confidence_groups"]:
        return True
    if _confidence_level(candidate) != "high":
        return False
    risk = str(candidate.get("false_positive_risk") or "").lower()
    generalization = str(candidate.get("generalization_value") or "").lower()
    return sample_count >= 2 and risk == "low" and generalization == "high"


def _decorate_candidate(candidate: dict[str, Any], group_name: str) -> dict[str, Any]:
    output: dict[str, Any] = {
        key: candidate.get(key)
        for key in (
            "type",
            "category",
            "value",
            "confidence",
            "false_positive_risk",
            "generalization_value",
            "sample_count",
            "sample_refs",
            "endpoint_observable",
            "suggested_detector",
        )
        if key in candidate
    }
    output["confidence_level"] = _confidence_level(candidate)
    output["artifact_group"] = group_name
    output["threattrace_artifact_type"] = "velociraptor_modular_candidate"
    output["threattrace_detection_purpose"] = group_name.rsplit(".", 1)[-1].lower()
    return output


def _build_artifact(group_name: str, candidates: list[dict[str, Any]], generated_at: str) -> dict[str, Any]:
    candidates = _limit_artifact_candidates(group_name, candidates)
    parameter_bundles = []
    for index in range(0, len(candidates), _PARAMETER_BUNDLE_SIZE):
        chunk = candidates[index : index + _PARAMETER_BUNDLE_SIZE]
        payload = json.dumps(chunk, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        parameter_bundles.append(
            {
                "bundle_id": f"{group_name}:bundle-{index // _PARAMETER_BUNDLE_SIZE + 1:03d}",
                "candidate_start": index,
                "candidate_end": index + len(chunk) - 1,
                "candidate_count": len(chunk),
                "sha256": hashlib.sha256(payload.encode()).hexdigest(),
                "candidates": chunk,
            }
        )
    return {
        "name": group_name,
        "type": "velociraptor_vql_skeleton",
        "description": str(_group_config(group_name)["description"]),
        "source": "threattrace.detection.ioc_export",
        "generated_at": generated_at,
        "candidate_count": len(candidates),
        "candidate_categories": sorted({str(item.get("category")) for item in candidates}),
        "candidate_values": [item.get("value") for item in candidates],
        "candidates": candidates,
        "parameter_bundles": parameter_bundles,
    }


def _candidate_rank(candidate: dict[str, Any]) -> tuple[int, float, int, str]:
    confidence = float(candidate.get("confidence") or 0)
    sample_count = int(candidate.get("sample_count") or 0)
    value = str(candidate.get("value") or "")
    source = str(candidate.get("source") or "")
    has_behavior_source = int(source.startswith("sample_artifacts:") or source.startswith("behavior:"))
    return (-has_behavior_source, -confidence, -sample_count, value.lower())


def _limit_artifact_candidates(group_name: str, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    limit = _MAX_NATIVE_CANDIDATES_BY_ARTIFACT.get(group_name, _MAX_NATIVE_CANDIDATES_DEFAULT)
    if len(candidates) <= limit:
        return candidates
    return sorted(candidates, key=_candidate_rank)[:limit]


def _refined_velociraptor_candidates(ioc_payload: dict[str, Any]) -> tuple[str, list[dict[str, Any]], int]:
    source = "endpoint_iocs" if ioc_payload.get("endpoint_iocs") is not None else "indicators"
    raw_candidates = (
        ioc_payload.get("endpoint_iocs")
        if source == "endpoint_iocs"
        else ioc_payload.get("indicators", [])
    ) or []
    refined: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    duplicates_removed = 0
    for item in raw_candidates:
        if not (
            "velociraptor" in item.get("observability", [])
            or str(item.get("suggested_detector", "")).startswith("velociraptor")
        ):
            continue
        if classify_noise(item, layer="velociraptor").action != "keep":
            continue
        key = (str(item.get("category") or "").lower(), str(item.get("value") or "").lower())
        if key in seen:
            duplicates_removed += 1
            continue
        seen.add(key)
        refined.append(item)
    return source, refined, duplicates_removed


def _artifact_candidate_allowed(candidate: dict[str, Any], group_name: str) -> bool:
    if group_name == "Windows.ThreatTrace.Ransomware.NetworkIndicators":
        category = str(candidate.get("category") or "").lower()
        value = str(candidate.get("value") or "").strip().lower()
        sample_count = int(candidate.get("sample_count") or 0)
        confidence = float(candidate.get("confidence") or 0)
        if category == "domain":
            return (
                value.endswith(".onion")
                or sample_count >= 2
                or confidence >= 0.95
                or len(value) >= 30
            )
        if category == "url":
            return (
                ".onion" in value
                or _SUSPICIOUS_NETWORK_URL_RE.search(value) is not None
                or sample_count >= 2
            )
        if category == "ip":
            return sample_count >= 3 or confidence >= 0.95
        return False
    if group_name != "Windows.ThreatTrace.Ransomware.ExactIoCMatches":
        return True
    policy = _artifact_configs()["exact_ioc_policy"]
    confidence = float(candidate.get("confidence") or 0)
    sample_count = int(candidate.get("sample_count") or 0)
    risk = str(candidate.get("false_positive_risk") or "").lower()
    generalization = str(candidate.get("generalization_value") or "").lower()
    if confidence >= float(policy.get("min_confidence", 0.9)) or sample_count >= int(policy.get("min_sample_count", 2)):
        return True
    if risk in {str(item).lower() for item in policy.get("allow_risks", ["low"])}:
        return True
    if generalization in {str(item).lower() for item in policy.get("allow_generalization_values", ["high"])}:
        return True
    return has_suspicious_context(candidate)


def build_velociraptor_artifact_bundle(ioc_payload: dict[str, Any]) -> dict[str, Any]:
    generated_at = datetime.now(UTC).isoformat()
    source, candidates, duplicates_removed = _refined_velociraptor_candidates(ioc_payload)
    grouped: dict[str, list[dict[str, Any]]] = {}
    high_confidence: list[dict[str, Any]] = []
    for candidate in candidates:
        group_name = _candidate_group(candidate)
        if not _artifact_candidate_allowed(candidate, group_name):
            continue
        decorated = _decorate_candidate(candidate, group_name)
        grouped.setdefault(group_name, []).append(decorated)
        if _is_high_confidence(candidate, group_name):
            high_confidence.append(_decorate_candidate(candidate, "Windows.ThreatTrace.Ransomware.CorrelatedEvidenceBundle"))
    if high_confidence:
        grouped["Windows.ThreatTrace.Ransomware.CorrelatedEvidenceBundle"] = high_confidence
    if "Windows.ThreatTrace.Ransomware.NetworkIndicators" in grouped:
        grouped["Windows.ThreatTrace.Ransomware.NetworkIndicators"] = sorted(
            grouped["Windows.ThreatTrace.Ransomware.NetworkIndicators"],
            key=lambda item: (
                not str(item.get("value") or "").lower().endswith(".onion"),
                -int(item.get("sample_count") or 0),
                -float(item.get("confidence") or 0),
                str(item.get("category") or ""),
                str(item.get("value") or ""),
            ),
        )[:_MAX_NETWORK_CANDIDATES]
    artifacts = [
        _build_artifact(group_name, items, generated_at)
        for group_name, items in grouped.items()
        if items
    ]
    artifacts.sort(key=lambda item: item["name"])
    summary = build_velociraptor_artifact_summary(artifacts, candidates, duplicates_removed)
    return {
        "metadata": {
            "source": source,
            "generated_at": generated_at,
            "artifact_candidate_count": sum(len(item["candidates"]) for item in artifacts),
            "artifact_group_counts": {item["name"]: len(item["candidates"]) for item in artifacts},
            "duplicates_removed": duplicates_removed,
        },
        "summary": summary,
        "artifacts": artifacts,
    }


def build_velociraptor_artifact_summary(
    artifacts: list[dict[str, Any]],
    refined_candidates: list[dict[str, Any]],
    duplicates_removed: int,
) -> dict[str, Any]:
    all_candidates = [candidate for artifact in artifacts for candidate in artifact.get("candidates", [])]
    confidence_counts = Counter(candidate.get("confidence_level") for candidate in all_candidates)
    sample_refs: Counter[str] = Counter()
    for candidate in refined_candidates:
        for ref in candidate.get("sample_refs", []) or []:
            sample_refs[str(ref.get("sha256") or ref.get("sample_id"))] += 1
    grouped_values = {
        (candidate.get("category"), candidate.get("value"))
        for artifact in artifacts
        if artifact.get("name") != "Windows.ThreatTrace.Ransomware.CorrelatedEvidenceBundle"
        for candidate in artifact.get("candidates", [])
    }
    refined_values = {(candidate.get("category"), candidate.get("value")) for candidate in refined_candidates}
    return {
        "total_refined_candidates": len(refined_candidates),
        "total_artifact_groups": len(artifacts),
        "candidate_count_by_group": {artifact["name"]: len(artifact.get("candidates", [])) for artifact in artifacts},
        "candidate_count_by_category": dict(Counter(candidate.get("category") for candidate in all_candidates)),
        "duplicates_removed": duplicates_removed,
        "unclassified_count": len(refined_values - grouped_values),
        "high_confidence_count": confidence_counts.get("high", 0),
        "medium_confidence_count": confidence_counts.get("medium", 0),
        "low_confidence_count": confidence_counts.get("low", 0),
        "top_sample_refs": [{"sample_ref": ref, "count": count} for ref, count in sample_refs.most_common(20)],
    }


def write_velociraptor_artifact_summary(bundle: dict[str, Any], output: Path) -> None:
    summary_path = output.with_name("velociraptor_artifact_suite_summary.json")
    markdown_path = output.with_name("velociraptor_artifact_suite_summary.md")
    summary = bundle.get("summary", {})
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = ["# Velociraptor Artifact Suite Summary", ""]
    for key in (
        "total_refined_candidates",
        "total_artifact_groups",
        "duplicates_removed",
        "unclassified_count",
        "high_confidence_count",
        "medium_confidence_count",
        "low_confidence_count",
    ):
        lines.append(f"- {key}: {summary.get(key, 0)}")
    lines.extend(["", "## Groups", ""])
    for name, count in summary.get("candidate_count_by_group", {}).items():
        lines.append(f"- `{name}`: {count}")
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _yaml_scalar(value: Any) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _yaml_block_scalar(value: Any, indent: int = 4) -> list[str]:
    text = str(value)
    prefix = " " * indent
    if not text:
        return [f"{prefix}a^"]
    return [f"{prefix}{line}" for line in text.splitlines()]


def _candidate_regex(candidates: list[dict[str, Any]], *, regex_mode: str = "substring") -> str:
    values = [str(candidate.get("value") or "") for candidate in candidates if candidate.get("value")]
    if not values:
        return r"a^"
    if regex_mode == "exact":
        body = "|".join(f"^{re.escape(value)}$" for value in values)
    else:
        body = "|".join(re.escape(value) for value in values)
    return rf"(?i)(?:{body})"


def _candidate_process_regexes(candidates: list[dict[str, Any]]) -> dict[str, str]:
    """Build field-specific RE2 patterns for paths, basenames and command lines."""
    values = [str(item.get("value") or "").strip() for item in candidates if item.get("value")]
    if not values:
        return {"path": r"a^", "name": r"a^", "command_line": r"a^"}
    paths: list[str] = []
    names: list[str] = []
    full_commands: list[str] = []
    executable_tokens: list[str] = []
    for value in values:
        normalized = value.strip('"')
        looks_like_command = bool(re.search(r"\.(?:exe|com|bat|cmd|ps1|vbs|js|hta)\s+", normalized, re.I))
        if looks_like_command:
            full_commands.append(re.escape(normalized))
            executable = re.split(r"\s+", normalized, maxsplit=1)[0].strip('"')
        else:
            executable = normalized
        paths.append(re.escape(executable))
        basename = re.split(r"[\\/]", executable)[-1]
        names.append(re.escape(basename))
        executable_tokens.extend((re.escape(executable), re.escape(basename)))
    path_regex = rf"(?i)(?:{'|'.join(f'^{value}$' for value in dict.fromkeys(paths))})"
    name_regex = rf"(?i)(?:{'|'.join(f'^{value}$' for value in dict.fromkeys(names))})"
    token_body = "|".join(dict.fromkeys(executable_tokens))
    command_parts = [rf"(?:^|[\"'\s])(?:{token_body})(?:$|[\"'\s])"]
    command_parts.extend(f"^{value}$" for value in dict.fromkeys(full_commands))
    return {
        "path": path_regex,
        "name": name_regex,
        "command_line": rf"(?i)(?:{'|'.join(command_parts)})",
    }


def _native_query_for_artifact(name: str, glob_name: str) -> str:
    if name.endswith(".Persistence.Services"):
        return _service_persistence_query()
    if name.endswith(".Persistence.ScheduledTasks"):
        return _scheduled_task_persistence_query()
    profile = str(_group_config(name).get("query_profile") or "file_glob")
    if profile in {"process_trace", "proxy_execution_trace"}:
        return _process_trace_query()
    if profile == "network_eventlog":
        return _network_eventlog_query()
    if profile == "behavioral_composite":
        return _behavioral_composite_query(glob_name)
    query = str(_artifact_configs()["query_profiles"][profile]["query"])
    query = _normalize_native_query(profile, query)
    if "LET Regex <= CandidateRegex" in query:
        query = query.replace("LET Regex <= CandidateRegex", "LET FilePathRegex <= CandidateFilePathRegex")
        query = query.replace(" =~ Regex", " =~ FilePathRegex")
    return query.replace("FileGlobs", glob_name).replace("RegistryGlobs", glob_name)


def _native_regex_mode_for_artifact(name: str) -> str:
    profile = str(_group_config(name).get("query_profile") or "file_glob")
    if profile == "behavioral_composite":
        return "substring"
    return str(_artifact_configs()["query_profiles"][profile]["regex_mode"])


def _native_requires_windows_client(name: str) -> bool:
    if name.endswith((".Persistence.Services", ".Persistence.ScheduledTasks")):
        return True
    profile = str(_group_config(name).get("query_profile") or "file_glob")
    return profile in {"process_trace", "proxy_execution_trace", "network_eventlog", "high_confidence_bundle", "exact_ioc_bundle", "behavioral_composite"}


def _native_default_globs(name: str) -> tuple[str, str]:
    def ensure_required_globs(value: str) -> str:
        parts = [part.strip() for part in str(value).split(",") if part.strip()]
        seen = set(parts)
        for required in _REQUIRED_VALIDATION_GLOBS:
            if required not in seen:
                parts.append(required)
                seen.add(required)
        return ",".join(parts)

    lowered = name.lower()
    if lowered.endswith(".ransomnotes"):
        return "RansomNoteGlobs", ensure_required_globs(
            str(_artifact_configs()["glob_profiles"].get("ransom_note_glob", {}).get("default") or _FALLBACK_RANSOM_NOTE_GLOBS)
        )
    if lowered.endswith((".suspiciousdroppedfiles", ".ransomwarebinaries", ".encryptedextensions", ".exactiocmatches", ".highconfidencebundle")):
        return "FileGlobs", ensure_required_globs(
            str(_artifact_configs()["glob_profiles"].get("file_glob", {}).get("default") or _FALLBACK_FILE_GLOBS)
        )
    profile = str(_group_config(name).get("glob_profile") or "file_glob")
    glob_config = _artifact_configs()["glob_profiles"][profile]
    default_value = str(glob_config["default"])
    if profile in {"file_glob", "ransom_note_glob"}:
        default_value = ensure_required_globs(default_value)
    return str(glob_config["parameter_name"]), default_value


def _default_ttp_candidate_regex_for_artifact(name: str) -> str | None:
    for ttp_id, mapping in _TTP_ARTIFACTS.items():
        if str(mapping.get("name")) == name:
            candidate_regex, _ = _generalized_ttp_pattern(ttp_id, [])
            return candidate_regex
    return None


def build_native_velociraptor_artifact(artifact: dict[str, Any]) -> str:
    name = str(artifact["name"])
    config_name = str(artifact.get("base_name") or name)
    candidates = artifact.get("candidates", [])
    regex_mode = _native_regex_mode_for_artifact(config_name)
    candidate_regex = _candidate_regex(candidates, regex_mode=regex_mode)
    if candidate_regex == r"a^":
        candidate_regex = _default_ttp_candidate_regex_for_artifact(config_name) or candidate_regex
    process_regexes = _candidate_process_regexes(candidates)
    glob_name, glob_default = _native_default_globs(config_name)
    lines = [
        f"name: {name}",
        "description: |",
        *[f"  {line}" for line in _artifact_configs()["description_lines"]],
        "type: CLIENT",
    ]
    if _native_requires_windows_client(config_name):
        lines.extend(
            [
                "precondition: |",
                "  SELECT OS FROM info() WHERE OS = 'windows'",
            ]
        )
    lines.extend(
        [
            "parameters:",
            "  - name: CandidateRegex",
            "    default: |-",
            *_yaml_block_scalar(candidate_regex, indent=6),
            "  - name: CandidateFilePathRegex",
            "    default: |-",
            *_yaml_block_scalar(candidate_regex, indent=6),
            "  - name: CandidateProcessPathRegex",
            "    default: |-",
            *_yaml_block_scalar(process_regexes["path"], indent=6),
            "  - name: CandidateProcessNameRegex",
            "    default: |-",
            *_yaml_block_scalar(process_regexes["name"], indent=6),
            "  - name: CandidateCommandLineRegex",
            "    default: |-",
            *_yaml_block_scalar(process_regexes["command_line"], indent=6),
            "  - name: MaxRows",
            "    default: \"1000\"",
            "  - name: TimeWindowHours",
            "    default: \"24\"",
            f"  - name: {glob_name}",
            f"    default: {_yaml_scalar(glob_default)}",
            "sources:",
            "  - query: |",
            f"      LET ArtifactName <= {_yaml_scalar(name)}",
        ]
    )
    lines.extend(f"      {line}" for line in _native_query_for_artifact(config_name, glob_name).splitlines())
    lines.append("")
    return "\n".join(lines)


def write_native_velociraptor_artifacts(bundle: dict[str, Any], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_map = {
        str(artifact["name"]): artifact
        for artifact in bundle.get("artifacts", [])
        if artifact.get("name")
    }
    paths: list[Path] = []
    for group_name in _artifact_configs()["groups"]:
        artifact = artifact_map.get(group_name, {"name": group_name, "candidates": []})
        bundles = artifact.get("parameter_bundles") or [{"candidates": artifact.get("candidates", [])}]
        for index, bundle in enumerate(bundles, start=1):
            multiple = len(bundles) > 1
            name = f"{group_name}.Bundle{index:03d}" if multiple else group_name
            bundled_artifact = {
                **artifact,
                "name": name,
                "base_name": group_name,
                "candidates": bundle.get("candidates", []),
                "parameter_bundle_id": bundle.get("bundle_id", f"{group_name}:bundle-001"),
                "parameter_bundle_sha256": bundle.get("sha256", ""),
            }
            path = output_dir / f"{name}.yaml"
            path.write_text(build_native_velociraptor_artifact(bundled_artifact), encoding="utf-8")
            paths.append(path)
    return paths


def write_velociraptor_artifacts(bundle: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for artifact in bundle.get("artifacts", []):
        path = output_dir / f"{artifact['name']}.json"
        path.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate Velociraptor artifact skeletons from exported IoCs")
    parser.add_argument("--input")
    parser.add_argument("--ttp-input", help="Dry-run TTP-to-artifact mapping from a TTP inference JSON payload")
    parser.add_argument("--ttp-dry-run-output", help="Write TTP artifact dry-run plan JSON")
    parser.add_argument("--output")
    parser.add_argument("--output-dir")
    parser.add_argument("--native-output-dir")
    parser.add_argument("--limit", type=int, default=None)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.ttp_input:
        payload = json.loads(Path(args.ttp_input).read_text(encoding="utf-8"))
        plan = build_ttp_velociraptor_artifact_plan(payload)
        if args.ttp_dry_run_output:
            output = Path(args.ttp_dry_run_output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        return
    if not args.output and not args.output_dir:
        raise SystemExit("Provide --output or --output-dir")
    if args.input:
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    else:
        from threattrace.detection.ioc_export import export_detection_iocs

        payload = export_detection_iocs(limit=args.limit)
    bundle = build_velociraptor_artifact_bundle(payload)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        write_velociraptor_artifact_summary(bundle, output)
        if args.native_output_dir:
            write_native_velociraptor_artifacts(bundle, Path(args.native_output_dir))
        print(json.dumps({"generated": len(bundle["artifacts"]), "output": args.output}, indent=2))
    else:
        write_velociraptor_artifacts(bundle, Path(args.output_dir))
        if args.native_output_dir:
            write_native_velociraptor_artifacts(bundle, Path(args.native_output_dir))
        print(json.dumps({"generated": len(bundle["artifacts"]), "output_dir": args.output_dir}, indent=2))


if __name__ == "__main__":
    main()
