from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from threattrace.common.io import parse_json_object
from threattrace.detection.noise import classify_noise

HIGH_CONFIDENCE = "Windows.ThreatTrace.Ransomware.HighConfidenceBundle"
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
WINDOW_MARGIN_SECONDS = 120
MIN_CORROBORATING_EVIDENCE_FAMILIES = 2
TIMESTAMP_FIELD_CANDIDATES = (
    "EventTime",
    "event_time",
    "Timestamp",
    "timestamp",
    "TimeCreated",
    "time_created",
    "Created",
    "created",
    "CreationTime",
    "creation_time",
    "CreatedAt",
    "created_at",
    "Modified",
    "modified",
    "ModifiedTime",
    "modified_time",
    "Mtime",
    "mtime",
    "LastWriteTime",
    "last_write_time",
    "Btime",
    "btime",
    "Ctime",
    "ctime",
)


WINDOW_REQUIRED_ARTIFACT_FRAGMENTS = (
    "behavioralcomposite",
    "network",
    "suspiciousdroppedfiles",
    "persistence.registry",
    "persistence.services",
    "persistence.scheduledtasks",
    "lolbins",
    "shadowcopy",
    "bootrecovery",
)
PROCESS_CONTEXT_FIELDS = (
    "CommandLine",
    "command_line",
    "CmdLine",
    "cmdline",
    "Message",
    "message",
    "EventType",
    "event_type",
    "ParentCommandLine",
    "parent_command_line",
    "Image",
    "image",
    "Exe",
    "exe",
 )
SUSPICIOUS_FILE_NAME_RE = re.compile(
    r"(?i)(readme|decrypt|recover|restore|how_to|locked|crypt|enc|pay|shadow|backup|payload)"
)
SUSPICIOUS_FILE_EXT_RE = re.compile(
    r"(?i)\.(locked|lock|crypted|crypt|enc|encrypted|ava|exe|dll|bat|cmd|ps1|vbs|js|jse|hta|tmp|bin|scr)$"
)
MICROSOFT_DOMAIN_RE = re.compile(
    r"(?i)(^|\.)("
    r"microsoft|windowsupdate|update\.microsoft|download\.microsoft|msftconnecttest|"
    r"msftncsi|office|office365|live|bing|azure|akadns|msedge|edgesuite"
    r")\.(com|net)$"
)
SYSTEM_PATH_PREFIXES = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
)
RANSOM_NOTE_NOISE_FRAGMENTS = (
    "\\users\\default\\",
    "\\appdata\\roaming\\microsoft\\",
    "\\internet explorer\\",
    "\\quick launch\\",
    "\\network shortcuts\\",
    "\\printer shortcuts\\",
    "\\recent\\",
    "\\sendto\\",
    "\\start menu\\",
    "\\templates\\",
    "\\users\\public\\music\\",
    "\\users\\public\\pictures\\",
    "\\users\\public\\videos\\",
    "\\users\\public\\libraries\\",
    "\\users\\public\\accountpictures\\",
)
USER_FACING_NOTE_FRAGMENTS = (
    "\\users\\public\\desktop\\",
    "\\users\\public\\documents\\",
    "\\users\\public\\downloads\\",
    "\\desktop\\",
    "\\documents\\",
    "\\downloads\\",
    "c:\\programdata\\",
)

VALUE_FIELDS = (
    "Value",
    "value",
    "OSPath",
    "Path",
    "FullPath",
    "Name",
    "Data",
    "Message",
    "CommandLine",
    "Exe",
    "Target",
    "Domain",
    "domain",
    "Url",
    "url",
    "RemoteAddr",
    "remote_addr",
    "RemoteIP",
    "remote_ip",
    "Hash",
    "hash",
    "SHA256",
    "sha256",
)


def _load_rows(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        rows: list[dict[str, Any]] = []
        for line in text.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
        return rows
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        if isinstance(payload.get("rows"), list):
            return [item for item in payload["rows"] if isinstance(item, dict)]
        return [payload] if payload else []
    return []


def _artifact_from_path(path: Path) -> str:
    return path.stem.replace("_", ".")


def _parse_dt(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 1_000_000_000_000:
            number /= 1000.0
        try:
            return datetime.fromtimestamp(number, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _execution_window_from_metadata(
    result_dir: Path,
    started_at: str | None,
    completed_at: str | None,
) -> tuple[datetime, datetime] | None:
    if not started_at or not completed_at:
        metadata_path = result_dir / "sample_metadata.json"
        if metadata_path.exists():
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                metadata = {}
            if not started_at:
                started_at = metadata.get("execution_started_at_utc") or metadata.get("started_at")
            if not completed_at:
                completed_at = metadata.get("completed_at")
    start_dt = _parse_dt(started_at)
    end_dt = _parse_dt(completed_at)
    if not start_dt or not end_dt:
        return None
    if end_dt < start_dt:
        start_dt, end_dt = end_dt, start_dt
    margin = timedelta(seconds=WINDOW_MARGIN_SECONDS)
    return start_dt - margin, end_dt + margin


def _sample_execution_paths(result_dir: Path) -> set[str]:
    metadata_path = result_dir / "sample_metadata.json"
    metadata: dict[str, Any] = {}
    if metadata_path.exists():
        try:
            loaded = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            loaded = {}
        metadata = loaded if isinstance(loaded, dict) else {}
    staging = metadata.get("staging") or {}
    sha256 = str(metadata.get("sha256") or "").strip().lower()
    filename = str(staging.get("filename") or "").strip()
    paths: set[str] = set()
    if sha256 and filename:
        paths.add(f"c:\\vr-malware-test\\{sha256}\\{filename}".lower())
    winrm_log = metadata.get("winrm_execution_log") or {}
    winrm_path = result_dir / "winrm_execution_log.json"
    if not winrm_log and winrm_path.exists():
        try:
            loaded_winrm = json.loads(winrm_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            loaded_winrm = {}
        winrm_log = loaded_winrm if isinstance(loaded_winrm, dict) else {}
    stdout = str(winrm_log.get("stdout") or "").strip()
    if stdout.startswith("STARTED "):
        paths.add(stdout.removeprefix("STARTED ").strip().lower())
    execution_payload = parse_json_object(stdout) if stdout else None
    if isinstance(execution_payload, dict):
        for key in ("path", "sample_path"):
            value = str(execution_payload.get(key) or "").strip()
            if value:
                paths.add(value.lower())
    return {item.replace("/", "\\") for item in paths if item}


def _row_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _row_timestamps(row: dict[str, Any]) -> list[datetime]:
    seen: set[datetime] = set()
    parsed: list[datetime] = []
    for key in TIMESTAMP_FIELD_CANDIDATES:
        dt = _parse_dt(row.get(key))
        if dt is None or dt in seen:
            continue
        seen.add(dt)
        parsed.append(dt)
    return parsed


def _row_timestamp_details(row: dict[str, Any]) -> list[dict[str, str]]:
    details: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for key in TIMESTAMP_FIELD_CANDIDATES:
        raw_value = row.get(key)
        dt = _parse_dt(raw_value)
        if dt is None:
            continue
        pair = (key, dt.isoformat())
        if pair in seen:
            continue
        seen.add(pair)
        details.append({"field": key, "raw_value": str(raw_value), "parsed_at": dt.isoformat()})
    return details


def _compact_row_context(row: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "OSPath",
        "Path",
        "FullPath",
        "Name",
        "Data",
        "Message",
        "CommandLine",
        "Exe",
        "Domain",
        "domain",
        "Url",
        "url",
        "RemoteAddr",
        "RemoteIP",
        "Mtime",
        "Btime",
        "EventTime",
        "Timestamp",
        "Created",
        "Modified",
        "source",
        "_Source",
    )
    context = {key: row[key] for key in allowed if row.get(key) not in (None, "")}
    if not context:
        for key, value in row.items():
            if value in (None, ""):
                continue
            context[key] = value
            if len(context) >= 6:
                break
    return context


def _inside_execution_window(
    timestamps: list[datetime],
    window: tuple[datetime, datetime] | None,
) -> bool | None:
    if window is None:
        return None
    if not timestamps:
        return False
    start_dt, end_dt = window
    return any(start_dt <= stamp <= end_dt for stamp in timestamps)


def _has_process_context(row: dict[str, Any]) -> bool:
    for field in PROCESS_CONTEXT_FIELDS:
        value = str(row.get(field) or "").strip()
        if not value:
            continue
        lowered = value.lower()
        if field.lower() in {"image", "exe"} and lowered.endswith((".exe", ".dll", ".scr", ".mui")) and " " not in lowered:
            continue
        return True
    return False


def _artifact_requires_window(artifact: str) -> bool:
    lowered = artifact.lower()
    return any(fragment in lowered for fragment in WINDOW_REQUIRED_ARTIFACT_FRAGMENTS)


def _is_behavioral_artifact(artifact: str) -> bool:
    lowered = artifact.lower()
    return "behavioralcomposite" in lowered or "behavioralsignals" in lowered


def _artifact_requires_process_context(artifact: str) -> bool:
    lowered = artifact.lower()
    return any(fragment in lowered for fragment in ("lolbins", "shadowcopy", "bootrecovery"))


def _is_recent_suspicious_drop(artifact: str, value: str) -> bool:
    if "suspiciousdroppedfiles" not in artifact.lower():
        return False
    lowered = value.lower().replace("/", "\\")
    in_scope = (
        lowered.startswith("c:\\vr-malware-test\\")
        or lowered.startswith("c:\\programdata\\")
        or lowered.startswith("c:\\windows\\temp\\")
        or (
            lowered.startswith("c:\\users\\")
            and any(
                fragment in lowered
                for fragment in (
                    "\\appdata\\local\\temp\\",
                    "\\appdata\\roaming\\",
                    "\\desktop\\",
                    "\\documents\\",
                )
            )
        )
    )
    if not in_scope:
        return False
    return bool(SUSPICIOUS_FILE_NAME_RE.search(lowered) or SUSPICIOUS_FILE_EXT_RE.search(lowered))


def _artifact_rejection_reason(
    artifact: str,
    row: dict[str, Any],
    window: tuple[datetime, datetime] | None,
    sample_paths: set[str],
) -> str | None:
    lowered = artifact.lower()
    value = _value_for(row).lower().replace("/", "\\")
    match_type = str(_row_value(row, "match_type") or "").lower()
    if value in sample_paths and not _is_behavioral_artifact(artifact):
        return "staged_sample_binary"
    if "ransomnotes" in lowered and match_type == "suspicious_ransom_note_name":
        if any(fragment in value for fragment in RANSOM_NOTE_NOISE_FRAGMENTS):
            return "non_user_facing_ransom_note_location"
    timestamps = _row_timestamps(row)
    if window and timestamps:
        start_dt, end_dt = window
        if not any(start_dt <= stamp <= end_dt for stamp in timestamps):
            return "outside_execution_window"
    elif window and _artifact_requires_window(artifact):
        return "missing_execution_timestamp"
    if _artifact_requires_process_context(artifact) and not _has_process_context(row):
        return "missing_process_execution_context"
    if "persistence" in lowered and not timestamps:
        return "missing_execution_timestamp"
    return None


def _is_known_benign_windows_update_task(hit: dict[str, Any]) -> bool:
    artifact = str(hit.get("source_artifact") or "").lower()
    if not any(part in artifact for part in ("persistence.scheduledtasks", "lolbins")):
        return False
    row = hit.get("row") if isinstance(hit.get("row"), dict) else {}
    process_text = " ".join(
        str(_row_value(row, field) or "")
        for field in ("CommandLine", "ParentProcessName", "CreatorProcessName", "EventDataJson", "Message")
    ).lower().replace("/", "\\")
    return (
        "plugscheduler" in process_text
        and "microsoft\\windows\\windowsupdate\\ruxim" in process_text
        and "msiexec.exe" in process_text
    )


def _category_for(artifact: str, row: dict[str, Any]) -> str:
    lowered = artifact.lower()
    if _is_behavioral_artifact(artifact):
        return "behavior"
    if "network" in lowered:
        return (
            "domain"
            if _row_value(row, "Domain", "domain")
            else ("url" if _row_value(row, "Url", "url") else "ip")
        )
    if "registry" in lowered or "persistence.services" in lowered or "persistence.scheduledtasks" in lowered:
        return "registry"
    if "mutex" in lowered:
        return "mutex"
    if any(part in lowered for part in ("lolbins", "shadowcopy", "bootrecovery")):
        return "process"
    if _row_value(row, "Hash", "hash", "SHA256", "sha256"):
        return "hash"
    return "file"


def _value_for(row: dict[str, Any]) -> str:
    for field in VALUE_FIELDS:
        value = row.get(field)
        if value not in (None, ""):
            return str(value)
    return json.dumps(row, sort_keys=True, default=str)


def _match_type_for(artifact: str, row: dict[str, Any]) -> str:
    if _row_value(row, "match_type"):
        return str(row["match_type"])
    if artifact == HIGH_CONFIDENCE:
        return "high_confidence"
    if _row_value(row, "CandidateRegex", "candidate_regex", "CandidateId", "candidate_id"):
        return "exact_candidate"
    return "artifact_row"


def _network_values(row: dict[str, Any]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    values: list[tuple[str, str]] = []

    def add(category: str, value: Any) -> None:
        text = str(value or "").strip()
        if not text:
            return
        key = (category, text.lower())
        if key in seen:
            return
        seen.add(key)
        values.append((category, text))

    for key in ("Url", "url"):
        add("url", row.get(key))
    for key in ("Domain", "domain"):
        add("domain", row.get(key))
    for key in ("RemoteAddr", "remote_addr", "RemoteIP", "remote_ip"):
        add("ip", row.get(key))

    message = str(_row_value(row, "Message", "message", "_Source") or "")
    for value in _URL_RE.findall(message):
        add("url", value)
    for value in _DOMAIN_RE.findall(message):
        add("domain", value)
    for value in _IP_RE.findall(message):
        add("ip", value)
    return values


def _hit_text(hit: dict[str, Any]) -> str:
    row = hit.get("row") if isinstance(hit.get("row"), dict) else {}
    values = [
        hit.get("value"),
        hit.get("CommandLine"),
        hit.get("command_line"),
        hit.get("Message"),
        hit.get("message"),
    ]
    values.extend(row.get(field) for field in PROCESS_CONTEXT_FIELDS)
    return " ".join(str(value or "") for value in values).lower().replace("/", "\\")


def _is_local_or_microsoft_indicator(category: str, value: str) -> bool:
    text = value.strip().lower()
    host = text
    if category == "url":
        parsed = urlparse(text)
        host = parsed.hostname or ""
    if not host or host in {"localhost", "localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    return bool(MICROSOFT_DOMAIN_RE.search(host))


def _is_useful_external_indicator(hit: dict[str, Any]) -> bool:
    category = str(hit.get("category") or "").lower()
    if category not in {"domain", "url", "ip"}:
        return False
    value = str(hit.get("value") or "")
    return not _is_local_or_microsoft_indicator(category, value)


def _is_non_system_path(value: str) -> bool:
    lowered = value.lower().replace("/", "\\")
    if not re.match(r"^[a-z]:\\", lowered):
        return True
    return not lowered.startswith(SYSTEM_PATH_PREFIXES)


def _is_lab_execution_text(text: str) -> bool:
    lowered = text.lower().replace("/", "\\")
    return "\\vr-malware-test\\" in lowered or "\\threattrace-bait\\" in lowered


def _hit_is_lab_only(hit: dict[str, Any]) -> bool:
    row = hit.get("row") if isinstance(hit.get("row"), dict) else {}
    behavior_type = str(_row_value(row, "BehaviorType", "behavior_type") or "").lower()
    if behavior_type.startswith("lab_"):
        return True
    text = _hit_text(hit) + " " + str(_row_value(row, "ProcessEvidenceJson", "EvidenceJson", "CommandLine") or "")
    if _is_lab_execution_text(text) and behavior_type in {
        "writable_process_execution_4688",
        "writable_live_process_memory",
        "writable_live_process_context",
        "writable_recent_binary_context",
    }:
        return True
    return False


def _is_scheduled_task_lolbin_text(text: str) -> bool:
    return bool(
        re.search(r"\bschtasks(?:\.exe)?\b", text)
        and re.search(r"(-create|-change|-run|-delete|/create|/change|/run|/delete)", text)
    ) or bool(re.search(r"\b(register|start|unregister)-scheduledtask\b", text))


def _ttps_for_hit(hit: dict[str, Any]) -> set[str]:
    artifact = str(hit.get("source_artifact") or "").lower()
    value = str(hit.get("value") or "")
    text = _hit_text(hit)
    ttps: set[str] = set()

    if "ransomnotes" in artifact or "encryptedextensions" in artifact:
        ttps.add("T1486")
    if "shadowcopytampering" in artifact or "bootrecoverytampering" in artifact:
        ttps.add("T1490")
    if "bootrecoverytampering" in artifact:
        ttps.add("T1562")
    if "persistence.registry" in artifact:
        ttps.add("T1112")
        if any(fragment in text for fragment in ("\\run\\", "\\runonce\\", "\\startup\\", "currentversion\\run")):
            ttps.add("T1547.001")
    if "persistence.services" in artifact:
        ttps.add("T1543.003")
    if "persistence.scheduledtasks" in artifact:
        ttps.add("T1053.005")
    if "lolbins" in artifact:
        if re.search(r"\b(cmd|powershell|wscript|cscript)(\.exe)?\b", text):
            ttps.add("T1059")
        if re.search(r"\b(rundll32|regsvr32|mshta)(\.exe)?\b", text):
            ttps.add("T1218")
        if _is_scheduled_task_lolbin_text(text):
            ttps.add("T1053.005")
        if any(fragment in text for fragment in ("shadow", "delete", "recovery", "bcdedit", "vssadmin", "wbadmin")):
            ttps.add("T1490")
    if "network" in artifact and _is_useful_external_indicator(hit):
        ttps.add("T1105")
    if "suspiciousdroppedfiles" in artifact and (_is_non_system_path(value) or hit.get("inside_execution_window") is True):
        ttps.update({"T1027", "T1105"})
    if _is_behavioral_artifact(artifact):
        row = hit.get("row") if isinstance(hit.get("row"), dict) else {}
        behavior_type = str(_row_value(row, "BehaviorType", "behavior_type") or "").lower()
        if any(part in behavior_type for part in ("bait_file_churn", "ransom_note_spread", "mass_ransom_note", "encrypted_extension")):
            ttps.add("T1486")
        if "impact_tampering" in behavior_type:
            ttps.add("T1490")
        if "proxy_execution" in behavior_type:
            ttps.add("T1218")
        if "external_network" in behavior_type:
            ttps.add("T1105")
        if "writable_process_network" in behavior_type:
            ttps.update({"T1059", "T1105"})
        if (
            "deployable_writable_process_execution" in behavior_type
            or
            "suspicious_live_process" in behavior_type
            or "writable_live_process" in behavior_type
            or "writable_recent_binary" in behavior_type
            or "writable_process_execution" in behavior_type
        ):
            ttps.add("T1059")
    return ttps


def _ttp_mapping(cleaned_hits: list[dict[str, Any]]) -> tuple[list[str], int, dict[str, Any]]:
    ttps: set[str] = set()
    mapped_artifacts: dict[str, list[str]] = {}
    mapped_hit_count = 0
    for hit in cleaned_hits:
        hit_ttps = _ttps_for_hit(hit)
        if not hit_ttps:
            continue
        mapped_hit_count += 1
        ttps.update(hit_ttps)
        artifact = str(hit.get("source_artifact") or "unknown")
        mapped_artifacts.setdefault(artifact, [])
        mapped_artifacts[artifact] = sorted(set(mapped_artifacts[artifact]) | hit_ttps)
    sorted_ttps = sorted(ttps)
    return sorted_ttps, len(sorted_ttps), {
        "ttp_count": len(sorted_ttps),
        "mapped_hit_count": mapped_hit_count,
        "mapped_artifacts": mapped_artifacts,
        "techniques": sorted_ttps,
    }


def _non_empty_text(row: dict[str, Any], *fields: str) -> list[str]:
    values: list[str] = []
    for field in fields:
        value = row.get(field)
        if value in (None, ""):
            continue
        text = str(value).strip()
        if text:
            values.append(text)
    return values


def _secondary_evidence_strength(cleaned_hits: list[dict[str, Any]], triage: dict[str, Any]) -> dict[str, Any]:
    counts = {
        "bait_modification": 0,
        "ransom_note": 0,
        "impact_event": 0,
        "process_event": 0,
        "child_process": 0,
        "live_process": 0,
        "persistence": 0,
        "lolbin": 0,
        "network": 0,
        "mutex": 0,
        "memory_context": 0,
    }
    examples: dict[str, list[dict[str, Any]]] = {key: [] for key in counts}

    def add(kind: str, hit: dict[str, Any], evidence: str) -> None:
        counts[kind] += 1
        if len(examples[kind]) >= 5:
            return
        row = hit.get("row") if isinstance(hit.get("row"), dict) else {}
        examples[kind].append(
            {
                "artifact": hit.get("source_artifact"),
                "value": hit.get("value"),
                "event_time": _row_value(row, "EventTime", "Timestamp", "Mtime", "Btime"),
                "evidence": evidence,
            }
        )

    for hit in cleaned_hits:
        artifact = str(hit.get("source_artifact") or "")
        lower_artifact = artifact.lower()
        row = hit.get("row") if isinstance(hit.get("row"), dict) else {}
        behavior = str(_row_value(row, "BehaviorType", "behavior_type") or "").lower()
        text = _hit_text(hit)
        process_evidence = " ".join(_non_empty_text(row, "ProcessEvidenceJson", "CommandLine", "ParentProcessName", "NewProcessName", "Exe", "OSPath"))
        if _row_value(row, "BaitModifiedCount") or "bait_file_churn" in behavior:
            add("bait_modification", hit, process_evidence or str(hit.get("value") or ""))
        if _row_value(row, "RansomNoteCount") or "ransomnotes" in lower_artifact or "ransom_note" in behavior:
            add("ransom_note", hit, str(_row_value(row, "EvidenceJson", "OSPath", "Path") or hit.get("value") or ""))
        if _row_value(row, "ImpactEventCount") or "impact" in behavior or "shadowcopy" in lower_artifact or "bootrecovery" in lower_artifact:
            add("impact_event", hit, process_evidence or text)
        if _row_value(row, "ProcessEventCount") or _row_value(row, "RecordID") or "4688" in behavior:
            add("process_event", hit, process_evidence or text)
        if _row_value(row, "ParentProcessName") and _row_value(row, "NewProcessName"):
            add("child_process", hit, process_evidence or text)
        if _row_value(row, "LiveSuspiciousProcessCount") or "live_process" in behavior:
            add("live_process", hit, process_evidence or text)
        if "persistence." in lower_artifact or "scheduled_task" in text:
            add("persistence", hit, process_evidence or text)
        if "lolbins" in lower_artifact or "proxy_execution" in behavior or _suspicious_proxy_text(text):
            add("lolbin", hit, process_evidence or text)
        if _is_useful_external_indicator(hit) or _row_value(row, "ExternalConnectionCount") or "network" in behavior:
            add("network", hit, " ".join(_non_empty_text(row, "NetworkEvidenceJson", "RemoteAddr", "RemoteIP", "Domain", "Url")) or str(hit.get("value") or ""))
        if "mutex" in lower_artifact:
            add("mutex", hit, str(hit.get("value") or ""))
        memory_values = _non_empty_text(row, "MemoryEvidenceJson")
        if memory_values or _row_value(row, "WorkingSet64", "PrivateMemorySize64", "HandleCount", "ThreadCount"):
            add("memory_context", hit, " ".join(memory_values) or process_evidence or text)

    triage_counts = triage.get("section_counts") if isinstance(triage.get("section_counts"), dict) else {}
    return {
        "counts": counts,
        "examples": {key: value for key, value in examples.items() if value},
        "triage_counts": triage_counts,
        "strength_score": min(100, sum(min(value, 5) for value in counts.values()) * 4),
    }


def _hit(path: Path, row: dict[str, Any], index: int) -> list[dict[str, Any]]:
    artifact = str(_row_value(row, "source_artifact", "SourceArtifact") or _artifact_from_path(path))
    match_type = _match_type_for(artifact, row)
    candidate_id = _row_value(row, "candidate_id", "CandidateId") or f"{artifact}:{index}"
    if "network" in artifact.lower():
        hits = []
        timestamp_details = _row_timestamp_details(row)
        for subindex, (category, value) in enumerate(_network_values(row), start=1):
            hits.append(
                {
                    "candidate_id": f"{candidate_id}:{subindex}",
                    "source_artifact": artifact,
                    "match_type": match_type,
                    "category": category,
                    "value": value,
                    "row": row,
                    "CommandLine": row.get("CommandLine"),
                    "command_line": row.get("command_line"),
                    "Message": row.get("Message"),
                    "message": row.get("message"),
                    "timestamp_details": timestamp_details,
                    "row_context": _compact_row_context(row),
                }
            )
        return hits
    category = str(_row_value(row, "category", "Category") or _category_for(artifact, row))
    value = _value_for(row)
    return [
        {
            "candidate_id": str(candidate_id),
            "source_artifact": artifact,
            "match_type": match_type,
            "category": category,
            "value": value,
            "row": row,
            "CommandLine": row.get("CommandLine"),
            "command_line": row.get("command_line"),
            "Message": row.get("Message"),
            "message": row.get("message"),
            "timestamp_details": _row_timestamp_details(row),
            "row_context": _compact_row_context(row),
        }
    ]


def _write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _evidence_summary(
    *,
    execution_window: tuple[datetime, datetime] | None,
    raw_hits: list[dict[str, Any]],
    cleaned_hits: list[dict[str, Any]],
    rejected_hits: list[dict[str, Any]],
) -> dict[str, Any]:
    raw_by_artifact: dict[str, int] = {}
    inside_by_artifact: dict[str, int] = {}
    rejected_by_reason: dict[str, int] = {}
    rejected_by_artifact_reason: dict[str, dict[str, int]] = {}
    kept_by_artifact: dict[str, int] = {}
    missing_timestamp_by_artifact: dict[str, int] = {}

    for hit in raw_hits:
        artifact = str(hit["source_artifact"])
        raw_by_artifact[artifact] = raw_by_artifact.get(artifact, 0) + 1
        timestamps = [_parse_dt(item["parsed_at"]) for item in hit.get("timestamp_details", [])]
        timestamps = [item for item in timestamps if item is not None]
        inside = _inside_execution_window(timestamps, execution_window)
        if inside:
            inside_by_artifact[artifact] = inside_by_artifact.get(artifact, 0) + 1
        if execution_window and not timestamps:
            missing_timestamp_by_artifact[artifact] = missing_timestamp_by_artifact.get(artifact, 0) + 1

    for hit in cleaned_hits:
        artifact = str(hit["source_artifact"])
        kept_by_artifact[artifact] = kept_by_artifact.get(artifact, 0) + 1

    for hit in rejected_hits:
        artifact = str(hit["source_artifact"])
        reason = str(hit.get("fp_filter_reason") or "unknown")
        rejected_by_reason[reason] = rejected_by_reason.get(reason, 0) + 1
        rejected_by_artifact_reason.setdefault(artifact, {})
        rejected_by_artifact_reason[artifact][reason] = rejected_by_artifact_reason[artifact].get(reason, 0) + 1

    no_clean_reason = None
    if not cleaned_hits:
        if sum(inside_by_artifact.values()) == 0:
            no_clean_reason = "no_in_window_evidence_found"
        elif rejected_by_reason:
            no_clean_reason = "all_in_window_evidence_rejected"
        else:
            no_clean_reason = "no_raw_hits_found"

    return {
        "execution_window": {
            "started_at": execution_window[0].isoformat() if execution_window else None,
            "completed_at": execution_window[1].isoformat() if execution_window else None,
            "margin_seconds": WINDOW_MARGIN_SECONDS,
        },
        "raw_hits_by_artifact": raw_by_artifact,
        "inside_window_hits_by_artifact": inside_by_artifact,
        "kept_hits_by_artifact": kept_by_artifact,
        "missing_timestamp_hits_by_artifact": missing_timestamp_by_artifact,
        "rejected_hits_by_reason": rejected_by_reason,
        "rejected_hits_by_artifact_reason": rejected_by_artifact_reason,
        "raw_hit_count": len(raw_hits),
        "inside_window_hit_count": sum(inside_by_artifact.values()),
        "clean_hit_count": len(cleaned_hits),
        "rejected_hit_count": len(rejected_hits),
        "no_clean_hit_reason": no_clean_reason,
    }


def _load_post_execution_triage(result_dir: Path) -> dict[str, Any]:
    path = result_dir / "post_execution_triage.json"
    payload: dict[str, Any] = {}
    if not path.exists():
        payload = {}
    else:
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            loaded = {}
        payload = loaded if isinstance(loaded, dict) else {}

    winrm_path = result_dir / "winrm_execution_log.json"
    if winrm_path.exists():
        try:
            winrm_log = json.loads(winrm_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            winrm_log = {}
        stdout = str(winrm_log.get("stdout") or "").strip() if isinstance(winrm_log, dict) else ""
        execution_payload = parse_json_object(stdout) if stdout else None
        if execution_payload is None and stdout.startswith("STARTED "):
            execution_payload = {
                "status": "STARTED",
                "path": stdout.removeprefix("STARTED ").strip(),
                "process_snapshots": [],
            }
        if execution_payload is None and winrm_log.get("status_code") == 124 and "execute_sample.ps1" in str(winrm_log.get("command") or ""):
            execution_payload = {
                "status": "STARTED_TIMEOUT",
                "path": None,
                "process_snapshots": [],
                "evidence_mode": "winrm_execution_timeout_after_launch",
            }
        if isinstance(execution_payload, dict):
            snapshots = execution_payload.get("process_snapshots")
            if not isinstance(snapshots, list):
                snapshots = []
            alive_snapshots = [row for row in snapshots if isinstance(row, dict) and row.get("alive") is True]
            payload["execution_context"] = {
                "sample_execution_observed": str(execution_payload.get("status") or "").startswith("STARTED"),
                "sample_process_alive": bool(
                    execution_payload.get("alive_after_5s")
                    or execution_payload.get("alive_after_15s")
                    or execution_payload.get("alive_after_30s")
                    or alive_snapshots
                ),
                "alive_snapshot_count": len(alive_snapshots),
                "has_memory_context": any(
                    isinstance(row, dict)
                    and any(row.get(key) not in (None, 0, "") for key in ("working_set64", "private_memory_size64", "virtual_memory_size64", "handle_count", "thread_count"))
                    for row in snapshots
                ),
                "pid": execution_payload.get("pid"),
                "path": execution_payload.get("path"),
                "evidence_mode": execution_payload.get("evidence_mode"),
            }
    return payload


def _triage_section_count(triage: dict[str, Any], section: str) -> int:
    counts = triage.get("section_counts")
    if isinstance(counts, dict):
        try:
            return int(counts.get(section) or 0)
        except (TypeError, ValueError):
            return 0
    return 0


def _is_user_facing_note_path(value: str) -> bool:
    lowered = value.lower().replace("/", "\\")
    return lowered.startswith("c:\\") and any(fragment in lowered for fragment in USER_FACING_NOTE_FRAGMENTS)


def _is_in_window_ransom_note_candidate(artifact: str, value: str, row: dict[str, Any], inside_window: bool) -> bool:
    if not inside_window or "ransomnotes" not in artifact.lower():
        return False
    lowered = value.lower().replace("/", "\\")
    if any(fragment in lowered for fragment in RANSOM_NOTE_NOISE_FRAGMENTS):
        return False
    match_type = str(_row_value(row, "match_type") or "").lower()
    return match_type in {"suspicious_ransom_note_name", "exact_path"} and bool(SUSPICIOUS_FILE_NAME_RE.search(lowered))


def _is_in_window_encrypted_extension(artifact: str, value: str, inside_window: bool) -> bool:
    return bool(inside_window and "encryptedextensions" in artifact.lower() and SUSPICIOUS_FILE_EXT_RE.search(value.lower()))


def _is_in_window_behavioral_signal(artifact: str, row: dict[str, Any], inside_window: bool | None) -> bool:
    if not inside_window or not _is_behavioral_artifact(artifact):
        return False
    behavior_type = str(_row_value(row, "BehaviorType", "behavior_type") or "").lower()
    if behavior_type not in {
        "deployable_writable_process_execution_4688",
        "lab_controlled_execution_4688",
        "writable_process_execution_4688",
        "writable_live_process_memory",
        "writable_live_process_context",
        "bait_file_churn",
        "encrypted_extension_correlated",
        "ransom_note_spread_correlated",
    }:
        return False
    try:
        confidence = float(_row_value(row, "Confidence", "confidence") or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    if behavior_type.startswith("lab_"):
        return True
    return confidence >= 0.70 or str(_row_value(row, "Severity", "severity") or "").lower() == "high"


def _is_in_window_attributable_impact(
    artifact: str,
    row: dict[str, Any],
    inside_window: bool | None,
    sample_paths: set[str],
) -> bool:
    lowered_artifact = artifact.lower()
    if inside_window is not True or not any(part in lowered_artifact for part in ("shadowcopytampering", "bootrecoverytampering")):
        return False
    command = str(_row_value(row, "CommandLine", "Message", "EventDataJson") or "").lower().replace("/", "\\")
    destructive = any(
        fragment in command
        for fragment in (
            "vssadmin delete shadows",
            "wbadmin delete catalog",
            "wmic shadowcopy delete",
            "recoveryenabled no",
            "bootstatuspolicy ignoreallfailures",
        )
    )
    parent = str(_row_value(row, "ParentProcessName", "CreatorProcessName") or "").lower().replace("/", "\\")
    return destructive and parent in sample_paths


def _parent_dir(value: str) -> str:
    lowered = value.lower().replace("/", "\\")
    if "\\" not in lowered:
        return lowered
    return lowered.rsplit("\\", 1)[0]


def _suspicious_proxy_text(text: str) -> bool:
    lowered = text.lower().replace("/", "\\")
    if not re.search(r"\b(rundll32|regsvr32|mshta|wscript|cscript)(\.exe)?\b", lowered):
        return False
    return any(
        fragment in lowered
        for fragment in (
            "\\vr-malware-test\\",
            "\\appdata\\local\\temp\\",
            "\\appdata\\roaming\\",
            "\\users\\public\\",
            ",#",
            ".dll,",
            ".js ",
            ".vbs ",
            ".hta",
        )
    )


def _is_strong_explicit_ioc_hit(hit: dict[str, Any]) -> bool:
    artifact = str(hit.get("source_artifact") or "").lower()
    if "exactiocmatches" not in artifact and artifact != HIGH_CONFIDENCE.lower():
        return False
    category = str(hit.get("category") or "").lower()
    match_type = str(hit.get("match_type") or "").lower()
    value = str(hit.get("value") or "").lower().replace("/", "\\")
    if category in {"hash", "mutex", "registry", "domain", "url", "ip", "process"}:
        return True
    if match_type in {"exact_hash", "exact_mutex", "exact_registry", "exact_domain", "exact_ip", "exact_url", "exact_process"}:
        return True
    if category == "file":
        if SUSPICIOUS_FILE_NAME_RE.search(value) and value.endswith((".txt", ".html", ".hta", ".md", ".rtf", ".url")):
            return False
        return value.endswith((".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta"))
    return False


def _correlate_detection(cleaned_hits: list[dict[str, Any]], triage: dict[str, Any], *, allow_lab_execution_context: bool = True) -> dict[str, Any]:
    counts: dict[str, int] = {}
    artifact_hits: dict[str, list[dict[str, Any]]] = {}
    for hit in cleaned_hits:
        artifact = str(hit.get("source_artifact") or "")
        counts[artifact] = counts.get(artifact, 0) + 1
        artifact_hits.setdefault(artifact, []).append(hit)

    observable = sorted(counts)
    triggered_artifacts: set[str] = set()
    supporting_artifacts: set[str] = set(observable)
    reasons: list[str] = []
    high_confidence_reasons: list[str] = []
    supporting_reasons: list[str] = []

    ransom_hits = [hit for artifact, hits in artifact_hits.items() if "ransomnotes" in artifact.lower() for hit in hits]
    user_facing_notes = [hit for hit in ransom_hits if _is_user_facing_note_path(str(hit.get("value") or ""))]
    unique_note_dirs = {_parent_dir(str(hit.get("value") or "")) for hit in user_facing_notes}
    all_note_dirs = {_parent_dir(str(hit.get("value") or "")) for hit in ransom_hits}
    sample_related_4688 = _triage_section_count(triage, "security_4688_sample_related")
    bait_recent_files = _triage_section_count(triage, "bait_recent_files")
    execution_context = triage.get("execution_context") if isinstance(triage.get("execution_context"), dict) else {}
    sample_process_alive = bool(execution_context.get("sample_process_alive"))
    has_memory_context = bool(execution_context.get("has_memory_context"))
    sample_execution_observed = bool(execution_context.get("sample_execution_observed"))
    if not allow_lab_execution_context:
        sample_related_4688 = 0
        bait_recent_files = 0
        sample_process_alive = False
        has_memory_context = False
        sample_execution_observed = False
    note_spread_hits = user_facing_notes
    if len(note_spread_hits) < 3 and len(ransom_hits) >= 8 and len(all_note_dirs) >= 5:
        note_spread_hits = ransom_hits
    if len(note_spread_hits) >= 3 or len(unique_note_dirs) >= 3:
        if sample_process_alive and has_memory_context:
            reasons.append("ransom_note_spread_correlated")
            high_confidence_reasons.append("ransom_note_spread_with_process_liveness")
            triggered_artifacts.update({str(hit["source_artifact"]) for hit in note_spread_hits})
        elif sample_related_4688 > 0:
            reasons.append("ransom_note_spread_correlated")
            high_confidence_reasons.append("ransom_note_spread_with_process_trace")
            triggered_artifacts.update({str(hit["source_artifact"]) for hit in note_spread_hits})
        elif bait_recent_files >= 8:
            reasons.append("ransom_note_spread_correlated")
            high_confidence_reasons.append("ransom_note_spread_with_bait_file_activity")
            triggered_artifacts.update({str(hit["source_artifact"]) for hit in note_spread_hits})
        else:
            supporting_reasons.append("ransom_note_spread_uncorrelated")
    elif ransom_hits:
        supporting_reasons.append("single_ransom_note_hit")

    behavioral_hits = [
        hit
        for artifact, hits in artifact_hits.items()
        if _is_behavioral_artifact(artifact)
        for hit in hits
    ]
    recent_binary_behavior_hits = [
        hit
        for hit in behavioral_hits
        if "writable_recent_binary" in str(_row_value(hit.get("row") if isinstance(hit.get("row"), dict) else {}, "BehaviorType", "behavior_type") or "").lower()
    ]
    if recent_binary_behavior_hits:
        if sample_process_alive and has_memory_context:
            reasons.append("writable_binary_execution_with_memory")
            high_confidence_reasons.append("writable_binary_execution_with_memory")
            triggered_artifacts.update({str(hit["source_artifact"]) for hit in recent_binary_behavior_hits})
        elif sample_related_4688 > 0:
            reasons.append("writable_binary_execution_with_process_trace")
            high_confidence_reasons.append("writable_binary_execution_with_process_trace")
            triggered_artifacts.update({str(hit["source_artifact"]) for hit in recent_binary_behavior_hits})
        else:
            supporting_reasons.append("behavioral_writable_recent_binary_context")
    if ransom_hits and recent_binary_behavior_hits:
        reasons.append("ransom_note_spread_with_recent_writable_binary")
        high_confidence_reasons.append("ransom_note_spread_with_recent_writable_binary")
        triggered_artifacts.update({str(hit["source_artifact"]) for hit in ransom_hits + recent_binary_behavior_hits})
    behavior_reason_map = {
        "bait_file_churn": "file_io_churn",
        "deployable_writable_process_execution_4688": "deployable_writable_process_execution_4688",
        "encrypted_extension_correlated": "encrypted_extension_correlated",
        "ransom_note_spread_correlated": "ransom_note_spread_correlated",
        "mass_ransom_note_drop_with_process_trace": "ransom_note_spread_with_process_trace",
        "impact_tampering": "impact_tampering",
        "proxy_execution": "proxy_execution",
        "suspicious_live_process_correlated": "suspicious_live_process_correlated",
        "writable_live_process_context": "writable_live_process_context",
        "writable_live_process_memory": "writable_live_process_memory",
        "writable_process_execution_4688": "writable_process_execution_4688",
        "writable_process_network_correlated": "writable_process_network_correlated",
        "external_network_correlated": "external_network_correlated",
    }
    for hit in behavioral_hits:
        row = hit.get("row") if isinstance(hit.get("row"), dict) else {}
        behavior_type = str(_row_value(row, "BehaviorType", "behavior_type") or hit.get("value") or "").lower()
        if behavior_type.startswith("lab_"):
            supporting_reasons.append(behavior_type)
            continue
        reason = behavior_reason_map.get(behavior_type)
        if not reason:
            supporting_reasons.append(f"behavioral_{behavior_type}" if behavior_type else "behavioral_signal")
            continue
        if reason not in reasons:
            reasons.append(reason)
        triggered_artifacts.add(str(hit["source_artifact"]))
        severity = str(_row_value(row, "Severity", "severity") or "").lower()
        try:
            confidence = float(_row_value(row, "Confidence", "confidence") or 0)
        except (TypeError, ValueError):
            confidence = 0.0
        if severity == "high" or confidence >= 0.85:
            high_confidence_reasons.append(reason)

    tamper_artifacts = [artifact for artifact in counts if any(part in artifact.lower() for part in ("shadowcopytampering", "bootrecoverytampering"))]
    if tamper_artifacts:
        reasons.append("impact_tampering")
        high_confidence_reasons.append("impact_tampering")
        triggered_artifacts.update(tamper_artifacts)

    persistence_artifacts = [artifact for artifact in counts if "persistence." in artifact.lower()]
    if persistence_artifacts:
        reasons.append("persistence_artifact")
        high_confidence_reasons.append("persistence_artifact")
        triggered_artifacts.update(persistence_artifacts)

    scheduled_task_lolbin_hits = [
        hit
        for artifact, hits in artifact_hits.items()
        if "lolbins" in artifact.lower()
        for hit in hits
        if _is_scheduled_task_lolbin_text(_hit_text(hit))
    ]
    if scheduled_task_lolbin_hits:
        reasons.append("scheduled_task_persistence")
        high_confidence_reasons.append("scheduled_task_persistence")
        triggered_artifacts.update({str(hit["source_artifact"]) for hit in scheduled_task_lolbin_hits})

    explicit_ioc_hits = [hit for hit in cleaned_hits if _is_strong_explicit_ioc_hit(hit)]
    if explicit_ioc_hits:
        reasons.append("explicit_exact_ioc")
        high_confidence_reasons.append("explicit_exact_ioc")
        triggered_artifacts.update({str(hit["source_artifact"]) for hit in explicit_ioc_hits})

    proxy_hits = [hit for artifact, hits in artifact_hits.items() if any(part in artifact.lower() for part in ("proxyexecution", "lolbins")) for hit in hits]
    suspicious_proxy_hits = [hit for hit in proxy_hits if _suspicious_proxy_text(_hit_text(hit))]
    if suspicious_proxy_hits:
        reasons.append("proxy_execution")
        high_confidence_reasons.append("proxy_execution")
        triggered_artifacts.update({str(hit["source_artifact"]) for hit in suspicious_proxy_hits})
    elif proxy_hits:
        supporting_reasons.append("generic_lolbin_activity")

    useful_network_hits = [hit for hit in cleaned_hits if _is_useful_external_indicator(hit)]
    if useful_network_hits:
        network_artifacts = {str(hit["source_artifact"]) for hit in useful_network_hits}
        if reasons or any(part in artifact.lower() for artifact in counts for part in ("suspiciousdroppedfiles", "ransomwarebinaries", "encryptedextensions")):
            reasons.append("external_network_correlated")
            triggered_artifacts.update(network_artifacts)
        else:
            reasons.append("useful_external_network_indicator")
            triggered_artifacts.update(network_artifacts)

    encrypted_artifacts = [artifact for artifact in counts if "encryptedextensions" in artifact.lower()]
    if encrypted_artifacts and (ransom_hits or useful_network_hits):
        reasons.append("encryption_artifact_correlated")
        triggered_artifacts.update(encrypted_artifacts)
    elif encrypted_artifacts and (sample_process_alive or sample_related_4688 > 0 or recent_binary_behavior_hits):
        reasons.append("encrypted_extension_correlated")
        high_confidence_reasons.append("encrypted_extension_correlated")
        triggered_artifacts.update(encrypted_artifacts)
    elif encrypted_artifacts:
        supporting_reasons.append("encrypted_extension_only")

    binary_artifacts = [artifact for artifact in counts if any(part in artifact.lower() for part in ("suspiciousdroppedfiles", "ransomwarebinaries"))]
    if binary_artifacts and (useful_network_hits or suspicious_proxy_hits or tamper_artifacts or persistence_artifacts):
        reasons.append("binary_artifact_correlated")
        triggered_artifacts.update(binary_artifacts)
    elif binary_artifacts:
        supporting_reasons.append("isolated_binary_artifact")

    if not reasons and _triage_section_count(triage, "security_4688") >= 20 and len(user_facing_notes) >= 2:
        reasons.append("ransom_note_with_process_audit_window")
        triggered_artifacts.update({str(hit["source_artifact"]) for hit in user_facing_notes})

    if not reasons and sample_process_alive and has_memory_context:
        reasons.append("live_sample_process_memory")
        high_confidence_reasons.append("live_sample_process_memory")
    elif not reasons and sample_process_alive and cleaned_hits:
        reasons.append("live_sample_process_correlated_artifact")
        high_confidence_reasons.append("live_sample_process_correlated_artifact")

    if sample_execution_observed:
        supporting_reasons.append("controlled_sample_execution_observed")

    supporting_artifacts -= triggered_artifacts
    family_by_reason = {
        "persistence_artifact": "persistence",
        "scheduled_task_persistence": "persistence",
        "impact_tampering": "impact",
        "ransom_note_spread_correlated": "ransom_note",
        "ransom_note_spread_with_recent_writable_binary": "ransom_note",
        "ransom_note_with_process_audit_window": "ransom_note",
        "explicit_exact_ioc": "exact_ioc",
        "proxy_execution": "proxy_execution",
        "external_network_correlated": "network",
        "useful_external_network_indicator": "network",
        "encryption_artifact_correlated": "encryption",
        "encrypted_extension_correlated": "encryption",
        "binary_artifact_correlated": "binary",
        "file_io_churn": "file_activity",
    }
    evidence_families: set[str] = set()
    for reason in reasons:
        family = family_by_reason.get(reason)
        if family:
            evidence_families.add(family)
        elif any(part in reason for part in ("process", "writable_binary", "live_sample")):
            evidence_families.add("process_execution")
        elif "ransom_note" in reason:
            evidence_families.add("ransom_note")
    strong_families = {"persistence", "impact", "ransom_note", "exact_ioc", "encryption"}
    if "persistence" in evidence_families:
        persistence_hits = [
            hit
            for hit in cleaned_hits
            if "persistence." in str(hit.get("source_artifact") or "").lower()
            or _is_scheduled_task_lolbin_text(_hit_text(hit))
        ]
        if persistence_hits and all(_is_known_benign_windows_update_task(hit) for hit in persistence_hits):
            evidence_families.discard("persistence")
    candidate_detected = bool(reasons)
    corroborated_detected = (
        len(evidence_families) >= MIN_CORROBORATING_EVIDENCE_FAMILIES
        and bool(evidence_families & strong_families)
    )
    detection_score = len(reasons) * 10 + len(high_confidence_reasons) * 5 + min(len(cleaned_hits), 9)
    return {
        "observable_artifacts_found": observable,
        "triggered_artifacts": sorted(triggered_artifacts),
        "supporting_artifacts": sorted(supporting_artifacts),
        "detection_reasons": reasons,
        "supporting_reasons": sorted(set(supporting_reasons)),
        "high_confidence_reasons": sorted(set(high_confidence_reasons)),
        "evidence_families": sorted(evidence_families),
        "evidence_family_count": len(evidence_families),
        "minimum_evidence_family_count": MIN_CORROBORATING_EVIDENCE_FAMILIES,
        "candidate_detected": candidate_detected,
        "corroborated_detected": corroborated_detected,
        "detection_score": detection_score,
        "detected": candidate_detected,
        "high_confidence_detected": bool(high_confidence_reasons),
    }


def apply_false_positive_filter(
    result_dir: Path,
    *,
    sample_id: int,
    sha256: str,
    vm: str,
    client_id: str | None,
    flow_id: str | None,
    partial_export: bool,
    final_revert: dict[str, Any] | None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> dict[str, Any]:
    execution_window = _execution_window_from_metadata(result_dir, started_at, completed_at)
    sample_paths = _sample_execution_paths(result_dir)
    post_execution_triage = _load_post_execution_triage(result_dir)
    raw_dir = result_dir / "raw_exports"
    raw_hits = [
        hit
        for path in sorted(raw_dir.glob("*.json")) if raw_dir.exists()
        for index, row in enumerate(_load_rows(path), start=1)
        for hit in _hit(path, row, index)
    ]
    cleaned_hits: list[dict[str, Any]] = []
    rejected_hits: list[dict[str, Any]] = []
    for hit in raw_hits:
        parsed_timestamps = [item["parsed_at"] for item in hit.get("timestamp_details", [])]
        parsed_datetimes = [parsed for item in parsed_timestamps if (parsed := _parse_dt(item)) is not None]
        inside_window = _inside_execution_window(parsed_datetimes, execution_window)
        artifact_reason = _artifact_rejection_reason(str(hit["source_artifact"]), hit["row"], execution_window, sample_paths)
        if artifact_reason:
            rejected_hits.append({**hit, "parsed_timestamps": parsed_timestamps, "inside_execution_window": inside_window, "fp_filter_reason": artifact_reason})
            continue
        decision = classify_noise(hit, layer="velociraptor")
        if decision.action != "keep" and _is_recent_suspicious_drop(str(hit["source_artifact"]), str(hit["value"])):
            decision = type(decision)(action="keep", reason=None)
        if decision.action != "keep" and _is_in_window_ransom_note_candidate(str(hit["source_artifact"]), str(hit["value"]), hit["row"], inside_window):
            decision = type(decision)(action="keep", reason=None)
        if decision.action != "keep" and _is_in_window_encrypted_extension(str(hit["source_artifact"]), str(hit["value"]), bool(inside_window)):
            decision = type(decision)(action="keep", reason=None)
        if decision.action != "keep" and _is_in_window_behavioral_signal(str(hit["source_artifact"]), hit["row"], inside_window):
            decision = type(decision)(action="keep", reason=None)
        if decision.action != "keep" and _is_in_window_attributable_impact(
            str(hit["source_artifact"]), hit["row"], inside_window, sample_paths
        ):
            decision = type(decision)(action="keep", reason=None)
        if decision.action == "keep":
            cleaned_hits.append({**hit, "parsed_timestamps": parsed_timestamps, "inside_execution_window": inside_window, "fp_filter_reason": None})
        else:
            rejected_hits.append({**hit, "parsed_timestamps": parsed_timestamps, "inside_execution_window": inside_window, "fp_filter_reason": decision.reason or decision.action})

    deduped_cleaned: list[dict[str, Any]] = []
    seen_cleaned: set[tuple[str, str, str]] = set()
    for hit in cleaned_hits:
        key = (str(hit["source_artifact"]), str(hit["category"]), str(hit["value"]).lower())
        if key in seen_cleaned:
            continue
        seen_cleaned.add(key)
        deduped_cleaned.append(hit)
    cleaned_hits = deduped_cleaned

    counts: dict[str, int] = {}
    for hit in cleaned_hits:
        artifact = str(hit["source_artifact"])
        counts[artifact] = counts.get(artifact, 0) + 1
    correlation = _correlate_detection(cleaned_hits, post_execution_triage)
    deployable_hits = [hit for hit in cleaned_hits if not _hit_is_lab_only(hit)]
    deployable_correlation = _correlate_detection(deployable_hits, post_execution_triage, allow_lab_execution_context=False)
    ttps, ttp_score, behavior_summary = _ttp_mapping(cleaned_hits)
    behavior_summary["detection_reasons"] = correlation["detection_reasons"]
    behavior_summary["supporting_reasons"] = correlation["supporting_reasons"]
    behavior_summary["high_confidence_reasons"] = correlation["high_confidence_reasons"]
    secondary_evidence = _secondary_evidence_strength(cleaned_hits, post_execution_triage)
    behavior_summary["secondary_evidence"] = secondary_evidence
    behavior_summary["lab_only_hit_count"] = len(cleaned_hits) - len(deployable_hits)
    behavior_summary["deployable_hit_count"] = len(deployable_hits)
    payload = {
        "sample_id": sample_id,
        "sha256": sha256,
        "vm": vm,
        "client_id": client_id,
        "flow_id": flow_id,
        "partial_export": partial_export,
        "final_revert": final_revert,
        "execution_window": {
            "started_at": execution_window[0].isoformat() if execution_window else None,
            "completed_at": execution_window[1].isoformat() if execution_window else None,
            "margin_seconds": WINDOW_MARGIN_SECONDS,
        },
        "raw_hit_count": len(raw_hits),
        "clean_hit_count": len(cleaned_hits),
        "rejected_hit_count": len(rejected_hits),
        "artifact_hit_counts": counts,
        "observable_artifacts_found": correlation["observable_artifacts_found"],
        "triggered_artifacts": correlation["triggered_artifacts"],
        "supporting_artifacts": correlation["supporting_artifacts"],
        "detection_reasons": correlation["detection_reasons"],
        "supporting_reasons": correlation["supporting_reasons"],
        "detection_score": correlation["detection_score"],
        "candidate_detected": correlation["candidate_detected"],
        "corroborated_detected": correlation["corroborated_detected"],
        "detected": correlation["detected"],
        "historical_consolidated_detected": correlation["detected"],
        "high_confidence_detected": correlation["high_confidence_detected"],
        "lab_execution_observability_detected": correlation["detected"],
        "lab_execution_observability_high_confidence": correlation["high_confidence_detected"],
        "deployable_detected": deployable_correlation["detected"],
        "deployable_historical_consolidated_detected": deployable_correlation["detected"],
        "deployable_candidate_detected": deployable_correlation["candidate_detected"],
        "deployable_corroborated_detected": deployable_correlation["corroborated_detected"],
        "deployable_high_confidence_detected": deployable_correlation["high_confidence_detected"],
        "deployable_detection_reasons": deployable_correlation["detection_reasons"],
        "deployable_triggered_artifacts": deployable_correlation["triggered_artifacts"],
        "evidence_families": correlation["evidence_families"],
        "evidence_family_count": correlation["evidence_family_count"],
        "minimum_evidence_family_count": correlation["minimum_evidence_family_count"],
        "deployable_evidence_families": deployable_correlation["evidence_families"],
        "deployable_evidence_family_count": deployable_correlation["evidence_family_count"],
        "lab_only_hit_count": len(cleaned_hits) - len(deployable_hits),
        "ttps": ttps,
        "ttp_score": ttp_score,
        "behavior_summary": behavior_summary,
        "secondary_evidence": secondary_evidence,
        "hits": cleaned_hits,
        "rejected_hits": rejected_hits,
    }
    evidence_summary = _evidence_summary(
        execution_window=execution_window,
        raw_hits=raw_hits,
        cleaned_hits=cleaned_hits,
        rejected_hits=rejected_hits,
    )
    _write(result_dir / "artifact_hits_raw.json", {"hits": raw_hits})
    _write(result_dir / "artifact_hits_cleaned.json", {"hits": cleaned_hits, "rejected_hits": rejected_hits})
    _write(result_dir / "execution_window_evidence_summary.json", evidence_summary)
    _write(result_dir / "artifact_hits.json", payload)
    return payload
