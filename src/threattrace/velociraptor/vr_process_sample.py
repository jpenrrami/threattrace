from __future__ import annotations

import argparse
import json
import os
import shutil
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from threattrace.common.io import parse_json_object, write_json
from threattrace.common.time import utcnow_iso
from threattrace.velociraptor.vr_binary_resolver import ResolvedSampleBinary, resolve_sample_binary
from threattrace.velociraptor.vr_clients import (
    CommandResult,
    lookup_client,
    resolve_client_id,
    run_command,
    velociraptor_base,
    velociraptor_server_base,
)
from threattrace.velociraptor.vr_collections import (
    collection_backend,
    export_vql,
    run_collection,
    wait_for_flow_completion,
)
from threattrace.velociraptor.vr_config import (
    DETECTION_ARCHIVE_ROOT,
    THREATTRACE_ARTIFACTS,
    effective_wait_seconds,
    ensure_safe_staging_bind,
    load_vr_config,
)
from threattrace.velociraptor.vr_pe import choose_dll_execution
from threattrace.velociraptor.vr_persistence import persist_runtime_result
from threattrace.velociraptor.vr_result_filter import apply_false_positive_filter
from threattrace.velociraptor.vr_staging import StagingHTTPServer, choose_free_port, http_server_command, stage_sample
from threattrace.velociraptor.vr_vm import (
    VMCommandResult,
    run_vm_command,
    snapshot_info_command,
    snapshot_revert_command,
)
from threattrace.velociraptor.vr_winrm import WinRMResult, build_execution_powershell, ps_single_quote, run_powershell


def _now() -> str:
    return utcnow_iso()


def _result_run_dir(result_root: Path, sha256: str, vm_name: str, started_at: str) -> Path:
    stamp = started_at.replace(":", "").replace("-", "").replace("+00:00", "Z").replace(".", "")
    return result_root / "results" / sha256 / vm_name / stamp


def _next_detection_archive_dir(sample_id: int, archive_root: Path) -> tuple[int, Path]:
    archive_root.mkdir(parents=True, exist_ok=True)
    prefix = f"v_detection_{sample_id}_"
    max_detection_number = 0

    for path in archive_root.glob(f"{prefix}*"):
        if not path.is_dir():
            continue
        suffix = path.name.removeprefix(prefix)
        if suffix.isdigit():
            max_detection_number = max(max_detection_number, int(suffix))

    detection_number = max_detection_number + 1
    return detection_number, archive_root / f"{prefix}{detection_number}"


def _copy_result_file(result_dir: Path, archive_dir: Path, filename: str) -> None:
    source = result_dir / filename
    if source.exists() and source.is_file():
        shutil.copy2(source, archive_dir / filename)


def _archive_detection_result(result_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    sample_id = int(payload["sample_id"])
    archive_root = DETECTION_ARCHIVE_ROOT
    detection_number, archive_dir = _next_detection_archive_dir(sample_id, archive_root)
    archive_dir.mkdir(parents=True, exist_ok=False)

    for filename in (
        "sample_metadata.json",
        "velociraptor_collection_summary.json",
        "execution_notes.md",
        "execution_window_evidence_summary.json",
        "winrm_execution_log.json",
        "post_execution_triage.json",
        "artifact_hits.json",
        "artifact_hits_cleaned.json",
        "artifact_hits_raw.json",
    ):
        _copy_result_file(result_dir, archive_dir, filename)

    raw_exports = result_dir / "raw_exports"
    if raw_exports.exists() and raw_exports.is_dir():
        shutil.copytree(raw_exports, archive_dir / "raw_exports")

    manifest = {
        "archive_name": archive_dir.name,
        "archive_dir": str(archive_dir),
        "archived_at": _now(),
        "detection_number": detection_number,
        "source_result_dir": str(result_dir),
        "sample_id": sample_id,
        "sha256": payload.get("sha256"),
        "vm": payload.get("vm"),
        "flow_id": payload.get("flow_id"),
        "detected": payload.get("detected"),
        "high_confidence_detected": payload.get("high_confidence_detected"),
        "detection_reasons": payload.get("detection_reasons") or [],
        "observable_artifacts_found": payload.get("observable_artifacts_found") or [],
        "collection_failed": payload.get("collection_failed"),
        "collection_failure_reason": payload.get("collection_failure_reason"),
        "partial_export": payload.get("partial_export"),
        "raw_exports_archived": (archive_dir / "raw_exports").exists(),
    }

    write_json(archive_dir / "manifest.json", manifest)
    return manifest

def collection_failure_reason(result: CommandResult, flow_id: str | None, execute: bool) -> str | None:
    output = f"{result.stdout}\n{result.stderr}".lower()
    if "plugin collect_client not found" in output:
        return "invalid_collect_client_vql"
    if "artifact" in output and ("not found" in output or "not known" in output or "unknown" in output):
        return "invalid_artifact_definition"
    if result.returncode == 124 and execute and flow_id:
        return None
    if result.returncode not in (None, 0):
        return f"collection_command_failed:{result.returncode}"
    if execute and not flow_id:
        return "missing_flow_id"
    return None


def effective_flow_wait_timeout(requested_timeout: int | None) -> int:
    return 300 if requested_timeout is None else max(int(requested_timeout), 0)


def _command_ok(result: CommandResult | VMCommandResult) -> bool:
    return result.returncode in (None, 0)


def _dry_winrm(script: str) -> WinRMResult:
    return WinRMResult(command=script, status_code=None, stdout="", stderr="", executed=False)


def _dry_vm(command: list[str]) -> VMCommandResult:
    return VMCommandResult(command=command, execute=False)


def _dry_command(command: list[str]) -> CommandResult:
    return CommandResult(command=command)


def _provided_client_id(args: argparse.Namespace) -> str | None:
    client_id = getattr(args, "client_id", None)
    if not client_id:
        return None
    client_id = str(client_id).strip()
    if not client_id.startswith("C."):
        raise SystemExit("Velociraptor client_id must start with C.")
    return client_id


def _validate_process_sample_flags(args: argparse.Namespace) -> None:
    if args.execute and not args.confirm_malware_execution:
        raise SystemExit("--execute requires --confirm-malware-execution")
    if args.execute and getattr(args, "no_flow_limit", False):
        raise SystemExit("--no-flow-limit is not allowed for execute runs")


def _post_execution_triage_script(
    *,
    execution_started_at_utc: str,
    sample_id: int,
    sha256: str,
    vm: str,
    client_id: str,
    sample_path: str,
) -> str:
    script = r"""
$ErrorActionPreference = 'Stop'
$executionStarted = [DateTimeOffset]::Parse(__EXECUTION_STARTED__).UtcDateTime
$triageStarted = (Get-Date).ToUniversalTime()
$sampleId = __SAMPLE_ID__
$sha256 = __SHA256__
$vmName = __VM_NAME__
$clientId = __CLIENT_ID__
$samplePath = __SAMPLE_PATH__
$sampleName = [System.IO.Path]::GetFileName($samplePath)
$sampleDir = Split-Path -Parent $samplePath
$triageScriptName = 'post_execution_triage.ps1'
$userProfile = $env:USERPROFILE
$baitRoots = @(
  $sampleDir,
  'C:\\ProgramData\\threattrace-bait',
  (Join-Path $userProfile 'Desktop\\threattrace-bait'),
  (Join-Path $userProfile 'Documents\\threattrace-bait'),
  (Join-Path $userProfile 'AppData\\Roaming\\threattrace-bait'),
  (Join-Path $userProfile 'AppData\\Local\\Temp\\threattrace-bait')
) | Select-Object -Unique
$recentRoots = @(
  (Join-Path $userProfile 'Desktop'),
  (Join-Path $userProfile 'Documents'),
  'C:\\ProgramData',
  (Join-Path $userProfile 'AppData\\Roaming'),
  (Join-Path $userProfile 'AppData\\Local\\Temp')
) | Select-Object -Unique
$ransomNameRegex = '(?i)(readme|restore|recover|decrypt|ransom|payment|bitcoin|unlock|encrypted|instructions?)'
$ransomExtRegex = '(?i)\\.(hta|html|txt)$'

function Normalize-Items($Value) {
  if ($null -eq $Value) { return @() }
  if ($Value -is [string]) { return @($Value) }
  if ($Value -is [System.Collections.IEnumerable]) { return @($Value) }
  return @($Value)
}

function Protect-Section([scriptblock]$Body) {
  try {
    $items = Normalize-Items (& $Body)
    [PSCustomObject]@{
      count = @($items).Count
      items = @($items)
      error = $null
    }
  } catch {
    [PSCustomObject]@{
      count = 0
      items = @()
      error = $_.Exception.Message
    }
  }
}

function Get-RecentFilesForPaths([string[]]$Paths, [DateTime]$Since, [int]$Limit = 200, [int]$Depth = 3) {
  $all = @()
  $perPathLimit = [Math]::Max([int]($Limit / [Math]::Max(@($Paths).Count, 1)), 20)
  foreach ($path in $Paths) {
    if (-not (Test-Path $path)) { continue }
    $gciArgs = @{ Path = $path; Force = $true; File = $true; ErrorAction = 'SilentlyContinue' }
    if ($Depth -gt 0) {
      $gciArgs['Recurse'] = $true
      $gciArgs['Depth'] = $Depth
    }
    $all += Get-ChildItem @gciArgs |
      Where-Object { $_.LastWriteTimeUtc -ge $Since -and $_.Name -ine $triageScriptName } |
      Select-Object FullName, Name, DirectoryName, Length, Extension,
        @{n='LastWriteTimeUtc';e={ $_.LastWriteTimeUtc.ToString('o') }},
        @{n='CreationTimeUtc';e={ $_.CreationTimeUtc.ToString('o') }} |
      Sort-Object LastWriteTimeUtc -Descending |
      Select-Object -First $perPathLimit
  }
  $all | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First $Limit
}

function Get-ExtensionSummary([string[]]$Paths, [int]$Depth = 2) {
  $all = @()
  foreach ($path in $Paths) {
    if (-not (Test-Path $path)) { continue }
    $gciArgs = @{ Path = $path; Force = $true; File = $true; ErrorAction = 'SilentlyContinue' }
    if ($Depth -gt 0) {
      $gciArgs['Recurse'] = $true
      $gciArgs['Depth'] = $Depth
    }
    $all += Get-ChildItem @gciArgs |
      Where-Object { $_.Name -ine $triageScriptName } |
      Group-Object Extension |
      Sort-Object Count -Descending |
      Select-Object @{n='Path';e={ $path }}, Name, Count
  }
  $all
}

function Get-RecentEventData([string]$LogName, [int[]]$Ids, [DateTime]$Since, [int]$Limit = 100) {
  $filter = @{ LogName = $LogName }
  if ($Ids -and $Ids.Count -gt 0) { $filter['Id'] = $Ids }
  Get-WinEvent -FilterHashtable $filter -MaxEvents $Limit -ErrorAction Stop |
    Where-Object { $_.TimeCreated.ToUniversalTime() -ge $Since } |
    ForEach-Object {
      $xml = [xml]$_.ToXml()
      $data = @{}
      foreach ($d in $xml.Event.EventData.Data) {
        $name = [string]$d.Name
        if ($name) { $data[$name] = [string]$d.'#text' }
      }
      [PSCustomObject]@{
        EventTime = $_.TimeCreated.ToUniversalTime().ToString('o')
        Channel = $_.LogName
        Provider = $_.ProviderName
        EventID = $_.Id
        RecordID = $_.RecordId
        Message = ''
        MessageFlat = ''
        NewProcessName = $data['NewProcessName']
        CommandLine = if ($data.ContainsKey('CommandLine')) { $data['CommandLine'] } else { $data['ProcessCommandLine'] }
        ParentProcessName = if ($data.ContainsKey('ParentProcessName')) { $data['ParentProcessName'] } else { $data['CreatorProcessName'] }
        CreatorProcessName = $data['CreatorProcessName']
        SubjectUserName = $data['SubjectUserName']
        EventDataJson = ($data | ConvertTo-Json -Compress -Depth 6)
      }
    }
}

function Get-ProcessLite([int]$Limit = 120) {
  Get-CimInstance Win32_Process -ErrorAction Stop |
    Select-Object -First $Limit `
      ProcessId,
      Name,
      ExecutablePath,
      CommandLine,
      ParentProcessId
}

function Get-SampleRelated4688([DateTime]$Since, [int]$Limit = 200) {
  $samplePathLower = $samplePath.ToLowerInvariant()
  $sampleNameLower = $sampleName.ToLowerInvariant()
  $shaLower = $sha256.ToLowerInvariant()
  $events = Get-RecentEventData -LogName 'Security' -Ids @(4688) -Since $Since -Limit 80
  $events |
    Where-Object {
      $joined = @(
        $_.NewProcessName,
        $_.CommandLine,
        $_.ParentProcessName,
        $_.CreatorProcessName,
        $_.Message,
        $_.EventDataJson
      ) -join ' '
      $text = $joined.ToLowerInvariant()
      $text.Contains($samplePathLower) -or
      $text.Contains($sampleNameLower) -or
      $text.Contains($shaLower) -or
      $text -match '(?i)\\(vssadmin|wbadmin|bcdedit|reagentc|rundll32|regsvr32|mshta|wscript|cscript|powershell|cmd)\.exe\b'
    } |
    Select-Object -First $Limit
}

$payload = [ordered]@{
  execution_started_at_utc = $executionStarted.ToString('o')
  triage_started_at_utc = $triageStarted.ToString('o')
  triage_completed_at_utc = $null
  sample_id = $sampleId
  sha256 = $sha256
  vm = $vmName
  client_id = $clientId
  sample_path = $samplePath
  section_counts = [ordered]@{}
  processes = Protect-Section {
    Get-ProcessLite -Limit 120
  }
  sample_process_matches = Protect-Section {
    Get-ProcessLite -Limit 120 |
      Where-Object {
        -not ($_.CommandLine -and $_.CommandLine -like ('*' + $triageScriptName + '*')) -and (
        ($_.ExecutablePath -and $_.ExecutablePath -ieq $samplePath) -or
        ($_.ExecutablePath -and $_.ExecutablePath -like ('*' + $sampleName)) -or
        ($_.CommandLine -and ($_.CommandLine -like ('*' + $sampleName + '*') -or $_.CommandLine -like ('*' + $sha256 + '*'))) -or
        ($_.Name -and $_.Name -ieq $sampleName)
        )
      } |
      Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId
  }
  bait_recent_files = Protect-Section { Get-RecentFilesForPaths -Paths $baitRoots -Since $executionStarted -Limit 30 -Depth 1 }
  ransom_note_like_files = Protect-Section {
    Get-RecentFilesForPaths -Paths $baitRoots -Since $executionStarted -Limit 20 -Depth 1 |
      Where-Object { $_.Name -match $ransomNameRegex -or $_.Name -match $ransomExtRegex }
  }
  file_extension_summary = Protect-Section { Get-ExtensionSummary -Paths @($sampleDir) -Depth 1 }
  broad_recent_files = Protect-Section { @() }
  security_4688 = Protect-Section { Get-RecentEventData -LogName 'Security' -Ids @(4688) -Since $executionStarted -Limit 40 }
  security_4688_sample_related = Protect-Section { Get-SampleRelated4688 -Since $executionStarted -Limit 40 }
  powershell_operational = Protect-Section { Get-RecentEventData -LogName 'Microsoft-Windows-PowerShell/Operational' -Ids @(4103,4104,600) -Since $executionStarted -Limit 20 }
  scheduled_tasks_recent = Protect-Section {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
      Select-Object -First 100 TaskName, TaskPath, State,
        @{n='Actions';e={ ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; ' }}
  }
  services_recent = Protect-Section {
    Get-CimInstance Win32_Service -ErrorAction Stop |
      Where-Object {
        $p = [string]$_.PathName
        $n = [string]$_.Name
        $p -match '(?i)(\\users\\|\\programdata\\|\\appdata\\|\\temp\\|\\vr-malware-test\\|powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)' -or
        $n -match '(?i)(svc|update|security|mssec|crypt|lock|restore|recover)'
      } |
      Select-Object -First 100 Name, DisplayName, State, StartMode, PathName, ProcessId
  }
  network_connections = Protect-Section {
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
      Select-Object -First 100 LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
        @{n='ProcessName';e={ try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { $null } }}
  }
}

foreach ($name in @('processes','sample_process_matches','bait_recent_files','ransom_note_like_files','file_extension_summary','broad_recent_files','security_4688','security_4688_sample_related','powershell_operational','scheduled_tasks_recent','services_recent','network_connections')) {
  $payload.section_counts[$name] = [int]$payload[$name].count
}
$payload.triage_completed_at_utc = (Get-Date).ToUniversalTime().ToString('o')
$payload | ConvertTo-Json -Depth 8
""".strip()
    return (
        script
        .replace("__EXECUTION_STARTED__", json.dumps(execution_started_at_utc))
        .replace("__SAMPLE_ID__", str(int(sample_id)))
        .replace("__SHA256__", json.dumps(sha256))
        .replace("__VM_NAME__", json.dumps(vm))
        .replace("__CLIENT_ID__", json.dumps(client_id))
        .replace("__SAMPLE_PATH__", json.dumps(sample_path))
        .replace("}}", "}\n}")
        .replace("} }", "}\n}")
    )


def _collect_post_execution_triage(
    *,
    vm: Any,
    result_dir: Path,
    execution_started_at_utc: str,
    sample_id: int,
    sha256: str,
    client_id: str,
    sample_path: str,
    winrm_timeout: int,
    staging_bind_host: str,
    http_port_min: int,
    http_port_max: int,
    guest_dir: str | None = None,
) -> dict[str, Any]:
    triage_path = result_dir / "post_execution_triage.json"
    if os.environ.get("THREATTRACE_VR_POST_TRIAGE_REMOTE") == "0":
        payload = {
            "execution_started_at_utc": execution_started_at_utc,
            "triage_started_at_utc": _now(),
            "triage_completed_at_utc": _now(),
            "sample_id": sample_id,
            "sha256": sha256,
            "vm": vm.name,
            "client_id": client_id,
            "sample_path": sample_path,
            "section_counts": {},
            "triage_error": "remote_triage_skipped",
            "note": "Execution liveness/process/memory evidence is stored in winrm_execution_log.json; endpoint artifacts supply log/filesystem evidence.",
        }
        write_json(triage_path, payload)
        return payload
    script = _post_execution_triage_script(
        execution_started_at_utc=execution_started_at_utc,
        sample_id=sample_id,
        sha256=sha256,
        vm=vm.name,
        client_id=client_id,
        sample_path=sample_path,
    )
    staging_dir = result_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    staged_script = staging_dir / "post_execution_triage.ps1"
    staged_script.write_text(script + "\n", encoding="utf-8")
    port = choose_free_port(staging_bind_host, http_port_min, http_port_max)
    guest_dir = guest_dir or f"C:\\vr-malware-test\\{sha256}"
    guest_script = f"{guest_dir}\\post_execution_triage.ps1"
    script_url = f"http://{staging_bind_host}:{port}/{staged_script.name}"
    launch_script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$ProgressPreference = 'SilentlyContinue'",
            f"$dir = {ps_single_quote(guest_dir)}",
            f"$scriptPath = {ps_single_quote(guest_script)}",
            f"$scriptUrl = {ps_single_quote(script_url)}",
            "New-Item -ItemType Directory -Force $dir | Out-Null",
            "Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath",
            "& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath",
        ]
    )
    triage_timeout = min(max(int(winrm_timeout), 60), 300)
    with StagingHTTPServer(staging_bind_host, port, staging_dir):
        result = run_powershell(vm, launch_script, execute=True, timeout_sec=triage_timeout)
    payload = parse_json_object(result.stdout)
    if payload is None:
        payload = {
            "execution_started_at_utc": execution_started_at_utc,
            "triage_started_at_utc": _now(),
            "triage_completed_at_utc": _now(),
            "sample_id": sample_id,
            "sha256": sha256,
            "vm": vm.name,
            "client_id": client_id,
            "sample_path": sample_path,
            "section_counts": {},
            "triage_error": "invalid_json_stdout",
            "winrm_result": result.as_dict(),
        }
    else:
        payload["winrm_result"] = result.as_dict()
    write_json(triage_path, payload)
    return payload


def _staged_powershell_launcher(*, guest_dir: str, script_path: str, script_url: str) -> str:
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$ProgressPreference = 'SilentlyContinue'",
            f"$dir = {ps_single_quote(guest_dir)}",
            f"$scriptPath = {ps_single_quote(script_path)}",
            f"$scriptUrl = {ps_single_quote(script_url)}",
            "New-Item -ItemType Directory -Force $dir | Out-Null",
            "Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath",
            "& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath",
        ]
    )


_ARTIFACT_MAX_ROWS = 1000


def _artifact_row_limit(artifact: str) -> int:
    del artifact
    return _ARTIFACT_MAX_ROWS + 1


def _bounded_artifact_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    """Keep max_rows and use one sentinel row to detect truncation."""
    return rows[:_ARTIFACT_MAX_ROWS], len(rows) > _ARTIFACT_MAX_ROWS


ACTIVE_ARTIFACT_REPO = Path("/opt/velociraptor/artifact_definitions")
GENERATED_NATIVE_ARTIFACT_DIR = Path("outputs/evaluation/velociraptor_native_artifacts_full_final")
FORBID_RECENT_SUSPICIOUS_PATH = frozenset(
    {
        "Windows.ThreatTrace.Ransomware.RansomNotes",
        "Windows.ThreatTrace.Ransomware.HighConfidenceBundle",
        "Windows.ThreatTrace.Ransomware.SuspiciousDroppedFiles",
        "Windows.ThreatTrace.Ransomware.ExactIoCMatches",
        "Windows.ThreatTrace.Ransomware.RansomwareBinaries",
        "Windows.ThreatTrace.Ransomware.EncryptedExtensions",
    }
)
REQUIRED_ARTIFACT_SNIPPETS = {
    "Windows.ThreatTrace.Ransomware.BehavioralComposite": (
        "NoteGlobs",
        "FROM pslist()",
        "vr-malware-test",
        "ransom_note_spread_correlated",
        "writable_live_process_context",
    ),
}
DISABLED_DEFAULT_ARTIFACTS = frozenset({"Windows.ThreatTrace.Ransomware.BehavioralComposite"})
EARLY_COLLECTION_ARTIFACTS = frozenset()


def _artifact_repo_path(artifact: str, repo_root: Path = ACTIVE_ARTIFACT_REPO) -> Path:
    flat = repo_root / "Windows" / "ThreatTrace" / "Ransomware" / f"{artifact}.yaml"
    try:
        if flat.is_file():
            return flat
    except OSError:
        pass
    parts = artifact.split(".")
    if len(parts) < 2:
        raise ValueError(f"Invalid artifact name: {artifact}")
    return repo_root.joinpath(*parts[:-1], f"{parts[-1]}.yaml")


def _generated_artifact_path(artifact: str, source_dir: Path = GENERATED_NATIVE_ARTIFACT_DIR) -> Path:
    return source_dir / f"{artifact}.yaml"


def _artifact_source_path(
    artifact: str,
    *,
    source_dir: Path = GENERATED_NATIVE_ARTIFACT_DIR,
    repo_root: Path = ACTIVE_ARTIFACT_REPO,
) -> Path:
    generated = _generated_artifact_path(artifact, source_dir=source_dir)
    if source_dir != GENERATED_NATIVE_ARTIFACT_DIR and generated.is_file():
        return generated
    active = _artifact_repo_path(artifact, repo_root=repo_root)
    try:
        active_exists = active.is_file()
    except OSError:
        active_exists = False
    if active_exists:
        return active
    if generated.is_file():
        return generated
    return active


def _artifact_set_vql(definition: str) -> str:
    return f"SELECT artifact_set(definition={json.dumps(definition)}) AS ok FROM scope()"


def _generated_threattrace_artifacts(
    source_dir: Path = GENERATED_NATIVE_ARTIFACT_DIR,
    repo_root: Path = ACTIVE_ARTIFACT_REPO,
) -> list[str]:
    active_names = sorted(
        {
            path.stem
            for path in _artifact_repo_path("Windows.ThreatTrace.Ransomware.Placeholder", repo_root=repo_root).parent.glob(
                "Windows.ThreatTrace.Ransomware*.yaml"
            )
        }
    )
    if active_names:
        return [name for name in active_names if name not in DISABLED_DEFAULT_ARTIFACTS]
    if not source_dir.is_dir():
        return [name for name in THREATTRACE_ARTIFACTS if name not in DISABLED_DEFAULT_ARTIFACTS]
    names = sorted(path.stem for path in source_dir.glob("Windows.ThreatTrace.Ransomware*.yaml"))
    selected = names or list(THREATTRACE_ARTIFACTS)
    return [name for name in selected if name not in DISABLED_DEFAULT_ARTIFACTS]


def _check_artifact_text_semantics(artifact: str, text: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    if artifact in FORBID_RECENT_SUSPICIOUS_PATH and "recent_suspicious_path" in text:
        hits.append({"artifact": artifact, "forbidden": "recent_suspicious_path"})
    for snippet in REQUIRED_ARTIFACT_SNIPPETS.get(artifact, ()):
        if snippet not in text:
            hits.append({"artifact": artifact, "missing": snippet})
    return hits


def _sync_artifacts_to_api_repo(
    artifacts: list[str],
    *,
    command_base: list[str],
    source_dir: Path = GENERATED_NATIVE_ARTIFACT_DIR,
    repo_root: Path = ACTIVE_ARTIFACT_REPO,
    execute: bool = True,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    missing_paths: list[str] = []
    stale_hits: list[dict[str, str]] = []
    failed: list[dict[str, Any]] = []

    for artifact in artifacts:
        path = _artifact_source_path(artifact, source_dir=source_dir, repo_root=repo_root)
        if not path.is_file():
            missing_paths.append(str(path))
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for hit in _check_artifact_text_semantics(artifact, text):
            stale_hits.append({**hit, "path": str(path)})
        if execute:
            result = run_command(list(command_base) + ["query", "--format", "json", _artifact_set_vql(text)], execute=True)
            record = {
                "artifact": artifact,
                "path": str(path),
                "command": result.command,
                "returncode": result.returncode,
                "stderr": result.stderr[:1000],
            }
            records.append(record)
            if result.returncode not in (None, 0):
                failed.append(record)
        else:
            records.append({"artifact": artifact, "path": str(path), "execute": False})

    payload = {
        "source_dir": str(source_dir),
        "repo_root": str(repo_root),
        "registered": records,
        "missing_paths": missing_paths,
        "stale_hits": stale_hits,
        "failed": failed,
        "ok": not missing_paths and not stale_hits and not failed,
    }
    if stale_hits:
        raise RuntimeError(f"Generated artifact source has stale semantics: {json.dumps(stale_hits)}")
    if missing_paths:
        raise RuntimeError(f"Generated/active artifact YAML missing: {json.dumps(missing_paths)}")
    if failed:
        raise RuntimeError(f"artifact_set failed: {json.dumps(failed)}")
    return payload


def _artifact_definitions_vql(artifacts: list[str]) -> str:
    filters = " OR ".join(f"name = {json.dumps(item)}" for item in artifacts)
    return f"SELECT name, sources FROM artifact_definitions() WHERE {filters}"


def _active_artifact_preflight(
    artifacts: list[str],
    repo_root: Path = ACTIVE_ARTIFACT_REPO,
    *,
    command_base: list[str] | None = None,
    execute: bool = True,
) -> dict[str, Any]:
    stale_hits: list[dict[str, str]] = []
    missing_paths: list[str] = []
    checked: list[str] = []

    if command_base is not None:
        command = list(command_base) + ["query", "--format", "json", _artifact_definitions_vql(artifacts)]
        if not execute:
            return {
                "repo_root": "artifact_definitions()",
                "checked_paths": list(artifacts),
                "missing_paths": [],
                "stale_hits": [],
                "ok": True,
                "command": command,
                "returncode": None,
                "stderr": "",
                "execute": False,
            }
        result = run_command(command, execute=execute)
        rows = _rows_from_stdout(result.stdout)
        names = {str(row.get("name") or ""): row for row in rows if isinstance(row, dict)}
        for artifact in artifacts:
            checked.append(artifact)
            row = names.get(artifact)
            if row is None:
                missing_paths.append(artifact)
                continue
            text = json.dumps(row.get("sources") or [], sort_keys=True)
            for hit in _check_artifact_text_semantics(artifact, text):
                stale_hits.append({**hit, "path": artifact})

        payload = {
            "repo_root": "artifact_definitions()",
            "checked_paths": checked,
            "missing_paths": missing_paths,
            "stale_hits": stale_hits,
            "ok": result.returncode in (None, 0) and not missing_paths and not stale_hits,
            "command": result.command,
            "returncode": result.returncode,
            "stderr": result.stderr[:4000],
        }
        if result.returncode not in (None, 0):
            raise RuntimeError(f"Active artifact preflight query failed: {result.stderr[:400]}")
        if not payload["ok"]:
            if stale_hits:
                raise RuntimeError(f"Active artifact repo has stale semantics: {json.dumps(stale_hits)}")
            raise RuntimeError(f"Active artifact repo missing artifacts: {json.dumps(missing_paths)}")
        return payload

    for artifact in artifacts:
        path = _artifact_repo_path(artifact, repo_root=repo_root)
        checked.append(str(path))
        if not path.is_file():
            missing_paths.append(str(path))
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for hit in _check_artifact_text_semantics(artifact, text):
            stale_hits.append({**hit, "path": str(path)})

    payload = {
        "repo_root": str(repo_root),
        "checked_paths": checked,
        "missing_paths": missing_paths,
        "stale_hits": stale_hits,
        "ok": not missing_paths and not stale_hits,
    }
    if not payload["ok"]:
        if stale_hits:
            raise RuntimeError(f"Active artifact repo has stale semantics: {json.dumps(stale_hits)}")
        raise RuntimeError(f"Active artifact repo missing artifacts: {json.dumps(missing_paths)}")
    return payload


def _live_threattrace_artifacts(*, command_base: list[str], execute: bool) -> list[str]:
    if not execute:
        return list(THREATTRACE_ARTIFACTS)
    query = (
        "SELECT name FROM artifact_definitions() "
        "WHERE name =~ '^Windows\\.ThreatTrace\\.Ransomware\\.' "
        "ORDER BY name"
    )
    result = run_command(list(command_base) + ["query", "--format", "json", query], execute=True)
    if result.returncode not in (None, 0):
        raise RuntimeError(f"Live artifact discovery failed: {result.stderr[:400]}")
    rows = _rows_from_stdout(result.stdout)
    names = sorted(
        {
            str(row.get("name") or "").strip()
            for row in rows
            if isinstance(row, dict) and str(row.get("name") or "").startswith("Windows.ThreatTrace.Ransomware.")
        }
    )
    if not names:
        raise RuntimeError("Live artifact discovery returned 0 Windows.ThreatTrace.Ransomware artifacts")
    return names


# Parse rows from Velociraptor stdout, handling both array and line-delimited JSON
def _rows_from_stdout(stdout: str | None) -> list[Any]:
    text = (stdout or "").strip()
    if not text:
        return []
    decoder = json.JSONDecoder()
    rows: list[Any] = []
    idx = 0
    length = len(text)
    while idx < length:
        while idx < length and text[idx].isspace():
            idx += 1
        if idx >= length:
            break
        try:
            parsed, next_idx = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            rows = []
            break
        if isinstance(parsed, list):
            rows.extend(parsed)
        elif isinstance(parsed, dict):
            if isinstance(parsed.get("rows"), list):
                rows.extend(parsed["rows"])
            else:
                rows.append(parsed)
        idx = next_idx
    if rows:
        return rows
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        if isinstance(parsed.get("rows"), list):
            return parsed["rows"]
        return [parsed]
    return []



def _export_artifact(client_id: str, flow_id: str, artifact: str, raw_dir: Path, execute: bool, api_base: list[str]) -> dict[str, Any]:
    command = api_base + ["query", "--format", "json", export_vql(client_id, flow_id, artifact, row_limit=_artifact_row_limit(artifact))]
    result = run_command(command, execute=execute)
    output_path = raw_dir / f"{artifact}.json"
    stdout = result.stdout or ""
    raw_rows = _rows_from_stdout(stdout)
    rows, truncated = _bounded_artifact_rows(raw_rows)
    row_count = len(rows)
    stdout_empty = not stdout.strip()
    output_written = False
    stderr = (result.stderr or "").lower()
    partial_failure = "grpc: received message larger than max" in stderr
    export_failure_reason = None

    if result.returncode not in (None, 0):
        export_failure_reason = f"export_command_failed:{result.returncode}"
    elif partial_failure:
        export_failure_reason = "grpc_message_too_large"
    elif stdout_empty:
        export_failure_reason = "export_stdout_empty"
    elif truncated:
        export_failure_reason = "truncated_requires_smaller_bundle"

    if execute:
        raw_dir.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(rows, ensure_ascii=False) + "\n" if truncated else stdout
        output_path.write_text(serialized if not stdout_empty else "[]\n", encoding="utf-8")
        output_written = True

    return {
        **result.as_dict(),
        "artifact": artifact,
        "output_path": str(output_path),
        "output_written": output_written,
        "stdout_empty": stdout_empty,
        "no_rows": row_count == 0,
        "row_count": row_count,
        "rows_received": len(raw_rows),
        "truncated": truncated,
        "retry_required": truncated,
        "retry_bundle_size": 50 if truncated else None,
        "export_failure_reason": export_failure_reason,
        "partial_failure": partial_failure,
        "partial_failure_reason": "grpc_message_too_large" if partial_failure else None,
        "row_limit": _artifact_row_limit(artifact),
    }



def _collect_artifact_direct(client_id: str, artifact: str, raw_dir: Path, execute: bool, api_base: list[str], timeout_seconds: int) -> dict[str, Any]:
    command = api_base + [
        "artifacts",
        "collect",
        "--client_id",
        client_id,
        "--timeout",
        str(timeout_seconds),
        "--format",
        "json",
        artifact,
    ]
    result = run_command(command, execute=execute)
    output_path = raw_dir / f"{artifact}.json"
    stdout = result.stdout or ""
    raw_rows = _rows_from_stdout(stdout)
    rows, truncated = _bounded_artifact_rows(raw_rows)
    row_count = len(rows)
    stdout_empty = not stdout.strip()
    output_written = False
    stderr = (result.stderr or "").lower()
    partial_failure = "grpc: received message larger than max" in stderr
    export_failure_reason = None

    if result.returncode not in (None, 0):
        export_failure_reason = f"collection_command_failed:{result.returncode}"
    elif partial_failure:
        export_failure_reason = "grpc_message_too_large"
    elif stdout_empty:
        export_failure_reason = "export_stdout_empty"
    elif truncated:
        export_failure_reason = "truncated_requires_smaller_bundle"

    if execute:
        raw_dir.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(rows, ensure_ascii=False) + "\n" if truncated else stdout
        output_path.write_text(serialized if not stdout_empty else "[]\n", encoding="utf-8")
        output_written = True

    return {
        **result.as_dict(),
        "artifact": artifact,
        "output_path": str(output_path),
        "output_written": output_written,
        "stdout_empty": stdout_empty,
        "no_rows": row_count == 0,
        "row_count": row_count,
        "rows_received": len(raw_rows),
        "truncated": truncated,
        "retry_required": truncated,
        "retry_bundle_size": 50 if truncated else None,
        "export_failure_reason": export_failure_reason,
        "partial_failure": partial_failure,
        "partial_failure_reason": "grpc_message_too_large" if partial_failure else None,
        "row_limit": _ARTIFACT_MAX_ROWS + 1,
    }


def _flow_unknown_to_client(flow_completion: dict[str, Any] | None) -> bool:
    if not isinstance(flow_completion, dict):
        return False
    payload = json.dumps(flow_completion, sort_keys=True)
    return "Flow not known" in payload or "UNKNOWN_FLOW" in payload


def _collect_artifacts_individually(
    client_id: str,
    artifacts: list[str],
    raw_dir: Path,
    execute: bool,
    api_base: list[str],
    flow_wait_timeout: int | None,
    flow_poll_seconds: int,
    launch_backend: str | None = None,
) -> dict[str, Any]:
    effective_backend = launch_backend or collection_backend()
    if effective_backend == "cli_query":
        return _collect_artifacts_directly(
            client_id=client_id,
            artifacts=artifacts,
            raw_dir=raw_dir,
            execute=execute,
            api_base=api_base,
            flow_wait_timeout=flow_wait_timeout,
        )
    artifact_flows: dict[str, Any] = {}
    exports: dict[str, Any] = {}
    primary_flow_id: str | None = None
    failed_reasons: list[str] = []
    exported_artifact_count = 0
    export_warning_count = 0

    for artifact in artifacts:
        run_base_command = None if effective_backend == "api" else api_base
        launch = run_collection(
            client_id,
            execute=execute,
            artifacts=[artifact],
            backend=effective_backend,
            collection_timeout_seconds=effective_flow_wait_timeout(flow_wait_timeout),
            base_command=run_base_command,
            new_flow_timeout_seconds=0 if effective_backend == "server_cli_query" else 10,
        )
        collection = launch.command_result
        collection_command = collection.command
        artifact_flow_id = launch.accepted_flow_id or ("DRY_RUN_FLOW_ID" if not execute else None)

        if primary_flow_id is None and artifact_flow_id:
            primary_flow_id = artifact_flow_id

        failure = collection_failure_reason(collection, artifact_flow_id, execute)
        if execute and launch.failure_reason:
            failure = launch.failure_reason
        flow_completion: dict[str, Any] | None = None
        export_result: dict[str, Any] | None = None
        completed = False
        exported = False
        completion_state = "not_started"
        retry_attempts: list[dict[str, Any]] = []

        if execute and effective_backend == "server_cli_query":
            if collection.returncode not in (None, 0):
                failure = f"collection_command_failed:{collection.returncode}"
            else:
                failure = None
                raw_dir.mkdir(parents=True, exist_ok=True)
                direct_stdout = collection.stdout.strip() or "[]"
                (raw_dir / f"{artifact}.json").write_text(direct_stdout + ("\n" if not direct_stdout.endswith("\n") else ""), encoding="utf-8")
                export_result = {
                    "backend": "server_cli_query",
                    "mode": "direct_server_collect",
                    "returncode": collection.returncode,
                    "row_bytes": len(direct_stdout),
                    "export_failure_reason": None,
                }
                exports[artifact] = export_result
                completed = True
                exported = True
                exported_artifact_count += 1
                completion_state = "completed"

        if execute and effective_backend != "server_cli_query" and artifact_flow_id and not failure:
            flow_completion = wait_for_flow_completion(
                client_id,
                artifact_flow_id,
                execute=True,
                timeout_seconds=effective_flow_wait_timeout(flow_wait_timeout),
                poll_seconds=flow_poll_seconds,
                base_command=api_base,
            )
            completion_state = str(flow_completion.get("state") or "unknown")

            if flow_completion.get("timed_out"):
                failure = "flow_completion_timeout"
            elif flow_completion.get("failed"):
                failure = "flow_completion_failed"
            elif flow_completion.get("state") == "missing":
                failure = "flow_status_missing"
            elif not flow_completion.get("completed"):
                failure = "flow_completion_incomplete"
            else:
                completed = True
                export_result = _export_artifact(client_id, artifact_flow_id, artifact, raw_dir, execute=True, api_base=api_base)
                exports[artifact] = export_result
                if export_result.get("returncode") not in (None, 0):
                    failure = "export_failed"
                elif export_result.get("export_failure_reason"):
                    failure = str(export_result["export_failure_reason"])
                else:
                    exported = True
                    exported_artifact_count += 1
                    if export_result.get("partial_failure", False):
                        export_warning_count += 1
                completion_state = "completed"

        elif not execute:
            flow_completion = wait_for_flow_completion(
                client_id,
                artifact_flow_id or "DRY_RUN_FLOW_ID",
                execute=False,
                timeout_seconds=effective_flow_wait_timeout(flow_wait_timeout),
                poll_seconds=flow_poll_seconds,
            )
            completed = True
            exported = True
            exported_artifact_count += 1
            completion_state = "dry_run"

        if execute and failure == "flow_completion_failed" and _flow_unknown_to_client(flow_completion):
            retry_attempts.append(
                {
                    "reason": "client_reported_unknown_flow",
                    "previous_flow_id": artifact_flow_id,
                    "previous_flow_completion": flow_completion,
                }
            )
            time.sleep(max(flow_poll_seconds, 1))
            retry_launch = run_collection(
                client_id,
                execute=True,
                artifacts=[artifact],
                backend=effective_backend,
                collection_timeout_seconds=effective_flow_wait_timeout(flow_wait_timeout),
                base_command=run_base_command,
            )
            retry_flow_id = retry_launch.accepted_flow_id
            retry_failure = collection_failure_reason(retry_launch.command_result, retry_flow_id, True)
            if retry_launch.failure_reason:
                retry_failure = retry_launch.failure_reason
            retry_completion: dict[str, Any] | None = None
            retry_export: dict[str, Any] | None = None
            retry_completed = False
            retry_exported = False
            retry_completion_state = "not_started"
            if retry_flow_id and not retry_failure:
                retry_completion = wait_for_flow_completion(
                    client_id,
                    retry_flow_id,
                    execute=True,
                    timeout_seconds=effective_flow_wait_timeout(flow_wait_timeout),
                    poll_seconds=flow_poll_seconds,
                    base_command=api_base,
                )
                retry_completion_state = str(retry_completion.get("state") or "unknown")
                if retry_completion.get("timed_out"):
                    retry_failure = "flow_completion_timeout"
                elif retry_completion.get("failed"):
                    retry_failure = "flow_completion_failed"
                elif retry_completion.get("state") == "missing":
                    retry_failure = "flow_status_missing"
                elif not retry_completion.get("completed"):
                    retry_failure = "flow_completion_incomplete"
                else:
                    retry_completed = True
                    retry_export = _export_artifact(client_id, retry_flow_id, artifact, raw_dir, execute=True, api_base=api_base)
                    exports[artifact] = retry_export
                    if retry_export.get("returncode") not in (None, 0):
                        retry_failure = "export_failed"
                    elif retry_export.get("export_failure_reason"):
                        retry_failure = str(retry_export["export_failure_reason"])
                    else:
                        retry_exported = True
                        exported_artifact_count += 1
                        if retry_export.get("partial_failure", False):
                            export_warning_count += 1
                    retry_completion_state = "completed"
            retry_attempts.append(
                {
                    "flow_id": retry_flow_id,
                    "flow_tracking": retry_launch.as_record(),
                    "collection": retry_launch.command_result.as_dict(),
                    "flow_completion": retry_completion,
                    "completion_state": retry_completion_state,
                    "failure": retry_failure,
                    "export": retry_export,
                }
            )
            if retry_exported:
                if primary_flow_id == artifact_flow_id:
                    primary_flow_id = retry_flow_id
                artifact_flow_id = retry_flow_id
                launch = retry_launch
                collection = retry_launch.command_result
                collection_command = collection.command
                flow_completion = retry_completion
                export_result = retry_export
                failure = None
                completed = retry_completed
                exported = True
                completion_state = retry_completion_state

        if failure:
            failed_reasons.append(f"{artifact}:{failure}")

        artifact_flows[artifact] = {
            "artifact": artifact,
            "flow_id": artifact_flow_id,
            "flow_is_new": launch.is_new_flow,
            "launch_backend": launch.backend,
            "flow_tracking": launch.as_record(),
            "collection_command": collection_command,
            "collection": collection.as_dict(),
            "flow_completion": flow_completion,
            "completion_state": completion_state,
            "completed": completed,
            "failed": failure is not None,
            "failure_reason": f"{artifact}:{failure}" if failure else None,
            "collection_failed": failure is not None,
            "collection_failure_reason": failure,
            "exported": exported,
            "export_status": "exported" if exported else ("failed" if export_result else "not_started"),
            "export": export_result,
            "retry_attempts": retry_attempts,
        }

    failed_artifact_count = len(failed_reasons)
    partial_export = exported_artifact_count > 0 and failed_artifact_count > 0
    total_failure = exported_artifact_count == 0 and failed_artifact_count > 0
    collection_failure_reason_value = ";".join(failed_reasons) if total_failure else None

    return {
        "flow_id": primary_flow_id,
        "collection": {
            "mode": "per_artifact",
            "backend": next((details["launch_backend"] for details in artifact_flows.values()), "api"),
            "artifacts_requested": artifacts,
            "artifact_count": len(artifacts),
            "exported_artifact_count": exported_artifact_count,
            "failed_artifact_count": failed_artifact_count,
            "export_warning_count": export_warning_count,
        },
        "artifact_flows": artifact_flows,
        "artifact_results": artifact_flows,
        "flow_completion": {
            "mode": "per_artifact",
            "completed": exported_artifact_count > 0,
            "failed": total_failure,
            "partial_export": partial_export,
            "artifact_count": len(artifact_flows),
            "exported_artifact_count": exported_artifact_count,
            "failed_artifact_count": failed_artifact_count,
            "failed_reasons": failed_reasons,
        },
        "collection_failed": total_failure,
        "collection_failure_reason": collection_failure_reason_value,
        "exports": exports,
        "partial_export": partial_export,
    }


def _combine_collection_results(*results: dict[str, Any] | None) -> dict[str, Any]:
    active = [item for item in results if item]
    if not active:
        return {
            "flow_id": None,
            "collection": {"mode": "per_artifact", "artifacts_requested": [], "artifact_count": 0, "exported_artifact_count": 0, "failed_artifact_count": 0, "export_warning_count": 0},
            "artifact_flows": {},
            "artifact_results": {},
            "flow_completion": {"mode": "per_artifact", "completed": False, "failed": False, "partial_export": False, "artifact_count": 0, "exported_artifact_count": 0, "failed_artifact_count": 0, "failed_reasons": []},
            "collection_failed": False,
            "collection_failure_reason": None,
            "exports": {},
            "partial_export": False,
        }
    if len(active) == 1:
        return active[0]

    artifact_flows: dict[str, Any] = {}
    exports: dict[str, Any] = {}
    artifacts_requested: list[str] = []
    failed_reasons: list[str] = []
    exported_artifact_count = 0
    failed_artifact_count = 0
    export_warning_count = 0
    flow_id = None
    backend = None

    for result in active:
        flow_id = flow_id or result.get("flow_id")
        collection = result.get("collection") if isinstance(result.get("collection"), dict) else {}
        backend = backend or collection.get("backend")
        artifacts_requested.extend(str(item) for item in collection.get("artifacts_requested", []) or [])
        exported_artifact_count += int(collection.get("exported_artifact_count") or 0)
        failed_artifact_count += int(collection.get("failed_artifact_count") or 0)
        export_warning_count += int(collection.get("export_warning_count") or 0)
        artifact_flows.update(result.get("artifact_flows") or {})
        exports.update(result.get("exports") or {})
        completion = result.get("flow_completion") if isinstance(result.get("flow_completion"), dict) else {}
        failed_reasons.extend(str(item) for item in completion.get("failed_reasons", []) or [])

    total_failure = exported_artifact_count == 0 and failed_artifact_count > 0
    partial_export = exported_artifact_count > 0 and failed_artifact_count > 0
    return {
        "flow_id": flow_id,
        "collection": {
            "mode": "per_artifact",
            "backend": backend or "api",
            "artifacts_requested": artifacts_requested,
            "artifact_count": len(artifact_flows),
            "exported_artifact_count": exported_artifact_count,
            "failed_artifact_count": failed_artifact_count,
            "export_warning_count": export_warning_count,
        },
        "artifact_flows": artifact_flows,
        "artifact_results": artifact_flows,
        "flow_completion": {
            "mode": "per_artifact",
            "completed": exported_artifact_count > 0,
            "failed": total_failure,
            "partial_export": partial_export,
            "artifact_count": len(artifact_flows),
            "exported_artifact_count": exported_artifact_count,
            "failed_artifact_count": failed_artifact_count,
            "failed_reasons": failed_reasons,
        },
        "collection_failed": total_failure,
        "collection_failure_reason": ";".join(failed_reasons) if total_failure else None,
        "exports": exports,
        "partial_export": partial_export,
    }


def _collect_artifacts_directly(
    client_id: str,
    artifacts: list[str],
    raw_dir: Path,
    execute: bool,
    api_base: list[str],
    flow_wait_timeout: int | None,
) -> dict[str, Any]:
    artifact_flows: dict[str, Any] = {}
    exports: dict[str, Any] = {}
    failed_reasons: list[str] = []
    exported_artifact_count = 0
    export_warning_count = 0
    timeout_seconds = effective_flow_wait_timeout(flow_wait_timeout)

    for artifact in artifacts:
        export_result = _collect_artifact_direct(client_id, artifact, raw_dir, execute, api_base, timeout_seconds)
        failure = None
        if execute:
            if export_result.get("returncode") not in (None, 0):
                failure = f"collection_command_failed:{export_result.get('returncode')}"
            elif export_result.get("export_failure_reason"):
                failure = str(export_result["export_failure_reason"])
        completed = failure is None
        exported = completed and bool(export_result.get("output_written")) and int(export_result.get("row_count") or 0) > 0
        if exported:
            exported_artifact_count += 1
            if export_result.get("partial_failure", False):
                export_warning_count += 1
        if failure:
            failed_reasons.append(f"{artifact}:{failure}")
        artifact_flows[artifact] = {
            "artifact": artifact,
            "flow_id": None,
            "flow_is_new": False,
            "launch_backend": "cli_query",
            "flow_tracking": {
                "accepted_flow_id": None,
                "backend": "cli_query",
                "collect_response_flow_id": None,
                "failure_reason": failure,
                "is_new_flow": False,
                "new_flow_ids": [],
                "requested_artifacts": [artifact],
                "tracking_source": "direct_artifacts_collect",
            },
            "collection_command": export_result["command"],
            "collection": {
                "command": export_result["command"],
                "returncode": export_result.get("returncode"),
                "stdout": export_result.get("stdout", "")[:8000],
                "stderr": export_result.get("stderr", "")[:8000],
            },
            "flow_completion": None,
            "completion_state": "completed" if completed else "failed",
            "completed": completed,
            "failed": failure is not None,
            "failure_reason": f"{artifact}:{failure}" if failure else None,
            "collection_failed": failure is not None,
            "collection_failure_reason": failure,
            "exported": exported,
            "export_status": "exported" if exported else "failed",
            "export": export_result,
        }
        exports[artifact] = export_result

    failed_artifact_count = len(failed_reasons)
    partial_export = exported_artifact_count > 0 and failed_artifact_count > 0
    total_failure = exported_artifact_count == 0 and failed_artifact_count > 0
    collection_failure_reason_value = ";".join(failed_reasons) if total_failure else None

    return {
        "flow_id": None,
        "collection": {
            "mode": "per_artifact",
            "backend": "cli_query",
            "artifacts_requested": artifacts,
            "artifact_count": len(artifacts),
            "exported_artifact_count": exported_artifact_count,
            "failed_artifact_count": failed_artifact_count,
            "export_warning_count": export_warning_count,
        },
        "artifact_flows": artifact_flows,
        "artifact_results": artifact_flows,
        "flow_completion": {
            "mode": "per_artifact",
            "completed": exported_artifact_count > 0,
            "failed": total_failure,
            "partial_export": partial_export,
            "artifact_count": len(artifact_flows),
            "exported_artifact_count": exported_artifact_count,
            "failed_artifact_count": failed_artifact_count,
            "failed_reasons": failed_reasons,
        },
        "collection_failed": total_failure,
        "collection_failure_reason": collection_failure_reason_value,
        "exports": exports,
        "partial_export": partial_export,
    }


def _write_notes(result_dir: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# Velociraptor Process Sample Notes",
        "",
        f"- sample_id: `{payload['sample_id']}`",
        f"- sha256: `{payload['sha256']}`",
        f"- vm: `{payload['vm']}`",
        f"- execute: `{str(payload['execute']).lower()}`",
        f"- client_id: `{payload.get('client_id')}`",
        f"- flow_id: `{payload.get('flow_id')}`",
        f"- detected: `{str(payload.get('detected')).lower()}`",
        f"- high_confidence_detected: `{str(payload.get('high_confidence_detected')).lower()}`",
        f"- final_revert: `{json.dumps(payload.get('final_revert'), sort_keys=True)}`",
    ]
    (result_dir / "execution_notes.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _resolve_sample_from_args(args: argparse.Namespace) -> ResolvedSampleBinary:
    explicit_sample_path = getattr(args, "sample_path", None)
    explicit_sample_sha256 = str(getattr(args, "sample_sha256", "") or "").strip().lower()
    explicit_sample_source = str(getattr(args, "sample_source", "") or "unknown").strip() or "unknown"
    explicit_source_provenance = str(getattr(args, "sample_source_provenance", "") or "explicit_cli").strip() or "explicit_cli"
    if explicit_sample_path and explicit_sample_sha256:
        explicit = Path(str(explicit_sample_path))
        return ResolvedSampleBinary(
            sample_id=int(args.sample_id),
            sha256=explicit_sample_sha256,
            source=explicit_sample_source,
            source_provenance=explicit_source_provenance,
            resolved_binary_path=str(explicit),
            binary_source="explicit_sample_path",
            read_only_source=False,
            file_exists=explicit.is_file(),
            detected_arch="unknown",
        )

    resolved = resolve_sample_binary(args.sample_id)
    if explicit_sample_path:
        explicit = Path(str(explicit_sample_path))
        return ResolvedSampleBinary(
            sample_id=resolved.sample_id,
            sha256=resolved.sha256,
            source=resolved.source,
            source_provenance=resolved.source_provenance,
            resolved_binary_path=str(explicit),
            binary_source="explicit_sample_path",
            read_only_source=False,
            file_exists=explicit.is_file(),
            detected_arch=getattr(resolved, "detected_arch", "unknown"),
        )
    return resolved


def _vm_for_sample(cfg: Any, requested_vm: str, resolved: ResolvedSampleBinary) -> Any:
    if requested_vm != "auto":
        return cfg.vm(requested_vm)
    wanted_arch = str(getattr(resolved, "detected_arch", "") or "").lower()
    if wanted_arch in {"x86", "x64"}:
        for vm in cfg.vms.values():
            if vm.arch == wanted_arch:
                return vm
    for vm in cfg.vms.values():
        if vm.arch == "x64":
            return vm
    return cfg.vm(sorted(cfg.vms)[0])


def process_sample(args: argparse.Namespace) -> dict[str, Any]:
    _validate_process_sample_flags(args)
    provided_client_id = _provided_client_id(args)
    cfg = load_vr_config()
    if args.result_root:
        cfg = replace(cfg, result_root=Path(args.result_root))
    api_base = velociraptor_base(definitions_dir=None)
    server_base = velociraptor_server_base()
    ensure_safe_staging_bind(cfg.staging_bind_host)
    resolved = _resolve_sample_from_args(args)
    vm = _vm_for_sample(cfg, args.vm, resolved)
    if not resolved.file_exists:
        raise SystemExit(f"Sample binary missing: {resolved.resolved_binary_path}")
    source_path = Path(resolved.resolved_binary_path)
    source_suffix = source_path.suffix.lower()
    if source_suffix not in {".exe", ".dll"}:
        raise SystemExit("Unsupported file type for Windows execution: only .exe and .dll are supported")
    execution_mode = "dll" if source_suffix == ".dll" else "exe"
    dll_execution = choose_dll_execution(source_path) if execution_mode == "dll" else None
    started_at = _now()
    result_dir = _result_run_dir(cfg.result_root, resolved.sha256, vm.name, started_at)
    result_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = result_dir / "raw_exports"
    wait_seconds = effective_wait_seconds(args.wait_seconds, cfg.wait_seconds_default)
    snapshot_info = run_vm_command(snapshot_info_command(cfg, vm), execute=args.execute)
    client_preflight = _dry_command(["client-id", provided_client_id]) if provided_client_id else lookup_client(vm, execute=args.execute)
    client_lookup_pre = {"mode": "explicit" if provided_client_id else "not_run"}
    if args.execute:
        if not _command_ok(snapshot_info):
            raise SystemExit("Snapshot preflight failed")
        client_id, client_lookup_pre = resolve_client_id(vm, execute=True, provided_client_id=provided_client_id)
    else:
        client_id, client_lookup_pre = resolve_client_id(vm, execute=False, provided_client_id=provided_client_id)

    pre_revert = run_vm_command(snapshot_revert_command(cfg, vm), execute=args.execute, timeout_sec=180)
    client_after_revert = _dry_command(["client-id", client_id]) if provided_client_id else lookup_client(vm, execute=args.execute)
    client_lookup_post = {"mode": "explicit" if provided_client_id else "not_run"}
    if args.execute:
        client_id, client_lookup_post = resolve_client_id(vm, execute=True, provided_client_id=provided_client_id)
        winrm_preflight = run_powershell(vm, "Write-Output 'WINRM_OK'", execute=True, timeout_sec=args.winrm_timeout)
        if winrm_preflight.status_code != 0:
            raise SystemExit("WinRM preflight failed")
    else:
        winrm_preflight = _dry_winrm("Write-Output 'WINRM_OK'")

    staged = stage_sample(resolved, result_dir, execute=args.execute)
    port = args.http_port or (choose_free_port(cfg.staging_bind_host, cfg.http_port_min, cfg.http_port_max) if args.execute else cfg.http_port_min)
    url = f"http://{cfg.staging_bind_host}:{port}/{staged.filename}"
    execution_script_name = "execute_sample.ps1"
    execution_script = build_execution_powershell(
        url,
        resolved.sha256,
        staged.filename,
        execution_mode=execution_mode,
        execution_arch=str(getattr(resolved, "detected_arch", "unknown") or "unknown"),
        dll_loader=dll_execution.loader if dll_execution else "rundll32",
        dll_entrypoint=dll_execution.entrypoint if dll_execution else "#1",
        return_fast=True,
        reference_time_utc=started_at,
        guest_root=str(getattr(args, "guest_root", None) or r"C:\vr-malware-test"),
    )
    execution_script_path = staged.staging_dir / execution_script_name
    if args.execute:
        execution_script_path.write_text(execution_script + "\n", encoding="utf-8")
    guest_dir = str(getattr(args, "guest_root", None) or r"C:\vr-malware-test").rstrip("\\/") + f"\\{resolved.sha256}"
    guest_script = f"{guest_dir}\\{execution_script_name}"
    script_url = f"http://{cfg.staging_bind_host}:{port}/{execution_script_name}"
    ps = _staged_powershell_launcher(guest_dir=guest_dir, script_path=guest_script, script_url=script_url)
    server_payload = {"command": http_server_command(cfg.staging_bind_host, port, staged.staging_dir), "pid": None, "listening": False}
    if args.execute:
        with StagingHTTPServer(cfg.staging_bind_host, port, staged.staging_dir) as server:
            server_payload = server.as_dict()
            winrm = run_powershell(vm, ps, execute=True, timeout_sec=args.winrm_timeout)
    else:
        winrm = _dry_winrm(ps)

    collection_result: dict[str, Any] = {
        "flow_id": "DRY_RUN_FLOW_ID" if not args.execute else None,
        "collection": {"mode": "per_artifact", "artifacts_requested": []},
        "artifact_flows": {},
        "flow_completion": {"mode": "per_artifact", "completed": False, "failed": False},
        "collection_failure_reason": None,
        "exports": {},
        "partial_export": False,
    }
    post_execution_triage: dict[str, Any] | None = None
    guest_execution_started_at = started_at
    final_revert_command = snapshot_revert_command(cfg, vm)
    final_revert: dict[str, Any] | None = None
    final_client: dict[str, Any] | None = None
    try:
        requested_override = [str(item).strip() for item in (getattr(args, "artifact", None) or []) if str(item).strip()]
        artifacts_requested = requested_override or _generated_threattrace_artifacts()
        selected_backend = collection_backend()
        collection_base = api_base if selected_backend == "api" else server_base
        api_artifact_sync = _sync_artifacts_to_api_repo(
            artifacts_requested,
            command_base=api_base,
            execute=args.execute and selected_backend == "api",
        )
        write_json(result_dir / "api_artifact_sync.json", api_artifact_sync)
        active_artifact_preflight = _active_artifact_preflight(artifacts_requested, command_base=collection_base, execute=args.execute)
        write_json(result_dir / "active_artifact_preflight.json", active_artifact_preflight)
        if args.execute:
            write_json(result_dir / "winrm_execution_log.json", winrm.as_dict())
            if winrm.status_code != 0:
                write_json(
                    result_dir / "winrm_execution_warning.json",
                    {
                        "warning": "winrm_execution_timeout" if winrm.status_code == 124 else "winrm_execution_nonzero",
                        "detail": "continuing with observation and artifact collection because sample may already be running",
                        "winrm_status_code": winrm.status_code,
                        "stderr": winrm.stderr[:2000],
                    },
                )
            winrm_payload = parse_json_object(winrm.stdout)
            if isinstance(winrm_payload, dict):
                started_value = str(winrm_payload.get("started_at_utc") or "").strip()
                if started_value:
                    guest_execution_started_at = started_value
            early_artifacts = [artifact for artifact in artifacts_requested if artifact in EARLY_COLLECTION_ARTIFACTS]
            early_collection_result = None
            if early_artifacts:
                early_collection_result = _collect_artifacts_individually(
                    client_id=client_id,
                    artifacts=early_artifacts,
                    raw_dir=raw_dir,
                    execute=True,
                    api_base=collection_base,
                    flow_wait_timeout=effective_flow_wait_timeout(args.flow_wait_timeout),
                    flow_poll_seconds=args.flow_poll_seconds,
                    launch_backend=selected_backend,
                )
                write_json(result_dir / "early_collection_summary.json", early_collection_result)
            late_artifacts = [artifact for artifact in artifacts_requested if artifact not in early_artifacts]
            if early_collection_result and os.environ.get("THREATTRACE_VR_SKIP_LATE_AFTER_EARLY_HIGH", "1") != "0":
                early_cleaned = apply_false_positive_filter(
                    result_dir,
                    sample_id=resolved.sample_id,
                    sha256=resolved.sha256,
                    vm=vm.name,
                    client_id=client_id,
                    flow_id=early_collection_result.get("flow_id"),
                    partial_export=True,
                    final_revert=None,
                    started_at=guest_execution_started_at,
                    completed_at=_now(),
                )
                write_json(result_dir / "early_detection_filter.json", early_cleaned)
                if early_cleaned.get("high_confidence_detected"):
                    late_artifacts = []
                    wait_seconds = 0
                    write_json(
                        result_dir / "late_collection_skipped.json",
                        {
                            "reason": "early_high_confidence_detection",
                            "detection_reasons": early_cleaned.get("detection_reasons") or [],
                        },
                    )
            if wait_seconds > 0:
                print(json.dumps({"event": "observation_wait", "wait_seconds": wait_seconds}, sort_keys=True))
                time.sleep(wait_seconds)
        else:
            early_collection_result = None
            late_artifacts = artifacts_requested
            stale_log = result_dir / "winrm_execution_log.json"
            if stale_log.exists():
                stale_log.unlink()

        late_collection_result = (
            _collect_artifacts_individually(
                client_id=client_id,
                artifacts=late_artifacts,
                raw_dir=raw_dir,
                execute=args.execute,
                api_base=collection_base,
                flow_wait_timeout=effective_flow_wait_timeout(args.flow_wait_timeout),
                flow_poll_seconds=args.flow_poll_seconds,
                launch_backend=selected_backend,
            )
            if late_artifacts
            else None
        )
        collection_result = _combine_collection_results(early_collection_result, late_collection_result)
    finally:
        if args.execute and not args.skip_final_revert:
            if getattr(winrm, "status_code", None) == 124 and os.environ.get("THREATTRACE_VR_TRIAGE_AFTER_WINRM_TIMEOUT", "0") != "1":
                post_execution_triage = {
                    "execution_started_at_utc": guest_execution_started_at,
                    "triage_started_at_utc": _now(),
                    "triage_completed_at_utc": _now(),
                    "sample_id": resolved.sample_id,
                    "sha256": resolved.sha256,
                    "vm": vm.name,
                    "client_id": client_id,
                    "sample_path": f"{guest_dir}\\{staged.filename}",
                    "section_counts": {},
                    "skipped": True,
                    "skip_reason": "execution_winrm_timeout",
                }
                write_json(result_dir / "post_execution_triage.json", post_execution_triage)
            else:
                try:
                    post_execution_triage = _collect_post_execution_triage(
                        vm=vm,
                        result_dir=result_dir,
                        execution_started_at_utc=guest_execution_started_at,
                        sample_id=resolved.sample_id,
                        sha256=resolved.sha256,
                        client_id=client_id,
                        sample_path=f"{guest_dir}\\{staged.filename}",
                        winrm_timeout=min(int(args.winrm_timeout), 180),
                        staging_bind_host=cfg.staging_bind_host,
                        http_port_min=cfg.http_port_min,
                        http_port_max=cfg.http_port_max,
                        guest_dir=guest_dir,
                    )
                except Exception as exc:
                    post_execution_triage = {
                        "execution_started_at_utc": guest_execution_started_at,
                        "triage_started_at_utc": _now(),
                        "triage_completed_at_utc": _now(),
                        "sample_id": resolved.sample_id,
                        "sha256": resolved.sha256,
                        "vm": vm.name,
                        "client_id": client_id,
                        "sample_path": f"{guest_dir}\\{staged.filename}",
                        "section_counts": {},
                        "triage_error": str(exc),
                    }
                    write_json(result_dir / "post_execution_triage.json", post_execution_triage)
            try:
                final_revert = run_vm_command(final_revert_command, execute=True, timeout_sec=180).as_dict()
            except Exception as exc:
                final_revert = {
                    "command": final_revert_command,
                    "execute": True,
                    "returncode": 1,
                    "stdout": "",
                    "stderr": str(exc),
                    "failed": True,
                }
            try:
                final_client = (_dry_command(["client-id", client_id]) if provided_client_id else lookup_client(vm, execute=True)).as_dict()
            except Exception as exc:
                final_client = {"error": str(exc)}
        elif args.skip_final_revert:
            final_revert = {"skipped": True}
            final_client = None
        else:
            post_execution_triage = {
                "execution_started_at_utc": started_at,
                "triage_started_at_utc": _now(),
                "triage_completed_at_utc": _now(),
                "sample_id": resolved.sample_id,
                "sha256": resolved.sha256,
                "vm": vm.name,
                "client_id": client_id,
                "sample_path": f"{guest_dir}\\{staged.filename}",
                "section_counts": {},
                "skipped": True,
            }
            write_json(result_dir / "post_execution_triage.json", post_execution_triage)
            final_revert = _dry_vm(final_revert_command).as_dict()
            final_client = None

    flow_id = collection_result["flow_id"] or ("DRY_RUN_FLOW_ID" if not args.execute else None)
    collection = collection_result["collection"]
    artifact_flows = collection_result["artifact_flows"]
    flow_completion = collection_result["flow_completion"]
    collection_failure = collection_result["collection_failure_reason"]
    exports = collection_result["exports"]
    partial_export = collection_result["partial_export"]
    completed_at = _now()
    cleaned = apply_false_positive_filter(
        result_dir,
        sample_id=resolved.sample_id,
        sha256=resolved.sha256,
        vm=vm.name,
        client_id=client_id,
        flow_id=flow_id,
        partial_export=partial_export,
        final_revert=final_revert,
        started_at=guest_execution_started_at,
        completed_at=completed_at,
    )
    collection_summary = {
        "generated_at": _now(),
        "artifacts_requested": artifacts_requested,
        "client_id": client_id,
        "flow_id": flow_id,
        "collection": collection,
        "artifact_flows": artifact_flows,
        "flow_completion": flow_completion,
        "collection_failed": collection_failure is not None,
        "collection_failure_reason": collection_failure,
        "exports": exports,
        "partial_export": partial_export,
        "raw_exports_dir": str(raw_dir),
        "cleaned": cleaned,
    }
    write_json(result_dir / "velociraptor_collection_summary.json", collection_summary)
    payload = {
        "generated_at": _now(),
        "started_at": started_at,
        "execution_started_at_utc": guest_execution_started_at,
        "completed_at": completed_at,
        "execute": args.execute,
        "dry_run": not args.execute,
        "sample_id": resolved.sample_id,
        "sha256": resolved.sha256,
        "source": resolved.source,
        "source_provenance": resolved.source_provenance,
        "vm": vm.name,
        "vm_arch": vm.arch,
        "snapshot": vm.snapshot,
        "binary": resolved.as_dict(),
        "dll_execution": (
            {
                "loader": dll_execution.loader,
                "entrypoint": dll_execution.entrypoint,
                "exports": [{"name": item.name, "ordinal": item.ordinal} for item in dll_execution.exports[:64]],
                "export_count": len(dll_execution.exports),
            }
            if dll_execution
            else None
        ),
        "result_dir": str(result_dir),
        "snapshot_info": snapshot_info.as_dict(),
        "pre_execution_revert": pre_revert.as_dict(),
        "winrm_preflight": winrm_preflight.as_dict(),
        "staging": staged.as_dict(),
        "http": {**server_payload, "bind": cfg.staging_bind_host, "port": port, "url": url},
        "planned_winrm_command": ps if not args.execute else None,
        "winrm_execution_log": winrm.as_dict() if args.execute else None,
        "post_execution_triage": post_execution_triage,
        "client_preflight": client_preflight.as_dict(),
        "client_after_revert": client_after_revert.as_dict(),
        "client_lookup_pre": client_lookup_pre,
        "client_lookup_post": client_lookup_post,
        "client_id": client_id,
        "flow_id": flow_id,
        "wait_seconds": wait_seconds,
        "flow_wait_timeout": effective_flow_wait_timeout(args.flow_wait_timeout),
        "flow_poll_seconds": args.flow_poll_seconds,
        "collection": collection,
        "artifact_flows": artifact_flows,
        "flow_completion": flow_completion,
        "collection_failed": collection_failure is not None,
        "collection_failure_reason": collection_failure,
        "partial_export": partial_export,
        "detected": cleaned["detected"],
        "high_confidence_detected": cleaned["high_confidence_detected"],
        "detection_reasons": cleaned.get("detection_reasons") or [],
        "supporting_reasons": cleaned.get("supporting_reasons") or [],
        "observable_artifacts_found": cleaned.get("observable_artifacts_found") or [],
        "triggered_artifacts": cleaned.get("triggered_artifacts") or [],
        "detection_score": cleaned.get("detection_score") or 0,
        "final_revert": final_revert,
        "final_client_check": final_client,
        "collection_command_base": api_base,
    }
    write_json(result_dir / "sample_metadata.json", payload)
    if not args.execute:
        write_json(
            result_dir / "planned_actions.json",
            {
                "dry_run": True,
                "execute": False,
                "planned_winrm_command": ps,
                "collection_mode": "per_artifact",
                "artifacts_requested": artifacts_requested,
                "export_count": len(artifacts_requested),
                "final_revert_default": not args.skip_final_revert,
            },
        )
    _write_notes(result_dir, payload)

    if args.execute:
        archived_detection = _archive_detection_result(result_dir, payload)
        payload["archived_detection"] = archived_detection
        write_json(result_dir / "sample_metadata.json", payload)
        write_json(Path(archived_detection["archive_dir"]) / "sample_metadata.json", payload)
        if resolved.source_provenance == "contrast_holdout" or int(resolved.sample_id) >= 9_000_000:
            payload["db_persistence_skipped"] = "contrast_holdout_synthetic_sample"
        else:
            try:
                payload["db_persistence"] = persist_runtime_result(result_dir)
            except Exception as exc:
                payload["db_persistence_error"] = str(exc)
        write_json(result_dir / "sample_metadata.json", payload)
        write_json(Path(archived_detection["archive_dir"]) / "sample_metadata.json", payload)

    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Process one Velociraptor validation sample")
    parser.add_argument("--sample-id", type=int, required=True)
    parser.add_argument(
        "--vm",
        required=True,
        metavar="VM",
        help="Validation VM name from config, or auto",
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-malware-execution", action="store_true")
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=None,
        help="Observation wait before collection; default uses THREATTRACE_VR_WAIT_SECONDS_DEFAULT",
    )
    parser.add_argument("--http-port", type=int)
    parser.add_argument("--winrm-timeout", type=int, default=120)
    parser.add_argument(
        "--flow-wait-timeout",
        type=int,
        default=None,
        help="Maximum seconds to wait for each Velociraptor artifact flow; default is 300 seconds",
    )
    parser.add_argument("--flow-poll-seconds", type=int, default=10)
    parser.add_argument("--artifact", action="append", help="Artifact to collect; may be repeated. Defaults to generated ThreatTrace ransomware artifacts.")
    parser.add_argument("--no-flow-limit", action="store_true", help="Rejected for execute runs; kept for compatibility")
    parser.add_argument("--client-id")
    parser.add_argument("--skip-final-revert", action="store_true")
    parser.add_argument("--guest-root", default=r"C:\vr-malware-test")
    parser.add_argument("--result-root")
    parser.add_argument("--sample-path")
    parser.add_argument("--sample-sha256")
    parser.add_argument("--sample-source", default="unknown")
    parser.add_argument("--sample-source-provenance", default="explicit_cli")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    print(json.dumps(process_sample(args), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
