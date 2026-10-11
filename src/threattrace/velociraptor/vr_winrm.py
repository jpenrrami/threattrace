from __future__ import annotations

import multiprocessing
import queue
import warnings
from dataclasses import dataclass
from typing import Any

from threattrace.common.redaction import redact_secrets
from threattrace.velociraptor.vr_config import VelociraptorVMConfig


class WinRMFailureCode:
    WINRM_UNREACHABLE = "WINRM_UNREACHABLE"
    DOWNLOAD_FAILED = "DOWNLOAD_FAILED"
    HASH_MISMATCH = "HASH_MISMATCH"
    PROCESS_LAUNCH_FAILED = "PROCESS_LAUNCH_FAILED"
    VM_UNREACHABLE_AFTER_EXEC = "VM_UNREACHABLE_AFTER_EXEC"
    WINRM_SESSION_FAILED = "WINRM_SESSION_FAILED"


@dataclass(frozen=True)
class WinRMResult:
    command: str
    status_code: int | None
    stdout: str
    stderr: str
    executed: bool = True

    def as_dict(self) -> dict[str, Any]:
        return redact_secrets({
            "command": self.command,
            "status_code": self.status_code,
            "executed": self.executed,
            "stdout": self.stdout[:8000],
            "stderr": self.stderr[:8000],
        })


def ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


PROCESS_CREATION_SUBCATEGORY_GUID = "{0CCE922B-69AE-11D9-BED3-505054503030}"


def _pywinrm_run_child(vm_data: dict[str, str | int], script: str, timeout_sec: int, output: multiprocessing.Queue) -> None:
    try:
        import winrm

        effective_timeout = max(int(timeout_sec), 30)
        try:
            session = winrm.Session(
                str(vm_data["endpoint"]),
                auth=(str(vm_data["user"]), str(vm_data["password"])),
                transport="basic",
                read_timeout_sec=effective_timeout,
                operation_timeout_sec=max(effective_timeout - 10, 20),
            )
        except TypeError:
            session = winrm.Session(
                str(vm_data["endpoint"]),
                auth=(str(vm_data["user"]), str(vm_data["password"])),
                transport="basic",
            )
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message="There was a problem converting the Powershell error message.*",
                category=UserWarning,
                module="winrm",
            )
            result = session.run_ps(script)
        output.put(
            {
                "status_code": int(result.status_code),
                "stdout": (result.std_out or b"").decode("utf-8", errors="replace"),
                "stderr": (result.std_err or b"").decode("utf-8", errors="replace"),
            }
        )
    except Exception as exc:
        output.put({"error": str(exc)})


def build_execution_powershell(
    download_url: str,
    sha256: str,
    filename: str,
    execution_mode: str = "exe",
    execution_arch: str = "unknown",
    dll_loader: str = "rundll32",
    dll_entrypoint: str = "#1",
    return_fast: bool = False,
    reference_time_utc: str | None = None,
    guest_root: str = r"C:\vr-malware-test",
) -> str:
    guest_dir = guest_root.rstrip("\\/") + f"\\{sha256}"
    guest_path = f"{guest_dir}\\{filename}"
    target_time_lines = []
    if reference_time_utc:
        target_time_lines = [
            f"$targetUtc = [DateTimeOffset]::Parse({ps_single_quote(reference_time_utc)})",
            "try { Set-Date -Date $targetUtc.LocalDateTime | Out-Null } catch {}",
        ]
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "$ProgressPreference = 'SilentlyContinue'",
            f"$dir = {ps_single_quote(guest_dir)}",
            f"$path = {ps_single_quote(guest_path)}",
            "$guestTimeBefore = (Get-Date).ToUniversalTime().ToString('o')",
            "try { Start-Service w32time -ErrorAction SilentlyContinue | Out-Null } catch {}",
            *target_time_lines,
            "try { w32tm /resync /force | Out-Null } catch {}",
            "Start-Sleep -Seconds 3",
            "$guestTimeAfterSync = (Get-Date).ToUniversalTime().ToString('o')",
            f"try {{ auditpol /set /subcategory:{ps_single_quote(PROCESS_CREATION_SUBCATEGORY_GUID)} /success:enable /failure:enable | Out-Null }} catch {{}}",
            "try { New-Item -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Force | Out-Null } catch {}",
            "try { New-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -PropertyType DWord -Value 1 -Force | Out-Null } catch {}",
            "New-Item -ItemType Directory -Force $dir | Out-Null",
            "$baitRoots = @(",
            "  (Join-Path $env:USERPROFILE 'Desktop\\\\threattrace-bait'),",
            "  (Join-Path $env:USERPROFILE 'Documents\\\\threattrace-bait'),",
            "  (Join-Path $env:USERPROFILE 'AppData\\\\Roaming\\\\threattrace-bait'),",
            "  (Join-Path $env:USERPROFILE 'AppData\\\\Local\\\\Temp\\\\threattrace-bait'),",
            "  'C:\\ProgramData\\threattrace-bait',",
            "  $dir",
            ")",
            "$baitNames = @('invoice-2026-05.txt', 'accounts-q2.xlsx', 'notes-for-review.docx', 'customer-list.csv')",
            "foreach ($root in $baitRoots) {",
            "  New-Item -ItemType Directory -Force $root | Out-Null",
            "  foreach ($name in $baitNames) {",
            "    $baitPath = Join-Path $root $name",
            "    if (-not (Test-Path $baitPath)) {",
            "      Set-Content -Path $baitPath -Value 'threattrace bait file' -Encoding ASCII",
            "    }",
            "  }",
            "}",
            f"Invoke-WebRequest -Uri {ps_single_quote(download_url)} -OutFile $path",
            "$hash = (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()",
            f"if ($hash -ne {ps_single_quote(sha256.lower())}) {{ throw 'HASH_MISMATCH' }}",
            f"$executionMode = {ps_single_quote(execution_mode)}",
            f"$executionArch = {ps_single_quote(execution_arch.lower())}",
            f"$dllLoader = {ps_single_quote(dll_loader.lower())}",
            f"$dllEntrypoint = {ps_single_quote(dll_entrypoint)}",
            "$returnFast = " + ("$true" if return_fast else "$false"),
            "$startedAt = Get-Date",
            "if ($executionMode -eq 'dll') {",
            "  $rundll32 = $(if ($executionArch -eq 'x86' -and (Test-Path 'C:\\Windows\\SysWOW64\\rundll32.exe')) { 'C:\\Windows\\SysWOW64\\rundll32.exe' } else { 'C:\\Windows\\System32\\rundll32.exe' })",
            "  $regsvr32 = $(if ($executionArch -eq 'x86' -and (Test-Path 'C:\\Windows\\SysWOW64\\regsvr32.exe')) { 'C:\\Windows\\SysWOW64\\regsvr32.exe' } else { 'C:\\Windows\\System32\\regsvr32.exe' })",
            "  if ($dllLoader -eq 'regsvr32') {",
            "    $p = Start-Process -FilePath $regsvr32 -ArgumentList ('/s \"' + $path + '\"') -WorkingDirectory $dir -PassThru",
            "  } else {",
            "    $p = Start-Process -FilePath $rundll32 -ArgumentList ('\"' + $path + '\",' + $dllEntrypoint) -WorkingDirectory $dir -PassThru",
            "  }",
            "} else {",
            "  $p = Start-Process -FilePath $path -WorkingDirectory $dir -PassThru",
            "}",
            "if ($returnFast) {",
            "  [PSCustomObject]@{",
            "    status = 'STARTED_FAST';",
            "    path = $path;",
            "    sha256 = $hash;",
            "    pid = $p.Id;",
            "    process_name = $p.ProcessName;",
            "    guest_time_before_utc = $guestTimeBefore;",
            "    guest_time_after_sync_utc = $guestTimeAfterSync;",
            "    started_at_utc = $startedAt.ToUniversalTime().ToString('o');",
            "    evidence_mode = 'fast_async_launch_for_live_artifact_collection'",
            "  } | ConvertTo-Json -Depth 6",
            "  exit 0",
            "}",
            "function Get-ThreatTraceProcessSnapshot($Label) {",
            "  $gp = Get-Process -Id $p.Id -ErrorAction SilentlyContinue",
            "  $wm = Get-CimInstance Win32_Process -Filter (\"ProcessId={0}\" -f $p.Id) -ErrorAction SilentlyContinue",
            "  [PSCustomObject]@{",
            "    label = $Label;",
            "    timestamp_utc = (Get-Date).ToUniversalTime().ToString('o');",
            "    alive = [bool]$gp;",
            "    pid = $p.Id;",
            "    name = $(if ($gp) { $gp.ProcessName } else { $null });",
            "    path = $(if ($wm) { $wm.ExecutablePath } else { $null });",
            "    command_line = $(if ($wm) { $wm.CommandLine } else { $null });",
            "    parent_pid = $(if ($wm) { $wm.ParentProcessId } else { $null });",
            "    working_set64 = $(if ($gp) { $gp.WorkingSet64 } else { $null });",
            "    private_memory_size64 = $(if ($gp) { $gp.PrivateMemorySize64 } else { $null });",
            "    virtual_memory_size64 = $(if ($gp) { $gp.VirtualMemorySize64 } else { $null });",
            "    handle_count = $(if ($gp) { $gp.HandleCount } else { $null });",
            "    thread_count = $(if ($gp) { $gp.Threads.Count } else { $null });",
            "    cpu_seconds = $(if ($gp) { $gp.CPU } else { $null })",
            "  }",
            "}",
            "$processSnapshots = @()",
            "Start-Sleep -Seconds 5",
            "$processSnapshots += Get-ThreatTraceProcessSnapshot '5s'",
            "$alive5 = $processSnapshots[0].alive",
            "$alive15 = $null",
            "$alive30 = $null",
            "[PSCustomObject]@{",
            "  status = 'STARTED_WITH_PROCESS_EVIDENCE';",
            "  path = $path;",
            "  sha256 = $hash;",
            "  pid = $p.Id;",
            "  process_name = $p.ProcessName;",
            "  guest_time_before_utc = $guestTimeBefore;",
            "  guest_time_after_sync_utc = $guestTimeAfterSync;",
            "  started_at_utc = $startedAt.ToUniversalTime().ToString('o');",
            "  alive_after_5s = [bool]$alive5;",
            "  alive_after_15s = [bool]$alive15;",
            "  alive_after_30s = [bool]$alive30;",
            "  has_exited = $p.HasExited;",
            "  exit_code = $(if ($p.HasExited) { $p.ExitCode } else { $null });",
            "  process_snapshots = $processSnapshots;",
            "  expected_note_search_deferred = $true;",
            "  evidence_mode = 'early_process_liveness_memory_context'",
            "} | ConvertTo-Json -Depth 8",
        ]
    )


def run_powershell(vm: VelociraptorVMConfig, script: str, execute: bool, timeout_sec: int = 120) -> WinRMResult:
    """Run PowerShell through pywinrm with hard process timeout."""
    if not execute:
        return WinRMResult(command=script, status_code=None, stdout="", stderr="", executed=False)
    try:
        import winrm
    except ImportError as exc:
        raise RuntimeError("pywinrm is required for execution") from exc
    del winrm
    effective_timeout = max(int(timeout_sec), 1)
    output: multiprocessing.Queue = multiprocessing.Queue(maxsize=1)
    process = multiprocessing.Process(
        target=_pywinrm_run_child,
        args=(
            {
                "endpoint": vm.endpoint(),
                "user": vm.user,
                "password": vm.password,
            },
            script,
            effective_timeout,
            output,
        ),
    )
    process.start()
    process.join(effective_timeout)
    if process.is_alive():
        process.terminate()
        process.join(5)
        return WinRMResult(
            command=script,
            status_code=124,
            stdout="",
            stderr=f"{WinRMFailureCode.WINRM_SESSION_FAILED}: timeout_sec={effective_timeout}",
        )
    try:
        payload = output.get_nowait()
    except queue.Empty:
        raise RuntimeError(f"{WinRMFailureCode.WINRM_SESSION_FAILED}: no child result")
    if payload.get("error"):
        raise RuntimeError(f"{WinRMFailureCode.WINRM_SESSION_FAILED}: {payload['error']}")
    return WinRMResult(
        command=script,
        status_code=int(payload["status_code"]),
        stdout=str(payload["stdout"]),
        stderr=str(payload["stderr"]),
    )
