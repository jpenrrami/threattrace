from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any

from threattrace.common.redaction import redact_secrets
from threattrace.velociraptor.vr_config import VelociraptorValidationConfig, VelociraptorVMConfig


@dataclass(frozen=True)
class VMCommandResult:
    command: list[str]
    execute: bool
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""

    def as_dict(self) -> dict[str, Any]:
        return redact_secrets({
            "command": self.command,
            "execute": self.execute,
            "returncode": self.returncode,
            "stdout": self.stdout[:4000],
            "stderr": self.stderr[:4000],
        })


def snapshot_info_command(cfg: VelociraptorValidationConfig, vm: VelociraptorVMConfig) -> list[str]:
    return ["virsh", "-c", cfg.libvirt_uri, "snapshot-info", vm.name, vm.snapshot]


def snapshot_revert_command(cfg: VelociraptorValidationConfig, vm: VelociraptorVMConfig) -> list[str]:
    return ["virsh", "-c", cfg.libvirt_uri, "snapshot-revert", vm.name, vm.snapshot, "--running"]


def domain_state_command(cfg: VelociraptorValidationConfig, vm: VelociraptorVMConfig) -> list[str]:
    return ["virsh", "-c", cfg.libvirt_uri, "domstate", vm.name]


def domain_start_command(cfg: VelociraptorValidationConfig, vm: VelociraptorVMConfig) -> list[str]:
    return ["virsh", "-c", cfg.libvirt_uri, "start", vm.name]


def domain_resume_command(cfg: VelociraptorValidationConfig, vm: VelociraptorVMConfig) -> list[str]:
    return ["virsh", "-c", cfg.libvirt_uri, "resume", vm.name]


def run_vm_command(command: list[str], execute: bool, timeout_sec: int | None = None) -> VMCommandResult:
    if not execute:
        return VMCommandResult(command=command, execute=False)
    try:
        completed = subprocess.run(command, check=False, text=True, capture_output=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"VM command timed out: {' '.join(command)}") from exc
    result = VMCommandResult(command, True, completed.returncode, completed.stdout, completed.stderr)
    if completed.returncode != 0:
        raise RuntimeError(f"VM command failed: {' '.join(command)}")
    return result
