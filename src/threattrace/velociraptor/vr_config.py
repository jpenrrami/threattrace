from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from threattrace.common.json_config import config_path, load_json_config
from threattrace.common.redaction import redact_secrets
from threattrace.config.settings import get_settings

CONFIG_PATH = config_path("velociraptor", "validation_rules.json")


def _vr_validation_rules() -> dict[str, Any]:
    return load_json_config(str(CONFIG_PATH))


RESULT_ROOT = Path(_vr_validation_rules()["result_root"])
DETECTION_ARCHIVE_ROOT = Path(_vr_validation_rules()["detection_archive_root"])
VALIDATION_SOURCE = str(_vr_validation_rules()["validation_source"])
VALIDATION_DATASET_ROLE = str(_vr_validation_rules()["dataset_role"])
DEFAULT_VELOCIRAPTOR_BINARY = str(_vr_validation_rules()["default_binary"])
DEFAULT_HTTP_BIND = str(_vr_validation_rules()["default_http_bind"])
THREATTRACE_ARTIFACTS = tuple(str(item) for item in _vr_validation_rules()["threattrace_artifacts"])
SUPPORTED_RESULT_FILES = tuple(str(item) for item in _vr_validation_rules()["supported_result_files"])


@dataclass(frozen=True)
class VelociraptorVMConfig:
    name: str
    arch: str
    host: str
    user: str
    password: str
    snapshot: str
    expected_hostname: str
    client_id: str | None = None
    winrm_port: int = 5985

    def endpoint(self) -> str:
        return f"http://{self.host}:{self.winrm_port}/wsman"

    def redacted(self) -> dict[str, Any]:
        return redact_secrets(asdict(self))


@dataclass(frozen=True)
class VelociraptorValidationConfig:
    vms: dict[str, VelociraptorVMConfig]
    staging_bind_host: str
    snapshot: str
    libvirt_uri: str
    wait_seconds_default: int
    http_port_min: int
    http_port_max: int
    velociraptor_config: Path
    velociraptor_use_sudo: bool
    velociraptor_api_config: Path | None
    artifact_definitions_dir: Path | None
    cape_binary_fallback: Path
    result_root: Path = RESULT_ROOT

    def vm(self, name: str) -> VelociraptorVMConfig:
        try:
            return self.vms[name]
        except KeyError as exc:
            allowed = ", ".join(sorted(self.vms))
            raise ValueError(f"VM not allowed: {name}. Allowed: {allowed}") from exc

    def redacted(self) -> dict[str, Any]:
        return {
            "vms": {name: vm.redacted() for name, vm in self.vms.items()},
            "staging_bind_host": self.staging_bind_host,
            "snapshot": self.snapshot,
            "libvirt_uri": self.libvirt_uri,
            "wait_seconds_default": self.wait_seconds_default,
            "http_port_min": self.http_port_min,
            "http_port_max": self.http_port_max,
            "velociraptor_config": str(self.velociraptor_config),
            "velociraptor_use_sudo": self.velociraptor_use_sudo,
            "velociraptor_api_config": str(self.velociraptor_api_config) if self.velociraptor_api_config else None,
            "artifact_definitions_dir": str(self.artifact_definitions_dir) if self.artifact_definitions_dir else None,
            "cape_binary_fallback": str(self.cape_binary_fallback),
            "result_root": str(self.result_root),
        }


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


def _artifact_definitions_dir() -> Path | None:
    explicit = os.environ.get("THREATTRACE_VR_ARTIFACT_DEFINITIONS_DIR", "").strip()
    if explicit:
        path = Path(explicit)
        return path if path.exists() and path.is_dir() else None
    candidates = tuple(Path(item) for item in _vr_validation_rules()["artifact_definitions_dir_candidates"])
    for path in candidates:
        if path.exists() and path.is_dir():
            return path
    return None


def load_vr_config() -> VelociraptorValidationConfig:
    settings = get_settings()
    snapshot = settings.vr_validation_snapshot
    x64_name = _env("THREATTRACE_VR_X64_NAME", "windows-x64-validation")
    x86_name = _env("THREATTRACE_VR_X86_NAME", "windows-x86-validation")
    vms = {
        x64_name: VelociraptorVMConfig(
            name=x64_name,
            arch="x64",
            host=settings.vr_x64_host,
            user=settings.vr_x64_user,
            password=settings.vr_x64_password or "",
            snapshot=snapshot,
            expected_hostname=_env("THREATTRACE_VR_X64_EXPECTED_HOSTNAME", x64_name),
            client_id=_env("THREATTRACE_VR_X64_CLIENT_ID", "").strip() or None,
        ),
        x86_name: VelociraptorVMConfig(
            name=x86_name,
            arch="x86",
            host=settings.vr_x86_host,
            user=settings.vr_x86_user,
            password=settings.vr_x86_password or "",
            snapshot=snapshot,
            expected_hostname=_env("THREATTRACE_VR_X86_EXPECTED_HOSTNAME", x86_name),
            client_id=_env("THREATTRACE_VR_X86_CLIENT_ID", "").strip() or None,
        ),
    }
    return VelociraptorValidationConfig(
        vms=vms,
        staging_bind_host=settings.vr_staging_bind_host,
        snapshot=snapshot,
        libvirt_uri=settings.vr_libvirt_uri,
        wait_seconds_default=settings.vr_wait_seconds_default,
        http_port_min=settings.vr_http_port_min,
        http_port_max=settings.vr_http_port_max,
        velociraptor_config=settings.vr_velociraptor_config,
        velociraptor_use_sudo=settings.vr_velociraptor_use_sudo,
        velociraptor_api_config=settings.vr_velociraptor_api_config,
        artifact_definitions_dir=_artifact_definitions_dir(),
        cape_binary_fallback=settings.vr_cape_binary_fallback,
    )


def ensure_safe_staging_bind(bind_host: str) -> None:
    if bind_host.strip().lower() in {"", "0.0.0.0", "::", "*"}:  # nosec B104: rejecting, not binding
        raise ValueError("HTTP bind must be non-wildcard")


def effective_wait_seconds(requested_wait_seconds: int | None, cfg_wait_seconds_default: int) -> int:
    if requested_wait_seconds is None:
        return cfg_wait_seconds_default
    if requested_wait_seconds < 0:
        return cfg_wait_seconds_default
    return requested_wait_seconds


def vm_names() -> list[str]:
    return sorted(load_vr_config().vms)
