from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from threattrace.common.json_config import config_path, load_json_config
from threattrace.etl.ioc_engine.observability import normalize_registry_key, normalize_windows_path

NoiseLayer = Literal["detection", "endpoint", "velociraptor"]
NoiseAction = Literal["keep", "reject", "keep_only_with_context", "research_only"]


@dataclass(frozen=True)
class NoiseDecision:
    action: NoiseAction
    reason: str | None = None


ROOT_DIR = Path(__file__).resolve().parents[3]
CONFIG_PATH = config_path("detection", "noise_rules.json")


@lru_cache(maxsize=1)
def _noise_config() -> dict[str, Any]:
    payload = load_json_config(str(CONFIG_PATH))
    return {
        "regex": {
            str(name): re.compile(str(pattern), re.IGNORECASE)
            for name, pattern in payload.get("regex", {}).items()
        },
        "sets": {
            str(name): {str(item) for item in items}
            for name, items in payload.get("sets", {}).items()
        },
        "fragments": {
            str(name): tuple(str(item) for item in items)
            for name, items in payload.get("fragments", {}).items()
        },
    }


def _regex(name: str) -> re.Pattern[str]:
    return _noise_config()["regex"][name]


def _set(name: str) -> set[str]:
    return _noise_config()["sets"][name]


def _fragments(name: str) -> tuple[str, ...]:
    return _noise_config()["fragments"][name]


def normalize_candidate_text(value: Any) -> str:
    text = str(value or "").strip().strip("\"'").lower().replace("/", "\\")
    text = re.sub(r"\\\\\?\\", r"\\??\\", text)
    for prefix in ("device", "??", "pipe"):
        if text.startswith(f"\\\\{prefix}"):
            text = text[1:]
    while "\\\\" in text and not text.startswith("\\\\"):
        text = text.replace("\\\\", "\\")
    return text


def has_suspicious_context(candidate: dict[str, Any]) -> bool:
    category = str(candidate.get("category") or "").lower()
    value = normalize_candidate_text(candidate.get("value"))
    joined = " ".join(
        str(candidate.get(key) or "")
        for key in _fragments("suspicious_context_join_keys")
    ).lower()

    if category in {"ip", "domain", "url"}:
        return True
    if _regex("hash").search(value):
        return True
    if category == "file":
        return bool(
            _regex("ransom_note").search(value)
            or _regex("ransom_ext").search(value)
            or _regex("suspicious_file").search(value)
        )
    if category == "process":
        return bool(_regex("suspicious_process").search(value))
    if category == "registry":
        return bool(
            _regex("persistence").search(value)
            and (
                any(fragment in value for fragment in _fragments("registry_suspicious_literals"))
                or _regex("hash").search(value)
            )
        )
    if category == "mutex":
        return bool(_regex("mutex_random").search(value))
    if "ransom" in joined or "persistence" in joined:
        return True
    return False


def has_suspicious_lolbin_context(candidate: dict[str, Any]) -> bool:
    joined = " ".join(
        str(candidate.get(key) or "")
        for key in (*_fragments("suspicious_context_join_keys"), "command_line", "CommandLine", "message", "Message")
    ).lower()
    return bool(_regex("suspicious_process").search(joined) or "ransom" in joined)


def _network_rejection(category: str, value: str) -> str | None:
    if category == "url":
        parsed = urlparse(str(value).replace("\\", "/"))
        host = parsed.hostname or str(value).split("/")[0]
    else:
        host = str(value).strip("[]")
    host_l = host.lower().rstrip(".").strip("\\/")
    if ":" in host_l and not host_l.endswith(".onion"):
        host_l = host_l.split(":", 1)[0]
    if category == "ip":
        try:
            addr = ipaddress.ip_address(host_l)
        except ValueError:
            return None
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_link_local
            or addr.is_unspecified
        ):
            return "non_public_network_indicator"
    if category in {"domain", "url"}:
        if any(fragment in host_l for fragment in _fragments("benign_domain_fragments")):
            return "known_benign_vendor"
        if (
            host_l in _set("pseudo_domain_values")
            or host_l.endswith((".local", ".lan", ".home", ".invalid"))
            or ("." not in host_l and not host_l.endswith(".onion"))
        ):
            return "pseudo_domain"
    return None


def _path_rejection(value: str) -> str | None:
    normalized_path = normalize_candidate_text(normalize_windows_path(value) or value)
    if normalized_path.startswith("c:\\programdata\\microsoft\\diagnosis\\downloadedsettings\\"):
        return "generic_windows_component_path"
    if normalized_path.startswith("c:\\programdata\\microsoft\\windows\\power efficiency diagnostics\\"):
        return "generic_windows_component_path"
    if _regex("windows_malware_file").search(normalized_path):
        return None
    if _regex("powershell_base_file").search(normalized_path):
        return "generic_powershell_base_file"
    if normalized_path.startswith("c:\\windows\\softwaredistribution\\"):
        return "generic_root_path"
    system_dll_match = _regex("generic_system_dll").search(normalized_path)
    if system_dll_match:
        return f"generic_windows_{system_dll_match.group(1).lower()}_dll"
    if _regex("generic_windows_root_dll").search(normalized_path):
        return "generic_windows_root_dll"
    if _regex("windows_system_dll").search(normalized_path):
        return "generic_windows_system_dll"
    if _regex("generic_system_scr").search(normalized_path):
        return "generic_windows_screensaver"
    if _regex("generic_windows_component_store").search(normalized_path):
        return "generic_windows_component_store"
    if _regex("generic_windows_language_pack").search(normalized_path):
        return "generic_windows_language_pack"
    if _regex("generic_windows_locale_resource").search(normalized_path):
        return "generic_windows_locale_resource"
    if _regex("generic_windows_root_library").search(normalized_path):
        return "generic_windows_root_library"
    if _regex("generic_system_script").search(normalized_path):
        return "generic_windows_system_script"
    system_exe_match = _regex("generic_system_exe").search(normalized_path)
    if system_exe_match:
        filename = normalized_path.rsplit("\\", 1)[-1]
        if filename in _set("lolbin_file_names"):
            return "generic_windows_lolbin_without_context"
        return "generic_windows_lolbin_without_context"
    if _regex("generic_windows_root_exe").search(normalized_path):
        return "generic_windows_root_executable"
    if any(fragment in normalized_path for fragment in _fragments("generic_windows_component_fragments")):
        return "generic_windows_component_path"
    if _regex("dotnet_gac").search(normalized_path):
        return "generic_dotnet_gac_artifact"
    if _regex("dotnet_nativeimage").search(normalized_path) or _regex("dotnet_nativeimage_file").search(normalized_path):
        return "generic_dotnet_nativeimage_artifact"
    if _regex("powershell_resource").search(normalized_path):
        return "generic_powershell_resource_artifact"
    if _regex("non_public_ip_path_fragment").search(normalized_path):
        return "non_public_network_indicator"
    if any(fragment in normalized_path for fragment in _fragments("sandbox_paths")):
        return "cape_agent_path" if "agent.py" in normalized_path or r"c:\agents" in normalized_path else "sandbox_environment_path"
    if normalized_path in _set("generic_roots") or any(fragment in normalized_path for fragment in _fragments("generic_root_fragments")):
        return "generic_root_path"
    if any(fragment in normalized_path for fragment in _fragments("device_fragments")):
        return "generic_device_path"
    if any(fragment in normalized_path for fragment in _fragments("pipe_fragments")):
        return "generic_named_pipe"
    if any(fragment in normalized_path for fragment in _fragments("powershell_profile_fragments")):
        return "generic_powershell_profile_path"
    if any(fragment in normalized_path for fragment in _fragments("wmi_fragments")):
        return "generic_wmi_path"
    return None


def _registry_rejection(value: str) -> str | None:
    key = normalize_registry_key(value) or normalize_candidate_text(value)
    if key in _set("registry_roots"):
        return "generic_registry_path"
    if any(fragment in key for fragment in _fragments("registry_generic_fragments")):
        if r"\control\nls" in key or r"\control panel\international" in key:
            return "generic_locale_registry_path"
        return "generic_registry_path"
    if _regex("registry_driver_service").search(key):
        return "generic_windows_driver_service_registry"
    if _regex("registry_generic_appid").search(key):
        return "generic_windows_appid_registry"
    if _regex("registry_service_generic").search(key):
        return "generic_windows_service_path"
    return None


def classify_noise(candidate: dict[str, Any], *, layer: NoiseLayer) -> NoiseDecision:
    category = str(candidate.get("category") or "").lower()
    value_raw = str(candidate.get("value") or "").strip()
    value = normalize_candidate_text(value_raw)

    if not value:
        return NoiseDecision("reject", "missing_endpoint_context")
    if _regex("attack_id").match(value):
        return NoiseDecision("reject", "attack_technique_not_ioc")
    if layer == "velociraptor" and category in {"domain", "url"} and "microsoft" in value:
        return NoiseDecision("reject", "known_benign_vendor")
    if layer == "velociraptor" and category == "file" and (
        any(fragment in value for fragment in _fragments("velociraptor_temp_file_fragments"))
        or value.endswith(".tmp")
    ):
        return NoiseDecision("reject", "generic_root_path")

    network_reason = _network_rejection(category, value_raw)
    if network_reason:
        return NoiseDecision("reject", network_reason)

    if category == "process" and _regex("generic_process").match(value):
        return NoiseDecision("reject", "generic_process_without_context")
    if category == "mutex" and value in _set("generic_mutexes"):
        return NoiseDecision("reject", "generic_mutex")

    path_reason = _path_rejection(value)
    if path_reason:
        if path_reason == "generic_windows_lolbin_without_context" and has_suspicious_lolbin_context(candidate):
            return NoiseDecision("keep")
        return NoiseDecision("reject", path_reason)

    if category == "registry":
        registry_reason = _registry_rejection(value)
        if registry_reason:
            if registry_reason in {"generic_windows_driver_service_registry", "generic_windows_appid_registry"}:
                return NoiseDecision("reject", registry_reason)
            if has_suspicious_context(candidate):
                return NoiseDecision("keep")
            return NoiseDecision("reject", registry_reason)

    if category in {"file", "registry", "process", "mutex"} and layer == "velociraptor" and not has_suspicious_context(candidate):
        return NoiseDecision("keep_only_with_context", "missing_endpoint_context")

    return NoiseDecision("keep")
