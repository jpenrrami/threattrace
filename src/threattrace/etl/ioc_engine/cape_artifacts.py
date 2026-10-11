from __future__ import annotations

import ipaddress
import json
import logging
import ntpath
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from threattrace.common.collections import coerce_dict, coerce_list, dedupe_strings_lower_preserve
from threattrace.common.io import read_json_dict
from threattrace.common.json_config import load_json_config

try:
    from bson import decode_all as _bson_decode_all
except Exception:  # pragma: no cover - optional dependency
    _bson_decode_all = None


ROOT_DIR = Path(__file__).resolve().parents[4]
CONFIG_PATH = ROOT_DIR / "config" / "detection" / "cape_artifact_rules.json"
logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _cape_artifact_config() -> dict[str, Any]:
    payload = load_json_config(str(CONFIG_PATH))
    payload["compiled_regex"] = {
        str(name): re.compile(str(pattern), re.IGNORECASE)
        for name, pattern in payload.get("regex", {}).items()
    }
    return payload


def _regex(name: str) -> re.Pattern[str]:
    return _cape_artifact_config()["compiled_regex"][name]


def _norm(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    return cleaned or None


def _hashes_from_dir(path: Path) -> list[str]:
    values: list[str] = []
    if not path.exists() or not path.is_dir():
        return values

    for item in sorted(path.iterdir()):
        if not item.is_file():
            continue
        if _regex("sha256").match(item.name):
            values.append(item.name.lower())

    return values


def _safe_str(value: Any) -> str | None:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="ignore")
        except Exception:
            return None
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _load_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return []

    rows: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except Exception as exc:
            logger.warning("invalid NDJSON row path=%s error=%s", path, exc)
            continue
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def _parse_digisig(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {}

    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}

    signers: list[str] = []
    for signer in coerce_list(coerce_dict(payload).get("signers")):
        if isinstance(signer, dict):
            for key in ("name", "subject", "common_name"):
                value = _norm(signer.get(key))
                if value:
                    signers.append(value)
        else:
            value = _norm(signer)
            if value:
                signers.append(value)

    return {
        "valid": bool(payload.get("valid", False)),
        "error": bool(payload.get("error", False)),
        "error_desc": _norm(payload.get("error_desc")),
        "signers": dedupe_strings_lower_preserve(signers),
    }


def _tlsdump_entry_count(path: Path) -> int:
    if not path.exists() or not path.is_file():
        return 0
    count = 0
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "client_random:" in raw_line and "master_secret:" in raw_line:
            count += 1
    return count


def _split_guest_paths(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in (_safe_str(v) for v in value) if item]

    raw = _safe_str(value)
    if not raw:
        return []

    if ";?" in raw:
        parts = [part.strip() for part in raw.split(";?")]
    else:
        parts = [raw]

    paths: list[str] = []
    for part in parts:
        if not part:
            continue
        if part.startswith("0x"):
            continue
        if "\\" not in part and "/" not in part:
            continue
        paths.append(part)
    return paths


def _iter_strings(value: Any) -> list[str]:
    results: list[str] = []

    if isinstance(value, str):
        cleaned = _safe_str(value)
        if cleaned:
            results.append(cleaned)
        return results

    if isinstance(value, dict):
        for item in value.values():
            results.extend(_iter_strings(item))
        return results

    if isinstance(value, list):
        for item in value:
            results.extend(_iter_strings(item))

    return results


def _extract_indicators_from_strings(values: list[str]) -> dict[str, list[str]]:
    urls: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    file_paths: list[str] = []
    registry_keys: list[str] = []
    user_agents: list[str] = []

    for value in values:
        for match in _regex("url").findall(value):
            urls.append(match.strip().lower().rstrip("/"))
            try:
                parsed = urlparse(match)
            except ValueError:
                continue
            host = (parsed.hostname or "").lower().strip()
            if host:
                domains.append(host)
                try:
                    ipaddress.ip_address(host)
                    ips.append(host)
                except ValueError:
                    pass

        for match in _regex("ipv4").findall(value):
            try:
                ipaddress.ip_address(match)
            except ValueError:
                continue
            ips.append(match)

        for match in _regex("user_agent").findall(value):
            user_agents.append(match)

        if "\\" in value or "/" in value:
            continue

        candidate = value.lower().strip().strip(".,;:()[]{}<>\"'")
        if _regex("domain").fullmatch(candidate):
            domains.append(candidate)

        for match in _regex("windows_path").findall(value):
            file_paths.append(match)

        for match in _regex("registry").findall(value):
            registry_keys.append(match)

    return {
        "config_urls": dedupe_strings_lower_preserve(urls),
        "config_domains": dedupe_strings_lower_preserve(domains),
        "config_ips": dedupe_strings_lower_preserve(ips),
        "config_file_paths": dedupe_strings_lower_preserve(file_paths),
        "config_registry_keys": dedupe_strings_lower_preserve(registry_keys),
        "config_user_agents": dedupe_strings_lower_preserve(user_agents),
    }


def _extract_report_json_artifacts(report_path: Path) -> dict[str, Any]:
    report = read_json_dict(report_path)
    if not report:
        return {}

    dropped = coerce_list(report.get("dropped"))
    procdump = coerce_list(report.get("procdump"))
    cape = coerce_dict(report.get("CAPE"))
    payloads = coerce_list(cape.get("payloads"))
    configs = coerce_dict(cape.get("configs"))
    decryptpcap = coerce_dict(report.get("decryptpcap"))
    network = coerce_dict(report.get("network"))
    behavior = coerce_dict(report.get("behavior"))
    enhanced = coerce_list(behavior.get("enhanced"))

    reported_file_paths: list[str] = []
    reported_process_names: list[str] = []
    reported_process_paths: list[str] = []
    dropped_hashes: list[str] = []
    procdump_hashes: list[str] = []
    payload_hashes: list[str] = []
    def collect_entry(entry: dict[str, Any], hash_bucket: list[str]) -> None:
        sha256 = _norm(entry.get("sha256"))
        if sha256 and _regex("sha256").match(sha256):
            hash_bucket.append(sha256)

        for key in _cape_artifact_config().get("report_hash_entry_path_keys", []):
            value = _safe_str(entry.get(key))
            if value and ("\\" in value or "/" in value):
                reported_file_paths.append(value)
                if key in set(_cape_artifact_config().get("report_process_path_keys", [])):
                    reported_process_paths.append(value)

        reported_file_paths.extend(_split_guest_paths(entry.get("guest_paths")))

        process_name = _safe_str(entry.get("process_name"))
        if process_name:
            reported_process_names.append(process_name)

    for entry in dropped:
        if isinstance(entry, dict):
            collect_entry(entry, dropped_hashes)

    for entry in procdump:
        if isinstance(entry, dict):
            collect_entry(entry, procdump_hashes)

    for entry in payloads:
        if isinstance(entry, dict):
            collect_entry(entry, payload_hashes)

    config_families = dedupe_strings_lower_preserve([key for key in configs.keys() if isinstance(key, str)])
    config_strings = _iter_strings(configs)
    config_indicators = _extract_indicators_from_strings(config_strings)

    enhanced_buckets = {
        str(rule["target"]): []
        for rule in _cape_artifact_config().get("enhanced_rules", [])
    }

    for entry in enhanced:
        if not isinstance(entry, dict):
            continue

        obj = _norm(entry.get("object"))
        evt = _norm(entry.get("event"))
        data = coerce_dict(entry.get("data"))
        for rule in _cape_artifact_config().get("enhanced_rules", []):
            if obj != _norm(rule.get("object")) or evt != _norm(rule.get("event")):
                continue
            value = None
            for key in rule.get("data_keys", []):
                value = _safe_str(data.get(key))
                if value:
                    break
            if value is None and rule.get("data_key"):
                value = _safe_str(data.get(rule["data_key"]))
            if value:
                enhanced_buckets[str(rule["target"])].append(value)
            break

    return {
        "report_json_dropped_hashes": dedupe_strings_lower_preserve(dropped_hashes),
        "report_json_procdump_hashes": dedupe_strings_lower_preserve(procdump_hashes),
        "report_json_payload_hashes": dedupe_strings_lower_preserve(payload_hashes),
        "reported_file_paths": dedupe_strings_lower_preserve(reported_file_paths),
        "reported_process_names": dedupe_strings_lower_preserve(reported_process_names),
        "reported_process_paths": dedupe_strings_lower_preserve(reported_process_paths),
        "pcap_sha256": _norm(network.get("pcap_sha256")),
        "decrypted_pcap_sha256": _norm(decryptpcap.get("decrypted_pcap_sha256")),
        "mixed_pcap_sha256": _norm(decryptpcap.get("mixed_pcap_sha256")),
        "cape_config_families": config_families,
        "enhanced_registry_read": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_registry_read", [])),
        "enhanced_registry_write": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_registry_write", [])),
        "enhanced_registry_delete": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_registry_delete", [])),
        "enhanced_file_read": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_file_read", [])),
        "enhanced_file_write": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_file_write", [])),
        "enhanced_file_delete": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_file_delete", [])),
        "enhanced_file_execute": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_file_execute", [])),
        "enhanced_file_copy": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_file_copy", [])),
        "enhanced_file_move": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_file_move", [])),
        "enhanced_dir_create": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_dir_create", [])),
        "enhanced_libraries": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_libraries", [])),
        "enhanced_services": dedupe_strings_lower_preserve(enhanced_buckets.get("enhanced_services", [])),
        **config_indicators,
    }


def _looks_like_path(value: str) -> bool:
    lowered = value.lower()
    return (
        "\\" in value
        or lowered.startswith("\\??\\")
        or lowered.startswith("c:\\")
        or lowered.startswith("%")
    )


def _looks_like_registry(value: str) -> bool:
    lowered = value.lower()
    return any(
        token in lowered
        for token in (
            "\\registry\\",
            "hkey_",
            "hkcu\\",
            "hklm\\",
            "hkcr\\",
            "hku\\",
            "hkcc\\",
        )
    )


def _norm_domain_or_ip(value: str) -> tuple[str | None, str | None]:
    cleaned = value.strip().lower().strip("[]")
    try:
        ipaddress.ip_address(cleaned)
        return None, cleaned
    except ValueError:
        pass
    if _regex("domain").fullmatch(cleaned):
        return cleaned, None
    return None, None


def _extract_bson_artifacts(logs_dir: Path) -> dict[str, Any]:
    if _bson_decode_all is None:
        return {}
    if not logs_dir.exists() or not logs_dir.is_dir():
        return {}

    templates: dict[int, tuple[str, str, list[str]]] = {}
    process_names: list[str] = []
    process_paths: list[str] = []
    command_lines: list[str] = []
    file_paths: list[str] = []
    registry_keys: list[str] = []
    services: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    urls: list[str] = []
    user_agents: list[str] = []
    api_names: list[str] = []

    for bson_path in sorted(logs_dir.glob("*.bson")):
        try:
            docs = _bson_decode_all(bson_path.read_bytes())
        except Exception as exc:
            logger.warning("BSON artifact could not be decoded path=%s error=%s", bson_path, exc)
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            if doc.get("type") == "info":
                index = doc.get("I")
                if not isinstance(index, int):
                    continue
                arg_names: list[str] = []
                for item in coerce_list(doc.get("args")):
                    if isinstance(item, list) and item:
                        name = _safe_str(item[0])
                    else:
                        name = _safe_str(item)
                    if name:
                        arg_names.append(name)
                templates[index] = (
                    _safe_str(doc.get("category")) or "",
                    _safe_str(doc.get("name")) or "",
                    arg_names,
                )
                continue

            index = doc.get("I")
            if not isinstance(index, int) or index not in templates:
                continue

            category, name, arg_names = templates[index]
            values = coerce_list(doc.get("args"))
            arg_map: dict[str, str] = {}
            for idx, arg_name in enumerate(arg_names):
                if idx >= len(values):
                    break
                value = _safe_str(values[idx])
                if value:
                    arg_map[arg_name] = value

            if name:
                api_names.append(name)

            templates = _cape_artifact_config().get("bson_notification_templates", {})
            if category == "__notification__" and name == "__process__":
                module_path = arg_map.get(str(templates.get("__process__", {}).get("module_path_key", "ModulePath")))
                if module_path:
                    process_paths.append(module_path)
                    process_names.append(ntpath.basename(module_path) or module_path)
                continue

            if category == "__notification__" and name == "__environ__":
                command_line = arg_map.get(str(templates.get("__environ__", {}).get("command_line_key", "CommandLine")))
                if command_line:
                    command_lines.append(command_line)
                continue

            for field_name, field_value in arg_map.items():
                for rule in _cape_artifact_config().get("bson_field_rules", []):
                    field_names = set(rule.get("field_names", []))
                    if field_name not in field_names:
                        continue
                    if rule.get("add_path") and _looks_like_path(field_value):
                        file_paths.append(field_value)
                    if rule.get("add_process") and _looks_like_path(field_value):
                        process_paths.append(field_value)
                        process_names.append(ntpath.basename(field_value) or field_value)
                    if rule.get("add_command"):
                        command_lines.append(field_value)
                    if rule.get("add_registry_if_registry_like") and _looks_like_registry(field_value):
                        registry_keys.append(field_value)
                    if rule.get("add_service"):
                        services.append(field_value)
                    if rule.get("add_domain_or_ip"):
                        domain, ip = _norm_domain_or_ip(field_value)
                        if domain:
                            domains.append(domain)
                        if ip:
                            ips.append(ip)
                    if rule.get("add_url_or_domain_or_ip"):
                        parsed = _safe_str(field_value)
                        if parsed and parsed.lower().startswith(("http://", "https://")):
                            urls.append(parsed.lower().rstrip("/"))
                        elif parsed:
                            domain, ip = _norm_domain_or_ip(parsed)
                            if domain:
                                domains.append(domain)
                            if ip:
                                ips.append(ip)
                    if rule.get("add_user_agent"):
                        user_agents.append(field_value)
                    break

    return {
        "bson_process_names": dedupe_strings_lower_preserve(process_names),
        "bson_process_paths": dedupe_strings_lower_preserve(process_paths),
        "bson_command_lines": dedupe_strings_lower_preserve(command_lines),
        "bson_file_paths": dedupe_strings_lower_preserve(file_paths),
        "bson_registry_keys": dedupe_strings_lower_preserve(registry_keys),
        "bson_services": dedupe_strings_lower_preserve(services),
        "bson_domains": dedupe_strings_lower_preserve(domains),
        "bson_ips": dedupe_strings_lower_preserve(ips),
        "bson_urls": dedupe_strings_lower_preserve(urls),
        "bson_user_agents": dedupe_strings_lower_preserve(user_agents),
        "bson_api_names": dedupe_strings_lower_preserve(api_names),
        "bson_log_count": len(list(logs_dir.glob("*.bson"))),
    }


def _run_strings(path: Path) -> list[str]:
    if not path.exists() or not path.is_file():
        return []
    try:
        output = subprocess.run(
            ["strings", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return []
    if output.returncode not in {0, 1}:
        return []
    return [line.strip() for line in output.stdout.splitlines() if line.strip()]


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _extract_text_tree_artifacts(base_dir: Path) -> dict[str, Any]:
    collected_lines: list[str] = []
    process_names: list[str] = []
    process_paths: list[str] = []
    command_lines: list[str] = []
    file_paths: list[str] = []
    registry_keys: list[str] = []

    roots = [base_dir / name for name in _cape_artifact_config().get("text_tree_roots", [])]

    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in set(_cape_artifact_config().get("text_tree_file_suffixes", [])):
                continue
            text = _read_text_file(path)
            if not text:
                continue
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            collected_lines.extend(lines)

            indicators = _extract_indicators_from_strings(lines)
            file_paths.extend(indicators.get("config_file_paths", []))
            registry_keys.extend(indicators.get("config_registry_keys", []))

            for line in lines:
                if _looks_like_path(line):
                    file_paths.append(line)
                    process_paths.append(line)
                    process_names.append(ntpath.basename(line) or line)
                if _looks_like_registry(line):
                    registry_keys.append(line)
                if any(token in line.lower() for token in _cape_artifact_config().get("text_tree_command_tokens", [])):
                    command_lines.append(line)

    indicators = _extract_indicators_from_strings(collected_lines)
    return {
        "tree_domains": indicators.get("config_domains", []),
        "tree_ips": indicators.get("config_ips", []),
        "tree_urls": indicators.get("config_urls", []),
        "tree_user_agents": indicators.get("config_user_agents", []),
        "tree_file_paths": dedupe_strings_lower_preserve(file_paths + indicators.get("config_file_paths", [])),
        "tree_registry_keys": dedupe_strings_lower_preserve(registry_keys + indicators.get("config_registry_keys", [])),
        "tree_process_names": dedupe_strings_lower_preserve(process_names),
        "tree_process_paths": dedupe_strings_lower_preserve(process_paths),
        "tree_command_lines": dedupe_strings_lower_preserve(command_lines),
    }


def _extract_pcap_artifacts(base_dir: Path) -> dict[str, Any]:
    lines: list[str] = []
    for filename in _cape_artifact_config().get("pcap_string_files", []):
        lines.extend(_run_strings(base_dir / filename))

    indicators = _extract_indicators_from_strings(lines)
    domains = indicators.get("config_domains", [])
    urls = indicators.get("config_urls", [])
    ips = indicators.get("config_ips", [])
    user_agents = indicators.get("config_user_agents", [])

    return {
        "pcap_domains": domains,
        "pcap_urls": urls,
        "pcap_ips": ips,
        "pcap_user_agents": user_agents,
        "pcap_file_paths": indicators.get("config_file_paths", []),
        "pcap_registry_keys": indicators.get("config_registry_keys", []),
    }


def extract_cape_analysis_artifacts(analysis_dir: str | Path) -> dict[str, Any]:
    base_dir = Path(analysis_dir)

    file_rows = _load_ndjson(base_dir / "files.json")
    observed_paths: list[str] = []
    category_counts: dict[str, int] = {}

    for row in file_rows:
        filepath = _norm(row.get("filepath"))
        if filepath:
            observed_paths.append(filepath)

        category = _norm(row.get("category")) or "unknown"
        category_counts[category] = category_counts.get(category, 0) + 1

    digisig = _parse_digisig(base_dir / "aux" / "DigiSig.json")
    cape_payload_hashes = _hashes_from_dir(base_dir / "CAPE")
    files_hashes = _hashes_from_dir(base_dir / "files")
    procdump_hashes = _hashes_from_dir(base_dir / "procdump")
    selfextracted_hashes = _hashes_from_dir(base_dir / "selfextracted")
    report_json_artifacts = _extract_report_json_artifacts(base_dir / "reports" / "report.json")
    bson_artifacts = _extract_bson_artifacts(base_dir / "logs")
    pcap_artifacts = _extract_pcap_artifacts(base_dir)
    tree_artifacts = _extract_text_tree_artifacts(base_dir)

    analysis_artifacts = {
        "analysis_dir": str(base_dir),
        "files_json_entries": len(file_rows),
        "files_json_categories": category_counts,
        "files_json_paths": dedupe_strings_lower_preserve(observed_paths),
        "selfextracted_hashes": selfextracted_hashes,
        "digisig_valid": digisig.get("valid", False),
        "digisig_error": digisig.get("error", False),
        "digisig_error_desc": digisig.get("error_desc"),
        "digisig_signers": digisig.get("signers", []),
        "tlsdump_entry_count": _tlsdump_entry_count(base_dir / "tlsdump" / "tlsdump.log"),
        "reported_file_paths": coerce_list(report_json_artifacts.get("reported_file_paths")),
        "reported_process_names": coerce_list(report_json_artifacts.get("reported_process_names")),
        "reported_process_paths": coerce_list(report_json_artifacts.get("reported_process_paths")),
        "pcap_sha256": report_json_artifacts.get("pcap_sha256"),
        "decrypted_pcap_sha256": report_json_artifacts.get("decrypted_pcap_sha256"),
        "mixed_pcap_sha256": report_json_artifacts.get("mixed_pcap_sha256"),
        "cape_config_families": coerce_list(report_json_artifacts.get("cape_config_families")),
        "enhanced_registry_read": coerce_list(report_json_artifacts.get("enhanced_registry_read")),
        "enhanced_registry_write": coerce_list(report_json_artifacts.get("enhanced_registry_write")),
        "enhanced_registry_delete": coerce_list(report_json_artifacts.get("enhanced_registry_delete")),
        "enhanced_file_read": coerce_list(report_json_artifacts.get("enhanced_file_read")),
        "enhanced_file_write": coerce_list(report_json_artifacts.get("enhanced_file_write")),
        "enhanced_file_delete": coerce_list(report_json_artifacts.get("enhanced_file_delete")),
        "enhanced_file_execute": coerce_list(report_json_artifacts.get("enhanced_file_execute")),
        "enhanced_file_copy": coerce_list(report_json_artifacts.get("enhanced_file_copy")),
        "enhanced_file_move": coerce_list(report_json_artifacts.get("enhanced_file_move")),
        "enhanced_dir_create": coerce_list(report_json_artifacts.get("enhanced_dir_create")),
        "enhanced_libraries": coerce_list(report_json_artifacts.get("enhanced_libraries")),
        "enhanced_services": coerce_list(report_json_artifacts.get("enhanced_services")),
        "bson_process_names": coerce_list(bson_artifacts.get("bson_process_names")),
        "bson_process_paths": coerce_list(bson_artifacts.get("bson_process_paths")),
        "bson_command_lines": coerce_list(bson_artifacts.get("bson_command_lines")),
        "bson_file_paths": coerce_list(bson_artifacts.get("bson_file_paths")),
        "bson_registry_keys": coerce_list(bson_artifacts.get("bson_registry_keys")),
        "bson_services": coerce_list(bson_artifacts.get("bson_services")),
        "bson_domains": coerce_list(bson_artifacts.get("bson_domains")),
        "bson_ips": coerce_list(bson_artifacts.get("bson_ips")),
        "bson_urls": coerce_list(bson_artifacts.get("bson_urls")),
        "bson_user_agents": coerce_list(bson_artifacts.get("bson_user_agents")),
        "bson_api_names": coerce_list(bson_artifacts.get("bson_api_names")),
        "bson_log_count": bson_artifacts.get("bson_log_count", 0),
        "pcap_domains": coerce_list(pcap_artifacts.get("pcap_domains")),
        "pcap_urls": coerce_list(pcap_artifacts.get("pcap_urls")),
        "pcap_ips": coerce_list(pcap_artifacts.get("pcap_ips")),
        "tree_process_names": coerce_list(tree_artifacts.get("tree_process_names")),
        "tree_process_paths": coerce_list(tree_artifacts.get("tree_process_paths")),
        "tree_command_lines": coerce_list(tree_artifacts.get("tree_command_lines")),
    }

    sources = {
        "cape_payload_hashes": cape_payload_hashes,
        "files_hashes": files_hashes,
        "procdump_hashes": procdump_hashes,
        "report_json": report_json_artifacts,
        "bson": bson_artifacts,
        "pcap": pcap_artifacts,
        "tree": tree_artifacts,
    }
    for output_field, refs in _cape_artifact_config().get("merged_output_sources", {}).items():
        merged: list[str] = []
        for ref in refs:
            if "." in ref:
                group, field = ref.split(".", 1)
                merged.extend(coerce_list(sources.get(group, {}).get(field)))
            else:
                value = sources.get(ref, [])
                if isinstance(value, list):
                    merged.extend(value)
                else:
                    merged.extend(coerce_list(value))
        analysis_artifacts[output_field] = dedupe_strings_lower_preserve(merged)

    return {"analysis_artifacts": analysis_artifacts}
