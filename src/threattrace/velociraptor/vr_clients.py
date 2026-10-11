from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threattrace.common.redaction import redact_secrets
from threattrace.velociraptor.vr_config import DEFAULT_VELOCIRAPTOR_BINARY, VelociraptorVMConfig, load_vr_config


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""

    def as_dict(self) -> dict[str, Any]:
        return redact_secrets({
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout[:8000],
            "stderr": self.stderr[:8000],
        })


def velociraptor_base(
    config_path: Path | str | None = None,
    *,
    definitions_dir: Path | str | None | object = ...,
) -> list[str]:
    cfg = load_vr_config()
    binary = os.environ.get("THREATTRACE_VELOCIRAPTOR_BIN", DEFAULT_VELOCIRAPTOR_BINARY)

    if cfg.velociraptor_api_config is not None:
        command = [binary, "--api_config", str(cfg.velociraptor_api_config)]
    else:
        selected_config = config_path if isinstance(config_path, (str, Path)) else cfg.velociraptor_config
        command = [binary, "--config", str(selected_config)]

    selected_definitions_dir = cfg.artifact_definitions_dir if definitions_dir is ... else definitions_dir
    if selected_definitions_dir is not None:
        command.extend(["--definitions", str(selected_definitions_dir)])

    if cfg.velociraptor_use_sudo:
        return ["sudo", "-n", *command]
    return command


def velociraptor_server_base(config_path: Path | str | None = None) -> list[str]:
    cfg = load_vr_config()
    binary = os.environ.get("THREATTRACE_VELOCIRAPTOR_SERVER_BIN", "/usr/local/bin/velociraptor")
    selected_config = config_path if isinstance(config_path, (str, Path)) else cfg.velociraptor_config
    command = [binary, "--config", str(selected_config)]
    return ["sudo", "-n", *command]


def run_command(command: list[str], execute: bool) -> CommandResult:
    if not execute:
        return CommandResult(command=command)
    try:
        completed = subprocess.run(command, check=False, text=True, capture_output=True)
    except FileNotFoundError as exc:
        return CommandResult(command, 127, "", str(exc))
    return CommandResult(command, completed.returncode, completed.stdout, completed.stderr)


def client_lookup_vql(expected_hostname: str) -> str:
    hostname_regex = json.dumps(rf"(?i)^{re.escape(expected_hostname)}$")
    return (
        "SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, "
        "os_info.machine AS arch, last_seen_at "
        "FROM clients(search=" + json.dumps(expected_hostname) + ") "
        "WHERE hostname =~ " + hostname_regex
    )


def client_lookup_by_id_vql(client_id: str) -> str:
    return (
        "SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, "
        "os_info.machine AS arch, last_seen_at "
        "FROM clients(search=" + json.dumps(client_id) + ") "
        "WHERE client_id = " + json.dumps(client_id)
    )


def live_clients_vql(limit: int = 50) -> str:
    return (
        "SELECT client_id, os_info.hostname AS hostname, last_seen_at, last_ip "
        "FROM clients() "
        f"LIMIT {int(limit)}"
    )


def lookup_client(vm: VelociraptorVMConfig, execute: bool) -> CommandResult:
    return run_command(velociraptor_base() + ["query", "--format", "json", client_lookup_vql(vm.expected_hostname)], execute)


def lookup_client_by_id(client_id: str, execute: bool) -> CommandResult:
    return run_command(velociraptor_base() + ["query", "--format", "json", client_lookup_by_id_vql(client_id)], execute)


def list_live_clients(execute: bool, limit: int = 50) -> CommandResult:
    return run_command(velociraptor_base() + ["query", "--format", "json", live_clients_vql(limit)], execute)


def lookup_rows(result: CommandResult) -> list[dict[str, Any]]:
    if not result.stdout:
        return []
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def lookup_diagnostics(result: CommandResult, expected_hostname: str) -> dict[str, Any]:
    rows = lookup_rows(result)
    hostname_lower = expected_hostname.lower()
    matches = [row for row in rows if str(row.get("hostname") or "").lower() == hostname_lower]
    return redact_secrets({
        "expected_hostname": expected_hostname,
        "command": result.command,
        "returncode": result.returncode,
        "row_count": len(rows),
        "match_count": len(matches),
        "rows": rows[:10],
        "stderr": result.stderr[:1000],
    })


def _last_seen_sort_value(row: dict[str, Any]) -> int:
    value = row.get("last_seen_at") or row.get("LastSeenAt") or 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def select_latest_client_row(rows: list[dict[str, Any]], expected_hostname: str) -> dict[str, Any] | None:
    hostname_lower = expected_hostname.lower()
    matches = [row for row in rows if str(row.get("hostname") or "").lower() == hostname_lower]
    candidates = matches or rows
    if not candidates:
        return None
    return max(candidates, key=_last_seen_sort_value)


_CLIENT_LOG_RE = re.compile(
    r"(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d).*?from\s+(?P<ip>\d+\.\d+\.\d+\.\d+):\d+\s+\((?P<client_id>C\.[A-Za-z0-9]+)\)"
)


def _system_year() -> int:
    return datetime.now(UTC).year


def live_clients_from_logs(limit: int = 20) -> list[dict[str, Any]]:
    try:
        completed = subprocess.run(
            ["journalctl", "-u", "velociraptor-server.service", "--since", "4 hours ago", "--no-pager"],
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError:
        return []
    if completed.returncode != 0:
        return []
    clients: dict[str, dict[str, Any]] = {}
    for line in completed.stdout.splitlines():
        match = _CLIENT_LOG_RE.search(line)
        if not match:
            continue
        ts_text = f"{_system_year()} {match.group('ts')}"
        try:
            last_seen = datetime.strptime(ts_text, "%Y %b %d %H:%M:%S").replace(tzinfo=UTC).isoformat()
        except ValueError:
            last_seen = match.group("ts")
        client_id = match.group("client_id")
        clients[client_id] = {
            "client_id": client_id,
            "hostname": None,
            "last_seen_at": last_seen,
            "last_ip": match.group("ip"),
            "source": "journalctl",
        }
    return list(clients.values())[:limit]


def client_exists_in_datastore(client_id: str) -> bool:
    """Return True when a Velociraptor client is present in the local datastore.

    Some lab deployments can have a visible client directory in the server
    datastore while the `clients()` VQL/API lookup returns no rows. This helper
    is only used as a fallback for explicit `--client-id` values.
    """
    if not client_id.startswith("C."):
        return False

    datastore_root = Path(os.environ.get("THREATTRACE_VELOCIRAPTOR_DATASTORE", "/opt/velociraptor"))
    client_dir = datastore_root / "clients" / client_id
    try:
        return client_dir.is_dir()
    except OSError:
        return False


def client_id_from_lookup(result: CommandResult, fallback: str) -> str:
    rows = lookup_rows(result)
    if not rows:
        return fallback
    client_id = rows[0].get("client_id") or rows[0].get("ClientId")
    return str(client_id or fallback)


def require_client_id_from_lookup(result: CommandResult, expected_hostname: str) -> str:
    diagnostics = lookup_diagnostics(result, expected_hostname)
    if result.returncode not in (None, 0):
        raise RuntimeError(
            f"Velociraptor client lookup failed for hostname={expected_hostname}; "
            f"returncode={result.returncode}; stderr={result.stderr[:300]}"
        )
    if not result.stdout:
        raise RuntimeError(
            f"Velociraptor client not found for hostname: {expected_hostname}. "
            f"lookup returned 0 rows; pass --client-id or set THREATTRACE_VR_{'X64' if 'x64' in expected_hostname else 'X86'}_CLIENT_ID"
        )
    rows = lookup_rows(result)
    if not rows:
        raise RuntimeError("Velociraptor client lookup returned non-JSON output")
    selected = select_latest_client_row(rows, expected_hostname)
    if not selected:
        raise RuntimeError(
            f"Velociraptor client not found for hostname: {expected_hostname}. "
            f"lookup rows={diagnostics['row_count']}"
        )
    client_id = selected.get("client_id") or selected.get("ClientId")
    if not client_id or str(client_id) == expected_hostname:
        raise RuntimeError(
            f"Velociraptor lookup did not return a real client_id for: {expected_hostname}. "
            f"rows={diagnostics['rows'][:3]}"
        )
    return str(client_id)


def resolve_client_id(
    vm: VelociraptorVMConfig,
    *,
    execute: bool,
    provided_client_id: str | None = None,
) -> tuple[str, dict[str, Any]]:
    if provided_client_id:
        if execute:
            result = lookup_client_by_id(provided_client_id, execute=True)
            diagnostics = lookup_diagnostics(result, provided_client_id)
            rows = lookup_rows(result)
            if any(str(row.get("client_id") or "") == provided_client_id for row in rows):
                return provided_client_id, {**diagnostics, "mode": "explicit_vql", "client_id": provided_client_id}
            log_clients = live_clients_from_logs(limit=20)
            if any(str(row.get("client_id") or "") == provided_client_id for row in log_clients):
                return provided_client_id, {
                    **diagnostics,
                    "mode": "explicit_log_fallback",
                    "client_id": provided_client_id,
                    "live_clients": log_clients[:10],
                }
            visible_clients = lookup_rows(list_live_clients(execute=True, limit=10))
            if any(str(row.get("client_id") or "") == provided_client_id for row in visible_clients):
                return provided_client_id, {
                    **diagnostics,
                    "mode": "explicit_live_clients_fallback",
                    "client_id": provided_client_id,
                    "live_clients": visible_clients[:10],
                }
            if client_exists_in_datastore(provided_client_id):
                return provided_client_id, {
                    **diagnostics,
                    "mode": "explicit_datastore_fallback",
                    "client_id": provided_client_id,
                    "datastore_client_dir": str(
                        Path(os.environ.get("THREATTRACE_VELOCIRAPTOR_DATASTORE", "/opt/velociraptor"))
                        / "clients"
                        / provided_client_id
                    ),
                    "live_clients": visible_clients[:10] or log_clients[:10],
                    "warning": "client_id was not visible through clients() lookup, but exists in the Velociraptor datastore",
                }
            raise RuntimeError(
                f"Velociraptor explicit client_id not visible: {provided_client_id}. "
                f"lookup rows={diagnostics['row_count']}; live clients={visible_clients[:5] or log_clients[:5]}; "
                f"config={velociraptor_base()}"
            )
        return provided_client_id, {"mode": "explicit", "client_id": provided_client_id}

    result = lookup_client(vm, execute=execute)
    diagnostics = lookup_diagnostics(result, vm.expected_hostname)
    rows = lookup_rows(result)
    selected = select_latest_client_row(rows, vm.expected_hostname)
    client_id = selected.get("client_id") if selected else None
    if client_id and str(client_id).startswith("C."):
        return str(client_id), {**diagnostics, "mode": "lookup_latest", "client_id": str(client_id)}
    if vm.client_id:
        return vm.client_id, {
            **diagnostics,
            "mode": "configured_fallback",
            "client_id": vm.client_id,
            "suggestion": "Set expected hostname correctly or keep configured client IDs in env",
        }
    if execute:
        raise RuntimeError(
            f"Velociraptor client not found for hostname: {vm.expected_hostname}. "
            f"lookup rows={diagnostics['row_count']}; pass --client-id or set a configured client ID"
        )
    return "DRY_RUN_CLIENT_ID", {**diagnostics, "mode": "dry_run_fallback", "client_id": "DRY_RUN_CLIENT_ID"}
