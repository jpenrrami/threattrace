from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import grpc

from threattrace.velociraptor.vr_api_client import (
    collect_artifact,
    collect_artifact_command_repr,
    collect_artifact_result_stdout,
)
from threattrace.velociraptor.vr_clients import CommandResult, run_command, velociraptor_base, velociraptor_server_base
from threattrace.velociraptor.vr_config import THREATTRACE_ARTIFACTS

DEFAULT_COLLECTION_BACKEND = "api"
SUPPORTED_COLLECTION_BACKENDS = frozenset({"api", "cli_query", "server_cli_query"})
DEFAULT_LAUNCH_COMMAND_TIMEOUT_SECONDS = 45


def collect_vql(client_id: str, artifacts: list[str] | None = None) -> str:
    selected = artifacts or list(THREATTRACE_ARTIFACTS)
    quoted = ", ".join(json.dumps(item) for item in selected)
    return (
        "SELECT collect_client("
        f"client_id={json.dumps(client_id)}, "
        f"artifacts=[{quoted}], "
        "env=dict(), "
        "urgent=TRUE) AS Flow FROM scope()"
    )


def server_collect_vql(client_id: str, artifact: str) -> str:
    return (
        "SELECT * FROM Artifact.Server.Utils.CollectClient("
        f"ArtifactName={json.dumps(artifact)}, "
        f"Client={json.dumps(client_id)}, "
        "Parameters='{}')"
    )


def collection_backend() -> str:
    backend = os.environ.get("THREATTRACE_VR_COLLECTION_BACKEND", DEFAULT_COLLECTION_BACKEND).strip().lower()
    if backend not in SUPPORTED_COLLECTION_BACKENDS:
        raise ValueError(
            f"Unsupported Velociraptor collection backend: {backend}. "
            f"Allowed: {', '.join(sorted(SUPPORTED_COLLECTION_BACKENDS))}"
        )
    return backend


def api_collect_command(
    client_id: str,
    artifacts: list[str] | None = None,
    *,
    timeout_seconds: int | None = None,
) -> list[str]:
    selected = artifacts or list(THREATTRACE_ARTIFACTS)
    if len(selected) != 1:
        raise ValueError("API collection backend requires exactly one artifact per launch")
    return collect_artifact_command_repr(
        client_id,
        selected[0],
        collection_timeout_seconds=timeout_seconds,
        rpc_timeout_seconds=launch_command_timeout_seconds(),
    )


def collection_command(
    client_id: str,
    artifacts: list[str] | None = None,
    *,
    backend: str | None = None,
    timeout_seconds: int | None = None,
) -> list[str]:
    selected_backend = backend or collection_backend()
    if selected_backend == "api":
        return api_collect_command(client_id, artifacts, timeout_seconds=timeout_seconds)
    if selected_backend == "cli_query":
        return velociraptor_base() + ["query", "--format", "json", collect_vql(client_id, artifacts)]
    if selected_backend == "server_cli_query":
        selected = artifacts or list(THREATTRACE_ARTIFACTS)
        if len(selected) != 1:
            raise ValueError("server_cli_query backend requires exactly one artifact per launch")
        return velociraptor_server_base() + ["query", "--format", "json", server_collect_vql(client_id, selected[0])]
    raise ValueError(
        f"Unsupported Velociraptor collection backend: {selected_backend}. "
        f"Allowed: {', '.join(sorted(SUPPORTED_COLLECTION_BACKENDS))}"
    )


def _velociraptor_datastore_root() -> Path:
    return Path(os.environ.get("THREATTRACE_VELOCIRAPTOR_DATASTORE", "/opt/velociraptor"))


def _client_collections_dir(client_id: str) -> Path:
    return _velociraptor_datastore_root() / "clients" / client_id / "collections"


def _list_datastore_flow_dirs(client_id: str) -> dict[str, float]:
    collections_dir = _client_collections_dir(client_id)
    try:
        entries = list(collections_dir.iterdir())
    except OSError:
        return {}

    flows: dict[str, float] = {}
    for entry in entries:
        if not entry.is_dir():
            continue
        if not entry.name.startswith("F."):
            continue
        try:
            flows[entry.name] = entry.stat().st_mtime
        except OSError:
            flows[entry.name] = 0.0
    return flows


def _new_flow_ids(before_flows: dict[str, float], after_flows: dict[str, float]) -> list[str]:
    return sorted(flow_id for flow_id in after_flows if flow_id not in before_flows)


def launch_command_timeout_seconds() -> int:
    raw = os.environ.get("THREATTRACE_VR_COLLECTION_LAUNCH_TIMEOUT_SECONDS", str(DEFAULT_LAUNCH_COMMAND_TIMEOUT_SECONDS))
    try:
        return max(int(raw), 1)
    except ValueError:
        return DEFAULT_LAUNCH_COMMAND_TIMEOUT_SECONDS


def run_collection_command(command: list[str], execute: bool, *, timeout_seconds: int) -> CommandResult:
    if not execute:
        return CommandResult(command=command)
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=max(int(timeout_seconds), 1),
        )
    except FileNotFoundError as exc:
        return CommandResult(command, 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        timeout_note = f"collection_launch_timeout:{max(int(timeout_seconds), 1)}"
        stderr = f"{stderr}\n{timeout_note}".strip()
        return CommandResult(command, 124, stdout, stderr)
    return CommandResult(command, completed.returncode, completed.stdout, completed.stderr)


def run_api_collection(client_id: str, artifact: str, *, execute: bool, collection_timeout_seconds: int | None, rpc_timeout_seconds: int) -> CommandResult:
    command = collect_artifact_command_repr(
        client_id,
        artifact,
        collection_timeout_seconds=collection_timeout_seconds,
        rpc_timeout_seconds=rpc_timeout_seconds,
    )
    if not execute:
        return CommandResult(command=command)
    try:
        payload = collect_artifact(
            client_id,
            artifact,
            collection_timeout_seconds=collection_timeout_seconds,
            rpc_timeout_seconds=rpc_timeout_seconds,
        )
    except grpc.RpcError as exc:
        return CommandResult(command=command, returncode=2, stdout="", stderr=exc.details() or str(exc))
    return CommandResult(
        command=command,
        returncode=0,
        stdout=collect_artifact_result_stdout(payload),
        stderr="" if payload.get("notify_sent", True) else str(payload.get("notify_error") or ""),
    )


def _rows_from_result(result: Any) -> list[dict[str, Any]]:
    stdout = getattr(result, "stdout", result)
    if not stdout:
        return []
    if isinstance(stdout, bytes):
        stdout = stdout.decode(errors="replace")
    if isinstance(stdout, str):
        try:
            rows = json.loads(stdout)
        except json.JSONDecodeError:
            return []
    else:
        rows = stdout
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _artifact_matches(row: dict[str, Any], requested_artifacts: list[str]) -> bool:
    artifacts = row.get("artifacts") or row.get("Artifacts") or row.get("artifact") or row.get("Artifact")
    if artifacts is None:
        return False
    if isinstance(artifacts, str):
        artifact_values = [artifacts]
    elif isinstance(artifacts, list):
        artifact_values = [str(item) for item in artifacts]
    else:
        artifact_values = [str(artifacts)]
    artifact_text = "\n".join(artifact_values)
    return any(artifact in artifact_text for artifact in requested_artifacts)


def flow_id_from_recent_flows(flows_result: Any, requested_artifacts: list[str]) -> str | None:
    for row in _rows_from_result(flows_result):
        if not _artifact_matches(row, requested_artifacts):
            continue
        flow_id = row.get("session_id") or row.get("flow_id") or row.get("FlowId")
        if flow_id:
            text = str(flow_id).strip()
            if text:
                return text
    return None


@dataclass(frozen=True)
class CollectionLaunchResult:
    command_result: CommandResult
    requested_artifacts: list[str]
    backend: str
    collect_response_flow_id: str | None
    accepted_flow_id: str | None
    is_new_flow: bool
    tracking_source: str
    new_flow_ids: list[str]
    failure_reason: str | None

    def as_record(self) -> dict[str, Any]:
        return {
            "requested_artifacts": list(self.requested_artifacts),
            "backend": self.backend,
            "collect_response_flow_id": self.collect_response_flow_id,
            "accepted_flow_id": self.accepted_flow_id,
            "is_new_flow": self.is_new_flow,
            "tracking_source": self.tracking_source,
            "new_flow_ids": list(self.new_flow_ids),
            "failure_reason": self.failure_reason,
        }


def flow_id_from_collection(collection_result: Any) -> str | None:
    """Extract a Velociraptor flow id from collect_client output.

    Velociraptor can return the created collection id in different fields
    depending on the command/API context. In this environment, the useful id
    can appear as `session_id`, while `request.flow_id` may be present but
    empty. Empty strings are never valid flow ids.
    """

    stdout = getattr(collection_result, "stdout", collection_result)
    if not stdout:
        return None

    if isinstance(stdout, bytes):
        stdout = stdout.decode(errors="replace")

    if isinstance(stdout, str):
        try:
            rows = json.loads(stdout)
        except json.JSONDecodeError:
            return None
    else:
        rows = stdout

    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return None

    def non_empty(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def extract_from_mapping(row: dict[str, Any]) -> str | None:
        direct = (
            non_empty(row.get("session_id"))
            or non_empty(row.get("flow_id"))
            or non_empty(row.get("FlowId"))
        )
        if direct:
            return direct

        flow = row.get("Flow")
        if isinstance(flow, str):
            return non_empty(flow)

        if isinstance(flow, dict):
            flow_id = (
                non_empty(flow.get("session_id"))
                or non_empty(flow.get("flow_id"))
                or non_empty(flow.get("FlowId"))
            )
            if flow_id:
                return flow_id

            request = flow.get("request")
            if isinstance(request, dict):
                return (
                    non_empty(request.get("session_id"))
                    or non_empty(request.get("flow_id"))
                    or non_empty(request.get("FlowId"))
                )

        return None

    for row in rows:
        if isinstance(row, dict):
            flow_id = extract_from_mapping(row)
            if flow_id:
                return flow_id

    return None


def export_vql(client_id: str, flow_id: str, artifact: str, row_limit: int | None = None) -> str:
    query = (
        "SELECT * FROM source("
        f"client_id={json.dumps(client_id)}, "
        f"flow_id={json.dumps(flow_id)}, "
        f"artifact={json.dumps(artifact)})"
    )
    if row_limit and row_limit > 0:
        return f"{query} LIMIT {int(row_limit)}"
    return query


def flow_status_vql(client_id: str, flow_id: str) -> str:
    return (
        "SELECT session_id, state, status, total_collected_rows, artifacts_with_results "
        f"FROM flows(client_id={json.dumps(client_id)}) "
        f"WHERE session_id={json.dumps(flow_id)}"
    )


def flow_status_from_result(status_result: Any) -> dict[str, Any] | None:
    stdout = getattr(status_result, "stdout", status_result)
    if not stdout:
        return None

    if isinstance(stdout, bytes):
        stdout = stdout.decode(errors="replace")

    if isinstance(stdout, str):
        try:
            rows = json.loads(stdout)
        except json.JSONDecodeError:
            return None
    else:
        rows = stdout

    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or not rows:
        return None

    first = rows[0]
    return first if isinstance(first, dict) else None


def _normalized_state(status: dict[str, Any] | None) -> str:
    if not status:
        return ""
    return str(status.get("state") or status.get("State") or "").strip().upper()


def _normalized_status(status: dict[str, Any] | None) -> str:
    if not status:
        return ""
    return str(status.get("status") or status.get("Status") or "").strip().upper()


def classify_flow_state(status: dict[str, Any] | None) -> str:
    if not status:
        return "missing"

    state = _normalized_state(status)
    status_text = _normalized_status(status)
    success_values = {"FINISHED", "COMPLETED", "DONE", "OK"}
    failed_values = {"ERROR", "FAILED", "CANCELLED", "CANCELED"}
    running_values = {"RUNNING", "IN_PROGRESS", "QUEUED", "WAITING"}

    if state in failed_values or status_text in failed_values:
        return "failed"
    if state in success_values or status_text in success_values:
        return "completed"
    if state in running_values or status_text in running_values:
        return "running"
    return "running"


def get_flow_status(client_id: str, flow_id: str, execute: bool, *, base_command: list[str] | None = None) -> CommandResult:
    command_base = list(base_command) if base_command is not None else velociraptor_base()
    return run_command(command_base + ["query", "--format", "json", flow_status_vql(client_id, flow_id)], execute)


def wait_for_flow_completion(
    client_id: str,
    flow_id: str,
    execute: bool,
    timeout_seconds: int | None = None,
    poll_seconds: int = 10,
    base_command: list[str] | None = None,
) -> dict[str, Any]:
    if not execute:
        return {
            "flow_id": flow_id,
            "completed": True,
            "failed": False,
            "timed_out": False,
            "state": "dry_run",
            "attempts": 0,
            "last_status": {"session_id": flow_id, "state": "DRY_RUN"},
        }
    effective_timeout = 300 if timeout_seconds is None else max(timeout_seconds, 0)
    deadline = time.monotonic() + effective_timeout
    attempts = 0
    last_status: dict[str, Any] | None = None
    last_command: dict[str, Any] | None = None
    missing_seen = 0

    while True:
        attempts += 1
        result = (
            get_flow_status(client_id, flow_id, execute=True, base_command=base_command)
            if base_command is not None
            else get_flow_status(client_id, flow_id, execute=True)
        )
        last_command = result.as_dict()
        last_status = flow_status_from_result(result)
        state = classify_flow_state(last_status)

        if state == "missing":
            missing_seen += 1
        else:
            missing_seen = 0

        if state == "completed":
            return {
                "flow_id": flow_id,
                "completed": True,
                "failed": False,
                "timed_out": False,
                "state": state,
                "attempts": attempts,
                "last_status": last_status,
                "last_command": last_command,
            }

        if state == "failed":
            return {
                "flow_id": flow_id,
                "completed": False,
                "failed": True,
                "timed_out": False,
                "state": state,
                "attempts": attempts,
                "last_status": last_status,
                "last_command": last_command,
            }

        if missing_seen >= 2:
            return {
                "flow_id": flow_id,
                "completed": False,
                "failed": False,
                "timed_out": False,
                "state": "missing",
                "attempts": attempts,
                "last_status": last_status,
                "last_command": last_command,
            }

        if time.monotonic() >= deadline:
            result = (
                get_flow_status(client_id, flow_id, execute=True, base_command=base_command)
                if base_command is not None
                else get_flow_status(client_id, flow_id, execute=True)
            )
            last_command = result.as_dict()
            last_status = flow_status_from_result(result) or last_status
            state = classify_flow_state(last_status)
            return {
                "flow_id": flow_id,
                "completed": state == "completed",
                "failed": state == "failed",
                "timed_out": state not in {"completed", "failed"},
                "state": "timed_out" if state not in {"completed", "failed"} else state,
                "attempts": attempts,
                "last_status": last_status,
                "last_command": last_command,
            }

        time.sleep(max(poll_seconds, 1))


def run_collection(
    client_id: str,
    execute: bool,
    artifacts: list[str] | None = None,
    *,
    backend: str | None = None,
    new_flow_timeout_seconds: int = 10,
    poll_seconds: int = 1,
    collection_timeout_seconds: int | None = None,
    base_command: list[str] | None = None,
) -> CollectionLaunchResult:
    requested_artifacts = artifacts or list(THREATTRACE_ARTIFACTS)
    selected_backend = backend or collection_backend()
    launch_timeout_seconds = launch_command_timeout_seconds()
    if base_command is None:
        command = collection_command(
            client_id,
            requested_artifacts,
            backend=selected_backend,
            timeout_seconds=collection_timeout_seconds,
        )
    else:
        if selected_backend == "api":
            raise ValueError("base_command override is not supported with api backend")
        if selected_backend == "server_cli_query":
            if len(requested_artifacts) != 1:
                raise ValueError("server_cli_query backend requires exactly one artifact per launch")
            query = server_collect_vql(client_id, requested_artifacts[0])
        else:
            query = collect_vql(client_id, requested_artifacts)
        command = list(base_command) + ["query", "--format", "json", query]
    before_flows = _list_datastore_flow_dirs(client_id) if execute else {}
    if selected_backend == "api":
        result = run_api_collection(
            client_id,
            requested_artifacts[0],
            execute=execute,
            collection_timeout_seconds=collection_timeout_seconds,
            rpc_timeout_seconds=launch_timeout_seconds,
        )
    else:
        result = run_collection_command(command, execute, timeout_seconds=launch_timeout_seconds)
    collect_response_flow_id = flow_id_from_collection(result)
    if not execute:
        dry_flow_id = collect_response_flow_id or "DRY_RUN_FLOW_ID"
        return CollectionLaunchResult(
            command_result=result,
            requested_artifacts=requested_artifacts,
            backend=selected_backend,
            collect_response_flow_id=collect_response_flow_id,
            accepted_flow_id=dry_flow_id,
            is_new_flow=True,
            tracking_source="dry_run",
            new_flow_ids=[dry_flow_id],
            failure_reason=None,
        )

    deadline = time.monotonic() + max(new_flow_timeout_seconds, 0)
    after_flows = before_flows
    new_flow_ids: list[str] = []
    while True:
        after_flows = _list_datastore_flow_dirs(client_id)
        new_flow_ids = _new_flow_ids(before_flows, after_flows)
        if new_flow_ids or time.monotonic() >= deadline:
            break
        time.sleep(max(poll_seconds, 1))

    if collect_response_flow_id and collect_response_flow_id in new_flow_ids:
        return CollectionLaunchResult(
            command_result=result,
            requested_artifacts=requested_artifacts,
            backend=selected_backend,
            collect_response_flow_id=collect_response_flow_id,
            accepted_flow_id=collect_response_flow_id,
            is_new_flow=True,
            tracking_source="collect_response_and_datastore",
            new_flow_ids=new_flow_ids,
            failure_reason=None,
        )

    if collect_response_flow_id and not new_flow_ids:
        return CollectionLaunchResult(
            command_result=result,
            requested_artifacts=requested_artifacts,
            backend=selected_backend,
            collect_response_flow_id=collect_response_flow_id,
            accepted_flow_id=None,
            is_new_flow=False,
            tracking_source="collect_response_only",
            new_flow_ids=[],
            failure_reason="no_new_flow_created",
        )

    if selected_backend == "api" and not new_flow_ids:
        return CollectionLaunchResult(
            command_result=result,
            requested_artifacts=requested_artifacts,
            backend=selected_backend,
            collect_response_flow_id=collect_response_flow_id,
            accepted_flow_id=None,
            is_new_flow=False,
            tracking_source="api_collect_no_flow",
            new_flow_ids=[],
            failure_reason="no_new_flow_created",
        )

    if collect_response_flow_id and collect_response_flow_id not in new_flow_ids:
        return CollectionLaunchResult(
            command_result=result,
            requested_artifacts=requested_artifacts,
            backend=selected_backend,
            collect_response_flow_id=collect_response_flow_id,
            accepted_flow_id=None,
            is_new_flow=False,
            tracking_source="collect_response_mismatch",
            new_flow_ids=new_flow_ids,
            failure_reason="flow_id_mismatch",
        )

    if len(new_flow_ids) == 1:
        accepted_flow_id = new_flow_ids[0]
        return CollectionLaunchResult(
            command_result=result,
            requested_artifacts=requested_artifacts,
            backend=selected_backend,
            collect_response_flow_id=None,
            accepted_flow_id=accepted_flow_id,
            is_new_flow=True,
            tracking_source="datastore_new_flow_after_launch_timeout" if result.returncode == 124 else "datastore_new_flow",
            new_flow_ids=new_flow_ids,
            failure_reason=None,
        )

    failure_reason = "no_new_flow_created" if not new_flow_ids else "ambiguous_new_flows_created"
    return CollectionLaunchResult(
        command_result=result,
        requested_artifacts=requested_artifacts,
        backend=selected_backend,
        collect_response_flow_id=collect_response_flow_id,
        accepted_flow_id=None,
        is_new_flow=False,
        tracking_source="datastore_new_flow",
        new_flow_ids=new_flow_ids,
        failure_reason=failure_reason,
    )


def export_artifact(
    client_id: str,
    flow_id: str,
    artifact: str,
    raw_dir: Path,
    execute: bool,
    *,
    base_command: list[str] | None = None,
) -> dict[str, Any]:
    command_base = list(base_command) if base_command is not None else velociraptor_base()
    result = run_command(command_base + ["query", "--format", "json", export_vql(client_id, flow_id, artifact)], execute)
    output_path = raw_dir / f"{artifact.replace('.', '_')}_{flow_id}.json"
    stdout = result.stdout or ""
    rows = _rows_from_result(result)
    row_count = len(rows)
    stdout_empty = not stdout.strip()
    output_written = False
    export_failure_reason = None

    if result.returncode != 0:
        export_failure_reason = "export_command_failed"
    elif stdout_empty:
        export_failure_reason = "export_stdout_empty"
    elif row_count == 0:
        export_failure_reason = "export_json_has_no_rows"

    if execute:
        raw_dir.mkdir(parents=True, exist_ok=True)
        if stdout_empty:
            output_path.write_text("[]\n", encoding="utf-8")
        else:
            output_path.write_text(stdout, encoding="utf-8")
        output_written = True

    return {
        **result.as_dict(),
        "artifact": artifact,
        "output_path": str(output_path),
        "output_written": output_written,
        "stdout_empty": stdout_empty,
        "row_count": row_count,
        "export_failure_reason": export_failure_reason,
    }
