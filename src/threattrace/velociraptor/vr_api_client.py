from __future__ import annotations

import json
import os
from pathlib import Path

import grpc

from threattrace.velociraptor import vr_minimal_api_pb2, vr_minimal_api_pb2_grpc
from threattrace.velociraptor.vr_config import load_vr_config


def _parse_api_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    current_key: str | None = None
    block_lines: list[str] = []

    for raw in path.read_text(encoding="utf-8").splitlines():
        if current_key is None:
            if not raw.strip() or raw.lstrip().startswith("#") or raw.startswith(" ") or ":" not in raw:
                continue
            key, rest = raw.split(":", 1)
            key = key.strip()
            rest = rest.strip()
            if rest == "|":
                current_key = key
                block_lines = []
            else:
                values[key] = rest
            continue

        if raw.startswith("  "):
            block_lines.append(raw[2:])
            continue

        values[current_key] = "\n".join(block_lines) + "\n"
        current_key = None

        if not raw.strip() or raw.lstrip().startswith("#") or raw.startswith(" ") or ":" not in raw:
            continue
        key, rest = raw.split(":", 1)
        key = key.strip()
        rest = rest.strip()
        if rest == "|":
            current_key = key
            block_lines = []
        else:
            values[key] = rest

    if current_key is not None:
        values[current_key] = "\n".join(block_lines) + "\n"

    return values


def _api_config_values() -> dict[str, str]:
    cfg = load_vr_config()
    if cfg.velociraptor_api_config is None:
        raise RuntimeError("Velociraptor API config is required for gRPC collection scheduling")
    return _parse_api_config(Path(cfg.velociraptor_api_config))


def _channel():
    values = _api_config_values()
    creds = grpc.ssl_channel_credentials(
        root_certificates=values["ca_certificate"].encode(),
        private_key=values["client_private_key"].encode(),
        certificate_chain=values["client_cert"].encode(),
    )
    return grpc.secure_channel(
        values["api_connection_string"],
        creds,
        (("grpc.ssl_target_name_override", os.environ.get("THREATTRACE_VR_API_TLS_SERVER_NAME_OVERRIDE", "VelociraptorServer")),),
    )


def collect_artifact(client_id: str, artifact: str, *, collection_timeout_seconds: int | None, rpc_timeout_seconds: int) -> dict[str, object]:
    with _channel() as channel:
        stub = vr_minimal_api_pb2_grpc.APIStub(channel)
        response = stub.CollectArtifact(
            vr_minimal_api_pb2.ArtifactCollectorArgs(
                client_id=client_id,
                artifacts=[artifact],
                timeout=max(int(collection_timeout_seconds or 0), 0),
                urgent=True,
            ),
            timeout=max(int(rpc_timeout_seconds), 1),
        )
        notify_error: str | None = None
        try:
            stub.NotifyClients(
                vr_minimal_api_pb2.NotificationRequest(client_id=client_id),
                timeout=max(int(rpc_timeout_seconds), 1),
            )
        except grpc.RpcError as exc:
            notify_error = exc.details() or str(exc)

    payload: dict[str, object] = {
        "flow_id": response.flow_id,
        "request": {
            "client_id": response.request.client_id,
            "artifacts": list(response.request.artifacts),
            "timeout": int(response.request.timeout),
            "urgent": bool(response.request.urgent),
        },
        "notify_sent": notify_error is None,
    }
    if notify_error:
        payload["notify_error"] = notify_error
    return payload


def collect_artifact_command_repr(client_id: str, artifact: str, *, collection_timeout_seconds: int | None, rpc_timeout_seconds: int) -> list[str]:
    command = [
        "grpc:CollectArtifact",
        "--client_id",
        client_id,
        "--artifact",
        artifact,
        "--urgent",
        "true",
        "--rpc-timeout",
        str(int(rpc_timeout_seconds)),
    ]
    if collection_timeout_seconds is not None:
        command.extend(["--timeout", str(int(collection_timeout_seconds))])
    command.extend(["&&", "grpc:NotifyClients", "--client_id", client_id])
    return command


def collect_artifact_result_stdout(payload: dict[str, object]) -> str:
    return json.dumps(payload)
