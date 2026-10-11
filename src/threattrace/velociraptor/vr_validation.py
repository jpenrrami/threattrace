from __future__ import annotations

import argparse
import csv
import json
import os
import random
import shutil
import socket
import subprocess
import time
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from threattrace.common.io import print_json as _print_json
from threattrace.common.io import read_json, write_json
from threattrace.common.pe import detect_pe_architecture
from threattrace.common.time import utcnow_iso
from threattrace.db.models import VelociraptorValidationCandidate
from threattrace.db.session import session_scope
from threattrace.velociraptor.vr_binary_resolver import resolve_sample_binary_from_row
from threattrace.velociraptor.vr_clients import (
    list_live_clients,
    live_clients_from_logs,
    lookup_rows,
    velociraptor_base,
)
from threattrace.velociraptor.vr_collections import collection_command
from threattrace.velociraptor.vr_config import (
    DEFAULT_HTTP_BIND,
    RESULT_ROOT,
    SUPPORTED_RESULT_FILES,
    THREATTRACE_ARTIFACTS,
    VALIDATION_DATASET_ROLE,
    VALIDATION_SOURCE,
    ensure_safe_staging_bind,
    load_vr_config,
)
from threattrace.velociraptor.vr_sample_providers import (
    LocalPathProvider,
    MalShareProvider,
    MalwareBazaarProvider,
    MalwareSampleProvider,
)
from threattrace.velociraptor.vr_vm import (
    domain_resume_command,
    domain_start_command,
    domain_state_command,
    snapshot_info_command,
    snapshot_revert_command,
)


def _rows(sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    try:
        with session_scope() as session:
            rows = session.execute(text(sql), params or {}).mappings().all()
            return [dict(row) for row in rows]
    except SQLAlchemyError as exc:
        raise SystemExit(f"DB query failed: {exc}") from exc


def _one(sql: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    rows = _rows(sql, params)
    return rows[0] if rows else {}


def _now() -> str:
    return utcnow_iso()


@lru_cache(maxsize=1)
def _existing_tables() -> set[str]:
    try:
        with session_scope() as session:
            rows = session.execute(
                text(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = current_schema()
                    """
                )
            ).scalars().all()
            return {str(row) for row in rows}
    except SQLAlchemyError:
        return set()


def _result_dir(sha256: str, vm_name: str) -> Path:
    return RESULT_ROOT / "results" / sha256 / vm_name


def _vr_config():
    return load_vr_config()


def _binary_path_for_sample(sample: dict[str, Any], *, cfg=None) -> Path:
    cfg = cfg or _vr_config()
    resolved = resolve_sample_binary_from_row(
        sample,
        cape_binary_fallback=cfg.cape_binary_fallback,
    )
    return Path(resolved.resolved_binary_path)


def _sample_providers() -> dict[str, MalwareSampleProvider]:
    return {
        "local": LocalPathProvider(),
        "malshare": MalShareProvider(),
        "malwarebazaar": MalwareBazaarProvider(),
    }


def _require_execute(args: argparse.Namespace, confirm_attr: str | None = None) -> None:
    if not getattr(args, "execute", False):
        return
    if confirm_attr and not getattr(args, confirm_attr, False):
        raise SystemExit(f"--execute requires --{confirm_attr.replace('_', '-')}")


def _run_or_dry(command: list[str], execute: bool) -> dict[str, Any]:
    payload = {"execute": execute, "command": command}
    if not execute:
        return payload
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    payload.update(
        {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    )
    if completed.returncode != 0:
        raise SystemExit(json.dumps(payload, indent=2))
    return payload


def _command_output(command: list[str], execute: bool) -> dict[str, Any]:
    payload = _run_or_dry(command, execute)
    payload["stdout_text"] = str(payload.get("stdout") or "").strip()
    return payload


def _client_rows(limit: int = 50) -> list[dict[str, Any]]:
    return lookup_rows(list_live_clients(execute=True, limit=limit))


def _client_row_for_vm(vm) -> dict[str, Any] | None:
    for row in _client_rows(limit=50):
        if vm.client_id and str(row.get("client_id") or "") == vm.client_id:
            return row
        if str(row.get("hostname") or "").lower() == vm.expected_hostname.lower():
            return row
    return None


def _client_last_seen(vm) -> int | None:
    row = _client_row_for_vm(vm)
    value = row.get("last_seen_at") if row else None
    return int(value) if value else None


def _wait_for_port(host: str, port: int, timeout_seconds: int, poll_seconds: int) -> dict[str, Any]:
    deadline = time.time() + max(timeout_seconds, 0)
    attempts = 0
    last_error = ""
    while True:
        attempts += 1
        sock = socket.socket()
        sock.settimeout(min(max(poll_seconds, 1), 5))
        try:
            sock.connect((host, port))
            return {"ready": True, "attempts": attempts, "last_error": last_error}
        except OSError as exc:
            last_error = str(exc)
        finally:
            sock.close()
        if time.time() >= deadline:
            return {"ready": False, "attempts": attempts, "last_error": last_error}
        time.sleep(max(poll_seconds, 1))


def _wait_for_client_reconnect(vm, baseline_last_seen: int | None, timeout_seconds: int, poll_seconds: int) -> dict[str, Any]:
    deadline = time.time() + max(timeout_seconds, 0)
    attempts = 0
    last_seen = baseline_last_seen
    while True:
        attempts += 1
        current = _client_last_seen(vm)
        if current and (baseline_last_seen is None or current > baseline_last_seen):
            return {"ready": True, "attempts": attempts, "last_seen_at": current}
        last_seen = current
        if time.time() >= deadline:
            return {"ready": False, "attempts": attempts, "last_seen_at": last_seen}
        time.sleep(max(poll_seconds, 1))


def _flow_rows(client_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
    query = (
        "SELECT client_id, session_id, create_time, start_time, active_time, "
        "state, status, total_collected_rows, artifacts_with_results "
        f"FROM flows(client_id={json.dumps(client_id)}) ORDER BY session_id DESC LIMIT {int(limit)}"
    )
    payload = _run_or_dry(_velociraptor_base() + ["query", "--format", "json", query], True)
    return json.loads(str(payload.get("stdout") or "[]"))


def _flow_age_seconds(flow: dict[str, Any]) -> float:
    now_us = int(datetime.now(UTC).timestamp() * 1_000_000)
    last_us = int(flow.get("active_time") or flow.get("start_time") or flow.get("create_time") or now_us)
    return max((now_us - last_us) / 1_000_000, 0.0)


def _stale_flows(flows: list[dict[str, Any]], min_age_seconds: int, include_rowful: bool) -> list[dict[str, Any]]:
    stale: list[dict[str, Any]] = []
    for flow in flows:
        if str(flow.get("state") or "").upper() not in {"RUNNING", "IN_PROGRESS"}:
            continue
        if _flow_age_seconds(flow) < min_age_seconds:
            continue
        if not include_rowful and int(flow.get("total_collected_rows") or 0) > 0:
            continue
        stale.append(
            {
                **flow,
                "age_seconds": round(_flow_age_seconds(flow), 2),
            }
        )
    return stale


def _cancel_flow(client_id: str, flow_id: str, execute: bool) -> dict[str, Any]:
    query = f"SELECT cancel_flow(client_id={json.dumps(client_id)}, flow_id={json.dumps(flow_id)}) FROM scope()"
    return _run_or_dry(_velociraptor_base() + ["query", "--format", "json", query], execute)


def _sample_where(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    if getattr(args, "sample_id", None):
        return "s.id = :sample_id", {"sample_id": args.sample_id}
    if getattr(args, "sha256", None):
        return "s.sha256 = :sha256", {"sha256": args.sha256}
    raise SystemExit("Provide --sample-id or --sha256")


def _allowed_vms(*, cfg=None) -> dict[str, str]:
    cfg = cfg or _vr_config()
    return {name: vm.snapshot for name, vm in cfg.vms.items()}


def _vm_for_arch(arch: str | None, *, cfg=None) -> str:
    cfg = cfg or _vr_config()
    for vm in cfg.vms.values():
        if vm.arch == arch:
            return vm.name
    for vm in cfg.vms.values():
        if vm.arch == "x86":
            return vm.name
    return sorted(cfg.vms)[0]


def _known_validation_role(dataset_role: str | None) -> bool:
    return str(dataset_role or "").startswith("validation")


def _metadata_arch(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"x86", "x64"}:
        return normalized
    return "unknown"


def _file_profile(path: Path, metadata_file_type: str | None, metadata_arch: str | None) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {
            "binary_exists": False,
            "effective_file_type": str(metadata_file_type or "unknown"),
            "effective_arch": _metadata_arch(metadata_arch),
            "is_windows_executable": False,
            "binary_kind": "missing",
        }
    head = path.read_bytes()[:8]
    if head.startswith(b"MZ"):
        arch = detect_pe_architecture(path)
        return {
            "binary_exists": True,
            "effective_file_type": "exe",
            "effective_arch": arch,
            "is_windows_executable": True,
            "binary_kind": "pe",
        }
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        kind = "7z"
    elif head.startswith(b"Rar!\x1a\x07"):
        kind = "rar"
    elif head.startswith(b"PK\x03\x04"):
        kind = "zip"
    elif head.startswith(b"{\\rtf"):
        kind = "rtf"
    else:
        kind = str(metadata_file_type or "unknown")
    return {
        "binary_exists": True,
        "effective_file_type": kind,
        "effective_arch": _metadata_arch(metadata_arch),
        "is_windows_executable": False,
        "binary_kind": kind,
    }


def _recommended_vm_for_candidate(candidate: dict[str, Any], cfg) -> str | None:
    effective_arch = candidate.get("effective_arch")
    if effective_arch == "x64":
        return _vm_for_arch("x64", cfg=cfg)
    if effective_arch == "x86":
        return _vm_for_arch("x86", cfg=cfg)
    return None


def _select_rows(*, source: str | None) -> list[dict[str, Any]]:
    tables = _existing_tables()
    has_candidate_state = "velociraptor_validation_candidates" in tables
    has_reports = "velociraptor_reports" in tables
    latest_validation_cte = """
    latest_validation AS (
      SELECT
        NULL::bigint AS sample_id,
        NULL::text AS candidate_state,
        NULL::text AS candidate_local_path,
        NULL::text AS retrieval_method,
        0::integer AS attempt_count,
        NULL::text AS last_error,
        1 AS rn
      WHERE false
    ),
    """
    if has_candidate_state:
        latest_validation_cte = """
    latest_validation AS (
      SELECT
        vvc.sample_id,
        vvc.candidate_state,
        vvc.local_path AS candidate_local_path,
        vvc.retrieval_method,
        vvc.attempt_count,
        vvc.last_error,
        row_number() OVER (PARTITION BY vvc.sample_id ORDER BY vvc.updated_at DESC, vvc.id DESC) AS rn
      FROM velociraptor_validation_candidates vvc
    ),
    """
    latest_reports_cte = """
    latest_reports AS (
      SELECT
        NULL::bigint AS sample_id,
        false AS detected,
        NULL::timestamptz AS completed_at,
        1 AS rn
      WHERE false
    ),
    """
    if has_reports:
        latest_reports_cte = """
    latest_reports AS (
      SELECT
        vr.sample_id,
        vr.detected,
        vr.completed_at,
        row_number() OVER (PARTITION BY vr.sample_id ORDER BY vr.completed_at DESC NULLS LAST, vr.id DESC) AS rn
      FROM velociraptor_reports vr
    ),
    """
    sql = f"""
    WITH latest_sources AS (
      SELECT
        s.id AS sample_id,
        ss.source,
        ss.dataset_role,
        ss.family_hint,
        ss.source_data,
        row_number() OVER (PARTITION BY s.id ORDER BY ss.created_at DESC, ss.id DESC) AS rn
      FROM samples s
      LEFT JOIN sample_sources ss ON ss.sample_id = s.id
    ),
    {latest_validation_cte}
    {latest_reports_cte}
    candidate_sources AS (
      SELECT
        s.id AS sample_id,
        COALESCE(ls.source, CASE
          WHEN s.malwarebazaar_data IS NOT NULL
           AND s.malwarebazaar_data::jsonb <> '{{}}'::jsonb
           AND COALESCE(s.malwarebazaar_data::jsonb->>'source', '') NOT IN ('', 'malshare')
          THEN 'malwarebazaar'
          ELSE NULL
        END) AS effective_source,
        (ls.source IS NOT NULL) AS source_row_exists,
        ls.dataset_role,
        ls.family_hint,
        ls.source_data
      FROM samples s
      LEFT JOIN latest_sources ls ON ls.sample_id = s.id AND ls.rn = 1
    )
    SELECT
      s.id AS sample_id,
      s.sha256,
      s.file_name,
      s.file_type,
      s.detected_arch,
      s.file_size,
      s.stored_file_path,
      cs.effective_source,
      cs.source_row_exists,
      cs.dataset_role,
      cs.family_hint,
      cs.source_data,
      s.malwarebazaar_data,
      COALESCE(sc.code, '') AS status,
      lv.candidate_state,
      lv.candidate_local_path,
      lv.retrieval_method,
      COALESCE(lv.attempt_count, 0) AS attempt_count,
      lv.last_error,
      COALESCE(lr.detected, false) AS validated_detected,
      (lr.sample_id IS NOT NULL) AS already_validated
    FROM samples s
    JOIN candidate_sources cs ON cs.sample_id = s.id
    LEFT JOIN status_catalog sc ON sc.id = s.status_id
    LEFT JOIN latest_validation lv ON lv.sample_id = s.id AND lv.rn = 1
    LEFT JOIN latest_reports lr ON lr.sample_id = s.id AND lr.rn = 1
    WHERE (CAST(:source AS text) IS NULL OR cs.effective_source = CAST(:source AS text))
    ORDER BY s.created_at DESC, s.id DESC
    """
    return _rows(sql, {"source": source})


def _requested_sources(source: str | None) -> list[str | None]:
    if source in {None, "all"}:
        return [None]
    if source == "local":
        return [None]
    if source == "mixed":
        return ["malshare", "malwarebazaar"]
    return [source]


def _provider_order(sample: dict[str, Any], requested_source: str | None) -> list[str]:
    order = ["local"]
    effective_source = str(sample.get("effective_source") or "")
    if requested_source == "malshare":
        order.extend(["malshare", "malwarebazaar"])
    elif requested_source == "malwarebazaar":
        order.extend(["malwarebazaar", "malshare"])
    elif requested_source == "local":
        return order
    elif effective_source == "malshare":
        order.extend(["malshare", "malwarebazaar"])
    else:
        order.extend(["malwarebazaar", "malshare"])
    seen: set[str] = set()
    unique: list[str] = []
    for item in order:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _normalize_requested_arch(value: str | None) -> str | None:
    if value in {None, "auto"}:
        return None
    return value


def _assess_candidate(
    candidate: dict[str, Any],
    *,
    requested_source: str | None,
    arch: str | None,
    include_unknown: bool,
    include_non_pe: bool,
    include_validated: bool,
    providers: dict[str, MalwareSampleProvider],
    cfg,
) -> dict[str, Any]:
    path = _binary_path_for_sample(candidate, cfg=cfg)
    profile = _file_profile(path, candidate.get("file_type"), candidate.get("detected_arch"))
    item = {
        **candidate,
        "binary_path_used": str(path),
        **profile,
    }
    if item.get("status") == "excluded_non_ransomware" and not _known_validation_role(item.get("dataset_role")):
        return {**item, "eligible": False, "skip_reason": "excluded_non_ransomware"}
    if item.get("already_validated") and not include_validated:
        return {**item, "eligible": False, "skip_reason": "already_validated"}
    if not include_non_pe and not item["is_windows_executable"]:
        return {**item, "eligible": False, "skip_reason": "non_pe"}
    effective_arch = item["effective_arch"]
    if arch:
        if effective_arch == arch:
            item["arch_match"] = "exact"
        elif effective_arch == "unknown" and include_unknown:
            item["arch_match"] = "fallback_unknown"
        else:
            return {**item, "eligible": False, "skip_reason": "arch_mismatch"}
    else:
        item["arch_match"] = "not_requested"

    provider_attempts: list[dict[str, Any]] = []
    selected_provider: str | None = None
    retrieval_method: str | None = None
    local_path: str | None = None
    requires_fetch = False
    for provider_name in _provider_order(item, requested_source):
        provider = providers[provider_name]
        plan = provider.can_fetch(item)
        provider_attempts.append(
            {
                "provider": provider_name,
                "available": plan.available,
                "reason": plan.reason,
            }
        )
        if not plan.available:
            continue
        selected_provider = provider_name
        if provider_name == "local":
            local_path = str(path)
            retrieval_method = "local_path"
        else:
            local_path = None
            retrieval_method = f"{provider_name}_download"
            requires_fetch = True
        break

    if not selected_provider:
        return {
            **item,
            "eligible": False,
            "skip_reason": "no_retrieval_path",
            "provider_attempts": provider_attempts,
        }

    return {
        **item,
        "eligible": True,
        "skip_reason": None,
        "provider_attempts": provider_attempts,
        "selected_provider": selected_provider,
        "retrieval_method": retrieval_method,
        "local_path": local_path,
        "requires_fetch": requires_fetch,
        "recommended_vm": _recommended_vm_for_candidate(item, cfg),
    }


def collect_sample_candidates(
    *,
    source: str | None,
    arch: str | None,
    limit: int,
    include_unknown: bool,
    include_non_pe: bool,
    include_validated: bool = False,
    shuffle: bool = False,
) -> dict[str, Any]:
    cfg = _vr_config()
    providers = _sample_providers()
    requested_arch = _normalize_requested_arch(arch)
    scanned: list[dict[str, Any]] = []
    for requested_source in _requested_sources(source):
        for row in _select_rows(source=requested_source):
            scanned.append(row)
    deduped: dict[int, dict[str, Any]] = {}
    for row in scanned:
        deduped.setdefault(int(row["sample_id"]), row)
    candidates = list(deduped.values())
    if shuffle:
        random.shuffle(candidates)
    else:
        candidates.sort(
            key=lambda item: (
                not Path(str(item.get("stored_file_path") or "")).is_file(),
                str(item.get("effective_source") or "zzz"),
                -int(item.get("sample_id") or 0),
            )
        )

    evaluated = [
        _assess_candidate(
            item,
            requested_source=source,
            arch=requested_arch,
            include_unknown=include_unknown,
            include_non_pe=include_non_pe,
            include_validated=include_validated,
            providers=providers,
            cfg=cfg,
        )
        for item in candidates
    ]
    accepted = [item for item in evaluated if item.get("eligible")][:limit]
    rejected = [item for item in evaluated if not item.get("eligible")]

    rejection_summary: dict[str, int] = {}
    source_summary: dict[str, dict[str, int]] = {}
    stats = {
        "total_samples_scanned": len(evaluated),
        "eligible_total": 0,
        "local_ready_total": 0,
        "fetch_required_total": 0,
        "already_validated_total": 0,
    }
    for row in evaluated:
        effective_source = str(row.get("effective_source") or "unknown")
        bucket = source_summary.setdefault(effective_source, {"eligible": 0, "rejected": 0, "selected": 0})
        if row.get("eligible"):
            bucket["eligible"] += 1
            stats["eligible_total"] += 1
            if row.get("requires_fetch"):
                stats["fetch_required_total"] += 1
            else:
                stats["local_ready_total"] += 1
        else:
            bucket["rejected"] += 1
            reason = str(row.get("skip_reason") or "unknown")
            rejection_summary[reason] = rejection_summary.get(reason, 0) + 1
        if row.get("already_validated"):
            stats["already_validated_total"] += 1
    for row in accepted:
        bucket = source_summary.setdefault(str(row.get("effective_source") or "unknown"), {"eligible": 0, "rejected": 0, "selected": 0})
        bucket["selected"] += 1

    return {
        "generated_at": _now(),
        "requested_source": source or "all",
        "selected_source": source or "all",
        "selection_rules": {
            "base_table": "samples",
            "source_filter_mode": "metadata_only",
            "cape_required": False,
            "ioc_report_required": False,
            "validated_excluded": not include_validated,
        },
        "provider_health": {
            name: provider.healthcheck().__dict__
            for name, provider in providers.items()
        },
        "stats": stats,
        "rejection_summary": rejection_summary,
        "source_summary": source_summary,
        "candidates": accepted,
        "rejected": rejected,
    }


def fetch_candidate_binary(sample: dict[str, Any]) -> dict[str, Any]:
    providers = _sample_providers()
    provider_name = str(sample.get("selected_provider") or "local")
    provider = providers[provider_name]
    result = provider.fetch(sample)
    return {
        **sample,
        "fetch_result": {
            "provider": result.provider,
            "local_path": result.local_path,
            "retrieval_method": result.retrieval_method,
            "fetched": result.fetched,
            "error": result.error,
        },
        "local_path": result.local_path or sample.get("local_path"),
        "retrieval_method": result.retrieval_method or sample.get("retrieval_method"),
    }


def persist_candidate_state(
    sample: dict[str, Any],
    *,
    state: str,
    batch_id: str | None,
    last_error: str | None = None,
    increment_attempt: bool = False,
) -> None:
    if "velociraptor_validation_candidates" not in _existing_tables():
        return
    with session_scope() as session:
        row = session.query(VelociraptorValidationCandidate).filter_by(sample_id=int(sample["sample_id"])).one_or_none()
        if row is None:
            row = VelociraptorValidationCandidate(
                sample_id=int(sample["sample_id"]),
                sha256=str(sample.get("sha256") or ""),
            )
            session.add(row)
        row.sha256 = str(sample.get("sha256") or row.sha256)
        row.source = str(sample.get("effective_source") or sample.get("source") or row.source or "")
        row.local_path = str(sample.get("local_path") or "") or None
        row.candidate_state = state
        row.batch_id = batch_id
        row.retrieval_method = str(sample.get("retrieval_method") or row.retrieval_method or "") or None
        row.last_error = last_error
        row.updated_at = datetime.now(UTC)
        if state == "selected":
            row.selected_at = datetime.now(UTC)
        if increment_attempt:
            row.last_attempt_at = datetime.now(UTC)
            row.attempt_count = int(row.attempt_count or 0) + 1


def _resolve_sample(args: argparse.Namespace) -> dict[str, Any]:
    where_sql, params = _sample_where(args)
    sample = _one(
        f"""
        SELECT s.id AS sample_id, s.sha256, s.detected_arch, s.file_name,
               s.file_size, s.stored_file_path, s.processed_report_path,
               s.raw_report_path, ar.id AS analysis_run_id, ar.cape_task_id,
               ar.execution_arch, ar.cape_machine,
               COALESCE(bs.ransomware_score, 0) AS ransomware_score,
               COALESCE(bs.persistence_score, 0) AS persistence_score,
               COALESCE(bs.severity_score, 0) AS severity_score,
               COALESCE(bs.confidence_score, 0) AS confidence_score,
               (cr.id IS NOT NULL) AS has_cape_report,
               (ir.analysis_run_id IS NOT NULL) AS has_ioc_report
        FROM samples s
        LEFT JOIN analysis_runs ar ON ar.sample_id = s.id AND ar.state = 'done'
        LEFT JOIN sample_behavior_scores bs ON bs.sample_id = s.id
        LEFT JOIN cape_reports cr ON cr.analysis_run_id = ar.id
        LEFT JOIN ioc_reports ir ON ir.analysis_run_id = ar.id
        WHERE {where_sql}
        ORDER BY ar.id DESC NULLS LAST
        LIMIT 1
        """,
        params,
    )
    if not sample:
        raise SystemExit("Sample not found")
    return sample


def select_samples(args: argparse.Namespace) -> None:
    include_unknown = args.arch not in {None, "auto"} and not args.exclude_unknown
    payload = collect_sample_candidates(
        source=args.source,
        arch=args.arch,
        limit=args.limit,
        include_unknown=include_unknown,
        include_non_pe=args.include_non_pe,
        include_validated=args.include_validated,
        shuffle=args.shuffle,
    )
    if args.output:
        output = Path(args.output)
        if output.suffix.lower() == ".csv":
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("w", newline="", encoding="utf-8") as handle:
                candidates = payload["candidates"]
                writer = csv.DictWriter(handle, fieldnames=list(candidates[0].keys()) if candidates else [])
                if candidates:
                    writer.writeheader()
                    writer.writerows(candidates)
        else:
            write_json(output, payload)
    _print_json(payload)


def expected_iocs(sample_id: int) -> dict[str, Any]:
    sample = _one(
        """
        SELECT s.id AS sample_id, s.sha256, s.detected_arch, s.file_size,
               s.stored_file_path, ar.id AS analysis_run_id,
               ar.cape_task_id, ar.execution_arch, ar.cape_machine
        FROM samples s
        LEFT JOIN analysis_runs ar ON ar.sample_id = s.id AND ar.state = 'done'
        WHERE s.id = :sample_id
        ORDER BY ar.id DESC NULLS LAST
        LIMIT 1
        """,
        {"sample_id": sample_id},
    )
    iocs = _rows(
        """
        SELECT type, value, source, confidence
        FROM sample_iocs
        WHERE sample_id = :sample_id
        ORDER BY type, value
        """,
        {"sample_id": sample_id},
    )
    artifacts = _rows(
        """
        SELECT artifact_type, artifact_value, source, confidence
        FROM sample_artifacts
        WHERE sample_id = :sample_id
        ORDER BY artifact_type, artifact_value
        """,
        {"sample_id": sample_id},
    )
    return {"sample": sample, "iocs": iocs, "artifacts": artifacts}


def prepare_sample_package(args: argparse.Namespace) -> None:
    _require_execute(args, "confirm_malware_handling")
    cfg = _vr_config()
    sample = _resolve_sample(args)
    source = _binary_path_for_sample(sample, cfg=cfg)
    source_exists = source.exists() and source.is_file()
    vm_name = args.vm or _vm_for_arch(
        str(sample.get("execution_arch") or sample.get("detected_arch") or "unknown"),
        cfg=cfg,
    )
    allowed_vms = _allowed_vms(cfg=cfg)
    if vm_name not in allowed_vms:
        raise SystemExit(f"VM not allowed: {vm_name}")
    dest_dir = _result_dir(sample["sha256"], vm_name)
    staging = dest_dir / "staging"
    dest = staging / sample["sha256"]
    guest_dir = f"C:\\vr-malware-test\\{sample['sha256']}"
    payload = {
        "execute": args.execute,
        "source": str(source),
        "source_exists": source_exists,
        "destination": str(dest),
        "result_dir": str(dest_dir),
        "staging_dir": str(staging),
        "vm_name": vm_name,
        "http_bind": args.http_bind,
        "http_command": [
            "python3",
            "-m",
            "http.server",
            str(args.http_port),
            "--bind",
            args.http_bind,
            "--directory",
            str(staging),
        ],
        "guest_download_url": f"http://{args.http_bind}:{args.http_port}/{sample['sha256']}",
        "guest_directory": guest_dir,
        "copied_sample": False,
        "sample": sample,
    }
    try:
        ensure_safe_staging_bind(args.http_bind)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if args.execute and not source_exists:
        raise SystemExit(f"Stored sample missing: {source}")
    staging.mkdir(parents=True, exist_ok=True)
    write_json(dest_dir / "sample_metadata.json", {**sample, "source_exists": source_exists})
    write_json(dest_dir / "expected_iocs.json", expected_iocs(int(sample["sample_id"])))
    (dest_dir / "execution_notes.md").write_text(
        "# Execution Notes\n\n"
        f"- sample: `{sample['sha256']}`\n"
        f"- vm: `{vm_name}`\n"
        "- prepare via `threattrace vr prepare`\n"
        "- execute manually inside guest only\n"
        "- wait: 5 minutes first pass\n"
        "- collect via `threattrace vr collect`\n"
        "- export via `threattrace vr export`\n"
        "- revert snapshot after collection\n",
        encoding="utf-8",
    )
    (dest_dir / "transfer_instructions.md").write_text(
        "# Transfer Instructions\n\n"
        f"Host HTTP, when approved later:\n\n"
        "```bash\n"
        f"python3 -m http.server {args.http_port} --bind {args.http_bind} --directory {staging}\n"
        "```\n\n"
        f"Guest URL: `http://{args.http_bind}:{args.http_port}/{sample['sha256']}`\n\n"
        f"Guest directory: `{guest_dir}`\n",
        encoding="utf-8",
    )
    (dest_dir / "recommended_collections.md").write_text(
        "# Recommended Collections\n\n"
        + "\n".join(f"- `{artifact}`" for artifact in THREATTRACE_ARTIFACTS)
        + "\n",
        encoding="utf-8",
    )
    if args.execute:
        shutil.copy2(source, dest)
        os.chmod(dest, 0o600)
        payload["copied_sample"] = True
    _print_json(payload)


def first_test_plan(args: argparse.Namespace) -> None:
    cfg = _vr_config()
    sample = _resolve_sample(args)
    vm_name = args.vm
    allowed_vms = _allowed_vms(cfg=cfg)
    if vm_name not in allowed_vms:
        raise SystemExit(f"VM not allowed: {vm_name}")
    dest_dir = _result_dir(sample["sha256"], vm_name)
    staging = dest_dir / "staging"
    guest_dir = f"C:\\vr-malware-test\\{sample['sha256']}"
    lines = [
        "# First Velociraptor Malware Validation Plan",
        "",
        f"- sample_id: `{sample['sample_id']}`",
        f"- sha256: `{sample['sha256']}`",
        f"- vm: `{vm_name}`",
        f"- snapshot: `{allowed_vms[vm_name]}`",
        f"- result_dir: `{dest_dir}`",
        "",
        "1. Revert VM to configured clean snapshot with `threattrace vr revert`.",
        "2. Prepare sample package with `threattrace vr prepare`; copy only with `--execute --confirm-malware-execution`.",
        f"3. Serve staging dir on configured non-wildcard bind: `python3 -m http.server 8000 --bind {DEFAULT_HTTP_BIND} --directory {staging}`.",
        f"4. Windows download path: `{guest_dir}`.",
        "5. Execute inside guest only after isolation checks and explicit operator confirmation.",
        "6. Wait window: 5 minutes first pass.",
        "7. Run targeted collections with `threattrace vr collect`:",
        *[f"   - `{artifact}`" for artifact in THREATTRACE_ARTIFACTS],
        "8. Export result rows with `threattrace vr export` into `raw_exports/`.",
        "9. Compare result with `threattrace vr compare`.",
        "10. Revert VM again with `threattrace vr revert`.",
        "",
    ]
    dest_dir.mkdir(parents=True, exist_ok=True)
    plan = "\n".join(lines)
    (dest_dir / "first_test_plan.md").write_text(plan, encoding="utf-8")
    print(plan)


def revert_client(args: argparse.Namespace) -> None:
    _require_execute(args)
    cfg = _vr_config()
    allowed_vms = _allowed_vms(cfg=cfg)
    if args.vm not in allowed_vms:
        raise SystemExit(f"VM not allowed: {args.vm}")
    vm = cfg.vm(args.vm)
    if args.snapshot != vm.snapshot:
        raise SystemExit(f"Snapshot must be {vm.snapshot}")
    baseline_last_seen = _client_last_seen(vm) if args.execute else None
    payload = {
        "baseline_last_seen_at": baseline_last_seen,
        "snapshot_info": _run_or_dry(snapshot_info_command(cfg, vm), args.execute),
        "revert": _run_or_dry(snapshot_revert_command(cfg, vm), args.execute),
    }
    domain_state = _command_output(domain_state_command(cfg, vm), args.execute)
    payload["domain_state"] = domain_state
    state_text = domain_state.get("stdout_text", "").lower()
    if args.execute and state_text == "paused":
        payload["domain_resume"] = _run_or_dry(domain_resume_command(cfg, vm), True)
        payload["domain_state_after_resume"] = _command_output(domain_state_command(cfg, vm), True)
        state_text = str(payload["domain_state_after_resume"].get("stdout_text") or "").lower()
    if args.execute and state_text != "running":
        payload["domain_start"] = _run_or_dry(domain_start_command(cfg, vm), True)
        payload["domain_state_after_start"] = _command_output(domain_state_command(cfg, vm), True)
    if args.execute and not args.skip_readiness_checks:
        payload["winrm_ready"] = _wait_for_port(vm.host, vm.winrm_port, args.wait_for_winrm_seconds, args.poll_seconds)
        payload["client_reconnected"] = _wait_for_client_reconnect(
            vm,
            baseline_last_seen,
            args.wait_for_client_seconds,
            args.poll_seconds,
        )
    _print_json(payload)


def list_flows(args: argparse.Namespace) -> None:
    cfg = _vr_config()
    vm = cfg.vm(args.vm)
    client_id = vm.client_id or (_client_row_for_vm(vm) or {}).get("client_id")
    if not client_id:
        raise SystemExit(f"No Velociraptor client_id found for {args.vm}")
    flows = _flow_rows(str(client_id), limit=args.limit)
    payload = {
        "vm": args.vm,
        "client_id": str(client_id),
        "flow_count": len(flows),
        "stale_candidates": _stale_flows(flows, args.min_age_seconds, args.include_rowful),
        "flows": flows,
    }
    _print_json(payload)


def cleanup_flows(args: argparse.Namespace) -> None:
    _require_execute(args)
    cfg = _vr_config()
    vm = cfg.vm(args.vm)
    client_id = vm.client_id or (_client_row_for_vm(vm) or {}).get("client_id")
    if not client_id:
        raise SystemExit(f"No Velociraptor client_id found for {args.vm}")
    flows = _flow_rows(str(client_id), limit=args.limit)
    stale = _stale_flows(flows, args.min_age_seconds, args.include_rowful)
    payload = {
        "vm": args.vm,
        "client_id": str(client_id),
        "canceled": [],
        "stale_candidates": stale,
    }
    if args.execute:
        for flow in stale:
            payload["canceled"].append(
                {
                    "session_id": flow["session_id"],
                    "result": _cancel_flow(str(client_id), str(flow["session_id"]), True),
                }
            )
    _print_json(payload)


def _vql_export(client_id: str, flow_id: str, artifact: str) -> str:
    return (
        "SELECT * FROM source("
        f"client_id={json.dumps(client_id)}, "
        f"flow_id={json.dumps(flow_id)}, "
        f"artifact={json.dumps(artifact)})"
    )


def _velociraptor_base() -> list[str]:
    config = os.environ.get("THREATTRACE_VELOCIRAPTOR_CONFIG")
    return velociraptor_base(config_path=config) if config else velociraptor_base()


def run_collection(args: argparse.Namespace) -> None:
    _require_execute(args)
    artifacts = args.artifact or list(THREATTRACE_ARTIFACTS)
    command = collection_command(args.client_id, artifacts)
    payload = _run_or_dry(command, args.execute)
    _print_json(payload)


def export_result(args: argparse.Namespace) -> None:
    _require_execute(args)
    if args.vm not in _allowed_vms():
        raise SystemExit(f"VM not allowed: {args.vm}")
    dest_dir = _result_dir(args.sha256, args.vm)
    raw_dir = dest_dir / "raw_exports"
    artifact = args.artifact
    command = _velociraptor_base() + ["query", "--format", "json", _vql_export(args.client_id, args.flow_id, artifact)]
    payload = _run_or_dry(command, args.execute)
    if args.execute:
        raw_dir.mkdir(parents=True, exist_ok=True)
        output_path = raw_dir / f"{artifact.replace('.', '_')}_{args.flow_id}.json"
        output_path.write_text(str(payload.get("stdout") or ""), encoding="utf-8")
    _print_json(payload)


def _flatten_values(value: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for item in value.values():
            out.update(_flatten_values(item))
    elif isinstance(value, list):
        for item in value:
            out.update(_flatten_values(item))
    elif value is not None:
        text_value = str(value).strip()
        if text_value:
            out.add(text_value.lower())
    return out


def compare_results(args: argparse.Namespace) -> None:
    base = Path(args.result_dir)
    expected = read_json(base / "expected_iocs.json")
    if expected is None:
        if not args.sample_id:
            raise SystemExit("Need expected_iocs.json or --sample-id")
        expected = expected_iocs(args.sample_id)
        write_json(base / "expected_iocs.json", expected)
    observed: dict[str, Any] = {}
    for filename in SUPPORTED_RESULT_FILES:
        loaded = read_json(base / filename)
        if loaded is not None:
            observed[filename] = loaded
    raw_values = _flatten_values(observed)
    expected_values = {
        str(item.get("value") or item.get("artifact_value") or "").lower()
        for group in ("iocs", "artifacts")
        for item in expected.get(group, [])
        if item.get("value") or item.get("artifact_value")
    }
    matches = sorted(value for value in expected_values if value and value in raw_values)
    comparison = {
        "generated_at": _now(),
        "result_dir": str(base),
        "expected_count": len(expected_values),
        "observed_value_count": len(raw_values),
        "matched_count": len(matches),
        "matched_values": matches,
        "unmatched_expected_values": sorted(expected_values - set(matches)),
    }
    write_json(base / "comparison.json", comparison)
    _print_json(comparison)


def validation_status(args: argparse.Namespace) -> None:
    root = Path(args.root)
    allowed_vms = _allowed_vms()
    live_result = list_live_clients(execute=True, limit=args.live_limit)
    live_clients = lookup_rows(live_result)
    live_source = "vql"
    if not live_clients:
        live_clients = live_clients_from_logs(limit=args.live_limit)
        live_source = "journalctl" if live_clients else "none"
    results = []
    for sample_dir in sorted((root / "results").glob("*")) if (root / "results").exists() else []:
        for vm_dir in sorted(path for path in sample_dir.iterdir() if path.is_dir()):
            results.append(
                {
                    "sha256": sample_dir.name,
                    "vm_name": vm_dir.name,
                    "has_sample_metadata": (vm_dir / "sample_metadata.json").exists(),
                    "has_expected_iocs": (vm_dir / "expected_iocs.json").exists(),
                    "has_summary": (vm_dir / "velociraptor_collection_summary.json").exists(),
                    "has_comparison": (vm_dir / "comparison.json").exists(),
                    "raw_export_count": len(list((vm_dir / "raw_exports").glob("*"))) if (vm_dir / "raw_exports").exists() else 0,
                }
            )
    _print_json(
        {
            "root": str(root),
            "allowed_vms": allowed_vms,
            "default_artifacts": THREATTRACE_ARTIFACTS,
            "live_clients_source": live_source,
            "live_clients_command": live_result.command,
            "live_clients_returncode": live_result.returncode,
            "live_clients": live_clients,
            "results": results,
        }
    )


def record_evaluation(args: argparse.Namespace) -> None:
    _require_execute(args, "confirm_db_write")
    base = Path(args.result_dir)
    metadata = read_json(base / "sample_metadata.json") or {}
    comparison = read_json(base / "comparison.json") or {}
    summary = read_json(base / "velociraptor_collection_summary.json") or {}
    sample_id = int(args.sample_id or metadata.get("sample_id") or 0)
    if not sample_id:
        raise SystemExit("Need sample_id from metadata or --sample-id")
    detector = args.detector
    detected = bool(args.detected or comparison.get("matched_count", 0) or summary.get("detected"))
    params = {
        "sample_id": sample_id,
        "analysis_run_id": args.analysis_run_id or metadata.get("analysis_run_id"),
        "source": VALIDATION_SOURCE,
        "dataset_role": VALIDATION_DATASET_ROLE,
        "detector": detector,
        "architecture": args.architecture or metadata.get("detected_arch") or "unknown",
        "test_machine": args.vm,
        "detected": detected,
        "detection_time_seconds": args.detection_time_seconds,
        "triggered_rules": json.dumps(summary.get("triggered_rules", [])),
        "triggered_iocs": json.dumps(comparison.get("matched_values", [])),
        "triggered_artifacts": json.dumps(summary.get("triggered_artifacts", [])),
        "velociraptor_report_path": str(base),
        "cape_task_id": args.cape_task_id or metadata.get("cape_task_id"),
        "notes": args.notes,
    }
    if not args.execute:
        _print_json({"execute": False, "params": params})
        return
    sql = """
    SELECT id FROM detection_evaluations
    WHERE sample_id = :sample_id
      AND detector = :detector
      AND test_machine = :test_machine
      AND dataset_role = :dataset_role
    LIMIT 1
    """
    with session_scope() as session:
        existing = session.execute(text(sql), params).scalar_one_or_none()
        if existing:
            session.execute(
                text(
                    """
                    UPDATE detection_evaluations
                    SET analysis_run_id = :analysis_run_id,
                        source = :source,
                        architecture = :architecture,
                        detected = :detected,
                        detection_time_seconds = :detection_time_seconds,
                        triggered_rules = CAST(:triggered_rules AS jsonb),
                        triggered_iocs = CAST(:triggered_iocs AS jsonb),
                        triggered_artifacts = CAST(:triggered_artifacts AS jsonb),
                        velociraptor_report_path = :velociraptor_report_path,
                        cape_task_id = :cape_task_id,
                        notes = :notes,
                        updated_at = now()
                    WHERE id = :id
                    """
                ),
                {**params, "id": existing},
            )
            evaluation_id = existing
        else:
            evaluation_id = session.execute(
                text(
                    """
                    INSERT INTO detection_evaluations (
                      sample_id, analysis_run_id, source, dataset_role, detector,
                      architecture, test_machine, detected, detection_time_seconds,
                      triggered_rules, triggered_iocs, triggered_artifacts,
                      velociraptor_report_path, cape_task_id, notes
                    ) VALUES (
                      :sample_id, :analysis_run_id, :source, :dataset_role, :detector,
                      :architecture, :test_machine, :detected, :detection_time_seconds,
                      CAST(:triggered_rules AS jsonb), CAST(:triggered_iocs AS jsonb),
                      CAST(:triggered_artifacts AS jsonb), :velociraptor_report_path,
                      :cape_task_id, :notes
                    )
                    RETURNING id
                    """
                ),
                params,
            ).scalar_one()
        session.execute(
            text(
                """
                INSERT INTO velociraptor_reports (evaluation_id, report_path, raw_report)
                VALUES (:evaluation_id, :report_path, CAST(:raw_report AS jsonb))
                """
            ),
            {
                "evaluation_id": evaluation_id,
                "report_path": str(base),
                "raw_report": json.dumps({"summary": summary, "comparison": comparison}),
            },
        )
    _print_json({"execute": True, "evaluation_id": evaluation_id})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Controlled Velociraptor validation helpers")
    sub = parser.add_subparsers(dest="command", required=True)
    allowed_vm_names = sorted(_allowed_vms())

    select = sub.add_parser("select-samples")
    select.add_argument("--arch", choices=["auto", "x86", "x64"], default="auto")
    select.add_argument("--source", choices=["all", "local", "malshare", "malwarebazaar", "mixed"], default="all")
    select.add_argument("--exclude-unknown", action="store_true")
    select.add_argument("--include-validated", action="store_true")
    select.add_argument("--include-non-pe", action="store_true")
    select.add_argument("--shuffle", action="store_true")
    select.add_argument("--limit", type=int, default=50)
    select.add_argument("--output")
    select.set_defaults(func=select_samples)

    prep = sub.add_parser("prepare-sample-package")
    prep.add_argument("--sample-id", type=int)
    prep.add_argument("--sha256")
    prep.add_argument("--vm", choices=allowed_vm_names)
    prep.add_argument("--http-bind", default=DEFAULT_HTTP_BIND)
    prep.add_argument("--http-port", type=int, default=8000)
    prep.add_argument("--execute", action="store_true")
    prep.add_argument("--confirm-malware-handling", action="store_true")
    prep.set_defaults(func=prepare_sample_package)

    first = sub.add_parser("first-test-plan")
    first.add_argument("--sample-id", type=int)
    first.add_argument("--sha256")
    first.add_argument("--vm", required=True, choices=allowed_vm_names)
    first.set_defaults(func=first_test_plan)

    revert = sub.add_parser("revert-client")
    revert.add_argument("--vm", required=True, choices=allowed_vm_names)
    revert.add_argument("--snapshot", required=True)
    revert.add_argument("--execute", action="store_true")
    revert.add_argument("--wait-for-winrm-seconds", type=int, default=180)
    revert.add_argument("--wait-for-client-seconds", type=int, default=180)
    revert.add_argument("--poll-seconds", type=int, default=5)
    revert.add_argument("--skip-readiness-checks", action="store_true")
    revert.set_defaults(func=revert_client)

    flows = sub.add_parser("list-flows")
    flows.add_argument("--vm", required=True, choices=allowed_vm_names)
    flows.add_argument("--limit", type=int, default=50)
    flows.add_argument("--min-age-seconds", type=int, default=300)
    flows.add_argument("--include-rowful", action="store_true")
    flows.set_defaults(func=list_flows)

    cleanup = sub.add_parser("cleanup-flows")
    cleanup.add_argument("--vm", required=True, choices=allowed_vm_names)
    cleanup.add_argument("--limit", type=int, default=50)
    cleanup.add_argument("--min-age-seconds", type=int, default=300)
    cleanup.add_argument("--include-rowful", action="store_true")
    cleanup.add_argument("--execute", action="store_true")
    cleanup.set_defaults(func=cleanup_flows)

    collect = sub.add_parser("run-collection")
    collect.add_argument("--client-id", required=True)
    collect.add_argument("--artifact", action="append")
    collect.add_argument("--execute", action="store_true")
    collect.set_defaults(func=run_collection)

    export = sub.add_parser("export-result")
    export.add_argument("--client-id", required=True)
    export.add_argument("--flow-id", required=True)
    export.add_argument("--artifact", required=True)
    export.add_argument("--sha256", required=True)
    export.add_argument("--vm", required=True, choices=allowed_vm_names)
    export.add_argument("--execute", action="store_true")
    export.set_defaults(func=export_result)

    compare = sub.add_parser("compare-results")
    compare.add_argument("--result-dir", required=True)
    compare.add_argument("--sample-id", type=int)
    compare.set_defaults(func=compare_results)

    record = sub.add_parser("record-evaluation")
    record.add_argument("--result-dir", required=True)
    record.add_argument("--vm", required=True, choices=allowed_vm_names)
    record.add_argument("--detector", default="Windows.ThreatTrace.Ransomware.HighConfidenceBundle")
    record.add_argument("--sample-id", type=int)
    record.add_argument("--analysis-run-id", type=int)
    record.add_argument("--cape-task-id", type=int)
    record.add_argument("--architecture")
    record.add_argument("--detection-time-seconds", type=float)
    record.add_argument("--detected", action="store_true")
    record.add_argument("--notes")
    record.add_argument("--execute", action="store_true")
    record.add_argument("--confirm-db-write", action="store_true")
    record.set_defaults(func=record_evaluation)

    status = sub.add_parser("status")
    status.add_argument("--root", default=str(RESULT_ROOT))
    status.add_argument("--live-limit", type=int, default=10)
    status.set_defaults(func=validation_status)
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
