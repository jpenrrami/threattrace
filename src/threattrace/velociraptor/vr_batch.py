from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threattrace.common.io import write_json
from threattrace.common.json_config import config_path, load_json_config
from threattrace.common.time import utcnow_iso
from threattrace.config.settings import get_settings
from threattrace.velociraptor.vr_process_sample import process_sample
from threattrace.velociraptor.vr_validation import (
    collect_sample_candidates,
    fetch_candidate_binary,
    persist_candidate_state,
)

BATCH_RULES_PATH = config_path("velociraptor", "batch_rules.json")


def _batch_rules() -> dict[str, Any]:
    return load_json_config(str(BATCH_RULES_PATH))


READY_FOR_EXECUTION = str(_batch_rules()["states"]["ready_for_execution"])
READY_FOR_MANUAL_EXECUTION = str(_batch_rules()["states"]["ready_for_manual_execution"])
RUNNING_SAMPLE = str(_batch_rules()["states"]["running_sample"])
SAMPLE_STAGED = str(_batch_rules()["states"]["sample_staged"])
SAMPLE_EXECUTED = str(_batch_rules()["states"]["sample_executed"])
OBSERVATION_WAIT = str(_batch_rules()["states"]["observation_wait"])
COLLECTIONS_RUNNING = str(_batch_rules()["states"]["collections_running"])
EXPORTING_RESULTS = str(_batch_rules()["states"]["exporting_results"])
SAMPLE_DONE = str(_batch_rules()["states"]["sample_done"])
SAMPLE_FAILED = str(_batch_rules()["states"]["sample_failed"])
SAMPLE_BLOCKED = str(_batch_rules()["states"]["sample_blocked"])
BATCH_DONE = str(_batch_rules()["states"]["batch_done"])
BATCH_FAILED = str(_batch_rules()["states"]["batch_failed"])


def now() -> str:
    return utcnow_iso()


@dataclass
class BatchState:
    batch_dir: Path
    state: str = READY_FOR_EXECUTION
    current_sample_id: int | None = None
    completed_sample_ids: list[int] | None = None
    failed_sample_ids: list[int] | None = None
    blocked_sample_ids: list[int] | None = None
    updated_at: str = ""

    @property
    def path(self) -> Path:
        return self.batch_dir / "batch_state.json"

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "current_sample_id": self.current_sample_id,
            "completed_sample_ids": self.completed_sample_ids or [],
            "failed_sample_ids": self.failed_sample_ids or [],
            "blocked_sample_ids": self.blocked_sample_ids or [],
            "updated_at": self.updated_at or now(),
        }

    def write(self) -> None:
        self.updated_at = now()
        write_json(self.path, self.as_dict())


def load_state(batch_dir: Path) -> BatchState:
    path = batch_dir / "batch_state.json"
    if not path.exists():
        return BatchState(batch_dir=batch_dir)
    data = load_json_config(str(path))
    return BatchState(
        batch_dir=batch_dir,
        state=data.get("state", READY_FOR_EXECUTION),
        current_sample_id=data.get("current_sample_id"),
        completed_sample_ids=list(data.get("completed_sample_ids") or []),
        failed_sample_ids=list(data.get("failed_sample_ids") or []),
        blocked_sample_ids=list(data.get("blocked_sample_ids") or []),
        updated_at=data.get("updated_at") or "",
    )


def load_selected_samples(batch_dir: Path) -> list[dict[str, Any]]:
    selected = batch_dir / "selected_samples.json"
    if not selected.exists():
        raise FileNotFoundError(f"Missing selected_samples.json in {batch_dir}")
    data = load_json_config(str(selected))
    if isinstance(data, dict):
        return list(data.get("candidates") or data.get("samples") or [])
    if isinstance(data, list):
        return data
    raise ValueError("selected_samples.json must be a list or object with candidates")


def _batch_dir(source: str, batch_id: str | None = None) -> Path:
    if batch_id:
        return get_settings().storage_root / "velociraptor_batch_logs" / batch_id
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    preferred_root = get_settings().storage_root
    try:
        preferred_root.mkdir(parents=True, exist_ok=True)
        root = preferred_root
    except OSError:
        root = Path.cwd() / "runtime_storage"
        root.mkdir(parents=True, exist_ok=True)
    return root / "velociraptor_batch_logs" / f"{stamp}_{source}"


def _load_plan(args: argparse.Namespace, batch_dir: Path) -> dict[str, Any]:
    if getattr(args, "resume", False):
        return {
            "generated_at": now(),
            "source": args.source,
            "limit": args.limit,
            "selection": {"stats": {}, "source_summary": {}, "rejection_summary": {}},
            "selected_sample_ids": [int(item["sample_id"]) for item in load_selected_samples(batch_dir)],
            "samples": load_selected_samples(batch_dir),
            "skipped_selection": [],
        }
    return build_batch_plan(args)


def _is_vm_error(message: str | None) -> bool:
    lowered = str(message or "").lower()
    return any(
        token in lowered
        for token in (
            "winrm",
            "vm",
            "snapshot",
            "client",
            "flow_completion_timeout",
            "no_new_flow_created",
            "ambiguous_new_flows_created",
            "flow_id_mismatch",
            "flow_status_missing",
        )
    )


def _resolve_vm(sample: dict[str, Any], requested_vm: str, include_unknown_arch: bool) -> tuple[str | None, str | None]:
    if requested_vm != "auto":
        return requested_vm, None
    effective_arch = str(sample.get("effective_arch") or "unknown")
    recommended_vm = sample.get("recommended_vm")
    if effective_arch == "unknown" and not include_unknown_arch:
        return None, "unknown_arch"
    if not recommended_vm:
        return None, "no_recommended_vm"
    return str(recommended_vm), None


def _resolve_client_id_for_vm(args: argparse.Namespace, vm_name: str) -> str | None:
    if getattr(args, "client_id", None):
        return args.client_id
    if vm_name.endswith("x64"):
        return getattr(args, "x64_client_id", None)
    if vm_name.endswith("x86"):
        return getattr(args, "x86_client_id", None)
    return None


def _append_unique(values: list[int], value: int) -> None:
    if value not in values:
        values.append(value)


def _requested_arch(args: argparse.Namespace) -> str | None:
    return None if args.architecture == "auto" else args.architecture


def build_batch_plan(args: argparse.Namespace) -> dict[str, Any]:
    payload = collect_sample_candidates(
        source=args.source,
        arch=_requested_arch(args),
        limit=max(args.limit * 4, args.limit),
        include_unknown=args.architecture == "auto" or args.include_unknown_arch,
        include_non_pe=args.include_non_pe,
        include_validated=args.include_validated,
        shuffle=args.shuffle,
    )
    accepted = list(payload["candidates"])
    if args.source == "mixed":
        malshare = [item for item in accepted if item.get("effective_source") == "malshare"]
        malwarebazaar = [item for item in accepted if item.get("effective_source") == "malwarebazaar"]
        mixed: list[dict[str, Any]] = []
        while (malshare or malwarebazaar) and len(mixed) < args.limit:
            if malshare:
                mixed.append(malshare.pop(0))
                if len(mixed) >= args.limit:
                    break
            if malwarebazaar:
                mixed.append(malwarebazaar.pop(0))
        selected = mixed
    else:
        selected = accepted[: args.limit]

    planned_samples: list[dict[str, Any]] = []
    skipped_selection: list[dict[str, Any]] = []
    for sample in selected:
        vm_name, skip_reason = _resolve_vm(sample, args.vm, args.include_unknown_arch)
        planned = {**sample, "planned_vm": vm_name, "skip_reason": skip_reason}
        if skip_reason:
            skipped_selection.append(planned)
        planned_samples.append(planned)

    return {
        "generated_at": now(),
        "source": args.source,
        "limit": args.limit,
        "selection": payload,
        "selected_sample_ids": [int(item["sample_id"]) for item in planned_samples],
        "samples": planned_samples,
        "skipped_selection": skipped_selection,
    }


def _sample_result_path(batch_dir: Path, sample_id: int) -> Path:
    return batch_dir / "samples" / f"{sample_id}.json"


def _diagnostic_recommendations(payload: dict[str, Any]) -> list[str]:
    recs: list[str] = []
    summary = payload.get("collection") or {}
    artifacts = list(payload.get("artifact_flows", {}).keys())
    if "Windows.ThreatTrace.Ransomware.Persistence.ScheduledTasks" not in artifacts:
        recs.append("add scheduled task artifact to default batch collection")
    if "Windows.ThreatTrace.Ransomware.LOLBins" in artifacts:
        recs.append("expand LOLBin matching for cmd, wscript, cscript, mshta")
    if payload.get("collection_failed"):
        recs.append("fix collection failure before judging artifact quality")
    if not payload.get("artifact_flows"):
        recs.append("verify artifact definitions loaded on server")
    if summary:
        recs.append("review no-hit artifacts against dropped files, persistence, process, and temp/AppData writes")
    return recs


def _no_detection_report(sample: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    artifact_flows = payload.get("artifact_flows") or {}
    collections_used = list(artifact_flows)
    collection_errors = {
        name: details.get("collection_failure_reason")
        for name, details in artifact_flows.items()
        if details.get("collection_failure_reason")
    }
    observable = [name for name, details in artifact_flows.items() if ((details.get("export") or {}).get("output_path"))]
    missing = [name for name in collections_used if name not in observable]
    return {
        "sample_id": int(sample["sample_id"]),
        "sha256": sample.get("sha256"),
        "source": sample.get("effective_source"),
        "architecture": sample.get("effective_arch"),
        "executed_command": ((payload.get("winrm_execution_log") or {}).get("command") or payload.get("planned_winrm_command")),
        "collections_used": collections_used,
        "collection_errors": collection_errors,
        "observable_artifacts_found": observable,
        "missing_expected_artifacts": missing,
        "recommendations": _diagnostic_recommendations(payload),
    }


def _finalize_summary(summary: dict[str, Any]) -> None:
    samples = summary["samples"]
    summary["samples_executed"] = len([item for item in samples if item.get("return_code") == 0])
    summary["samples_with_detections"] = len([item for item in samples if item.get("detected")])
    summary["samples_without_detections"] = len([item for item in samples if item.get("return_code") == 0 and not item.get("detected")])
    summary["collections_triggered"] = len([item for item in samples if item.get("collections_triggered")])
    summary["collections_empty"] = len([item for item in samples if item.get("collections_triggered") and not item.get("detected")])
    summary["artifact_errors"] = len([item for item in samples if item.get("collection_failed")])


def run_batch(args: argparse.Namespace) -> dict[str, Any]:
    if args.execute and not args.confirm_malware_execution:
        raise SystemExit("--execute requires --confirm-malware-execution")
    if args.execute and getattr(args, "no_flow_limit", False):
        raise SystemExit("--no-flow-limit is not allowed for execute runs")
    if args.vm == "auto" and args.client_id:
        raise SystemExit("--client-id requires an explicit --vm")
    resume = bool(getattr(args, "resume", False))
    batch_id = getattr(args, "batch_id", None)
    max_errors = int(getattr(args, "max_errors", 0) or 0)
    stop_on_vm_error = bool(getattr(args, "stop_on_vm_error", False))
    retry_failed = bool(getattr(args, "retry_failed", False))

    if resume and not batch_id:
        raise SystemExit("--resume requires --batch-id")
    batch_dir = _batch_dir(args.source, batch_id) if batch_id else _batch_dir(args.source)
    batch_dir.mkdir(parents=True, exist_ok=True)
    plan = _load_plan(args, batch_dir)
    if not resume:
        write_json(batch_dir / "selected_samples.json", {"candidates": plan["samples"]})
    state = load_state(batch_dir) if resume else BatchState(batch_dir=batch_dir)
    state.write()

    summary: dict[str, Any] = {
        "generated_at": now(),
        "source": args.source,
        "limit": args.limit,
        "execute": args.execute,
        "batch_dir": str(batch_dir),
        "selected_sample_ids": plan["selected_sample_ids"],
        "samples": [],
        "selection_stats": plan["selection"]["stats"],
        "source_summary": plan["selection"]["source_summary"],
        "rejection_summary": plan["selection"]["rejection_summary"],
    }
    if not args.execute or args.dry_run:
        summary["plan"] = plan
        _finalize_summary(summary)
        write_json(batch_dir / "batch_summary.json", summary)
        return summary

    completed: list[int] = []
    failed: list[int] = []
    blocked: list[int] = []
    if resume:
        completed = list(state.completed_sample_ids or [])
        failed = list(state.failed_sample_ids or [])
        blocked = list(state.blocked_sample_ids or [])
    for sample in plan["samples"]:
        sample_id = int(sample["sample_id"])
        if sample_id in completed:
            continue
        if resume and sample_id in failed and not retry_failed:
            continue
        state.current_sample_id = sample_id
        state.state = RUNNING_SAMPLE
        state.completed_sample_ids = completed
        state.failed_sample_ids = failed
        state.blocked_sample_ids = blocked
        state.write()

        planned_vm = sample.get("planned_vm")
        if not planned_vm:
            _append_unique(blocked, sample_id)
            sample_summary = {"sample_id": sample_id, "return_code": 1, "failure_reason": sample.get("skip_reason")}
            summary["samples"].append(sample_summary)
            write_json(_sample_result_path(batch_dir, sample_id), sample_summary)
            persist_candidate_state(sample, state="skipped", batch_id=batch_dir.name, last_error=str(sample.get("skip_reason") or "blocked"))
            if args.stop_on_error:
                break
            continue

        persist_candidate_state(sample, state="selected", batch_id=batch_dir.name)
        fetched_sample = sample
        if sample.get("requires_fetch"):
            fetched_sample = fetch_candidate_binary(sample)
            fetch_error = ((fetched_sample.get("fetch_result") or {}).get("error"))
            if fetch_error or not fetched_sample.get("local_path"):
                _append_unique(failed, sample_id)
                persist_candidate_state(sample, state="error", batch_id=batch_dir.name, last_error=str(fetch_error or "fetch_failed"), increment_attempt=True)
                sample_summary = {
                    "sample_id": sample_id,
                    "vm": planned_vm,
                    "return_code": 1,
                    "failure_reason": str(fetch_error or "fetch_failed"),
                    "retrieval_method": fetched_sample.get("retrieval_method"),
                }
                summary["samples"].append(sample_summary)
                write_json(_sample_result_path(batch_dir, sample_id), sample_summary)
                if args.stop_on_error or (max_errors and len(failed) >= max_errors) or (stop_on_vm_error and _is_vm_error(sample_summary["failure_reason"])):
                    break
                continue

        process_args = argparse.Namespace(
            sample_id=sample_id,
            vm=planned_vm,
            execute=True,
            confirm_malware_execution=True,
            wait_seconds=args.wait_seconds,
            http_port=args.http_port,
            winrm_timeout=args.winrm_timeout,
            flow_wait_timeout=None if args.no_flow_limit else args.flow_wait_timeout,
            flow_poll_seconds=args.flow_poll_seconds,
            client_id=getattr(args, "client_id", None),
            skip_final_revert=False,
            result_root=None,
            sample_path=fetched_sample.get("local_path"),
        )
        try:
            process_args.client_id = _resolve_client_id_for_vm(args, planned_vm)
            persist_candidate_state(fetched_sample, state="running", batch_id=batch_dir.name, increment_attempt=True)
            payload = process_sample(process_args)
            _append_unique(completed, sample_id)
            failed = [item for item in failed if item != sample_id]
            blocked = [item for item in blocked if item != sample_id]
            sample_summary = {
                "sample_id": sample_id,
                "vm": planned_vm,
                "return_code": 0,
                "archive_dir": (payload.get("archived_detection") or {}).get("archive_dir"),
                "detected": payload.get("detected"),
                "high_confidence_detected": payload.get("high_confidence_detected"),
                "collection_failed": payload.get("collection_failed"),
                "failure_reason": payload.get("collection_failure_reason"),
                "retrieval_method": fetched_sample.get("retrieval_method"),
                "local_path": fetched_sample.get("local_path"),
                "collections_triggered": bool(payload.get("artifact_flows")),
                "result_dir": payload.get("result_dir"),
            }
            summary["samples"].append(sample_summary)
            write_json(_sample_result_path(batch_dir, sample_id), payload)
            if payload.get("detected"):
                persist_candidate_state(fetched_sample, state="validated", batch_id=batch_dir.name)
            else:
                persist_candidate_state(fetched_sample, state="no_detection", batch_id=batch_dir.name)
        except SystemExit as exc:
            _append_unique(failed, sample_id)
            code = exc.code if isinstance(exc.code, int) else 1
            persist_candidate_state(fetched_sample, state="error", batch_id=batch_dir.name, last_error=str(exc))
            sample_summary = {"sample_id": sample_id, "vm": planned_vm, "return_code": code, "failure_reason": str(exc)}
            summary["samples"].append(sample_summary)
            write_json(_sample_result_path(batch_dir, sample_id), sample_summary)
            if args.stop_on_error or (max_errors and len(failed) >= max_errors) or (stop_on_vm_error and _is_vm_error(sample_summary["failure_reason"])):
                break
        except Exception as exc:
            _append_unique(failed, sample_id)
            persist_candidate_state(fetched_sample, state="error", batch_id=batch_dir.name, last_error=str(exc))
            sample_summary = {"sample_id": sample_id, "vm": planned_vm, "return_code": 1, "failure_reason": str(exc)}
            summary["samples"].append(sample_summary)
            write_json(_sample_result_path(batch_dir, sample_id), sample_summary)
            if args.stop_on_error or (max_errors and len(failed) >= max_errors) or (stop_on_vm_error and _is_vm_error(sample_summary["failure_reason"])):
                break

    state.current_sample_id = None
    state.completed_sample_ids = completed
    state.failed_sample_ids = failed
    state.blocked_sample_ids = blocked
    state.state = BATCH_DONE if not failed and not blocked else BATCH_FAILED
    state.write()
    summary["completed_sample_ids"] = completed
    summary["failed_sample_ids"] = failed
    summary["blocked_sample_ids"] = blocked
    no_detection_reports: list[dict[str, Any]] = []
    for sample in plan["samples"]:
        sample_path = _sample_result_path(batch_dir, int(sample["sample_id"]))
        if not sample_path.exists():
            continue
        payload = load_json_config(str(sample_path))
        if not isinstance(payload, dict):
            continue
        if payload.get("return_code", 0) != 0 or payload.get("detected", True):
            continue
        no_detection_reports.append(_no_detection_report(sample, payload))
    _finalize_summary(summary)
    write_json(batch_dir / "no_detection_report.json", no_detection_reports)
    write_json(batch_dir / "batch_summary.json", summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sequential Velociraptor batch validation")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--source", choices=["all", "local", "malshare", "malwarebazaar", "mixed"], default="all")
    parser.add_argument("--vm", default="auto", help="velo-win-x64, velo-win-x86, or auto")
    parser.add_argument("--architecture", choices=["auto", "x86", "x64"], default="auto")
    parser.add_argument("--wait-seconds", type=int, default=None)
    parser.add_argument("--http-port", type=int)
    parser.add_argument("--flow-wait-timeout", type=int, default=None)
    parser.add_argument("--flow-poll-seconds", type=int, default=10)
    parser.add_argument("--winrm-timeout", type=int, default=120)
    parser.add_argument("--include-unknown-arch", action="store_true")
    parser.add_argument("--include-validated", action="store_true")
    parser.add_argument("--include-non-pe", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--shuffle", action="store_true")
    parser.add_argument("--no-flow-limit", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-malware-execution", action="store_true")
    parser.add_argument("--stop-on-error", action="store_true")
    parser.add_argument("--stop-on-vm-error", action="store_true")
    parser.add_argument("--max-errors", type=int, default=0)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--batch-id")
    parser.add_argument("--client-id")
    parser.add_argument("--x64-client-id")
    parser.add_argument("--x86-client-id")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    print(json.dumps(run_batch(args), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
