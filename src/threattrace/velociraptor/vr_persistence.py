from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select

from threattrace.common.collections import coerce_dict, coerce_list
from threattrace.common.io import read_json_dict
from threattrace.db.models import DetectionEvaluation, VelociraptorArtifactResult, VelociraptorReport
from threattrace.db.session import session_scope
from threattrace.velociraptor.vr_config import DETECTION_ARCHIVE_ROOT, VALIDATION_DATASET_ROLE

DEFAULT_ARCHIVE_ROOT = DETECTION_ARCHIVE_ROOT
VR_DETECTOR = "velociraptor_validation"
VR_DATASET_ROLE = VALIDATION_DATASET_ROLE


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _safe_bool(value: Any) -> bool:
    return bool(value)


def _safe_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() == "none":
        return None
    return text


def _count_export_rows(path: Path) -> int | None:
    if not path.exists() or not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return 0
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                count += 1
        return count
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        rows = payload.get("rows")
        if isinstance(rows, list):
            return len(rows)
        return 1
    return 0


def _artifact_hit_counts(summary: dict[str, Any], artifact_hits: dict[str, Any] | None = None) -> dict[str, int]:
    if isinstance(artifact_hits, dict):
        counts = artifact_hits.get("artifact_hit_counts")
        if isinstance(counts, dict):
            return counts
    cleaned = coerce_dict(summary.get("cleaned"))
    counts = cleaned.get("artifact_hit_counts")
    return counts if isinstance(counts, dict) else {}


@dataclass(frozen=True)
class PersistPaths:
    archive_dir: Path
    manifest_path: Path
    metadata_path: Path
    summary_path: Path
    notes_path: Path
    winrm_log_path: Path
    raw_exports_dir: Path
    artifact_hits_path: Path
    artifact_hits_cleaned_path: Path
    artifact_hits_raw_path: Path


@dataclass(frozen=True)
class PersistPayload:
    paths: PersistPaths
    manifest: dict[str, Any]
    metadata: dict[str, Any]
    summary: dict[str, Any]
    artifact_hits: dict[str, Any]
    archive_name: str
    sample_id: int
    sha256: str
    source: str
    vm: str
    vm_arch: str | None
    client_id: str | None
    primary_flow_id: str | None
    snapshot: str | None
    execute: bool
    wait_seconds: int | None
    flow_wait_timeout: int | None
    flow_poll_seconds: int | None
    started_at: datetime | None
    generated_at: datetime | None
    completed_at: datetime | None
    detected: bool
    high_confidence_detected: bool
    collection_failed: bool
    collection_failure_reason: str | None
    partial_export: bool
    final_revert_ok: bool | None


def build_persist_payload(archive_dir: Path) -> PersistPayload:
    paths = PersistPaths(
        archive_dir=archive_dir,
        manifest_path=archive_dir / "manifest.json",
        metadata_path=archive_dir / "sample_metadata.json",
        summary_path=archive_dir / "velociraptor_collection_summary.json",
        notes_path=archive_dir / "execution_notes.md",
        winrm_log_path=archive_dir / "winrm_execution_log.json",
        raw_exports_dir=archive_dir / "raw_exports",
        artifact_hits_path=archive_dir / "artifact_hits.json",
        artifact_hits_cleaned_path=archive_dir / "artifact_hits_cleaned.json",
        artifact_hits_raw_path=archive_dir / "artifact_hits_raw.json",
    )
    manifest = read_json_dict(paths.manifest_path)
    metadata = read_json_dict(paths.metadata_path)
    summary = read_json_dict(paths.summary_path)
    artifact_hits = read_json_dict(paths.artifact_hits_path)
    binary = coerce_dict(metadata.get("binary"))
    final_revert = coerce_dict(metadata.get("final_revert"))
    archive_name = archive_dir.name
    sample_id = int(metadata.get("sample_id") or manifest.get("sample_id") or 0)
    sha256 = str(metadata.get("sha256") or manifest.get("sha256") or "")
    vm = str(metadata.get("vm") or manifest.get("vm") or "")
    return PersistPayload(
        paths=paths,
        manifest=manifest,
        metadata=metadata,
        summary=summary,
        artifact_hits=artifact_hits,
        archive_name=archive_name,
        sample_id=sample_id,
        sha256=sha256,
        source=str(binary.get("source") or "unknown"),
        vm=vm,
        vm_arch=str(metadata.get("vm_arch") or binary.get("arch") or "").strip() or None,
        client_id=_safe_text(metadata.get("client_id")),
        primary_flow_id=_safe_text(metadata.get("flow_id")),
        snapshot=_safe_text(metadata.get("snapshot")),
        execute=_safe_bool(metadata.get("execute")),
        wait_seconds=metadata.get("wait_seconds"),
        flow_wait_timeout=metadata.get("flow_wait_timeout"),
        flow_poll_seconds=metadata.get("flow_poll_seconds"),
        started_at=_parse_dt(metadata.get("started_at")),
        generated_at=_parse_dt(metadata.get("generated_at") or summary.get("generated_at") or manifest.get("archived_at")),
        completed_at=_parse_dt(metadata.get("completed_at") or manifest.get("archived_at")),
        detected=_safe_bool(
            artifact_hits.get("detected")
            if "detected" in artifact_hits
            else (metadata.get("detected") or manifest.get("detected"))
        ),
        high_confidence_detected=_safe_bool(
            artifact_hits.get("high_confidence_detected")
            if "high_confidence_detected" in artifact_hits
            else (metadata.get("high_confidence_detected") or manifest.get("high_confidence_detected"))
        ),
        collection_failed=_safe_bool(metadata.get("collection_failed") or manifest.get("collection_failed")),
        collection_failure_reason=_safe_text(
            metadata.get("collection_failure_reason")
            or summary.get("collection_failure_reason")
            or manifest.get("collection_failure_reason")
        ),
        partial_export=_safe_bool(
            metadata.get("partial_export") or summary.get("partial_export") or manifest.get("partial_export")
        ),
        final_revert_ok=(
            None if not final_revert else final_revert.get("returncode") in (None, 0) and not final_revert.get("skipped", False)
        ),
    )


def _evaluation_defaults(payload: PersistPayload) -> dict[str, Any]:
    triggered_artifacts = coerce_list(
        payload.artifact_hits.get("triggered_artifacts")
        if "triggered_artifacts" in payload.artifact_hits
        else coerce_dict(payload.summary.get("cleaned")).get("triggered_artifacts")
    )
    notes_parts = [f"archive={payload.archive_name}"]
    if payload.collection_failure_reason:
        notes_parts.append(f"collection_failure={payload.collection_failure_reason}")
    if payload.partial_export:
        notes_parts.append("partial_export=true")
    return {
        "sample_id": payload.sample_id,
        "analysis_run_id": None,
        "source": payload.source,
        "dataset_role": VR_DATASET_ROLE,
        "detector": VR_DETECTOR,
        "architecture": payload.vm_arch or "unknown",
        "test_machine": payload.vm,
        "detected": payload.detected,
        "detection_time_seconds": None,
        "first_detection_at": payload.completed_at if payload.detected else None,
        "execution_started_at": payload.started_at,
        "triggered_rules": [],
        "triggered_iocs": [],
        "triggered_artifacts": triggered_artifacts,
        "velociraptor_report_path": str(payload.paths.archive_dir),
        "cape_task_id": None,
        "notes": "; ".join(notes_parts),
    }


def _upsert_evaluation(session, payload: PersistPayload, existing_report: VelociraptorReport | None) -> DetectionEvaluation:
    if existing_report is not None:
        evaluation = session.get(DetectionEvaluation, existing_report.evaluation_id)
        if evaluation is None:
            raise RuntimeError(f"Missing detection_evaluations row for report id={existing_report.id}")
    else:
        evaluation = DetectionEvaluation()
        session.add(evaluation)
    for key, value in _evaluation_defaults(payload).items():
        setattr(evaluation, key, value)
    return evaluation


def _upsert_report(session, payload: PersistPayload, evaluation: DetectionEvaluation) -> VelociraptorReport:
    existing = session.execute(
        select(VelociraptorReport).where(VelociraptorReport.archive_name == payload.archive_name)
    ).scalar_one_or_none()
    report = existing or VelociraptorReport(archive_name=payload.archive_name)
    if existing is None:
        session.add(report)
    report.evaluation = evaluation
    report.sample_id = payload.sample_id
    report.sha256 = payload.sha256
    report.source = payload.source
    report.vm = payload.vm
    report.vm_arch = payload.vm_arch
    report.client_id = payload.client_id
    report.primary_flow_id = payload.primary_flow_id
    report.snapshot = payload.snapshot
    report.execute = payload.execute
    report.wait_seconds = payload.wait_seconds
    report.flow_wait_timeout = payload.flow_wait_timeout
    report.flow_poll_seconds = payload.flow_poll_seconds
    report.started_at = payload.started_at
    report.generated_at = payload.generated_at
    report.completed_at = payload.completed_at
    report.detected = payload.detected
    report.high_confidence_detected = payload.high_confidence_detected
    report.collection_failed = payload.collection_failed
    report.collection_failure_reason = payload.collection_failure_reason
    report.partial_export = payload.partial_export
    report.final_revert_ok = payload.final_revert_ok
    report.archive_name = payload.archive_name
    report.archive_dir = str(payload.paths.archive_dir)
    report.result_dir = str(payload.metadata.get("result_dir") or payload.manifest.get("source_result_dir") or "")
    report.raw_exports_dir = str(payload.summary.get("raw_exports_dir") or payload.paths.raw_exports_dir)
    report.metadata_path = str(payload.paths.metadata_path)
    report.summary_path = str(payload.paths.summary_path)
    report.notes_path = str(payload.paths.notes_path)
    report.winrm_log_path = str(payload.paths.winrm_log_path)
    report.manifest_path = str(payload.paths.manifest_path)
    report.report_path = str(payload.paths.archive_dir)
    report.raw_report = {
        "summary": payload.summary,
        "metadata": payload.metadata,
        "manifest": payload.manifest,
        "artifact_hits": payload.artifact_hits,
    }
    report.summary_json = payload.summary
    report.metadata_json = payload.metadata
    report.manifest_json = payload.manifest
    if payload.completed_at is not None:
        report.collected_at = payload.completed_at
    return report


def _artifact_rows(payload: PersistPayload) -> list[dict[str, Any]]:
    artifact_flows = coerce_dict(payload.summary.get("artifact_flows") or payload.metadata.get("artifact_flows"))
    hit_counts = _artifact_hit_counts(payload.summary, payload.artifact_hits)
    rows: list[dict[str, Any]] = []
    for artifact_name, details in artifact_flows.items():
        item = coerce_dict(details)
        flow_completion = coerce_dict(item.get("flow_completion"))
        last_status = coerce_dict(flow_completion.get("last_status"))
        export = coerce_dict(item.get("export"))
        raw_export_path = Path(str(export.get("output_path") or payload.paths.raw_exports_dir / f"{artifact_name}.json"))
        rows.append(
            {
                "artifact_name": artifact_name,
                "flow_id": item.get("flow_id"),
                "state": last_status.get("state") or last_status.get("State"),
                "status": last_status.get("status") or last_status.get("Status"),
                "completed": _safe_bool(flow_completion.get("completed")),
                "failed": _safe_bool(flow_completion.get("failed")),
                "timed_out": _safe_bool(flow_completion.get("timed_out")),
                "collection_failed": _safe_bool(item.get("collection_failed")),
                "collection_failure_reason": item.get("collection_failure_reason"),
                "total_collected_rows": last_status.get("total_collected_rows"),
                "artifacts_with_results": coerce_list(last_status.get("artifacts_with_results")),
                "filtered_hit_count": int(hit_counts.get(artifact_name, 0)),
                "export_returncode": export.get("returncode"),
                "export_stderr": export.get("stderr"),
                "raw_export_path": str(raw_export_path),
                "raw_export_rows": _count_export_rows(raw_export_path),
                "raw_export_size_bytes": raw_export_path.stat().st_size if raw_export_path.exists() else None,
                "artifact_summary_json": {
                    "artifact": artifact_name,
                    "flow": item,
                    "flow_completion": flow_completion,
                    "export": export,
                    "filtered_hit_count": int(hit_counts.get(artifact_name, 0)),
                },
            }
        )
    return rows


def _upsert_artifacts(session, report: VelociraptorReport, payload: PersistPayload) -> int:
    existing = {
        item.artifact_name: item
        for item in session.execute(
            select(VelociraptorArtifactResult).where(VelociraptorArtifactResult.velociraptor_report_id == report.id)
        ).scalars()
    }
    count = 0
    for row in _artifact_rows(payload):
        artifact = existing.get(row["artifact_name"]) or VelociraptorArtifactResult(
            velociraptor_report_id=report.id,
            sample_id=payload.sample_id,
            artifact_name=row["artifact_name"],
        )
        if row["artifact_name"] not in existing:
            session.add(artifact)
        artifact.sample_id = payload.sample_id
        artifact.flow_id = row["flow_id"]
        artifact.state = row["state"]
        artifact.status = row["status"]
        artifact.completed = row["completed"]
        artifact.failed = row["failed"]
        artifact.timed_out = row["timed_out"]
        artifact.collection_failed = row["collection_failed"]
        artifact.collection_failure_reason = row["collection_failure_reason"]
        artifact.total_collected_rows = row["total_collected_rows"]
        artifact.artifacts_with_results = row["artifacts_with_results"]
        artifact.filtered_hit_count = row["filtered_hit_count"]
        artifact.export_returncode = row["export_returncode"]
        artifact.export_stderr = row["export_stderr"]
        artifact.raw_export_path = row["raw_export_path"]
        artifact.raw_export_rows = row["raw_export_rows"]
        artifact.raw_export_size_bytes = row["raw_export_size_bytes"]
        artifact.artifact_summary_json = row["artifact_summary_json"]
        count += 1
    return count


def persist_archive(archive_dir: Path) -> dict[str, Any]:
    payload = build_persist_payload(archive_dir)
    if payload.sample_id <= 0:
        raise ValueError(f"Invalid sample_id in archive: {archive_dir}")
    if not payload.sha256:
        raise ValueError(f"Missing sha256 in archive: {archive_dir}")
    if not payload.vm:
        raise ValueError(f"Missing vm in archive: {archive_dir}")
    with session_scope() as session:
        existing = session.execute(
            select(VelociraptorReport).where(VelociraptorReport.archive_name == payload.archive_name)
        ).scalar_one_or_none()
        evaluation = _upsert_evaluation(session, payload, existing)
        session.flush()
        report = _upsert_report(session, payload, evaluation)
        session.flush()
        artifact_count = _upsert_artifacts(session, report, payload)
        session.flush()
        return {
            "evaluation_id": evaluation.id,
            "velociraptor_report_id": report.id,
            "artifact_result_count": artifact_count,
            "archive_name": payload.archive_name,
            "sample_id": payload.sample_id,
            "detected": payload.detected,
            "high_confidence_detected": payload.high_confidence_detected,
        }


def persist_runtime_result(result_dir: Path) -> dict[str, Any]:
    metadata = read_json_dict(result_dir / "sample_metadata.json")
    archived = coerce_dict(metadata.get("archived_detection"))
    archive_dir_raw = str(archived.get("archive_dir") or "").strip()
    if not archive_dir_raw:
        raise ValueError(f"Missing archived_detection.archive_dir in {result_dir}")
    archive_dir = Path(archive_dir_raw).expanduser()
    result = persist_archive(archive_dir)
    metadata["db_persistence"] = result
    (result_dir / "sample_metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    archive_metadata_path = archive_dir / "sample_metadata.json"
    if archive_metadata_path.exists():
        archive_metadata = read_json_dict(archive_metadata_path)
        archive_metadata["db_persistence"] = result
        archive_metadata_path.write_text(
            json.dumps(archive_metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    manifest_path = archive_dir / "manifest.json"
    if manifest_path.exists():
        manifest = read_json_dict(manifest_path)
        manifest["db_persistence"] = result
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def import_archives(archive_root: Path = DEFAULT_ARCHIVE_ROOT) -> dict[str, Any]:
    archives = sorted(path for path in archive_root.glob("v_detection_*_*") if path.is_dir())
    imported = 0
    artifact_rows = 0
    errors: list[dict[str, str]] = []
    for archive_dir in archives:
        try:
            result = persist_archive(archive_dir)
        except Exception as exc:
            errors.append({"archive_dir": str(archive_dir), "error": str(exc)})
            continue
        imported += 1
        artifact_rows += int(result["artifact_result_count"])
    return {
        "archive_root": str(archive_root),
        "archives_seen": len(archives),
        "reports_imported": imported,
        "artifact_rows_upserted": artifact_rows,
        "errors": errors,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Persist Velociraptor detection archives to PostgreSQL")
    parser.add_argument("--archive-root", default=str(DEFAULT_ARCHIVE_ROOT))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = import_archives(Path(args.archive_root))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
