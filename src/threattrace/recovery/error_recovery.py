from __future__ import annotations

import argparse
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from celery import chain
from sqlalchemy import func, select, text

from threattrace.cape.client import CapeClient
from threattrace.common.logging import configure_logging, get_logger
from threattrace.common.time import parse_optional_datetime as _coerce_utc
from threattrace.config.settings import get_settings
from threattrace.db.models import AnalysisRun, CapeReport, IOCReport
from threattrace.db.repositories import (
    get_analysis_run,
    get_malwarebazaar_daily_quota_usage,
    get_status_id,
    set_run_state,
)
from threattrace.db.session import session_scope
from threattrace.workers.pipeline import (
    download_sample_task,
    execute_fetch_report,
    poll_cape_until_reported_task,
    submit_to_cape_task,
)

logger = get_logger(__name__)

DEFAULT_MAX_FULL_RERUNS = 1
DEFAULT_MAX_POLL_REQUEUES = 2
DEFAULT_MAX_CAPE_BACKLOG = 2
DEFAULT_SINCE_HOURS = 48
DEFAULT_LIMIT = 500
QUOTA_DATE_RE = re.compile(r"quota reached for (\d{4}-\d{2}-\d{2})")
RECOVERY_ACTIVE_STATES = {'pending', 'reserved', 'running', 'rerunning'}
RECOVERY_NEWER_RUN_STATES = RECOVERY_ACTIVE_STATES | {'reported', 'done'}

def _cape_backlog_size() -> int:
    db_path = get_settings().cape_storage_path.parent / "db" / "cuckoo.db"
    if not db_path.exists():
        return 0
    try:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(cnt), 0)
                FROM (
                    SELECT COUNT(*) AS cnt
                    FROM tasks
                    WHERE status IN ('pending', 'running')
                )
                """
            ).fetchone()
    except Exception:
        logger.exception(
            "Failed to inspect CAPE backlog",
            extra={"service": "recovery", "stage": "cape_backlog"},
        )
        return 0
    return int((row or [0])[0] or 0)


def _report_exists(task_id: int) -> bool:
    return (_analysis_dir(task_id) / "reports" / "report.json").exists()


def _analysis_dir(task_id: int) -> Path:
    settings = get_settings()
    return settings.cape_storage_path / "analyses" / str(task_id)


def _task_dir_recent(task_id: int, threshold_seconds: int) -> bool:
    analysis_dir = _analysis_dir(task_id)
    if not analysis_dir.exists():
        return False
    try:
        age = datetime.now(UTC).timestamp() - analysis_dir.stat().st_mtime
    except OSError:
        return False
    return age <= threshold_seconds


def _reset_run_for_recovery(run_id: int, state: str, clear_cape_task_id: bool = False) -> None:
    with session_scope() as session:
        run = get_analysis_run(session, run_id)
        run.retry_count = 0
        run.next_retry_at = None
        run.error_stage = None
        run.error_message = None
        run.last_error = None
        run.finished_at = None
        run.reported_at = None
        run.locked = False
        run.locked_at = None
        if clear_cape_task_id:
            run.cape_task_id = None
            run.submitted_at = None
        set_run_state(session, run_id, state)


def _create_recovery_attempt(source_run_id: int, state: str = 'reserved') -> int:
    now = datetime.now(UTC)
    with session_scope() as session:
        source_run = session.execute(
            select(AnalysisRun).where(AnalysisRun.id == source_run_id).with_for_update()
        ).scalar_one()
        sample = source_run.sample
        next_attempt = int(
            session.execute(
                select(func.coalesce(func.max(AnalysisRun.attempt_no), 0) + 1).where(
                    AnalysisRun.sample_id == source_run.sample_id
                )
            ).scalar_one()
        )
        new_run = AnalysisRun(
            sample_id=source_run.sample_id,
            attempt_no=next_attempt,
            state=state,
            status_id=get_status_id(session, state),
            cape_machine=source_run.cape_machine or get_settings().cape_machine_x86,
            cape_platform=source_run.cape_platform or 'windows',
            cape_tags=(source_run.execution_arch or source_run.cape_tags or 'unknown'),
            execution_arch=(source_run.execution_arch or 'unknown'),
            fallback_used=False,
            retry_count=0,
            created_at=now,
            updated_at=now,
            scheduled_at=now,
        )
        session.add(new_run)
        session.flush()

        sample.status_id = get_status_id(session, state)
        sample.analyzed = False
        sample.updated_at = now

        return int(new_run.id)


def _sample_file_exists_for_run(run_id: int) -> bool:
    with session_scope() as session:
        run = get_analysis_run(session, run_id)
        stored_file_path = run.sample.stored_file_path if run.sample is not None else None
    return bool(stored_file_path and Path(stored_file_path).exists())


def _dispatch_recovery_attempt(source_run_id: int) -> tuple[int, str]:
    new_run_id = _create_recovery_attempt(source_run_id, state='reserved')
    if _sample_file_exists_for_run(new_run_id):
        launch_mode = 'submit_existing_sample'
        recovery_chain = chain(
            submit_to_cape_task.si(new_run_id),
            poll_cape_until_reported_task.si(new_run_id),
        )
    else:
        launch_mode = 'download_then_submit'
        recovery_chain = chain(
            download_sample_task.si(new_run_id),
            submit_to_cape_task.si(new_run_id),
            poll_cape_until_reported_task.si(new_run_id),
        )

    recovery_chain.apply_async(
        queue='threattrace',
        routing_key='threattrace',
        retry=False,
        ignore_result=False,
    )
    return new_run_id, launch_mode



def _run_outputs_complete_in_session(session, run_id: int) -> bool:
    row = session.execute(
        select(AnalysisRun, CapeReport, IOCReport)
        .outerjoin(CapeReport, CapeReport.analysis_run_id == AnalysisRun.id)
        .outerjoin(IOCReport, IOCReport.analysis_run_id == AnalysisRun.id)
        .where(AnalysisRun.id == run_id)
    ).first()
    if row is None:
        return False

    run, cape_report, ioc_report = row
    if run.state != 'done' or cape_report is None or ioc_report is None:
        return False
    if not cape_report.raw_json or not cape_report.etl_processed:
        return False

    unified_ioc = cape_report.unified_ioc or {}
    if not isinstance(unified_ioc, dict):
        return False
    return (
        'detection_candidates' in unified_ioc
        and 'endpoint_observability' in unified_ioc
    )


def _newer_recovery_runs(source_run_id: int) -> list[dict[str, Any]]:
    with session_scope() as session:
        source_run = session.execute(
            select(AnalysisRun).where(AnalysisRun.id == source_run_id)
        ).scalar_one()
        rows = session.execute(
            select(AnalysisRun.id, AnalysisRun.state, AnalysisRun.cape_task_id)
            .where(AnalysisRun.sample_id == source_run.sample_id)
            .where(AnalysisRun.id > source_run_id)
            .where(AnalysisRun.state.in_(tuple(RECOVERY_NEWER_RUN_STATES)))
            .order_by(AnalysisRun.id.desc())
        ).all()
        return [
            {
                'id': int(run_id),
                'state': str(state),
                'cape_task_id': int(cape_task_id) if cape_task_id is not None else None,
                'outputs_complete': _run_outputs_complete_in_session(session, int(run_id)),
            }
            for run_id, state, cape_task_id in rows
        ]


def _delete_superseded_error_run(source_run_id: int, successor_run_id: int) -> str:
    with session_scope() as session:
        source_run = session.get(AnalysisRun, source_run_id)
        successor_run = session.get(AnalysisRun, successor_run_id)
        if source_run is None or successor_run is None:
            return 'not_found'
        if source_run.state != 'error' or successor_run.id <= source_run.id:
            return 'not_superseded'
        if source_run.sample_id != successor_run.sample_id:
            return 'sample_mismatch'
        if not _run_outputs_complete_in_session(session, successor_run_id):
            return 'successor_outputs_incomplete'

        has_old_cape_report = bool(
            session.execute(
                select(func.count()).select_from(CapeReport).where(
                    CapeReport.analysis_run_id == source_run_id
                )
            ).scalar_one()
        )
        has_old_ioc_report = bool(
            session.execute(
                select(func.count()).select_from(IOCReport).where(
                    IOCReport.analysis_run_id == source_run_id
                )
            ).scalar_one()
        )
        has_old_detection_evaluations = bool(
            session.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM detection_evaluations WHERE analysis_run_id = :run_id)"
                ),
                {"run_id": source_run_id},
            ).scalar_one()
        )
        if has_old_cape_report or has_old_ioc_report or has_old_detection_evaluations:
            return 'blocked_dependencies'

        session.delete(source_run)
        return 'deleted'


def _quota_error_day(*messages: str | None) -> str | None:
    combined = " ".join(part for part in messages if part)
    match = QUOTA_DATE_RE.search(combined)
    if not match:
        return None
    return match.group(1)


def _is_malwarebazaar_quota_error(*messages: str | None) -> bool:
    combined = " ".join((part or "") for part in messages).lower()
    return (
        "malwarebazaar download quota reached" in combined
        or ("quota reached" in combined and "200/200" in combined)
    )


def _print_verbose(verbose: bool, **fields: Any) -> None:
    if not verbose:
        return
    print("recovery_decision " + " ".join(f"{key}={value}" for key, value in fields.items()))


def _stage_summary(rows: list[Any]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for row in rows:
        stage = row["error_stage"] or "unknown"
        summary[stage] = summary.get(stage, 0) + 1
    return summary


def recover_error_runs(
    *,
    max_full_reruns: int = DEFAULT_MAX_FULL_RERUNS,
    max_poll_requeues: int = DEFAULT_MAX_POLL_REQUEUES,
    max_cape_backlog: int = DEFAULT_MAX_CAPE_BACKLOG,
    dry_run: bool = False,
    since_hours: int = DEFAULT_SINCE_HOURS,
    limit: int = DEFAULT_LIMIT,
    include_all: bool = False,
    error_stages: list[str] | None = None,
    verbose: bool = False,
) -> dict[str, int]:
    settings = get_settings()
    configure_logging(settings.log_level)
    client = CapeClient()

    backlog = _cape_backlog_size()
    effective_max_cape_backlog = max_cape_backlog
    fetch_existing_report = 0
    requeued_poll = 0
    wait_cape_processing = 0
    full_rerun = 0
    full_rerun_created = 0
    requeue_download = 0
    skipped_backlog = 0
    skipped_limited = 0
    skipped_malwarebazaar_quota = 0
    already_has_active_rerun = 0
    resolved_by_newer_success = 0
    deleted_superseded_error = 0
    true_blocker = 0
    skipped_no_quota_remaining = 0
    errors = 0
    rerun_budget_used = 0

    with session_scope() as session:
        used_today = get_malwarebazaar_daily_quota_usage(session)
        filters = ["state = 'error'"]
        params: dict[str, Any] = {}
        if not include_all:
            filters.append(
                "COALESCE(updated_at, created_at) >= NOW() - (:since_hours * INTERVAL '1 hour')"
            )
            params["since_hours"] = since_hours
        if error_stages:
            filters.append("error_stage = ANY(:error_stages)")
            params["error_stages"] = error_stages

        rows = session.execute(
            text(
                f"""
                SELECT
                    id,
                    cape_task_id,
                    error_stage,
                    error_message,
                    last_error,
                    submitted_at,
                    updated_at,
                    created_at
                FROM analysis_runs
                WHERE {' AND '.join(filters)}
                ORDER BY COALESCE(updated_at, created_at) DESC, id DESC
                LIMIT :limit
                """
            ),
            {
                **params,
                "limit": limit,
            },
        ).mappings().all()

    quota_limit = settings.malwarebazaar_downloads_per_day_limit
    remaining_quota = max(0, quota_limit - used_today)
    today = datetime.now(UTC).date().isoformat()
    stage_counts = _stage_summary(rows)
    if include_all:
        effective_max_cape_backlog = max(max_cape_backlog, backlog + len(rows))

    for row in rows:
        run_id = int(row["id"])
        task_id = row["cape_task_id"]
        error_stage = row["error_stage"]
        error_message = row["error_message"]
        last_error = row["last_error"]
        submitted_at = _coerce_utc(row["submitted_at"])
        updated_at = _coerce_utc(row["updated_at"] or row["created_at"])
        is_quota_error = _is_malwarebazaar_quota_error(error_message, last_error)
        quota_error_day = _quota_error_day(error_message, last_error)
        age_seconds = None
        if submitted_at is not None:
            age_seconds = max(0, int((datetime.now(UTC) - submitted_at).total_seconds()))
        elif updated_at is not None:
            age_seconds = max(0, int((datetime.now(UTC) - updated_at).total_seconds()))


        newer_runs = _newer_recovery_runs(run_id)
        newer_done = next(
            (candidate for candidate in newer_runs if candidate['state'] == 'done'),
            None,
        )
        if newer_done is not None:
            if newer_done['outputs_complete']:
                resolved_by_newer_success += 1
                _print_verbose(
                    verbose,
                    analysis_run_id=run_id,
                    category='resolved_by_newer_success',
                    newer_analysis_run_id=newer_done['id'],
                    newer_cape_task_id=newer_done['cape_task_id'],
                )
                if dry_run:
                    _print_verbose(
                        verbose,
                        analysis_run_id=run_id,
                        category='would_delete_superseded_error',
                        newer_analysis_run_id=newer_done['id'],
                    )
                else:
                    delete_result = _delete_superseded_error_run(run_id, newer_done['id'])
                    if delete_result == 'deleted':
                        deleted_superseded_error += 1
                        _print_verbose(
                            verbose,
                            analysis_run_id=run_id,
                            category='deleted_superseded_error',
                            newer_analysis_run_id=newer_done['id'],
                        )
                    else:
                        true_blocker += 1
                        _print_verbose(
                            verbose,
                            analysis_run_id=run_id,
                            category='true_blocker',
                            reason=f'superseded_error_not_deleted:{delete_result}',
                            newer_analysis_run_id=newer_done['id'],
                        )
                continue
            true_blocker += 1
            _print_verbose(
                verbose,
                analysis_run_id=run_id,
                category='true_blocker',
                reason='newer_done_incomplete',
                newer_analysis_run_id=newer_done['id'],
                newer_cape_task_id=newer_done['cape_task_id'],
            )
            continue

        newer_reported = next(
            (candidate for candidate in newer_runs if candidate['state'] == 'reported'),
            None,
        )
        if newer_reported is not None:
            fetch_existing_report += 1
            _print_verbose(
                verbose,
                analysis_run_id=run_id,
                category='fetch_existing_report',
                newer_analysis_run_id=newer_reported['id'],
                cape_task_id=newer_reported['cape_task_id'],
                cape_status='reported',
            )
            if not dry_run:
                execute_fetch_report(newer_reported['id'])
            continue

        newer_active = next(
            (candidate for candidate in newer_runs if candidate['state'] in RECOVERY_ACTIVE_STATES),
            None,
        )
        if newer_active is not None:
            already_has_active_rerun += 1
            _print_verbose(
                verbose,
                analysis_run_id=run_id,
                category='already_has_active_rerun',
                newer_analysis_run_id=newer_active['id'],
                newer_state=newer_active['state'],
                newer_cape_task_id=newer_active['cape_task_id'],
            )
            continue

        if is_quota_error and (
            quota_error_day == today
            or (quota_error_day is None and remaining_quota <= 0)
        ):
            skipped_malwarebazaar_quota += 1
            _print_verbose(
                verbose,
                analysis_run_id=run_id,
                category="skipped_malwarebazaar_quota_today",
                error_stage=error_stage,
            )
            continue

        try:
            if task_id is not None:
                task_status = ""
                try:
                    task_data = client.get_task_status(task_id)
                    task_status = str(
                        task_data.get("status")
                        or task_data.get("data", {}).get("status")
                        or ""
                    ).strip().lower()
                except Exception:
                    task_status = ""

                if _report_exists(task_id) or task_status == "reported":
                    fetch_existing_report += 1
                    _print_verbose(
                        verbose,
                        analysis_run_id=run_id,
                        category="fetch_existing_report",
                        cape_task_id=task_id,
                        cape_status=task_status or "unknown",
                    )
                    if not dry_run:
                        execute_fetch_report(run_id)
                    continue

                recent_activity = bool(
                    (age_seconds is not None and age_seconds <= settings.cape_max_wait_seconds)
                    or _task_dir_recent(task_id, settings.cape_max_wait_seconds)
                )

                if task_status in {"pending", "running", "completed"}:
                    if requeued_poll >= max_poll_requeues:
                        skipped_limited += 1
                        continue
                    requeued_poll += 1
                    _print_verbose(
                        verbose,
                        analysis_run_id=run_id,
                        category="requeue_poll",
                        cape_task_id=task_id,
                        cape_status=task_status,
                    )
                    if not dry_run:
                        _reset_run_for_recovery(run_id, "rerunning")
                        poll_cape_until_reported_task.apply_async(
                            args=[run_id],
                            countdown=0,
                        )
                    continue

                if recent_activity:
                    wait_cape_processing += 1
                    _print_verbose(
                        verbose,
                        analysis_run_id=run_id,
                        category="wait_cape_processing",
                        cape_task_id=task_id,
                        cape_status=task_status or "unknown",
                    )
                    continue

                if backlog >= effective_max_cape_backlog:
                    skipped_backlog += 1
                    continue
                if remaining_quota <= 0:
                    skipped_no_quota_remaining += 1
                    continue
                if rerun_budget_used >= max_full_reruns:
                    skipped_limited += 1
                    continue

                full_rerun += 1
                full_rerun_created += 1
                rerun_budget_used += 1
                remaining_quota -= 1
                backlog += 1
                _print_verbose(
                    verbose,
                    analysis_run_id=run_id,
                    category="full_rerun_stale_cape_task",
                    cape_task_id=task_id,
                    cape_status=task_status or "unknown",
                )
                if not dry_run:
                    new_run_id, launch_mode = _dispatch_recovery_attempt(run_id)
                    _print_verbose(
                        verbose,
                        source_analysis_run_id=run_id,
                        category="full_rerun_created",
                        new_analysis_run_id=new_run_id,
                        relaunch_mode=launch_mode,
                    )
                continue

            if error_stage == "download":
                if remaining_quota <= 0:
                    skipped_no_quota_remaining += 1
                    continue
                if rerun_budget_used >= max_full_reruns:
                    skipped_limited += 1
                    continue
                requeue_download += 1
                full_rerun_created += 1
                rerun_budget_used += 1
                remaining_quota -= 1
                _print_verbose(
                    verbose,
                    analysis_run_id=run_id,
                    category="quota_error_retry_allowed" if is_quota_error else "requeue_download",
                    error_stage=error_stage,
                )
                if not dry_run:
                    new_run_id, launch_mode = _dispatch_recovery_attempt(run_id)
                    _print_verbose(
                        verbose,
                        source_analysis_run_id=run_id,
                        category="full_rerun_created",
                        new_analysis_run_id=new_run_id,
                        relaunch_mode=launch_mode,
                    )
                continue

            if backlog >= effective_max_cape_backlog:
                skipped_backlog += 1
                continue
            if remaining_quota <= 0:
                skipped_no_quota_remaining += 1
                continue
            if rerun_budget_used >= max_full_reruns:
                skipped_limited += 1
                continue

            full_rerun += 1
            full_rerun_created += 1
            rerun_budget_used += 1
            remaining_quota -= 1
            backlog += 1
            _print_verbose(
                verbose,
                analysis_run_id=run_id,
                category="full_rerun",
                error_stage=error_stage or "unknown",
            )
            if not dry_run:
                new_run_id, launch_mode = _dispatch_recovery_attempt(run_id)
                _print_verbose(
                    verbose,
                    source_analysis_run_id=run_id,
                    category="full_rerun_created",
                    new_analysis_run_id=new_run_id,
                    relaunch_mode=launch_mode,
                )
        except Exception:
            errors += 1
            logger.exception(
                "Recovery classification failed",
                extra={
                    "service": "recovery",
                    "stage": "error_recovery_classification",
                    "analysis_run_id": run_id,
                },
            )

    result = {
        "total_errors": len(rows),
        "fetch_existing_report": fetch_existing_report,
        "requeued_poll": requeued_poll,
        "wait_cape_processing": wait_cape_processing,
        "full_rerun": full_rerun,
        "full_rerun_created": full_rerun_created,
        "requeue_download": requeue_download,
        "already_has_active_rerun": already_has_active_rerun,
        "resolved_by_newer_success": resolved_by_newer_success,
        "deleted_superseded_error": deleted_superseded_error,
        "true_blocker": true_blocker,
        "skipped_malwarebazaar_quota": skipped_malwarebazaar_quota,
        "skipped_no_quota_remaining": skipped_no_quota_remaining,
        "skipped_backlog": skipped_backlog,
        "skipped_limited": skipped_limited,
        "errors": errors,
    }
    if stage_counts:
        print(
            "error_stage_summary "
            + " ".join(f"{key}={value}" for key, value in sorted(stage_counts.items()))
        )
    print(
        "error_recovery_summary "
        + " ".join(f"{key}={value}" for key, value in result.items())
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover errored analysis runs safely")
    parser.add_argument("--max-full-reruns", type=int, default=DEFAULT_MAX_FULL_RERUNS)
    parser.add_argument("--max-poll-requeues", type=int, default=DEFAULT_MAX_POLL_REQUEUES)
    parser.add_argument("--max-cape-backlog", type=int, default=DEFAULT_MAX_CAPE_BACKLOG)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--all", action="store_true", dest="include_all")
    parser.add_argument("--since-hours", type=int, default=DEFAULT_SINCE_HOURS)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--error-stage", action="append", dest="error_stages")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    recover_error_runs(
        max_full_reruns=args.max_full_reruns,
        max_poll_requeues=args.max_poll_requeues,
        max_cape_backlog=args.max_cape_backlog,
        dry_run=args.dry_run,
        since_hours=args.since_hours,
        limit=args.limit,
        include_all=args.include_all,
        error_stages=args.error_stages,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
