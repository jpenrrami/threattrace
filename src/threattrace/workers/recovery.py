from __future__ import annotations

from datetime import UTC, datetime, timedelta

from celery import shared_task
from sqlalchemy import func, select

from threattrace.common import get_logger
from threattrace.db.models import AnalysisRun, Sample
from threattrace.db.repositories import get_status_id
from threattrace.db.session import session_scope
from threattrace.scheduler.daily_batch import (
    create_daily_batch,
    dispatch_daily_batch,
)

logger = get_logger(__name__)


# =========================
# Recovery thresholds
# =========================
SUBMITTED_TIMEOUT_MINUTES = 600
REPORTED_TIMEOUT_MINUTES = 180
DOWNLOADED_TIMEOUT_MINUTES = 600

# Queue starvation protection
MAX_SUBMITTED_BACKLOG = 120
QUEUE_BLOCKED_PENDING_THRESHOLD = 5

MAX_RECOVERY_RETRY_COUNT = 3
STALE_LOCK_MINUTES = 30


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _should_trigger_submitted_recovery(
    session,
    stale_submitted_before: datetime,
    *,
    pending_status_id: int,
    running_status_id: int,
) -> list[AnalysisRun]:
    """
    Intelligent submitted-state recovery.

    Recovery only triggers when:
    - submitted jobs are stale beyond threshold
    AND
    - pending queue exists
    AND
    - pipeline starvation is detected

    Prevents valid long-running CAPE tasks from being killed.
    """

    pending_count = session.scalar(
        select(func.count())
        .select_from(Sample)
        .where(Sample.status_id == pending_status_id)
    ) or 0

    submitted_count = session.scalar(
        select(func.count())
        .select_from(AnalysisRun)
        .where(AnalysisRun.status_id == running_status_id)
    ) or 0

    if (
        pending_count < QUEUE_BLOCKED_PENDING_THRESHOLD
        and submitted_count < MAX_SUBMITTED_BACKLOG
    ):
        return []

    stale_runs = session.scalars(
        select(AnalysisRun).where(
            AnalysisRun.status_id == running_status_id,
            AnalysisRun.submitted_at.is_not(None),
            AnalysisRun.submitted_at < stale_submitted_before,
            AnalysisRun.retry_count < MAX_RECOVERY_RETRY_COUNT,
        )
    ).all()

    return stale_runs


def _recover_run(
    session,
    run: AnalysisRun,
    now: datetime,
    *,
    error_status_id: int,
    pending_status_id: int,
) -> None:
    sample = session.get(Sample, run.sample_id)
    if sample is not None:
        sample.status_id = error_status_id
        sample.analyzed = False
        sample.updated_at = now

    run.retry_count = (run.retry_count or 0) + 1
    run.state = "error"
    run.locked = False
    run.locked_at = None
    run.status_id = error_status_id
    run.error_stage = "recovery"
    run.error_message = "Recovered stale pipeline state"
    run.finished_at = now

    if sample is not None:
        sample.status_id = pending_status_id
        sample.updated_at = now


def recover_stale_pipeline_states() -> dict[str, int]:
    """
    Autonomous recovery engine for stuck pipeline states.

    Repairs:
    - submitted too long + queue starvation
    - reported too long
    - downloaded too long

    Recovery strategy:
    1. Delete broken analysis_runs
    2. Reset sample to pending
    3. Relaunch daily batch automatically

    Intelligent protections:
    - Avoid killing healthy long CAPE executions
    - Detect real pipeline blockage
    - Maintain ingestion continuity
    """

    now = _utcnow()

    stale_submitted_before = now - timedelta(
        minutes=SUBMITTED_TIMEOUT_MINUTES
    )

    stale_reported_before = now - timedelta(
        minutes=REPORTED_TIMEOUT_MINUTES
    )

    stale_downloaded_before = now - timedelta(
        minutes=DOWNLOADED_TIMEOUT_MINUTES
    )
    stale_locked_before = now - timedelta(minutes=STALE_LOCK_MINUTES)

    recovered_submitted = 0
    recovered_reported = 0
    recovered_downloaded = 0
    unlocked_runs = 0

    with session_scope() as session:
        pending_status_id = get_status_id(session, "pending")
        running_status_id = get_status_id(session, "running")
        error_status_id = get_status_id(session, "error")

        stale_locked_runs = session.scalars(
            select(AnalysisRun).where(
                AnalysisRun.locked.is_(True),
                AnalysisRun.locked_at.is_not(None),
                AnalysisRun.locked_at < stale_locked_before,
            )
        ).all()

        for run in stale_locked_runs:
            run.locked = False
            run.locked_at = None
            unlocked_runs += 1

        # =========================
        # Recover stale submitted (intelligent)
        # =========================
        stale_submitted = _should_trigger_submitted_recovery(
            session,
            stale_submitted_before,
            pending_status_id=pending_status_id,
            running_status_id=running_status_id,
        )

        for run in stale_submitted:
            logger.warning(
                "Recovering stale run",
                extra={
                    "service": "recovery",
                    "stage": "recover",
                    "sha256": run.sha256,
                    "task_id": getattr(run, "cape_task_id", None),
                    "status": "submitted",
                },
            )

            _recover_run(
                session,
                run,
                now,
                error_status_id=error_status_id,
                pending_status_id=pending_status_id,
            )
            recovered_submitted += 1

        # =========================
        # Recover stale reported
        # =========================
        stale_reported = session.scalars(
            select(AnalysisRun).where(
                AnalysisRun.state == "reported",
                AnalysisRun.reported_at.is_not(None),
                AnalysisRun.reported_at < stale_reported_before,
                AnalysisRun.retry_count < MAX_RECOVERY_RETRY_COUNT,
            )
        ).all()

        for run in stale_reported:
            logger.warning(
                "Recovering stale run",
                extra={
                    "service": "recovery",
                    "stage": "recover",
                    "sha256": run.sha256,
                    "task_id": getattr(run, "cape_task_id", None),
                    "status": "reported",
                },
            )

            _recover_run(
                session,
                run,
                now,
                error_status_id=error_status_id,
                pending_status_id=pending_status_id,
            )
            recovered_reported += 1

        # =========================
        # Recover stale downloaded
        # =========================
        stale_downloaded = session.scalars(
            select(AnalysisRun).where(
                AnalysisRun.status_id == running_status_id,
                AnalysisRun.downloaded_at.is_not(None),
                AnalysisRun.downloaded_at < stale_downloaded_before,
                AnalysisRun.retry_count < MAX_RECOVERY_RETRY_COUNT,
            )
        ).all()

        for run in stale_downloaded:
            logger.warning(
                "Recovering stale run",
                extra={
                    "service": "recovery",
                    "stage": "recover",
                    "sha256": run.sha256,
                    "task_id": getattr(run, "cape_task_id", None),
                    "status": "downloaded",
                },
            )

            _recover_run(
                session,
                run,
                now,
                error_status_id=error_status_id,
                pending_status_id=pending_status_id,
            )
            recovered_downloaded += 1

    total_recovered = (
        recovered_submitted
        + recovered_reported
        + recovered_downloaded
    )

    logger.info(
        "Recovery summary",
        extra={
            "service": "recovery",
            "stage": "summary",
            "submitted": recovered_submitted,
            "reported": recovered_reported,
            "downloaded": recovered_downloaded,
            "unlocked": unlocked_runs,
            "total": total_recovered,
        },
    )

    # =========================
    # Relaunch pipeline if needed
    # =========================
    if total_recovered > 0:
        logger.warning(
            "Recovered %s stuck samples. Relaunching daily batch.",
            total_recovered,
        )

        try:
            recovered_ids = create_daily_batch(limit=total_recovered)
            if not recovered_ids:
                return {
                    "submitted": recovered_submitted,
                    "reported": recovered_reported,
                    "downloaded": recovered_downloaded,
                    "unlocked": unlocked_runs,
                    "total": total_recovered,
                }
            dispatch_daily_batch(recovered_ids, sync=False)
        except Exception:
            logger.exception(
                "Failed to relaunch daily batch after recovery"
            )

    return {
        "submitted": recovered_submitted,
        "reported": recovered_reported,
        "downloaded": recovered_downloaded,
        "unlocked": unlocked_runs,
        "total": total_recovered,
    }


@shared_task(
    name="threattrace.workers.recovery.run_pipeline_recovery_task"
)
def run_pipeline_recovery_task() -> dict[str, int]:
    """
    Periodic Celery recovery task.

    Recommended schedule:
    Every 15 minutes via Celery Beat or systemd timer.
    """

    logger.info(
        "Recovery cycle start",
        extra={"service": "recovery", "stage": "start"},
    )

    result = recover_stale_pipeline_states()

    logger.info(
        "Recovery cycle completed",
        extra={
            "service": "recovery",
            "stage": "completed",
            "submitted": result["submitted"],
            "reported": result["reported"],
            "downloaded": result["downloaded"],
            "unlocked": result["unlocked"],
            "total": result["total"],
        },
    )

    return result
