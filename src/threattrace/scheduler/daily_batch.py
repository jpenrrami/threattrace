from __future__ import annotations

import os
import struct
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from celery import chain
from sqlalchemy import func, select

from threattrace.cape.client import CapeClient
from threattrace.common import get_logger
from threattrace.config.settings import get_settings
from threattrace.db.models import AnalysisRun, Sample, SampleTag, Tag
from threattrace.db.repositories import (
    get_analysis_run,
    get_malwarebazaar_daily_quota_usage,
    get_status_id,
    reserve_daily_batch,
)
from threattrace.db.session import session_scope
from threattrace.workers.pipeline import (
    download_sample_task,
    poll_cape_until_reported_task,
    run_minimal_pipeline_sync,
    submit_to_cape_task,
)

logger = get_logger(__name__)


@dataclass(frozen=True)
class ArchAwareCandidate:
    sample_id: int
    detected_arch: str | None
    real_pe_arch: str | None
    effective_arch: str | None
    cape_machine: str | None
    reason: str
    stored_file_path: str | None


def _machine_for_arch(arch: str | None) -> str | None:
    settings = get_settings()
    if arch == "x86":
        return settings.cape_machine_x86
    if arch == "x64":
        return settings.cape_machine_x64
    return None


def _metadata_arch(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().lower()
    if normalized in {"x86", "x64"}:
        return normalized
    return None


def _pe_arch_from_stored_file(stored_file_path: str | None) -> str | None:
    """
    Resolve PE architecture directly from file header.
    Returns x86/x64 when PE parsing succeeds, otherwise None.
    """
    if not stored_file_path:
        return None

    path = Path(stored_file_path)
    if not path.is_file():
        return None

    try:
        with path.open("rb") as fh:
            mz = fh.read(2)
            if mz != b"MZ":
                return None

            fh.seek(0x3C)
            pe_offset_raw = fh.read(4)
            if len(pe_offset_raw) != 4:
                return None

            pe_offset = struct.unpack("<I", pe_offset_raw)[0]
            fh.seek(pe_offset)
            pe_sig = fh.read(4)
            if pe_sig != b"PE\x00\x00":
                return None

            machine_raw = fh.read(2)
            if len(machine_raw) != 2:
                return None

            machine = struct.unpack("<H", machine_raw)[0]
            if machine == 0x014C:
                return "x86"
            if machine == 0x8664:
                return "x64"
            return None
    except Exception:
        return None


def _resolve_effective_arch(
    detected_arch: str | None,
    stored_file_path: str | None,
) -> tuple[str | None, str | None, str]:
    real_arch = _pe_arch_from_stored_file(stored_file_path)
    if real_arch in {"x86", "x64"}:
        return real_arch, real_arch, "real_pe_arch_from_stored_file"

    fallback_arch = _metadata_arch(detected_arch)
    if fallback_arch in {"x86", "x64"}:
        reason = (
            "metadata_fallback_missing_or_unreadable_binary"
            if stored_file_path
            else "metadata_fallback_no_stored_binary"
        )
        return fallback_arch, real_arch, reason

    return None, real_arch, "unknown_arch_skipped"


def _safe_redis_target(redis_url: str) -> str:
    try:
        parsed = urlsplit(redis_url)
    except Exception:
        return "configured"
    host = parsed.hostname or "unknown"
    port = f":{parsed.port}" if parsed.port else ""
    db = parsed.path or ""
    scheme = parsed.scheme or "redis"
    return f"{scheme}://{host}{port}{db}"


def preflight_or_raise() -> None:
    """
    Full scheduler preflight:
    - CAPE API reachable
    - CAPE machine inventory valid
    - Redis configured
    """
    settings = get_settings()

    if not settings.redis_url:
        raise RuntimeError("Redis URL missing from configuration")

    payload = CapeClient().preflight()

    logger.info(
        "CAPE preflight succeeded",
        extra={
            "service": "scheduler",
            "stage": "preflight",
            "machines_available": payload.get("machines_available"),
            "configured_x86": payload.get("configured_x86"),
            "configured_x64": payload.get("configured_x64"),
            "redis_target": _safe_redis_target(settings.redis_url),
        },
    )


def create_daily_batch(limit: int | None = None) -> Sequence[int]:
    settings = get_settings()
    requested_limit = limit or settings.daily_batch_size

    with session_scope() as session:
        quota_limit = settings.malwarebazaar_downloads_per_day_limit
        used_today = get_malwarebazaar_daily_quota_usage(session)
        remaining = max(0, quota_limit - used_today)
        effective_limit = min(requested_limit, remaining)

        logger.info(
            "MalwareBazaar daily quota guard",
            extra={
                "service": "scheduler",
                "stage": "quota_guard",
                "used_today": used_today,
                "limit": quota_limit,
                "requested": requested_limit,
                "effective": effective_limit,
            },
        )

        if effective_limit <= 0:
            logger.info(
                f"MalwareBazaar daily quota reached: {used_today}/{quota_limit}. Daily batch not dispatched.",
                extra={
                    "service": "scheduler",
                    "stage": "quota_guard",
                    "used_today": used_today,
                    "limit": quota_limit,
                },
            )
            return []

        pending_status_id = get_status_id(session, "pending")
        reserved_status_id = get_status_id(session, "reserved")

        runs = reserve_daily_batch(
            session,
            effective_limit,
        )
        if not runs:
            logger.warning(
                "Primary batch reservation returned zero samples; activating fallback selector",
                extra={
                    "service": "scheduler",
                    "stage": "fallback_selection",
                    "requested_limit": requested_limit,
                    "effective_limit": effective_limit,
                },
            )

            eligible_samples = session.scalars(
                select(Sample)
                .join(SampleTag, Sample.id == SampleTag.sample_id)
                .join(Tag, Tag.id == SampleTag.tag_id)
                .where(
                    Tag.name == "ransomware",
                    Sample.status_id == pending_status_id,
                    Sample.analyzed.is_(False),
                    Sample.file_type.in_(["exe", "dll"]),
                    Sample.detected_arch.in_(["x86", "x64"]),
                )
                .order_by(Sample.created_at.asc())
                .limit(effective_limit)
            ).all()

            fallback_runs = []
            sample_ids = [sample.id for sample in eligible_samples]
            next_attempt_by_sample: dict[int, int] = {}
            if sample_ids:
                attempt_rows = session.execute(
                    select(
                        AnalysisRun.sample_id,
                        func.coalesce(func.max(AnalysisRun.attempt_no), 0),
                    )
                    .where(AnalysisRun.sample_id.in_(sample_ids))
                    .group_by(AnalysisRun.sample_id)
                ).all()
                next_attempt_by_sample = {
                    int(sample_id): int(max_attempt) + 1
                    for sample_id, max_attempt in attempt_rows
                }

            for sample in eligible_samples:
                execution_arch = sample.detected_arch if sample.detected_arch in {"x86", "x64"} else "x86"
                cape_machine = _machine_for_arch(execution_arch) or get_settings().cape_machine_x86
                next_attempt = next_attempt_by_sample.get(sample.id, 1)

                analysis_run = AnalysisRun(
                    sample_id=sample.id,
                    attempt_no=next_attempt,
                    state="reserved",
                    status_id=reserved_status_id,
                    cape_machine=cape_machine,
                    cape_platform="windows",
                    cape_tags=execution_arch,
                    execution_arch=execution_arch,
                    retry_count=0,
                    fallback_used=True,
                )
                session.add(analysis_run)
                fallback_runs.append(analysis_run)

                logger.debug(
                    "Fallback run created",
                    extra={
                        "service": "scheduler",
                        "stage": "fallback_run",
                        "sha256": sample.sha256,
                        "execution_arch": execution_arch,
                        "cape_machine": cape_machine,
                    },
                )

                sample.status_id = reserved_status_id

            session.flush()
            runs = fallback_runs

        valid_runs = []

        for run in runs:
            sample = getattr(run, "sample", None)
            if not sample:
                continue

            if sample.status_id not in {pending_status_id, reserved_status_id}:
                logger.warning(
                    "Skipping non-pending sample during batch creation",
                    extra={
                        "service": "scheduler",
                        "stage": "batch_filter",
                        "analysis_run_id": run.id,
                        "sha256": run.sha256,
                        "sample_status_id": sample.status_id,
                    },
                )
                continue

            valid_runs.append(run)

        run_ids = [run.id for run in valid_runs]

        logger.info(
            "Reserved daily batch",
            extra={
                "service": "scheduler",
                "stage": "batch_create",
                "batch_size": len(run_ids),
                "requested_limit": requested_limit,
                "effective_limit": effective_limit,
            },
        )

        return run_ids


def plan_arch_aware_daily_batch(
    *,
    limit: int,
    rerun_existing: bool,
) -> list[ArchAwareCandidate]:
    """
    Build a deterministic architecture-aware plan without DB writes.
    PE architecture from stored_file_path has priority over metadata.
    """
    with session_scope() as session:
        query = select(
            Sample.id,
            Sample.detected_arch,
            Sample.stored_file_path,
        ).where(
            ~Sample.id.in_(
                select(AnalysisRun.sample_id).where(
                    AnalysisRun.state.in_(
                        ["pending", "reserved", "running", "rerunning", "reported"]
                    )
                )
            )
        )

        if rerun_existing:
            # Rerun pool comes from previously analyzed samples and must not depend
            # on tag completeness.
            query = query.where(
                Sample.analyzed.is_(True),
                Sample.id.in_(
                    select(AnalysisRun.sample_id).where(AnalysisRun.state.in_(["done", "error"]))
                ),
            )
        else:
            query = (
                query.join(SampleTag, Sample.id == SampleTag.sample_id)
                .join(Tag, Tag.id == SampleTag.tag_id)
                .where(
                    Tag.name == "ransomware",
                    Sample.analyzed.is_(False),
                )
            )

        # Pull a wider candidate window because arch filtering happens post-PE parse.
        rows = session.execute(
            query.order_by(Sample.updated_at.desc().nulls_last()).limit(max(limit * 8, 200))
        ).all()

    planned: list[ArchAwareCandidate] = []
    for sample_id, detected_arch, stored_file_path in rows:
        effective_arch, real_arch, reason = _resolve_effective_arch(detected_arch, stored_file_path)
        machine = _machine_for_arch(effective_arch)
        candidate = ArchAwareCandidate(
            sample_id=int(sample_id),
            detected_arch=_metadata_arch(detected_arch),
            real_pe_arch=real_arch,
            effective_arch=effective_arch,
            cape_machine=machine,
            reason=reason,
            stored_file_path=stored_file_path,
        )
        planned.append(candidate)
        if len([p for p in planned if p.cape_machine is not None]) >= limit:
            break

    return planned


def create_arch_aware_daily_batch(
    *,
    limit: int,
    rerun_existing: bool,
    dry_run: bool,
) -> tuple[list[ArchAwareCandidate], list[int]]:
    """
    Reserve analysis runs using architecture-aware routing.
    - No writes in dry_run mode.
    - Preserves history by inserting new analysis_runs (attempt_no increment).
    """
    plan = plan_arch_aware_daily_batch(limit=limit, rerun_existing=rerun_existing)
    selected = [p for p in plan if p.cape_machine is not None][:limit]
    if dry_run or not selected:
        return plan, []

    run_ids: list[int] = []
    with session_scope() as session:
        reserved_status_id = get_status_id(session, "reserved")

        created_runs: list[AnalysisRun] = []
        for candidate in selected:
            max_attempt = session.execute(
                select(func.coalesce(func.max(AnalysisRun.attempt_no), 0)).where(
                    AnalysisRun.sample_id == candidate.sample_id
                )
            ).scalar_one()

            run = AnalysisRun(
                sample_id=candidate.sample_id,
                attempt_no=int(max_attempt) + 1,
                state="reserved",
                status_id=reserved_status_id,
                cape_machine=candidate.cape_machine,
                cape_platform="windows",
                cape_tags=candidate.effective_arch,
                execution_arch=candidate.effective_arch,
                fallback_used=False,
                retry_count=0,
            )
            session.add(run)
            created_runs.append(run)

            sample = session.get(Sample, candidate.sample_id)
            if sample is not None:
                sample.status_id = reserved_status_id

        session.flush()
        run_ids = [int(run.id) for run in created_runs]

    return plan, run_ids


def dispatch_daily_batch(
    analysis_run_ids: Sequence[int],
    sync: bool = False,
) -> None:
    settings = get_settings()

    if not settings.redis_url:
        raise RuntimeError("Redis URL missing from configuration")

    if not analysis_run_ids:
        logger.info(
            "No analysis runs available for dispatch",
            extra={
                "service": "scheduler",
                "stage": "dispatch_skip",
            },
        )
        return

    # Force Redis runtime config
    os.environ["CELERY_BROKER_URL"] = settings.redis_url
    os.environ["CELERY_RESULT_BACKEND"] = settings.redis_url

    failed_run_ids: list[int] = []

    for analysis_run_id in analysis_run_ids:
        try:
            with session_scope() as validation_session:
                error_status_id = get_status_id(validation_session, "error")

                run = get_analysis_run(validation_session, analysis_run_id)

                max_retries = settings.pipeline_max_retries
                if (run.retry_count or 0) >= max_retries:
                    logger.error(
                        "Max retries reached, skipping run",
                        extra={
                            "service": "scheduler",
                            "stage": "retry_limit",
                            "analysis_run_id": analysis_run_id,
                            "retry_count": run.retry_count,
                        },
                    )
                    continue

                if run.status_id == error_status_id:
                    logger.warning(
                        "Skipping errored analysis run dispatch",
                        extra={
                            "service": "scheduler",
                            "stage": "dispatch_skip_error",
                            "analysis_run_id": analysis_run_id,
                            "sha256": run.sha256,
                        },
                    )
                    continue

            if sync:
                logger.info(
                    "Executing synchronous pipeline",
                    extra={
                        "service": "scheduler",
                        "stage": "sync_dispatch",
                        "analysis_run_id": analysis_run_id,
                    },
                )

                run_minimal_pipeline_sync(analysis_run_id)
                continue

            logger.info(
                "Dispatching async pipeline",
                extra={
                    "service": "scheduler",
                    "stage": "async_dispatch",
                    "analysis_run_id": analysis_run_id,
                    "broker": _safe_redis_target(settings.redis_url),
                    "queue": "threattrace",
                },
            )

            workflow = chain(
                download_sample_task.si(analysis_run_id),
                submit_to_cape_task.si(analysis_run_id),
                poll_cape_until_reported_task.si(analysis_run_id),
            )

            t0 = time.perf_counter()

            workflow.apply_async(
                queue="threattrace",
                routing_key="threattrace",
                retry=False,
                ignore_result=False,
            )

            dispatch_time_ms = int((time.perf_counter() - t0) * 1000)

            logger.info(
                "Dispatch completed",
                extra={
                    "service": "scheduler",
                    "stage": "dispatch_complete",
                    "analysis_run_id": analysis_run_id,
                    "dispatch_time_ms": dispatch_time_ms,
                },
            )

        except Exception as exc:
            with session_scope() as retry_session:
                run = get_analysis_run(retry_session, analysis_run_id)

                run.retry_count = (run.retry_count or 0) + 1
                run.last_error = str(exc)

            failed_run_ids.append(analysis_run_id)
            logger.exception(
                "Failed dispatching analysis run",
                extra={
                    "service": "scheduler",
                    "stage": "dispatch_error",
                    "analysis_run_id": analysis_run_id,
                    "error_message": str(exc),
                },
            )

    if failed_run_ids:
        raise RuntimeError(f"Failed dispatching analysis runs: {failed_run_ids}")
