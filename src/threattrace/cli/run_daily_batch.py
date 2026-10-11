from __future__ import annotations

import argparse
import os

from threattrace.common.logging import configure_logging, get_logger
from threattrace.config.settings import get_settings
from threattrace.db.models import AnalysisRun, Sample
from threattrace.db.repositories import get_status_id
from threattrace.db.session import session_scope
from threattrace.scheduler.daily_batch import (
    _safe_redis_target,
    create_arch_aware_daily_batch,
    create_daily_batch,
    dispatch_daily_batch,
)

logger = get_logger(__name__)

RANSOMWARE_KEYWORDS = {
    "ransom",
    "ransomware",
    "lockbit",
    "lockbit2",
    "lockbit3",
    "blackcat",
    "alphv",
    "conti",
    "revil",
    "sodinokibi",
    "ryuk",
    "hive",
    "maze",
    "clop",
    "babuk",
    "phobos",
    "dharma",
    "medusalocker",
    "ragnar",
    "ragnarlocker",
    "akira",
    "avaddon",
    "blackmatter",
    "darkside",
    "royal",
    "play",
    "basta",
    "blackbasta",
    "cuba",
    "zeppelin",
    "mountlocker",
    "locker",
    "crypt",
    "cryptolocker",
    "wannacry",
    "petya",
    "notpetya",
    "cerber",
    "gandcrab",
    "vice society",
    "nokoyawa",
    "suncrypt",
    "yanluowang",
    "mallox",
    "8base",
    "bianlian",
    "inc",
    "qilin",
    "medusa",
    "trigona",
    "proton",
    "ranion",
    "globeimposter",
    "encrypthub",
    "global",
}

NEGATIVE_KEYWORDS = {
    "stealer",
    "rat",
    "miner",
    "loader",
    "dropper",
    "adware",
    "installer",
    "patch",
    "crack",
    "toolbar",
    "keygen",
    "backdoor",
    "botnet",
    "coinminer",
    "spyware",
    "worm",
    "trojan",
    "hacktool",
    "remoteadmin",
    "updater",
    "driver",
}

RANSOMWARE_KEYWORDS_NORM = {k.strip().lower() for k in RANSOMWARE_KEYWORDS}
NEGATIVE_KEYWORDS_NORM = {k.strip().lower() for k in NEGATIVE_KEYWORDS}

def should_exclude_sample(sample: Sample) -> bool:
    searchable_parts = [
        getattr(sample, "file_name", "") or "",
        getattr(sample, "signature", "") or "",
        str(getattr(sample, "tags", "") or ""),
    ]

    combined = " ".join(str(part) for part in searchable_parts).lower()

    positive_match = any(k in combined for k in RANSOMWARE_KEYWORDS_NORM)
    negative_match = any(k in combined for k in NEGATIVE_KEYWORDS_NORM)

    return (not positive_match) or negative_match


def exclude_non_ransomware_pending() -> int:
    excluded_count = 0

    with session_scope() as session:
        pending_status_id = get_status_id(session, "pending")
        excluded_status_id = get_status_id(
            session,
            "excluded_non_ransomware",
        )

        batch_size = 500
        offset = 0
        while True:
            batch = (
                session.query(Sample)
                .filter(
                    Sample.status_id == pending_status_id,
                    Sample.analyzed.is_(False),
                )
                .limit(batch_size)
                .offset(offset)
                .all()
            )
            if not batch:
                break

            for sample in batch:
                if should_exclude_sample(sample):
                    sample.status_id = excluded_status_id
                    excluded_count += 1

            offset += batch_size

        logger.info(
            "Pre-batch ransomware scope filter completed",
            extra={
                "service": "scheduler",
                "stage": "scope_filter",
                "excluded_non_ransomware": excluded_count,
            },
        )

    return excluded_count


def cleanup_stuck_submitted() -> int:
    """
    Resets recoverable stuck pipeline states while preserving forensic history.
    Targets only unfinished states that can be safely re-queued.
    """
    reset_count = 0

    with session_scope() as session:
        error_status_id = get_status_id(session, "error")

        logger.info(
            "Scanning for recoverable stuck analysis runs",
            extra={
                "service": "scheduler",
                "stage": "recovery_scan",
            },
        )
        stuck_runs = (
            session.query(AnalysisRun)
            .filter(
                AnalysisRun.status_id != error_status_id,
                AnalysisRun.finished_at.is_(None),
                AnalysisRun.cape_task_id.isnot(None),
            )
            .all()
        )

        for run in stuck_runs:
            logger.warning(
                "Resetting stuck submitted sample",
                extra={
                    "service": "scheduler",
                    "stage": "recovery",
                    "analysis_run_id": run.id,
                    "sha256": run.sha256,
                },
            )
            run.status_id = error_status_id
            run.error_stage = "cli_recovery"
            run.cape_task_id = None
            run.next_retry_at = None
            run.finished_at = None
            run.error_message = "Auto-reset from recoverable stuck state"
            run.retry_count = (run.retry_count or 0) + 1
            reset_count += 1

    logger.info(
        "Recoverable stuck analysis scan completed",
        extra={
            "service": "scheduler",
            "stage": "recovery_complete",
            "recovered_count": reset_count,
        },
    )

    return reset_count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Schedule or execute the daily raw pipeline batch"
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan selection only; do not reserve or dispatch runs",
    )
    parser.add_argument(
        "--arch-aware",
        action="store_true",
        help="Use PE-aware architecture routing from THREATTRACE_CAPE_MACHINE_X86/X64",
    )
    parser.add_argument(
        "--rerun-existing",
        action="store_true",
        help="Select already analyzed ransomware samples for controlled rerun batches",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help="Run the reserved batch synchronously without Celery",
    )
    parser.add_argument(
        "--recover-stuck",
        action="store_true",
        help="Reset recoverable stuck samples before dispatch",
    )

    args = parser.parse_args()

    logger.info(
        "Daily batch CLI arguments parsed",
        extra={
            "service": "scheduler",
            "stage": "cli_args",
            "requested_limit": args.limit,
            "sync_mode": args.sync,
            "recover_stuck": args.recover_stuck,
            "dry_run": args.dry_run,
            "arch_aware": args.arch_aware,
            "rerun_existing": args.rerun_existing,
        },
    )

    if args.limit is not None and args.limit <= 0:
        raise ValueError("--limit must be greater than zero")
    if args.dry_run and not args.arch_aware:
        raise ValueError("--dry-run currently requires --arch-aware")

    settings = get_settings()
    configure_logging(settings.log_level)
    logger.info(
        "Launching daily malware pipeline batch module",
        extra={
            "service": "scheduler",
            "stage": "bootstrap",
            "daily_batch_size": settings.daily_batch_size,
        },
    )

    os.environ.setdefault("CELERY_BROKER_URL", settings.redis_url)
    os.environ.setdefault("CELERY_RESULT_BACKEND", settings.redis_url)

    logger.info(
        "Celery broker/backend environment configured",
        extra={
            "service": "scheduler",
            "stage": "broker_config",
            "broker": _safe_redis_target(settings.redis_url),
        },
    )


    logger.info(
        "Scheduler preflight complete",
        extra={
            "service": "scheduler",
            "stage": "startup",
            "sync_mode": args.sync,
            "recover_stuck": args.recover_stuck,
            "requested_limit": args.limit or settings.daily_batch_size,
            "redis_target": _safe_redis_target(settings.redis_url),
        },
    )

    if args.recover_stuck and not args.arch_aware:
        recovered = cleanup_stuck_submitted()
        logger.info(
            "Recovered stuck submitted samples",
            extra={
                "service": "scheduler",
                "stage": "recovery",
                "recovered_count": recovered,
            },
        )

    excluded = 0
    if not args.arch_aware:
        excluded = exclude_non_ransomware_pending()

    logger.info(
        "Pre-batch exclusion stage completed",
        extra={
            "service": "scheduler",
            "stage": "scope_filter_complete",
            "excluded_non_ransomware": excluded,
        },
    )

    logger.info(
        "Beginning daily batch sample selection",
        extra={
            "service": "scheduler",
            "stage": "selection",
            "selection_limit": args.limit or settings.daily_batch_size,
        },
    )

    selection_limit = args.limit or settings.daily_batch_size
    if args.arch_aware:
        plan, analysis_run_ids = create_arch_aware_daily_batch(
            limit=selection_limit,
            rerun_existing=args.rerun_existing,
            dry_run=args.dry_run,
        )
        print("sample_id,metadata_arch,real_pe_arch,effective_arch,cape_machine,reason")
        for row in plan[:selection_limit]:
            print(
                f"{row.sample_id},{row.detected_arch or '-'},"
                f"{row.real_pe_arch or '-'},"
                f"{row.effective_arch or '-'},"
                f"{row.cape_machine or '-'},"
                f"{row.reason}"
            )
    else:
        analysis_run_ids = create_daily_batch(limit=selection_limit)

    logger.info(
        "Daily batch sample selection completed",
        extra={
            "service": "scheduler",
            "stage": "selection_complete",
            "selected_samples": len(analysis_run_ids),
        },
    )

    if args.dry_run:
        logger.info(
            "Dry-run mode enabled; reservation/dispatch skipped",
            extra={
                "service": "scheduler",
                "stage": "dry_run",
                "selected_samples": len(analysis_run_ids),
                "arch_aware": args.arch_aware,
                "rerun_existing": args.rerun_existing,
            },
        )
        return

    if not analysis_run_ids:
        logger.info(
            "No samples available for daily batch",
            extra={
                "service": "scheduler",
                "stage": "selection",
                "batch_size": 0,
            },
        )
        return

    try:
        logger.info(
            "Dispatching daily malware analysis batch",
            extra={
                "service": "scheduler",
                "stage": "dispatch_start",
                "batch_size": len(analysis_run_ids),
                "sync_mode": args.sync,
            },
        )

        dispatch_daily_batch(
            analysis_run_ids,
            sync=args.sync,
        )

        logger.info(
            "Daily batch dispatched",
            extra={
                "service": "scheduler",
                "stage": "dispatch",
                "batch_size": len(analysis_run_ids),
                "sync_mode": args.sync,
                "broker": _safe_redis_target(settings.redis_url),
            },
        )

        logger.info(
            "Daily malware pipeline batch completed successfully",
            extra={
                "service": "scheduler",
                "stage": "complete",
                "batch_size": len(analysis_run_ids),
                "sync_mode": args.sync,
                "recover_stuck": args.recover_stuck,
            },
        )

    except Exception as exc:
        logger.exception(
            "Daily batch dispatch failed",
            extra={
                "service": "scheduler",
                "stage": "dispatch",
                "error": str(exc),
                "batch_size": len(analysis_run_ids) if analysis_run_ids else 0,
                "sync_mode": args.sync,
            },
        )
        raise

if __name__ == "__main__":
    main()
