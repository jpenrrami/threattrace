from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from celery import current_app, shared_task

from threattrace.cape.client import CapeClient
from threattrace.common.json_config import config_path, load_json_config
from threattrace.common.logging import configure_logging, get_logger
from threattrace.common.time import parse_optional_datetime as _coerce_utc
from threattrace.config.settings import get_settings
from threattrace.db.repositories import (
    get_analysis_run,
    get_sample,
    get_status_id,
    mark_analysis_error,
    mark_fallback_attempt,
    process_daily_pipeline,
    set_run_state,
    set_sample_downloaded,
    set_sample_submitted,
    store_cape_report,
)
from threattrace.db.session import session_scope
from threattrace.malwarebazaar.client import MalwareBazaarClient
from threattrace.storage.filesystem import (
    extract_malware_archive,
    persist_cape_report,
    persist_sample_file,
    sha256_file,
)

logger = get_logger(__name__)

PIPELINE_RUNTIME_CONFIG_PATH = config_path("pipeline", "runtime_rules.json")


def _pipeline_runtime_config() -> dict[str, Any]:
    return load_json_config(str(PIPELINE_RUNTIME_CONFIG_PATH))


@dataclass(slots=True)
class RunContext:
    analysis_run_id: int
    sample_id: int
    sha256: str
    file_name: str | None = None
    stored_file_path: str | None = None
    detected_arch: str | None = None
    malwarebazaar_detected_arch: str | None = None
    cape_task_id: int | None = None
    retry_count: int = 0
    submitted_at: datetime | None = None
    started_at: datetime | None = None
    scheduled_at: datetime | None = None


def _log(stage: str, message: str, analysis_run_id: int | None = None, sha256: str | None = None) -> None:
    logger.info(
        message,
        extra={
            "service": "pipeline",
            "stage": stage,
            "analysis_run_id": analysis_run_id,
            "sha256": sha256,
        },
    )


def _run_wait_exceeded(run: Any, settings: Any) -> bool:
    submitted_at = _coerce_utc(run.submitted_at or run.started_at or run.scheduled_at)
    if submitted_at is None:
        return False
    return (
        datetime.now(UTC) - submitted_at
    ).total_seconds() >= settings.cape_max_wait_seconds


def _saturated_retry_count(current_retry: int) -> int:
    return min(int(_pipeline_runtime_config()["max_total_retries"]), max(0, current_retry) + 1)


def _poll_delay_seconds(
    settings: Any,
    *,
    status: str,
    submitted_at: datetime | None,
    retry_count: int,
) -> int:
    rules = _pipeline_runtime_config()["poll_delay_rules"]
    now = datetime.now(UTC)
    submitted = _coerce_utc(submitted_at)
    elapsed = 0 if submitted is None else max(0, int((now - submitted).total_seconds()))

    if status == "running":
        base = settings.cape_poll_running_interval_seconds
    else:
        base = settings.cape_poll_interval_seconds

    if elapsed >= int(rules["after_6_hours_seconds"]):
        return settings.cape_poll_max_interval_seconds
    if elapsed >= int(rules["after_2_hours_seconds"]):
        return min(settings.cape_poll_max_interval_seconds, max(base, int(rules["after_2_hours_min_delay_seconds"])))
    if elapsed >= int(rules["after_30_minutes_seconds"]):
        return min(settings.cape_poll_max_interval_seconds, max(base, int(rules["after_30_minutes_min_delay_seconds"])))
    if retry_count >= int(rules["after_retry_count"]):
        return min(settings.cape_poll_max_interval_seconds, max(base, int(rules["after_retry_min_delay_seconds"])))
    return base

# New helper function for marking stage failure
def _mark_stage_failure(
    analysis_run_id: int,
    stage: str,
    error_message: str,
) -> None:
    with session_scope() as session:
        run = get_analysis_run(session, analysis_run_id)
        sample = get_sample(session, run.sample_id)
        mark_analysis_error(
            session,
            analysis_run_id,
            stage=stage,
            error_message=error_message,
        )
        set_run_state(session, analysis_run_id, "error")
        if sample is not None:
            sample.status_id = get_status_id(session, "error")


def _lock_run_context(analysis_run_id: int) -> RunContext | None:
    with session_scope() as session:
        run = get_analysis_run(session, analysis_run_id)
        if run.state == "done" or run.locked:
            return None
        run.mark_locked(datetime.now(UTC))
        sample = get_sample(session, run.sample_id)
        return RunContext(
            analysis_run_id=analysis_run_id,
            sample_id=run.sample_id,
            sha256=sample.sha256,
            file_name=sample.file_name,
            stored_file_path=sample.stored_file_path,
            detected_arch=sample.detected_arch,
            malwarebazaar_detected_arch=(sample.malwarebazaar_data or {}).get("detected_arch"),
            cape_task_id=run.cape_task_id,
            retry_count=run.retry_count or 0,
            submitted_at=_coerce_utc(run.submitted_at),
            started_at=_coerce_utc(run.started_at),
            scheduled_at=_coerce_utc(run.scheduled_at),
        )


def _unlock_run(analysis_run_id: int) -> None:
    with session_scope() as session:
        run = get_analysis_run(session, analysis_run_id)
        if run.locked:
            run.mark_unlocked()


def _schedule_poll_retry(
    analysis_run_id: int,
    retry_count: int,
    countdown: int,
    last_error: str,
) -> None:
    with session_scope() as session:
        run = get_analysis_run(session, analysis_run_id)
        run.retry_count = retry_count
        run.next_retry_at = None
        run.last_error = last_error
    poll_cape_until_reported_task.apply_async(
        args=[analysis_run_id],
        countdown=countdown,
    )


def _schedule_fetch_retry(
    analysis_run_id: int,
    retry_count: int,
    countdown: int,
) -> None:
    with session_scope() as session:
        run = get_analysis_run(session, analysis_run_id)
        run.retry_count = retry_count
        run.last_error = "REPORT_NOT_READY"
    fetch_report_task.apply_async(
        args=[analysis_run_id],
        countdown=countdown,
    )


def _sanitize_json_for_postgres(value: Any) -> Any:
    """
    Remove null characters (\x00 / \u0000) that break JSONB/PostgreSQL.
    Sanitize dicts, lists, and strings recursively.
    """
    if isinstance(value, dict):
        return {
            _sanitize_json_for_postgres(key): _sanitize_json_for_postgres(val)
            for key, val in value.items()
        }

    if isinstance(value, list):
        return [_sanitize_json_for_postgres(item) for item in value]

    if isinstance(value, str):
        return value.replace("\x00", "")

    return value

# Deep sanitization and roundtrip for safe storage
def _prepare_report_for_storage(report_json: Any) -> dict[str, Any]:
    """
    Sanitiza profundamente reportes CAPE para almacenamiento seguro en JSONB
    sin reparseo riesgoso.
    """
    import re

    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                clean(k): clean(v)
                for k, v in value.items()
            }

        if isinstance(value, list):
            return [clean(v) for v in value]

        if isinstance(value, str):
            value = value.replace("\x00", "")
            value = value.replace("\u0000", "")

            # Escape invalid backslashes before retrying JSON parse.
            value = re.sub(
                r'\\(?!["\\/bfnrtu])',
                r"\\\\",
                value,
            )

            # Reparar unicode roto
            value = re.sub(
                r'\\u(?![0-9a-fA-F]{4})',
                r"\\\\u",
                value,
            )

            return value

        return value

    return clean(report_json)


def _pe_arch_or_none(sample_bytes: bytes) -> str | None:
    """
    Detecta arquitectura PE:
    - x86
    - x64
    - None
    """
    try:
        if sample_bytes[:2] != b"MZ":
            return None

        pe_offset = int.from_bytes(sample_bytes[0x3C:0x40], "little")
        if sample_bytes[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return None

        machine = int.from_bytes(sample_bytes[pe_offset + 4:pe_offset + 6], "little")

        if machine == 0x014C:
            return "x86"
        if machine == 0x8664:
            return "x64"

        return None
    except Exception:
        return None


def _select_cape_target(arch: str) -> tuple[str, str]:
    settings = get_settings()
    normalized_arch = (arch or "unknown").strip().lower()

    if normalized_arch == "x86":
        return settings.cape_machine_x86, "x86"
    if normalized_arch == "x64":
        return settings.cape_machine_x64, "x64"
    if normalized_arch == "unknown":
        return settings.cape_machine_x86, "x86"

    raise RuntimeError(f"Unsupported architecture: {arch}")


def _fallback_cape_target(primary_machine: str) -> tuple[str, str]:
    settings = get_settings()
    normalized_machine = (primary_machine or "").strip().lower()
    x86 = settings.cape_machine_x86.strip().lower()
    x64 = settings.cape_machine_x64.strip().lower()

    if normalized_machine == x86:
        return settings.cape_machine_x64, "x64"
    if normalized_machine == x64:
        return settings.cape_machine_x86, "x86"

    raise RuntimeError(f"Unknown primary machine: {primary_machine}")


def execute_download_sample(analysis_run_id: int) -> None:
    client = MalwareBazaarClient()
    context = _lock_run_context(analysis_run_id)
    if context is None:
        return
    try:
        _log("download", "Downloading sample archive from MalwareBazaar", analysis_run_id, context.sha256)
        archive_bytes = client.download_sample_archive(context.sha256)
        sample_bytes, inner_filename = extract_malware_archive(archive_bytes)
        arch = _pe_arch_or_none(sample_bytes) or "unknown"
        stored_path = persist_sample_file(
            context.sha256,
            sample_bytes,
            inner_filename or context.file_name,
        )
        downloaded_sha256 = sha256_file(stored_path)
        if downloaded_sha256.lower() != context.sha256.lower():
            raise RuntimeError(
                f"SHA256 mismatch after download: expected={context.sha256} got={downloaded_sha256}"
            )
        with session_scope() as session:
            sample = get_sample(session, context.sample_id)
            if sample.malwarebazaar_data is None:
                sample.malwarebazaar_data = {}
            sample.malwarebazaar_data["detected_arch"] = arch
            sample.detected_arch = arch
            set_sample_downloaded(session, analysis_run_id, str(stored_path))
            get_analysis_run(session, analysis_run_id).mark_unlocked()
        _log("download", "Sample stored locally", analysis_run_id, context.sha256)
    finally:
        _unlock_run(analysis_run_id)


def execute_submit_to_cape(analysis_run_id: int) -> None:
    client = CapeClient()
    context = _lock_run_context(analysis_run_id)
    if context is None:
        return
    try:
        if not context.stored_file_path:
            raise RuntimeError("Stored sample path missing")
        stored_file_path = Path(context.stored_file_path)
        if not stored_file_path.exists():
            raise FileNotFoundError(f"Sample file not found at {stored_file_path}")
        _log("cape_submit", "Submitting sample to CAPE", analysis_run_id, context.sha256)
        detected_arch = (
            context.detected_arch
            or context.malwarebazaar_detected_arch
            or "unknown"
        ).strip().lower()
        selected_machine, selected_tags = _select_cape_target(detected_arch)
        fallback_used = False
        try:
            task_id = client.submit_file(
                stored_file_path,
                machine=selected_machine,
                tags=selected_tags,
            )
            if not isinstance(task_id, int) or task_id <= 0:
                raise RuntimeError("Invalid CAPE task_id returned")
        except Exception as primary_exc:
            logger.warning(
                "Primary CAPE submission failed",
                extra={
                    "service": "pipeline",
                    "stage": "cape_submit",
                    "analysis_run_id": analysis_run_id,
                    "sha256": context.sha256,
                    "machine": selected_machine,
                    "error_message": str(primary_exc),
                },
            )
            fallback_machine, fallback_tags = _fallback_cape_target(selected_machine)
            if fallback_machine == selected_machine:
                raise RuntimeError("Fallback machine identical to primary")
            _log(
                "cape_submit",
                f"Primary machine failed, retrying with fallback {fallback_machine}",
                analysis_run_id,
                context.sha256,
            )
            selected_machine, selected_tags = fallback_machine, fallback_tags
            fallback_used = True
            task_id = client.submit_file(
                stored_file_path,
                machine=selected_machine,
                tags=selected_tags,
            )
            if not isinstance(task_id, int) or task_id <= 0:
                raise RuntimeError("Invalid CAPE task_id returned")
        with session_scope() as session:
            if fallback_used:
                mark_fallback_attempt(
                    session,
                    analysis_run_id,
                    selected_machine,
                    selected_tags,
                )
            set_sample_submitted(
                session,
                analysis_run_id,
                task_id,
                selected_machine,
                selected_tags,
            )
            get_analysis_run(session, analysis_run_id).mark_unlocked()
        _log(
            "cape_submit",
            f"Submitted to CAPE task_id={task_id}",
            analysis_run_id,
            context.sha256,
        )
    finally:
        _unlock_run(analysis_run_id)


def execute_poll_cape(analysis_run_id: int) -> None:
    """
    Non-blocking CAPE polling:
    - Polls a limited number of times
    - If still not ready, requeues itself
    - Prevents Celery worker starvation
    """
    settings = get_settings()
    client = CapeClient()
    context = _lock_run_context(analysis_run_id)
    if context is None:
        return
    try:
        if context.cape_task_id is None:
            raise RuntimeError("CAPE task ID missing")
        if _run_wait_exceeded(context, settings):
            raise TimeoutError(
                f"CAPE polling exceeded max wait for task {context.cape_task_id}"
            )
        current_retry = max(0, context.retry_count)
        task_data = client.get_task_status(context.cape_task_id)
        status = str(
            task_data.get("status")
            or task_data.get("data", {}).get("status")
            or ""
        ).strip().lower()

        if status == "reported":
            with session_scope() as session:
                set_run_state(session, analysis_run_id, "reported")
                get_analysis_run(session, analysis_run_id).mark_unlocked()
            _log(
                "cape_poll",
                "CAPE task fully reported and ready for report fetch",
                analysis_run_id,
                context.sha256,
            )
            fetch_report_task.apply_async(
                args=[analysis_run_id],
                countdown=0,
            )
            return

        if status in {
            "failed_analysis",
            "failed_processing",
            "failed_reporting",
            "recovered",
            "reported_failed",
        }:
            raise RuntimeError(
                f"CAPE task {context.cape_task_id} failed with status={status}"
            )

        next_retry = _saturated_retry_count(current_retry)
        countdown = _poll_delay_seconds(
            settings,
            status=status or "pending",
            submitted_at=context.submitted_at or context.started_at or context.scheduled_at,
            retry_count=next_retry,
        )
        _log(
            "cape_poll",
            f"CAPE task status={status or 'pending'}; scheduling retry poll in {countdown}s",
            analysis_run_id,
            context.sha256,
        )
        _schedule_poll_retry(
            analysis_run_id,
            retry_count=next_retry,
            countdown=countdown,
            last_error=f"CAPE_STATUS:{status or 'pending'}",
        )
    finally:
        _unlock_run(analysis_run_id)

# Stage tasks used by scheduler chains.

@shared_task
def download_sample_task(analysis_run_id: int) -> None:
    try:
        execute_download_sample(analysis_run_id)
    except Exception as exc:
        _mark_stage_failure(
            analysis_run_id,
            "download",
            str(exc),
        )
        logger.exception(
            "Download stage failed",
            extra={
                "analysis_run_id": analysis_run_id,
                "error_message": str(exc),
            },
        )
        raise


@shared_task
def submit_to_cape_task(analysis_run_id: int) -> None:
    try:
        execute_submit_to_cape(analysis_run_id)
    except Exception as exc:
        _mark_stage_failure(
            analysis_run_id,
            "cape_submit",
            str(exc),
        )
        logger.exception(
            "CAPE submit stage failed",
            extra={
                "analysis_run_id": analysis_run_id,
                "error_message": str(exc),
            },
        )
        raise


@shared_task
def poll_cape_task(analysis_run_id: int) -> None:
    try:
        execute_poll_cape(analysis_run_id)
    except Exception as exc:
        _mark_stage_failure(
            analysis_run_id,
            "cape_poll",
            str(exc),
        )
        logger.exception(
            "CAPE poll stage failed",
            extra={
                "analysis_run_id": analysis_run_id,
                "error_message": str(exc),
            },
        )
        raise


@shared_task
def poll_cape_until_reported_task(analysis_run_id: int) -> None:
    try:
        execute_poll_cape(analysis_run_id)
    except Exception as exc:
        _mark_stage_failure(
            analysis_run_id,
            "cape_poll",
            str(exc),
        )
        logger.exception(
            "CAPE poll requeue stage failed",
            extra={
                "analysis_run_id": analysis_run_id,
                "error_message": str(exc),
            },
        )
        raise


@shared_task
def fetch_report_task(analysis_run_id: int) -> None:
    try:
        execute_fetch_report(analysis_run_id)
    except Exception as exc:
        error_msg = str(exc)

        # NON-BLOCKING retry for CAPE report not ready
        if "REPORT_NOT_READY" in error_msg:
            with session_scope() as session:
                run = get_analysis_run(session, analysis_run_id)
                settings = get_settings()
                if _run_wait_exceeded(run, settings):
                    _mark_stage_failure(
                        analysis_run_id,
                        "report_fetch",
                        "Max wait exceeded while waiting for CAPE report",
                    )
                    return
                retry_count = _saturated_retry_count(run.retry_count or 0)

            # exponential backoff (max ~10 min)
            retry_cfg = _pipeline_runtime_config()["fetch_report_retry"]
            delay = min(int(retry_cfg["max_delay_seconds"]), int(retry_cfg["base_exponent"]) ** retry_count)

            _log(
                "report",
                f"Requeueing fetch_report_task (attempt={retry_count}, delay={delay}s)",
                analysis_run_id,
                None,
            )

            _schedule_fetch_retry(
                analysis_run_id,
                retry_count=retry_count,
                countdown=delay,
            )
            return

        _mark_stage_failure(
            analysis_run_id,
            "report_fetch",
            error_msg,
        )

        logger.exception(
            "Report fetch stage failed",
            extra={
                "analysis_run_id": analysis_run_id,
                "error_message": error_msg,
            },
        )

        raise




def run_minimal_pipeline_sync(analysis_run_id: int) -> None:
    """Run the core pipeline synchronously with local error handling."""
    _run_pipeline_once(analysis_run_id, batch_mode=True)


def _run_pipeline_once(
    analysis_run_id: int,
    *,
    batch_mode: bool,
) -> None:
    try:
        execute_download_sample(analysis_run_id)
        execute_submit_to_cape(analysis_run_id)
        execute_poll_cape(analysis_run_id)
    except Exception as exc:
        with session_scope() as session:
            try:
                mark_analysis_error(
                    session,
                    analysis_run_id,
                    stage="pipeline",
                    error_message=str(exc),
                )
                set_run_state(session, analysis_run_id, "error")
            except Exception as mark_exc:
                logger.exception(
                    "Failed marking pipeline run as error",
                    extra={
                        "service": "pipeline",
                        "analysis_run_id": analysis_run_id,
                        "error_message": str(mark_exc),
                    },
                )
        logger.exception(
            "Pipeline failed but batch continues"
            if batch_mode
            else "Pipeline execution failed",
            extra={
                "service": "pipeline",
                "analysis_run_id": analysis_run_id,
                "error_message": str(exc),
            },
        )


def main(batch_size: int = 10) -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    _log("startup", f"Starting daily pipeline batch_size={batch_size}")
    with session_scope() as session:
        run_ids = process_daily_pipeline(session, batch_size=batch_size)
    if not run_ids:
        _log("startup", "No pending samples available")
        return
    for analysis_run_id in run_ids:
        _run_pipeline_once(analysis_run_id, batch_mode=False)


def execute_fetch_report(analysis_run_id: int) -> None:
    context = _lock_run_context(analysis_run_id)
    if context is None:
        return
    try:
        if context.cape_task_id is None:
            raise RuntimeError("CAPE task ID missing")
        _log("report", "Fetching CAPE report", analysis_run_id, context.sha256)
        try:
            settings = get_settings()
            analysis_dir = settings.cape_storage_path / "analyses" / str(context.cape_task_id)
            source_report_path = analysis_dir / "reports" / "report.json"
            _log(
                "report",
                f"Checking report path: {source_report_path}",
                analysis_run_id,
                context.sha256,
            )
            raw_text = source_report_path.read_text(encoding="utf-8", errors="ignore")
            if not raw_text.strip():
                _log("report", "Empty report file → requeue fetch", analysis_run_id, context.sha256)
                raise RuntimeError("REPORT_NOT_READY")
            try:
                report_json = json.loads(raw_text)
            except json.JSONDecodeError:
                _log("report", "Invalid JSON in CAPE report → requeue fetch", analysis_run_id, context.sha256)
                raise RuntimeError("REPORT_NOT_READY")
        except FileNotFoundError:
            _log("report", "Report file missing → requeue fetch", analysis_run_id, context.sha256)
            raise RuntimeError("REPORT_NOT_READY")

        if not isinstance(report_json, dict) or "info" not in report_json:
            _log("report", "Invalid CAPE report structure → requeue fetch", analysis_run_id, context.sha256)
            raise RuntimeError("REPORT_NOT_READY")
        sanitized_report_json = _prepare_report_for_storage(report_json)
        if not sanitized_report_json:
            raise RuntimeError("Empty CAPE report")
        if "behavior" not in sanitized_report_json:
            logger.warning(
                "CAPE report missing behavior section",
                extra={
                    "analysis_run_id": analysis_run_id,
                    "sha256": context.sha256,
                },
            )

        persisted_report_path = persist_cape_report(
            context.sha256,
            context.cape_task_id,
            sanitized_report_json,
            already_sanitized=True,
        )
        report_sha256 = sha256_file(persisted_report_path)

        with session_scope() as session:
            sample = get_sample(session, context.sample_id)
            store_cape_report(
                session,
                str(persisted_report_path),
                report_sha256,
                sanitized_report_json,
                analysis_run_id=analysis_run_id,
                sha256=context.sha256,
            )
            sample.raw_report_path = str(persisted_report_path)
            set_run_state(session, analysis_run_id, "reported")
            get_analysis_run(session, analysis_run_id).mark_unlocked()

        _log("report", "CAPE report stored", analysis_run_id, context.sha256)
        current_app.send_task(
            "threattrace.workers.process_reports.process_single_report",
            args=[str(persisted_report_path)],
            countdown=5,
        )
        _log("etl", "ETL task scheduled", analysis_run_id, context.sha256)
    finally:
        _unlock_run(analysis_run_id)

if __name__ == "__main__":
    main()
