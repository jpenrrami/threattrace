from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threattrace.config.settings import get_settings


class JsonFormatter(logging.Formatter):
    """
    Structured JSON formatter for operational pipeline logs.

    Features:
    - UTF-8 safe
    - Worker-safe
    - Multi-stage observability
    - Exception serialization
    - Operational traceability
    """

    STRUCTURED_FIELDS = (
        "sample_sha256",
        "sha256",
        "analysis_run_id",
        "cape_task_id",
        "stage",
        "service",
        "attempt",
        "duration_ms",
        "error_class",
        "error_message",
        "sample_count",
        "batch_size",
        "task_count",
        "machine",
        "fallback_used",
        "execution_arch",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "process": record.process,
            "thread": record.thread,
        }

        if record.exc_info and "exception" not in payload:
            payload["exception"] = self.formatException(record.exc_info)

        for field in self.STRUCTURED_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value

        return json.dumps(
            payload,
            ensure_ascii=False,
            default=str,
            separators=(",", ":"),
        )


class SafeExtraFilter(logging.Filter):
    """
    Prevents missing structured fields from breaking formatter consistency.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for field in JsonFormatter.STRUCTURED_FIELDS:
            if not hasattr(record, field):
                setattr(record, field, None)
        return True


def _build_log_file_path() -> Path:
    settings = get_settings()
    log_dir = settings.storage_root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "pipeline.log"


def configure_logging(level: str = "INFO") -> None:
    """
    Configures global logging safely for:
    - CLI
    - Celery workers
    - Scheduler
    - ETL
    - Production runtime
    """

    root_logger = logging.getLogger()

    if getattr(root_logger, "_threattrace_configured", False):
        return

    if root_logger.handlers:
        root_logger.handlers = []
    root_logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))

    formatter = JsonFormatter()
    extra_filter = SafeExtraFilter()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(extra_filter)

    # Rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        _build_log_file_path(),
        maxBytes=25 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(extra_filter)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    root_logger.propagate = False

    root_logger.info(
        "Logging configured",
        extra={
            "service": "logging",
            "stage": "init",
            "level": level,
        },
    )

    root_logger._threattrace_configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Standardized logger accessor.
    """
    return logging.getLogger(name)
