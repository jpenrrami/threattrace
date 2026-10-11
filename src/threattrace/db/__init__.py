"""Database package.

Centralized exports for:
- SQLAlchemy models
- Session helpers
- Repository layer
"""

from threattrace.db.models import AnalysisRun, CapeReport, Sample, SampleTag, Tag
from threattrace.db.repositories import (
    NormalizedSample,
    get_analysis_run,
    get_campaign_ready_samples,
    get_or_create_tag,
    get_pipeline_statistics,
    get_reported_samples,
    get_sample,
    get_samples_by_family_hint,
    get_samples_by_risk_level,
    get_samples_by_tag,
    get_samples_pending_postprocessing,
    mark_analysis_error,
    mark_fallback_attempt,
    process_daily_pipeline,
    reserve_daily_batch,
    sanitize_json_strings,
    set_run_state,
    set_sample_downloaded,
    set_sample_submitted,
    store_cape_report,
    upsert_sample,
)
from threattrace.db.session import check_db_health, get_session_factory, init_db, session_scope

__all__ = [
    # Models
    "AnalysisRun",
    "CapeReport",
    "Sample",
    "SampleTag",
    "Tag",

    # Session / DB
    "session_scope",
    "get_session_factory",
    "check_db_health",
    "init_db",

    # Repositories / DTOs
    "NormalizedSample",
    "get_analysis_run",
    "get_campaign_ready_samples",
    "get_or_create_tag",
    "get_pipeline_statistics",
    "get_reported_samples",
    "get_sample",
    "get_samples_by_family_hint",
    "get_samples_by_risk_level",
    "get_samples_by_tag",
    "get_samples_pending_postprocessing",
    "mark_analysis_error",
    "mark_fallback_attempt",
    "process_daily_pipeline",
    "reserve_daily_batch",
    "sanitize_json_strings",
    "set_run_state",
    "set_sample_downloaded",
    "set_sample_submitted",
    "store_cape_report",
    "upsert_sample",
]
