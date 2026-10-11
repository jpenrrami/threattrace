from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BIGINT,
    BOOLEAN,
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import ENUM as PG_ENUM
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threattrace.db.base import Base

# Centralized execution states.
STATE_PENDING = "pending"
STATE_RESERVED = "reserved"
STATE_RUNNING = "running"
STATE_RERUNNING = "rerunning"
STATE_REPORTED = "reported"
STATE_DONE = "done"
STATE_ERROR = "error"

TERMINAL_STATES = {STATE_DONE, STATE_ERROR}


JSONVariant = JSON().with_variant(JSONB, "postgresql")
INETVariant = INET().with_variant(String(64), "sqlite")

analysis_state_enum = PG_ENUM(
    "pending",
    "reserved",
    "running",
    "rerunning",
    "reported",
    "done",
    "error",
    name="analysis_state",
    create_type=True,
)
class Sample(Base):
    __tablename__ = "samples"
    __table_args__ = (
        UniqueConstraint("sha256", name="uq_samples_sha256"),
        CheckConstraint(
            "detected_arch IN ('x86','x64','unknown')",
            name="ck_samples_detected_arch",
        ),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sha256: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    md5: Mapped[str] = mapped_column(Text, nullable=False)
    sha1: Mapped[str] = mapped_column(Text, nullable=False)
    file_name: Mapped[str | None] = mapped_column(Text)
    file_type: Mapped[str | None] = mapped_column(Text)
    file_size: Mapped[int | None] = mapped_column(BIGINT)
    signature: Mapped[str | None] = mapped_column(Text)
    reporter: Mapped[str | None] = mapped_column(Text)
    origin_country: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    malwarebazaar_data: Mapped[dict] = mapped_column(JSONVariant, nullable=False)
    detected_arch: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="unknown",
        server_default="unknown",
    )
    analyzed: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text("false"))
    status_id: Mapped[int] = mapped_column(BIGINT, ForeignKey("status_catalog.id"), nullable=False)
    download_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stored_file_path: Mapped[str | None] = mapped_column(Text)
    processed_report_path: Mapped[str | None] = mapped_column(Text)
    raw_report_path: Mapped[str | None] = mapped_column(Text)
    ioc_report_path: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )
    tags: Mapped[list[SampleTag]] = relationship(back_populates="sample", cascade="all, delete-orphan")
    analysis_runs: Mapped[list[AnalysisRun]] = relationship(back_populates="sample", cascade="all, delete-orphan")


Index("idx_samples_status_analyzed", Sample.status_id, Sample.analyzed)
Index("idx_samples_created_at", Sample.created_at.desc())
Index("idx_samples_detected_arch", Sample.detected_arch)
Index("idx_samples_status_arch", Sample.status_id, Sample.detected_arch)
Index("idx_samples_analyzed", Sample.analyzed)
Index("idx_samples_sha256", Sample.sha256)
Index("idx_samples_status_id", Sample.status_id)


class Tag(Base):
    __tablename__ = "tags"
    __table_args__ = (
        Index("idx_tags_name", "name"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)

    samples: Mapped[list[SampleTag]] = relationship(back_populates="tag", cascade="all, delete-orphan")


class SampleTag(Base):
    __tablename__ = "sample_tags"
    __table_args__ = (
        Index("idx_sample_tags_tag_id", "tag_id"),
        Index("idx_sample_tags_sample_id", "sample_id"),
        UniqueConstraint("sample_id", "tag_id", name="uq_sample_tag"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), nullable=False)
    inserted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    sample: Mapped[Sample] = relationship(back_populates="tags")
    tag: Mapped[Tag] = relationship(back_populates="samples")


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    __table_args__ = (
        UniqueConstraint("sample_id", "attempt_no", name="uq_analysis_run_attempt"),
        Index("idx_analysis_runs_sample_id", "sample_id"),
        Index("idx_analysis_runs_retry", "retry_count"),
        Index("idx_analysis_runs_next_retry", "next_retry_at"),
        CheckConstraint(
            "execution_arch IN ('x86','x64','unknown')",
            name="ck_analysis_runs_execution_arch",
        ),
        {"extend_existing": True}
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    status_id: Mapped[int] = mapped_column(BIGINT, ForeignKey("status_catalog.id"), nullable=False)

    # Keep explicit state and status_id synchronized.
    state: Mapped[str] = mapped_column(
        analysis_state_enum,
        nullable=False,
        server_default=text("'pending'"),
        index=True,
    )

    # Soft locking to prevent concurrent processing
    locked: Mapped[bool] = mapped_column(
        BOOLEAN,
        nullable=False,
        default=False,
        server_default=text("false"),
        index=True,
    )

    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Extended error tracking (complements error_message)
    last_error: Mapped[str | None] = mapped_column(Text)
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    downloaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    etl_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cape_task_id: Mapped[int | None] = mapped_column(BIGINT, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )
    cape_machine: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="cape-x86",
        server_default="cape-x86",
    )
    cape_platform: Mapped[str] = mapped_column(Text, nullable=False, default="windows", server_default="windows")
    cape_tags: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="x86",
        server_default="x86",
    )
    error_stage: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_arch: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="x86",
        server_default="x86",
    )
    fallback_used: Mapped[bool] = mapped_column(
        BOOLEAN,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    sample: Mapped[Sample] = relationship(back_populates="analysis_runs")
    cape_report: Mapped[CapeReport | None] = relationship(back_populates="analysis_run", cascade="all, delete-orphan")

    @property
    def sha256(self) -> str | None:
        """
        Return the related sample SHA256 when available.
        """
        return self.sample.sha256 if self.sample is not None else None

    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def can_retry(self, max_retries: int) -> bool:
        return (self.retry_count or 0) < max_retries and not self.is_terminal()

    def mark_locked(self, now: datetime) -> None:
        self.locked = True
        self.locked_at = now

    def mark_unlocked(self) -> None:
        self.locked = False
        self.locked_at = None
    def set_state(self, state: str, session=None) -> None:
        """
        State machine canonical setter.
        Keeps status_id and state synchronized.
        """
        self.state = state
        self.updated_at = func.now()

        if session:
            status = session.scalar(
                select(StatusCatalog).where(StatusCatalog.code == state)
            )
            if status:
                self.status_id = status.id


Index("idx_analysis_runs_status", AnalysisRun.status_id)
Index("idx_analysis_runs_arch", AnalysisRun.execution_arch)
Index("idx_analysis_runs_machine", AnalysisRun.cape_machine)
Index(
    "idx_analysis_runs_status_retry",
    AnalysisRun.status_id,
    AnalysisRun.retry_count,
)
Index("idx_analysis_runs_locked", AnalysisRun.locked)
Index("idx_analysis_runs_polling", AnalysisRun.state, AnalysisRun.retry_count, AnalysisRun.next_retry_at)
Index("idx_analysis_runs_sample_state", AnalysisRun.sample_id, AnalysisRun.state)


class CapeReport(Base):
    __tablename__ = "cape_reports"
    __table_args__ = (
        UniqueConstraint("analysis_run_id", name="uq_cape_reports_analysis_run_id"),
        UniqueConstraint("cape_task_id", name="uq_cape_reports_cape_task_id"),
        Index("idx_cape_reports_campaign_ready_bool", "campaign_ready"),
        Index("idx_cape_reports_analysis_run", "analysis_run_id"),
        CheckConstraint(
            "persistence_score IS NULL OR persistence_score >= 0",
            name="ck_cape_reports_persistence_score",
        ),
        CheckConstraint(
            "severity_score IS NULL OR severity_score >= 0",
            name="ck_cape_reports_severity_score",
        ),
        CheckConstraint(
            "confidence_score IS NULL OR confidence_score BETWEEN 0 AND 100",
            name="ck_cape_reports_confidence_score",
        ),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False)
    cape_task_id: Mapped[int] = mapped_column(BIGINT, nullable=False)
    report_path: Mapped[str] = mapped_column(Text, nullable=False)
    report_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    raw_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    scheduled_tasks: Mapped[list | None] = mapped_column(JSONVariant)
    services: Mapped[list | None] = mapped_column(JSONVariant)
    lolbins: Mapped[list | None] = mapped_column(JSONVariant)
    attack_patterns: Mapped[dict | None] = mapped_column(JSONVariant)
    persistence_score: Mapped[int | None] = mapped_column(Integer)
    severity_score: Mapped[int | None] = mapped_column(Integer)
    confidence_score: Mapped[int | None] = mapped_column(Integer)
    ransomware_indicators: Mapped[list | None] = mapped_column(JSONVariant)
    credential_access_indicators: Mapped[list | None] = mapped_column(JSONVariant)
    defense_evasion_indicators: Mapped[list | None] = mapped_column(JSONVariant)
    process_chain: Mapped[list | None] = mapped_column(JSONVariant)
    resolved_apis: Mapped[list | None] = mapped_column(JSONVariant)
    file_extensions_touched: Mapped[list | None] = mapped_column(JSONVariant)
    unified_ioc: Mapped[dict | None] = mapped_column(JSONVariant)
    unified_ioc_normalized: Mapped[dict | None] = mapped_column(JSONVariant)
    unified_ioc_threat_intel: Mapped[dict | None] = mapped_column(JSONVariant)
    unified_ioc_scores: Mapped[dict | None] = mapped_column(JSONVariant)
    sample_category: Mapped[str | None] = mapped_column(Text)
    family_hints: Mapped[list | None] = mapped_column(JSONVariant)
    campaign_features: Mapped[dict | None] = mapped_column(JSONVariant)
    campaign_ready: Mapped[bool | None] = mapped_column(BOOLEAN)
    etl_processed: Mapped[bool] = mapped_column(
        BOOLEAN,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    analysis_run: Mapped[AnalysisRun] = relationship(back_populates="cape_report")


Index("idx_cape_reports_persistence_score", CapeReport.persistence_score)
Index("idx_cape_reports_severity_score", CapeReport.severity_score)
Index("idx_cape_reports_confidence_score", CapeReport.confidence_score)
Index(
    "idx_cape_reports_threat_risk",
    text("(raw_json->'threat_intelligence'->>'risk_level')"),
)
Index(
    "idx_cape_reports_sample_category",
    text("(raw_json->'threat_intelligence'->>'sample_category')"),
)
Index(
    "idx_cape_reports_campaign_ready",
    text("(raw_json->'threat_intelligence'->>'campaign_ready')"),
)

class IOCReport(Base):
    __tablename__ = "ioc_reports"
    __table_args__ = (
        Index("idx_ioc_reports_category", "sample_category"),
        Index("idx_ioc_reports_created", "created_at"),
    )

    analysis_run_id: Mapped[int] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        primary_key=True,
    )
    processed_report_path: Mapped[str] = mapped_column(Text, nullable=False)
    sample_category: Mapped[str | None] = mapped_column(Text)
    family_hints: Mapped[dict | None] = mapped_column(JSONVariant)
    campaign_features: Mapped[dict | None] = mapped_column(JSONVariant)
    unified_ioc: Mapped[dict] = mapped_column(JSONVariant, nullable=False)
    normalized_ioc: Mapped[dict | None] = mapped_column(JSONVariant)
    threat_intel: Mapped[dict | None] = mapped_column(JSONVariant)
    scores: Mapped[dict | None] = mapped_column(JSONVariant)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )


class SampleSource(Base):
    __tablename__ = "sample_sources"
    __table_args__ = (
        UniqueConstraint("sample_id", "source", name="uq_sample_sources_sample_source"),
        Index("idx_sample_sources_source", "source"),
        Index("idx_sample_sources_dataset_role", "dataset_role"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    source_sample_id: Mapped[str | None] = mapped_column(Text)
    source_query: Mapped[str | None] = mapped_column(Text)
    source_data: Mapped[dict] = mapped_column(JSONVariant, nullable=False, server_default=text("'{}'::jsonb"))
    dataset_role: Mapped[str] = mapped_column(Text, nullable=False)
    family_hint: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class GeneratedDetectionRule(Base):
    __tablename__ = "generated_detection_rules"
    __table_args__ = (
        Index("idx_generated_detection_rules_type", "rule_type"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    rule_name: Mapped[str] = mapped_column(Text, nullable=False)
    rule_type: Mapped[str] = mapped_column(Text, nullable=False)
    source_ioc_types: Mapped[list] = mapped_column(JSONVariant, nullable=False, server_default=text("'[]'::jsonb"))
    rule_content: Mapped[dict] = mapped_column(JSONVariant, nullable=False, server_default=text("'{}'::jsonb"))
    output_path: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class DetectionEvaluation(Base):
    __tablename__ = "detection_evaluations"
    __table_args__ = (
        Index("idx_detection_evaluations_sample_id", "sample_id"),
        Index("idx_detection_evaluations_detector", "detector"),
        Index("idx_detection_evaluations_detected", "detected"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    analysis_run_id: Mapped[int | None] = mapped_column(ForeignKey("analysis_runs.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(Text, nullable=False)
    dataset_role: Mapped[str] = mapped_column(Text, nullable=False)
    detector: Mapped[str] = mapped_column(Text, nullable=False)
    architecture: Mapped[str] = mapped_column(Text, nullable=False)
    test_machine: Mapped[str] = mapped_column(Text, nullable=False)
    detected: Mapped[bool] = mapped_column(BOOLEAN, nullable=False)
    detection_time_seconds: Mapped[float | None] = mapped_column(Numeric)
    first_detection_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    triggered_rules: Mapped[list] = mapped_column(JSONVariant, nullable=False, server_default=text("'[]'::jsonb"))
    triggered_iocs: Mapped[list] = mapped_column(JSONVariant, nullable=False, server_default=text("'[]'::jsonb"))
    triggered_artifacts: Mapped[list] = mapped_column(JSONVariant, nullable=False, server_default=text("'[]'::jsonb"))
    velociraptor_report_path: Mapped[str | None] = mapped_column(Text)
    cape_task_id: Mapped[int | None] = mapped_column(BIGINT)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    velociraptor_reports: Mapped[list[VelociraptorReport]] = relationship(
        back_populates="evaluation",
        cascade="all, delete-orphan",
    )


class VelociraptorReport(Base):
    __tablename__ = "velociraptor_reports"
    __table_args__ = (
        Index("idx_velociraptor_reports_evaluation_id", "evaluation_id"),
        Index("idx_velociraptor_reports_sample_id", "sample_id"),
        Index("idx_velociraptor_reports_sha256", "sha256"),
        Index("idx_velociraptor_reports_detected", "detected"),
        Index("idx_velociraptor_reports_high_confidence", "high_confidence_detected"),
        Index("idx_velociraptor_reports_vm_arch", "vm_arch"),
        Index("idx_velociraptor_reports_source", "source"),
        Index("idx_velociraptor_reports_flow", "primary_flow_id"),
        Index("idx_velociraptor_reports_created", "created_at"),
        UniqueConstraint("archive_name", name="uq_velociraptor_reports_archive_name"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    evaluation_id: Mapped[int] = mapped_column(ForeignKey("detection_evaluations.id", ondelete="CASCADE"), nullable=False)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    sha256: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(Text)
    vm: Mapped[str] = mapped_column(Text, nullable=False)
    vm_arch: Mapped[str | None] = mapped_column(Text)
    client_id: Mapped[str | None] = mapped_column(Text)
    primary_flow_id: Mapped[str | None] = mapped_column(Text)
    snapshot: Mapped[str | None] = mapped_column(Text)
    execute: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text("false"))
    wait_seconds: Mapped[int | None] = mapped_column(Integer)
    flow_wait_timeout: Mapped[int | None] = mapped_column(Integer)
    flow_poll_seconds: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    detected: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text("false"))
    high_confidence_detected: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text("false"))
    collection_failed: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text("false"))
    collection_failure_reason: Mapped[str | None] = mapped_column(Text)
    partial_export: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text("false"))
    final_revert_ok: Mapped[bool | None] = mapped_column(BOOLEAN)
    archive_name: Mapped[str] = mapped_column(Text, nullable=False)
    archive_dir: Mapped[str] = mapped_column(Text, nullable=False)
    result_dir: Mapped[str | None] = mapped_column(Text)
    raw_exports_dir: Mapped[str | None] = mapped_column(Text)
    metadata_path: Mapped[str | None] = mapped_column(Text)
    summary_path: Mapped[str | None] = mapped_column(Text)
    notes_path: Mapped[str | None] = mapped_column(Text)
    winrm_log_path: Mapped[str | None] = mapped_column(Text)
    manifest_path: Mapped[str | None] = mapped_column(Text)
    report_path: Mapped[str] = mapped_column(Text, nullable=False)
    raw_report: Mapped[dict] = mapped_column(JSONVariant, nullable=False, server_default=text("'{}'::jsonb"))
    summary_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, server_default=text("'{}'::jsonb"))
    metadata_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, server_default=text("'{}'::jsonb"))
    manifest_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, server_default=text("'{}'::jsonb"))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    evaluation: Mapped[DetectionEvaluation] = relationship(back_populates="velociraptor_reports")
    artifact_results: Mapped[list[VelociraptorArtifactResult]] = relationship(
        back_populates="report",
        cascade="all, delete-orphan",
    )


class VelociraptorArtifactResult(Base):
    __tablename__ = "velociraptor_artifact_results"
    __table_args__ = (
        UniqueConstraint("velociraptor_report_id", "artifact_name", name="uq_velociraptor_artifact_report_name"),
        Index("idx_vr_artifact_results_report_id", "velociraptor_report_id"),
        Index("idx_vr_artifact_results_sample_id", "sample_id"),
        Index("idx_vr_artifact_results_artifact_name", "artifact_name"),
        Index("idx_vr_artifact_results_flow_id", "flow_id"),
        Index("idx_vr_artifact_results_completed", "completed"),
        Index("idx_vr_artifact_results_failed", "failed"),
        Index("idx_vr_artifact_results_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    velociraptor_report_id: Mapped[int] = mapped_column(
        ForeignKey("velociraptor_reports.id", ondelete="CASCADE"),
        nullable=False,
    )
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    artifact_name: Mapped[str] = mapped_column(Text, nullable=False)
    flow_id: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str | None] = mapped_column(Text)
    completed: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text("false"))
    failed: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text("false"))
    timed_out: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text("false"))
    collection_failed: Mapped[bool] = mapped_column(BOOLEAN, nullable=False, default=False, server_default=text("false"))
    collection_failure_reason: Mapped[str | None] = mapped_column(Text)
    total_collected_rows: Mapped[int | None] = mapped_column(BIGINT)
    artifacts_with_results: Mapped[list] = mapped_column(JSONVariant, nullable=False, server_default=text("'[]'::jsonb"))
    filtered_hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    export_returncode: Mapped[int | None] = mapped_column(Integer)
    export_stderr: Mapped[str | None] = mapped_column(Text)
    raw_export_path: Mapped[str | None] = mapped_column(Text)
    raw_export_rows: Mapped[int | None] = mapped_column(Integer)
    raw_export_size_bytes: Mapped[int | None] = mapped_column(BIGINT)
    artifact_summary_json: Mapped[dict] = mapped_column(JSONVariant, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    report: Mapped[VelociraptorReport] = relationship(back_populates="artifact_results")


class RawEvidenceItem(Base):
    __tablename__ = "raw_evidence_items"
    __table_args__ = (
        UniqueConstraint("source_type", "source_record_id", name="uq_raw_evidence_source_record"),
        Index("idx_raw_evidence_sample", "sample_id"),
        Index("idx_raw_evidence_report", "cape_report_id"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    cape_report_id: Mapped[int | None] = mapped_column(ForeignKey("cape_reports.id", ondelete="SET NULL"))
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    source_record_id: Mapped[str] = mapped_column(Text, nullable=False)
    extractor: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONVariant, nullable=False, server_default=text("'{}'::jsonb"))
    provenance_status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'linked'"))
    provenance_reason: Mapped[str | None] = mapped_column(Text)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ThreatTraceSchemaMetadata(Base):
    __tablename__ = "threattrace_schema_metadata"
    __table_args__ = (
        CheckConstraint("singleton_id = 1", name="ck_schema_metadata_singleton"),
    )

    singleton_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    schema_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class VelociraptorValidationCandidate(Base):
    __tablename__ = "velociraptor_validation_candidates"
    __table_args__ = (
        UniqueConstraint("sample_id", name="uq_vr_validation_candidates_sample_id"),
        Index("idx_vr_validation_candidates_state", "candidate_state"),
        Index("idx_vr_validation_candidates_source", "source"),
        Index("idx_vr_validation_candidates_batch_id", "batch_id"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    sha256: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(Text)
    local_path: Mapped[str | None] = mapped_column(Text)
    candidate_state: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'candidate'"))
    selected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    last_error: Mapped[str | None] = mapped_column(Text)
    batch_id: Mapped[str | None] = mapped_column(Text)
    retrieval_method: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class StatusCatalog(Base):
    __tablename__ = "status_catalog"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)

class BehaviorPattern(Base):
    __tablename__ = "behavior_patterns"
    __table_args__ = (
        Index("idx_behavior_patterns_code", "pattern_code"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    pattern_code: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_version: Mapped[str] = mapped_column(Text, nullable=False)


class SampleAttackTechnique(Base):
    __tablename__ = "sample_attack_techniques"
    __table_args__ = (
        UniqueConstraint(
            "sample_id",
            "technique",
            name="uq_sample_attack_technique",
        ),
        Index("idx_attack_techniques_technique", "technique"),
        Index("idx_attack_techniques_sample_cat", "sample_id", "category"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    technique: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False, default=1.0, server_default="1.00")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

Index("idx_attack_techniques_sample_id", SampleAttackTechnique.sample_id)
Index("idx_attack_techniques_category", SampleAttackTechnique.category)


class SampleBehaviorScore(Base):
    __tablename__ = "sample_behavior_scores"
    __table_args__ = (
        CheckConstraint("persistence_score >= 0", name="ck_behavior_persistence_score"),
        CheckConstraint("severity_score >= 0", name="ck_behavior_severity_score"),
        CheckConstraint("confidence_score BETWEEN 0 AND 100", name="ck_behavior_confidence_score"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, unique=True)
    persistence_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    severity_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    confidence_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    ransomware_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    credential_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    defense_evasion_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

Index("idx_behavior_scores_ransomware", SampleBehaviorScore.ransomware_score)
Index("idx_behavior_scores_confidence", SampleBehaviorScore.confidence_score)


class SampleArtifact(Base):
    __tablename__ = "sample_artifacts"
    __table_args__ = (
        UniqueConstraint(
            "sample_id",
            "artifact_type",
            "artifact_value",
            name="uq_sample_artifact_unique",
        ),
        Index("idx_sample_artifacts_value", "artifact_value"),
        Index("idx_sample_artifacts_sample_type", "sample_id", "artifact_type"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    artifact_type: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False, default=1.0, server_default="1.00")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

Index("idx_sample_artifacts_sample_id", SampleArtifact.sample_id)
Index("idx_sample_artifacts_type", SampleArtifact.artifact_type)


class SampleIoC(Base):
    __tablename__ = "sample_iocs"
    __table_args__ = (
        UniqueConstraint(
            "sample_id",
            "type",
            "value",
            "entity_id",
            name="uq_sample_iocs_unique",
        ),
        Index("idx_sample_iocs_type", "type"),
        Index("idx_sample_iocs_entity", "entity_id"),
        Index("idx_sample_iocs_sample_id", "sample_id"),
        CheckConstraint(
            "type IN ('ip','domain','url','file','registry','mutex','process')",
            name="chk_ioc_type",
        ),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    type: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    entity_id: Mapped[int] = mapped_column(BIGINT)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False, default=1.0, server_default="1.00")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("domain", name="uq_domains_domain"),
        Index("idx_domains_registered_domain", "registered_domain"),
        Index("idx_domains_tld", "tld"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(Text, nullable=False)
    registered_domain: Mapped[str | None] = mapped_column(Text)
    tld: Mapped[str | None] = mapped_column(Text)


class IPAddress(Base):
    __tablename__ = "ips"
    __table_args__ = (
        Index("idx_ips_asn", "asn"),
        Index("idx_ips_country", "geo_country_code"),
    )

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(INETVariant, nullable=False, unique=True)
    ip_version: Mapped[int] = mapped_column(Integer, nullable=False)
    is_private: Mapped[bool] = mapped_column(BOOLEAN, nullable=False)
    geo_country_code: Mapped[str | None] = mapped_column(Text)
    geo_country_name: Mapped[str | None] = mapped_column(Text)
    asn: Mapped[str | None] = mapped_column(Text)
    as_org: Mapped[str | None] = mapped_column(Text)
    last_geoip_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


Index("idx_domains_domain", Domain.domain)
Index("idx_sample_iocs_value", SampleIoC.value)
Index(
    "idx_sample_iocs_value_trgm",
    text("value gin_trgm_ops"),
    postgresql_using="gin",
)
Index("idx_analysis_runs_retry_scheduler", AnalysisRun.status_id, AnalysisRun.next_retry_at)
Index("idx_ips_ip", IPAddress.ip)

Index(
    "idx_cape_reports_raw_json",
    CapeReport.raw_json,
    postgresql_using="gin",
    postgresql_ops={"raw_json": "jsonb_path_ops"}
)

# Model integrity validation helper
def validate_model_integrity() -> None:
    """
    Import-time validation helper for schema completeness.
    Ensures all critical ORM models are registered.
    """
    required_models = [
        Sample,
        Tag,
        SampleTag,
        AnalysisRun,
        CapeReport,
        BehaviorPattern,
        SampleAttackTechnique,
        SampleBehaviorScore,
        SampleArtifact,
        SampleIoC,
        IOCReport,
        SampleSource,
        GeneratedDetectionRule,
        DetectionEvaluation,
        VelociraptorReport,
        VelociraptorArtifactResult,
        VelociraptorValidationCandidate,
        Domain,
        IPAddress,
    ]

    if not all(required_models):
        raise RuntimeError("Database model integrity validation failed")


validate_model_integrity()
