from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, case, func, literal, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from threattrace.common.json_config import config_path, load_json_config
from threattrace.config.settings import get_settings
from threattrace.db.models import AnalysisRun, CapeReport, Sample, SampleTag, StatusCatalog, Tag


# --- Status catalog helper ---
def get_status_id(session: Session, code: str) -> int:
    cache = session.info.setdefault("_status_cache", {})
    if code in cache:
        return cache[code]

    value = session.execute(
        text("SELECT id FROM status_catalog WHERE code = :code"),
        {"code": code},
    ).scalar_one()

    cache[code] = value
    return value


REPOSITORY_CONFIG_PATH = config_path("db", "repository_rules.json")


def _repository_config() -> dict[str, Any]:
    return load_json_config(str(REPOSITORY_CONFIG_PATH))


OPEN_PIPELINE_STATES = set(_repository_config()["open_pipeline_states"])


SUPPORTED_RANSOMWARE_FILE_TYPES = set(_repository_config()["supported_ransomware_file_types"])


SUPPORTED_ARCHITECTURES = set(_repository_config()["supported_architectures"])


@dataclass(slots=True)
class NormalizedSample:
    sha256: str
    md5: str
    sha1: str
    file_name: str | None
    file_type: str | None
    file_size: int | None
    signature: str | None
    reporter: str | None
    origin_country: str | None
    first_seen: datetime | None
    malwarebazaar_data: dict[str, Any]
    detected_arch: str | None
    tags: list[str]
    last_seen: str | None = None


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _clear_run_errors(run: AnalysisRun) -> None:
    run.error_stage = None
    run.error_message = None
    run.last_error = None


# Helper to sanitize JSON strings (remove null bytes and invalid utf-8)
def sanitize_json_strings(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            sanitize_json_strings(k): sanitize_json_strings(v)
            for k, v in obj.items()
        }
    elif isinstance(obj, list):
        return [sanitize_json_strings(v) for v in obj]
    elif isinstance(obj, str):
        return obj.replace("\x00", "").encode("utf-8", "ignore").decode("utf-8", "ignore")
    return obj


def get_or_create_tag(session: Session, name: str) -> Tag:
    normalized_name = name.strip().lower()
    tag_id = session.execute(
        insert(Tag)
        .values(name=normalized_name)
        .on_conflict_do_nothing(index_elements=["name"])
        .returning(Tag.id)
    ).scalar_one_or_none()
    if tag_id is not None:
        return session.get(Tag, tag_id)

    tag = session.scalar(select(Tag).where(Tag.name == normalized_name))
    if tag is None:
        raise RuntimeError(f"Failed to resolve tag after upsert: {normalized_name}")
    return tag


def upsert_sample(session: Session, payload: NormalizedSample) -> Sample:
    now = _utcnow()

    stmt = (
        insert(Sample)
        .values(
            sha256=payload.sha256,
            md5=payload.md5,
            sha1=payload.sha1,
            file_name=payload.file_name,
            file_type=payload.file_type,
            file_size=payload.file_size,
            signature=payload.signature,
            reporter=payload.reporter,
            origin_country=payload.origin_country,
            first_seen=payload.first_seen,
            malwarebazaar_data=sanitize_json_strings(payload.malwarebazaar_data or {}),
            detected_arch=payload.detected_arch,
            analyzed=False,
            status_id=get_status_id(session, "pending"),
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=["sha256"],
            set_={
                "md5": payload.md5,
                "sha1": payload.sha1,
                "file_name": payload.file_name,
                "file_type": payload.file_type,
                "file_size": payload.file_size,
                "signature": payload.signature,
                "reporter": payload.reporter,
                "origin_country": payload.origin_country,
                "first_seen": payload.first_seen,
                "malwarebazaar_data": sanitize_json_strings(payload.malwarebazaar_data or {}),
                "detected_arch": payload.detected_arch,
            },
        )
    )

    session.execute(stmt)
    return session.scalar(
        select(Sample).where(Sample.sha256 == payload.sha256)
    )



def reserve_daily_batch(session: Session, limit: int) -> list[AnalysisRun]:
    """
    V2 ULTRA INDUSTRIAL SCHEDULER
    -----------------------------
    Guarantees:
    - 100% SQL-driven (no Python loops)
    - SKIP LOCKED concurrency safety
    - Strict idempotency (no duplicate active runs)
    - Atomic sample → run reservation
    - Correct FK usage (sample_id, not sha256)
    - Safe attempt_no increment per sample
    - Dual-VM routing preserved
    """

    reserved_status = get_status_id(session, "reserved")
    settings = get_settings()

    # ------------------------------------------------------------
    # STEP 1: Candidate selection with row-level locking
    # ------------------------------------------------------------
    candidates_cte = (
        select(
            Sample.id.label("sample_id"),
            Sample.detected_arch.label("arch")
        )
        .select_from(Sample)
        .join(SampleTag, Sample.id == SampleTag.sample_id)
        .join(Tag, Tag.id == SampleTag.tag_id)
        .where(Tag.name == "ransomware")
        .where(Sample.analyzed.is_(False))
        .where(
            Sample.status_id.in_(
                select(StatusCatalog.id).where(StatusCatalog.code.in_(["pending", "error"]))
            )
        )
        # Idempotency: exclude active runs
        .where(
            ~Sample.id.in_(
                select(AnalysisRun.sample_id).where(
                    AnalysisRun.status_id.in_(
                        select(StatusCatalog.id).where(
                            StatusCatalog.code.in_(
                                ["pending", "reserved", "running", "rerunning", "reported"]
                            )
                        )
                    )
                )
            )
        )
        .order_by(Sample.updated_at.asc().nulls_last())
        .limit(limit)
        .with_for_update(skip_locked=True)
        .cte("candidates")
    )

    # ------------------------------------------------------------
    # STEP 2: attempt_no (safe per sample, no race conditions)
    # ------------------------------------------------------------
    attempt_no_subq = (
        select(func.coalesce(func.max(AnalysisRun.attempt_no), 0) + 1)
        .where(AnalysisRun.sample_id == candidates_cte.c.sample_id)
        .correlate(candidates_cte)
        .scalar_subquery()
    )

    # ------------------------------------------------------------
    # STEP 3: Atomic insert (runs)
    # ------------------------------------------------------------
    insert_stmt = insert(AnalysisRun).from_select(
        [
            AnalysisRun.sample_id,
            AnalysisRun.attempt_no,
            AnalysisRun.state,
            AnalysisRun.status_id,
            AnalysisRun.cape_machine,
            AnalysisRun.cape_tags,
            AnalysisRun.execution_arch,
            AnalysisRun.fallback_used,
            AnalysisRun.retry_count,
        ],
        select(
            candidates_cte.c.sample_id,
            attempt_no_subq,
            literal("reserved"),
            reserved_status,
            case(
                (candidates_cte.c.arch == "x64", literal(settings.cape_machine_x64)),
                else_=literal(settings.cape_machine_x86)
            ),
            case(
                (candidates_cte.c.arch == "x64", literal("x64")),
                else_=literal("x86")
            ),
            func.coalesce(candidates_cte.c.arch, "unknown"),
            literal(False),
            literal(0),
        ),
    ).returning(AnalysisRun.id, AnalysisRun.sample_id)

    result = session.execute(insert_stmt)
    rows = result.all()

    runs = [
        session.get(AnalysisRun, r.id)
        for r in rows
    ]

    # ------------------------------------------------------------
    # STEP 4: Atomic sample state update (fully set-based)
    # ------------------------------------------------------------
    if rows:
        sample_ids = [r.sample_id for r in rows]

        session.execute(
            text("""
                UPDATE samples
                SET status_id = :reserved
                WHERE id = ANY(:ids)
            """),
            {"reserved": reserved_status, "ids": sample_ids},
        )

    session.flush()
    return runs


def get_malwarebazaar_daily_quota_usage(session: Session) -> int:
    stmt = (
        select(func.count(AnalysisRun.id))
        .select_from(AnalysisRun)
        .join(Sample, Sample.id == AnalysisRun.sample_id)
        .where(Sample.malwarebazaar_data.isnot(None))
        .where(
            text(
                """
                (
                    analysis_runs.created_at::date = CURRENT_DATE
                    OR analysis_runs.downloaded_at::date = CURRENT_DATE
                    OR analysis_runs.submitted_at::date = CURRENT_DATE
                    OR analysis_runs.reported_at::date = CURRENT_DATE
                    OR (
                        analysis_runs.error_stage = 'download'
                        AND analysis_runs.updated_at::date = CURRENT_DATE
                    )
                )
                """
            )
        )
    )
    return int(session.scalar(stmt) or 0)


def get_analysis_run(session: Session, analysis_run_id: int) -> AnalysisRun:
    stmt: Select[tuple[AnalysisRun]] = select(AnalysisRun).where(
        AnalysisRun.id == analysis_run_id
    )

    run = session.scalar(stmt)

    if run is None:
        raise ValueError(f"Analysis run {analysis_run_id} not found")

    return run


def get_sample(session: Session, sample_id: int) -> Sample:
    sample = session.get(Sample, sample_id)
    if sample is None:
        raise ValueError(f"Sample {sample_id} not found")
    return sample


def set_sample_downloaded(
    session: Session,
    analysis_run_id: int,
    stored_file_path: str,
) -> AnalysisRun:
    now = _utcnow()

    run = get_analysis_run(session, analysis_run_id)
    sample = session.get(Sample, run.sample_id)

    sample.download_date = now
    sample.stored_file_path = stored_file_path
    sample.status_id = get_status_id(session, "running")
    sample.updated_at = now

    run.started_at = run.started_at or now
    run.downloaded_at = now
    run.state = "running"
    run.status_id = get_status_id(session, "running")
    run.updated_at = now
    _clear_run_errors(run)

    session.flush()
    return run


def set_sample_submitted(
    session: Session,
    analysis_run_id: int,
    cape_task_id: int,
    machine: str,
    tags: str,
) -> AnalysisRun:
    """
    Ahora registra dinámicamente:
    - máquina usada
    - arquitectura/tag usada
    """

    now = _utcnow()

    run = get_analysis_run(session, analysis_run_id)
    sample = session.get(Sample, run.sample_id)

    sample.status_id = get_status_id(session, "running")
    sample.updated_at = now

    run.cape_task_id = cape_task_id
    run.cape_machine = machine
    run.cape_tags = tags
    run.execution_arch = (tags or "unknown").strip().lower()
    run.submitted_at = now
    run.state = "running"
    run.status_id = get_status_id(session, "running")
    run.updated_at = now
    _clear_run_errors(run)

    session.flush()
    return run


def set_run_state(
    session: Session,
    analysis_run_id: int,
    state: str,
) -> AnalysisRun:
    run = get_analysis_run(session, analysis_run_id)
    now = _utcnow()

    run.state = state
    run.status_id = get_status_id(session, state)
    run.updated_at = now
    sample = session.get(Sample, run.sample_id)

    if state == "error":
        sample.status_id = get_status_id(session, "error")
        sample.analyzed = False
        sample.updated_at = now
    else:
        _clear_run_errors(run)

    if state == "running":
        sample.status_id = get_status_id(session, "running")
        sample.updated_at = now

    if state == "rerunning":
        sample.status_id = get_status_id(session, "rerunning")
        sample.analyzed = False
        sample.updated_at = now
        run.started_at = run.started_at or now
        run.submitted_at = now
        run.reported_at = None
        run.finished_at = None
        run.next_retry_at = None

    if state == "reserved":
        sample.status_id = get_status_id(session, "reserved")
        sample.updated_at = now

    if state == "reported":
        sample.status_id = get_status_id(session, "reported")
        sample.updated_at = now
        run.reported_at = now

    if state == "done":
        sample.status_id = get_status_id(session, "done")
        sample.updated_at = now
        sample.analyzed = True
        run.finished_at = run.finished_at or now

    session.flush()

    return run


def store_cape_report(
    session: Session,
    report_path: str,
    report_sha256: str,
    raw_json: dict[str, Any],
    analysis_run_id: int | None = None,
    sha256: str | None = None,
    sample_sha256: str | None = None,
    **kwargs,
) -> CapeReport:
    now = _utcnow()
    report_path = str(report_path)

    if sha256 is None:
        sha256 = sample_sha256

    # Hard validation to avoid invalid pipeline identifiers leaking through
    if not sha256 or sha256 == "report":
        raise ValueError(f"Invalid sha256 provided to store_cape_report: {sha256}")

    if analysis_run_id is None and sha256 is None:
        raise ValueError("analysis_run_id or sha256/sample_sha256 is required")

    run = None

    if analysis_run_id is not None:
        run = session.scalar(
            select(AnalysisRun)
            .where(AnalysisRun.id == analysis_run_id)
            .with_for_update()
        )
    elif sha256 is not None:
        run = session.scalar(
            select(AnalysisRun)
            .join(Sample)
            .where(Sample.sha256 == sha256)
            .order_by(AnalysisRun.id.desc())
            .with_for_update()
        )

    if run is None:
        raise ValueError(
            f"Analysis run not found for analysis_run_id={analysis_run_id}, sha256={sha256}"
        )

    clean_raw_json = sanitize_json_strings(raw_json)

    # Preserve enriched threat intelligence fields when present for
    # analytics, reporting, and later reprocessing.
    unified_scores = clean_raw_json.get("unified_ioc_scores") or {}
    if not isinstance(unified_scores, dict):
        unified_scores = {}

    unified_threat_intel = clean_raw_json.get("unified_ioc_threat_intel") or {}
    if not isinstance(unified_threat_intel, dict):
        unified_threat_intel = {}

    ti = clean_raw_json.setdefault("threat_intelligence", {})
    if not isinstance(ti, dict):
        ti = {}
        clean_raw_json["threat_intelligence"] = ti

    ti.update(
        {
            "threat_score": unified_scores.get("threat_score"),
            "severity_score": unified_scores.get("severity_score"),
            "confidence_score": unified_scores.get("confidence_score"),
            "risk_level": unified_scores.get("risk_level"),
            "ttps": unified_threat_intel.get("ttps", []),
            "sample_category": unified_threat_intel.get("sample_category"),
            "family_hints": unified_threat_intel.get("family_hints", []),
            "campaign_features": unified_threat_intel.get("campaign_features", {}),
            "campaign_ready": unified_threat_intel.get("campaign_ready", False),
        }
    )

    if run.cape_task_id is None:
        raise RuntimeError(
            f"Analysis run {analysis_run_id} missing CAPE task ID"
        )

    report = session.scalar(
        select(CapeReport)
        .where(CapeReport.analysis_run_id == run.id)
        .with_for_update(of=CapeReport)
    )

    if report is None:
        report = CapeReport(
            analysis_run_id=run.id,
            cape_task_id=run.cape_task_id,
            report_path=report_path,
            report_sha256=report_sha256,
            raw_json=clean_raw_json,
            fetched_at=now,
            scheduled_tasks=clean_raw_json.get("scheduled_tasks", []),
            services=clean_raw_json.get("services", []),
            lolbins=clean_raw_json.get("lolbins", []),
            attack_patterns=clean_raw_json.get("attack_patterns", {}),
            persistence_score=unified_scores.get("threat_score"),
            severity_score=unified_scores.get("severity_score"),
            confidence_score=unified_scores.get("confidence_score"),
            process_chain=clean_raw_json.get("process_chain", []),
            resolved_apis=clean_raw_json.get("resolved_apis", []),
            file_extensions_touched=clean_raw_json.get("file_extensions_touched", []),
            ransomware_indicators=clean_raw_json.get("ransomware_indicators", []),
            credential_access_indicators=clean_raw_json.get("credential_access_indicators", []),
            defense_evasion_indicators=clean_raw_json.get("defense_evasion_indicators", []),
            sample_category=unified_threat_intel.get("sample_category"),
            family_hints=unified_threat_intel.get("family_hints", []),
            campaign_features=unified_threat_intel.get("campaign_features", {}),
            campaign_ready=unified_threat_intel.get("campaign_ready", False),
            unified_ioc=clean_raw_json.get("unified_ioc", {}),
            unified_ioc_normalized=clean_raw_json.get("unified_ioc_normalized", {}),
            unified_ioc_threat_intel=unified_threat_intel,
            unified_ioc_scores=unified_scores,
            etl_processed=True,
        )
        session.add(report)

    else:
        report.report_path = report_path
        report.report_sha256 = report_sha256
        # Preserve source CAPE evidence once stored. Derived enrichment fields are
        # recalculated elsewhere, but raw_json must remain the immutable base
        # evidence for reprocessing and operational traceability.
        if not report.raw_json:
            report.raw_json = clean_raw_json
        report.fetched_at = now
        report.scheduled_tasks = clean_raw_json.get("scheduled_tasks", [])
        report.services = clean_raw_json.get("services", [])
        report.lolbins = clean_raw_json.get("lolbins", [])
        report.attack_patterns = clean_raw_json.get("attack_patterns", {})
        report.persistence_score = unified_scores.get("threat_score")
        report.severity_score = unified_scores.get("severity_score")
        report.confidence_score = unified_scores.get("confidence_score")
        report.process_chain = clean_raw_json.get("process_chain", [])
        report.resolved_apis = clean_raw_json.get("resolved_apis", [])
        report.file_extensions_touched = clean_raw_json.get("file_extensions_touched", [])
        report.ransomware_indicators = clean_raw_json.get("ransomware_indicators", [])
        report.credential_access_indicators = clean_raw_json.get("credential_access_indicators", [])
        report.defense_evasion_indicators = clean_raw_json.get("defense_evasion_indicators", [])
        report.sample_category = unified_threat_intel.get("sample_category")
        report.family_hints = unified_threat_intel.get("family_hints", [])
        report.campaign_features = unified_threat_intel.get("campaign_features", {})
        report.campaign_ready = unified_threat_intel.get("campaign_ready", False)
        report.unified_ioc = clean_raw_json.get("unified_ioc", {})
        report.unified_ioc_normalized = clean_raw_json.get("unified_ioc_normalized", {})
        report.unified_ioc_threat_intel = unified_threat_intel
        report.unified_ioc_scores = unified_scores
        report.etl_processed = True

    return report


def mark_fallback_attempt(
    session: Session,
    analysis_run_id: int,
    fallback_machine: str,
    fallback_tags: str,
) -> AnalysisRun:
    """
    Marks that the pipeline switched architectures/VM due to primary failure.
    """
    run = get_analysis_run(session, analysis_run_id)

    run.cape_machine = fallback_machine
    run.cape_tags = fallback_tags
    run.execution_arch = (fallback_tags or "unknown").strip().lower()
    run.fallback_used = True
    run.retry_count = (run.retry_count or 0) + 1

    session.flush()
    return run


def mark_analysis_error(
    session: Session,
    analysis_run_id: int,
    stage: str,
    error_message: str,
) -> None:
    now = _utcnow()

    run = get_analysis_run(session, analysis_run_id)
    sample = session.get(Sample, run.sample_id)

    run.status_id = get_status_id(session, "error")
    run.error_stage = stage
    previous_error = run.error_message or ""
    run.error_message = (
        f"{previous_error}\n{error_message}".strip()
        if previous_error
        else error_message
    )
    run.finished_at = now

    sample.status_id = get_status_id(session, "error")
    sample.analyzed = False
    session.flush()


def process_daily_pipeline(session: Session, batch_size: int = 10) -> list[int]:
    """
    Reserva muestras pendientes para el pipeline diario.
    Devuelve lista de analysis_run IDs.
    """
    runs = reserve_daily_batch(session, limit=batch_size)
    return [run.id for run in runs]


# === Additional helper functions for analytics, enrichment, and reporting ===

def get_reported_samples(session: Session, limit: int = 100) -> list[Sample]:
    """
    Returns analyzed samples that already have completed CAPE reports.
    Useful for analytics, enrichment, and threat intelligence post-processing.
    """
    stmt = (
        select(Sample)
        .where(Sample.analyzed.is_(True))
        .where(Sample.status_id == get_status_id(session, "done"))
        .order_by(Sample.updated_at.desc())
        .limit(limit)
    )
    return list(session.scalars(stmt))


def get_samples_pending_postprocessing(session: Session, limit: int = 100) -> list[Sample]:
    """
    Returns completed samples that may require downstream enrichment,
    analytics correlation, or future intelligence-layer processing.
    """
    stmt = (
        select(Sample)
        .where(Sample.analyzed.is_(True))
        .where(Sample.status_id == get_status_id(session, "done"))
        .order_by(Sample.created_at.asc())
        .limit(limit)
    )
    return list(session.scalars(stmt))


def get_samples_by_tag(
    session: Session,
    tag_name: str,
    limit: int = 100,
) -> list[Sample]:
    """
    Retrieves samples associated with a specific normalized tag.
    Useful for ransomware family studies and clustering.
    """
    normalized_tag = tag_name.strip().lower()

    stmt = (
        select(Sample)
        .join(SampleTag, Sample.id == SampleTag.sample_id)
        .join(Tag, Tag.id == SampleTag.tag_id)
        .where(Tag.name == normalized_tag)
        .order_by(Sample.updated_at.desc().nullslast())
        .limit(limit)
    )

    return list(session.scalars(stmt))


def get_pipeline_statistics(session: Session) -> dict[str, int]:
    """
    Provides high-level operational statistics for pipeline health,
    dataset maturity, and future dashboard/reporting layers.
    """
    return {
        "total_samples": session.scalar(select(func.count()).select_from(Sample)) or 0,
        "analyzed_samples": session.scalar(
            select(func.count()).select_from(Sample).where(Sample.analyzed.is_(True))
        )
        or 0,
        "pending_samples": session.scalar(
            select(func.count()).select_from(Sample).where(Sample.status_id == get_status_id(session, "pending"))
        )
        or 0,
        "error_samples": session.scalar(
            select(func.count()).select_from(Sample).where(Sample.status_id == get_status_id(session, "error"))
        )
        or 0,
        "reported_runs": session.scalar(
            select(func.count()).select_from(AnalysisRun).where(
                AnalysisRun.status_id == get_status_id(session, "done")
            )
        )
        or 0,
    }


# === Threat intelligence and campaign analytics helpers ===

def get_samples_by_risk_level(
    session: Session,
    risk_level: str,
    limit: int = 100,
) -> list[CapeReport]:
    """
    Retrieves CAPE reports whose enriched threat intelligence matches
    a requested risk level.
    """
    normalized_risk = risk_level.strip().lower()

    stmt = (
        select(CapeReport)
        .where(
            CapeReport.raw_json["threat_intelligence"]["risk_level"].astext
            == normalized_risk
        )
        .order_by(CapeReport.fetched_at.desc())
        .limit(limit)
    )

    return list(session.scalars(stmt))


def get_samples_by_family_hint(
    session: Session,
    family_hint: str,
    limit: int = 100,
) -> list[CapeReport]:
    """
    Retrieves reports matching a specific family hint.
    Useful for ransomware family prevalence studies.
    """
    normalized_hint = family_hint.strip()

    stmt = (
        select(CapeReport)
        .where(CapeReport.raw_json["threat_intelligence"]["family_hints"].astext.ilike(
                    f'%{normalized_hint}%'
                ))
        .order_by(CapeReport.fetched_at.desc())
        .limit(limit)
    )

    return list(session.scalars(stmt))


def get_campaign_ready_samples(
    session: Session,
    limit: int = 100,
) -> list[CapeReport]:
    """
    Retrieves reports marked as campaign correlation ready.
    """
    stmt = (
        select(CapeReport)
        .where(
            CapeReport.raw_json["threat_intelligence"]["campaign_ready"].astext
            == "true"
        )
        .order_by(CapeReport.fetched_at.desc())
        .limit(limit)
    )

    return list(session.scalars(stmt))
