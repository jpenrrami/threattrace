from __future__ import annotations

from sqlalchemy import Connection, text

from threattrace.common.logging import configure_logging, get_logger
from threattrace.config.settings import get_settings
from threattrace.db.session import session_scope

logger = get_logger(__name__)


HARDENING_SQL = [
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_ioc_reports_updated'
      ) THEN
        CREATE TRIGGER trg_ioc_reports_updated
        BEFORE UPDATE ON public.ioc_reports
        FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
      END IF;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_behavior_scores_updated'
      ) THEN
        CREATE TRIGGER trg_behavior_scores_updated
        BEFORE UPDATE ON public.sample_behavior_scores
        FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
      END IF;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_sample_artifacts_confidence_range'
      ) THEN
        ALTER TABLE public.sample_artifacts
        ADD CONSTRAINT ck_sample_artifacts_confidence_range
        CHECK (confidence >= 0 AND confidence <= 1.00);
      END IF;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_sample_iocs_confidence_range'
      ) THEN
        ALTER TABLE public.sample_iocs
        ADD CONSTRAINT ck_sample_iocs_confidence_range
        CHECK (confidence >= 0 AND confidence <= 1.00);
      END IF;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_sample_attack_techniques_confidence_range'
      ) THEN
        ALTER TABLE public.sample_attack_techniques
        ADD CONSTRAINT ck_sample_attack_techniques_confidence_range
        CHECK (confidence >= 0 AND confidence <= 1.00);
      END IF;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_behavior_scores_all_ranges'
      ) THEN
        ALTER TABLE public.sample_behavior_scores
        ADD CONSTRAINT ck_behavior_scores_all_ranges
        CHECK (
          persistence_score BETWEEN 0 AND 100
          AND severity_score BETWEEN 0 AND 100
          AND confidence_score BETWEEN 0 AND 100
          AND ransomware_score BETWEEN 0 AND 100
          AND credential_score BETWEEN 0 AND 100
          AND defense_evasion_score BETWEEN 0 AND 100
        );
      END IF;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_behavior_pattern_severity_range'
      ) THEN
        ALTER TABLE public.behavior_patterns
        ADD CONSTRAINT ck_behavior_pattern_severity_range
        CHECK (severity BETWEEN 0 AND 10);
      END IF;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_sample_artifacts_nonempty'
      ) THEN
        ALTER TABLE public.sample_artifacts
        ADD CONSTRAINT ck_sample_artifacts_nonempty
        CHECK (
          btrim(artifact_type) <> ''
          AND btrim(artifact_value) <> ''
          AND btrim(source) <> ''
        );
      END IF;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_sample_iocs_nonempty'
      ) THEN
        ALTER TABLE public.sample_iocs
        ADD CONSTRAINT ck_sample_iocs_nonempty
        CHECK (
          btrim(type) <> ''
          AND btrim(value) <> ''
          AND btrim(source) <> ''
        );
      END IF;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_sample_attack_techniques_nonempty'
      ) THEN
        ALTER TABLE public.sample_attack_techniques
        ADD CONSTRAINT ck_sample_attack_techniques_nonempty
        CHECK (
          btrim(technique) <> ''
          AND btrim(category) <> ''
        );
      END IF;
    END
    $$;
    """,
    "CREATE INDEX IF NOT EXISTS idx_sample_artifacts_sample_id ON public.sample_artifacts(sample_id);",
    "CREATE INDEX IF NOT EXISTS idx_sample_artifacts_sample_type ON public.sample_artifacts(sample_id, artifact_type);",
    "CREATE INDEX IF NOT EXISTS idx_sample_artifacts_source ON public.sample_artifacts(source);",
    "CREATE INDEX IF NOT EXISTS idx_attack_techniques_sample_id ON public.sample_attack_techniques(sample_id);",
    "CREATE INDEX IF NOT EXISTS idx_attack_techniques_sample_cat ON public.sample_attack_techniques(sample_id, category);",
    "CREATE INDEX IF NOT EXISTS idx_sample_iocs_sample_type_value ON public.sample_iocs(sample_id, type, value);",
    "CREATE INDEX IF NOT EXISTS idx_sample_iocs_source_type ON public.sample_iocs(source, type);",
    "CREATE INDEX IF NOT EXISTS idx_sample_iocs_value_trgm ON public.sample_iocs USING gin (value gin_trgm_ops);",
    "CREATE INDEX IF NOT EXISTS idx_behavior_scores_sample_id ON public.sample_behavior_scores(sample_id);",
    "CREATE INDEX IF NOT EXISTS idx_behavior_patterns_severity ON public.behavior_patterns(severity);",
    "CREATE INDEX IF NOT EXISTS idx_ioc_reports_sample_category_created ON public.ioc_reports(sample_category, created_at);",
    "CREATE INDEX IF NOT EXISTS idx_ioc_reports_processed_report_path ON public.ioc_reports(processed_report_path);",
]


def apply_database_hardening(connection: Connection) -> int:
    """Apply every required hardening object inside the caller transaction."""
    for statement in HARDENING_SQL:
        connection.execute(text(statement))
    return len(HARDENING_SQL)


def harden_database() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)

    applied = 0
    with session_scope() as session:
        applied = apply_database_hardening(session.connection())

    print(f"db_hardening_applied={applied}")
    return applied


def main() -> None:
    harden_database()


if __name__ == "__main__":
    main()
