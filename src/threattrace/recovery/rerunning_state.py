from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from threattrace.common.logging import configure_logging, get_logger
from threattrace.config.settings import get_settings
from threattrace.db.session import session_scope

logger = get_logger(__name__)


def ensure_rerunning_state() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)

    with session_scope() as session:
        try:
            session.execute(
                text(
                    """
                    DO $$
                    BEGIN
                        IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'analysis_state')
                           AND NOT EXISTS (
                               SELECT 1
                               FROM pg_enum e
                               JOIN pg_type t ON t.oid = e.enumtypid
                               WHERE t.typname = 'analysis_state'
                                 AND e.enumlabel = 'rerunning'
                           ) THEN
                            ALTER TYPE public.analysis_state ADD VALUE 'rerunning';
                        END IF;
                    END$$;
                    """
                )
            )
        except ProgrammingError:
            session.rollback()

        session.execute(
            text(
                """
                INSERT INTO status_catalog (code, description)
                VALUES ('rerunning', 'Recovered errored analysis run re-entered into pipeline')
                ON CONFLICT (code) DO NOTHING
                """
            )
        )

        session.execute(
            text(
                """
                ALTER TABLE public.analysis_runs
                DROP CONSTRAINT IF EXISTS ck_analysis_runs_state
                """
            )
        )
        session.execute(
            text(
                """
                ALTER TABLE public.analysis_runs
                ADD CONSTRAINT ck_analysis_runs_state
                CHECK (
                    state = ANY (
                        ARRAY[
                            'pending',
                            'reserved',
                            'running',
                            'rerunning',
                            'reported',
                            'done',
                            'error'
                        ]::public.analysis_state[]
                    )
                )
                """
            )
        )

        session.execute(
            text(
                """
                ALTER TABLE public.analysis_runs
                DROP CONSTRAINT IF EXISTS chk_state_terminal_consistency
                """
            )
        )
        session.execute(
            text(
                """
                ALTER TABLE public.analysis_runs
                ADD CONSTRAINT chk_state_terminal_consistency
                CHECK (
                    (((state)::text = 'done'::text) AND (status_id IS NOT NULL))
                    OR (((state)::text = 'error'::text) AND (status_id IS NOT NULL))
                    OR ((state)::text = ANY (
                        (
                            ARRAY[
                                'pending'::character varying,
                                'reserved'::character varying,
                                'running'::character varying,
                                'rerunning'::character varying,
                                'reported'::character varying
                            ]
                        )::text[]
                    ))
                )
                """
            )
        )

    logger.info("rerunning state ensured")


def main() -> None:
    ensure_rerunning_state()


if __name__ == "__main__":
    main()
