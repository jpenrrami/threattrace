from __future__ import annotations

import argparse
import logging

from threattrace.common.logging import configure_logging, get_logger

logger = get_logger(__name__)


# Simple verification helper for post-init checks
def _verify_schema(engine, required_tables: set[str]) -> dict[str, object]:
    from sqlalchemy import inspect

    existing = set(inspect(engine).get_table_names())
    details = {table: table in existing for table in sorted(required_tables)}
    return {"ok": all(details.values()), "tables": details}


def main() -> None:
    """
    Production-safe database initialization CLI.

    Responsibilities:
    - Configure logging
    - Bootstrap full schema
    - Validate schema integrity
    - Surface deployment errors clearly
    """
    parser = argparse.ArgumentParser(description="Initialize DB schema")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show initialization plan without connecting or applying schema",
    )
    args = parser.parse_args()

    if args.dry_run:
        print("dry_run=connectivity_check,initialize_database,ensure_rerunning_state,schema_verification")
        return

    try:
        from threattrace.config.settings import get_settings

        settings = get_settings()

        from sqlalchemy import text

        from threattrace.db.schema import REQUIRED_TABLES, initialize_database
        from threattrace.db.session import engine, session_scope
        from threattrace.recovery.rerunning_state import ensure_rerunning_state

        configure_logging(settings.log_level)
        logger.info("Initializing database schema", extra={"service": "db", "stage": "init_db"})

        with session_scope() as s:
            s.execute(text("SELECT 1"))
            s.execute(text("SET search_path TO public"))

        initialize_database()
        ensure_rerunning_state()

        try:
            with session_scope() as s:
                s.execute(text("SELECT similarity('a','a')"))
        except Exception:
            logger.warning("pg_trgm functions not available; trigram indexes may fail", extra={"service": "db", "stage": "init_db_warn"})

        verification = _verify_schema(engine, REQUIRED_TABLES)
        logger.info(
            "Schema verification",
            extra={
                "service": "db",
                "stage": "init_db_verify",
                "ok": verification["ok"],
                "tables": verification["tables"],
            },
        )

        if not verification["ok"]:
            raise RuntimeError(f"Schema verification failed: {verification}")

        logger.info(
            "Database initialization completed successfully",
            extra={
                "service": "db",
                "stage": "init_db_complete",
            },
        )

    except ValueError as exc:
        parser.error(str(exc))
    except Exception as exc:
        logger.exception(
            "Database initialization failed",
            extra={
                "service": "db",
                "stage": "init_db_error",
                "error_message": str(exc),
            },
        )
        raise


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    main()
