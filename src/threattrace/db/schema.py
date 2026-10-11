from __future__ import annotations

import logging

from sqlalchemy import Connection, inspect, text

from threattrace.db import models  # noqa: F401  # Load ORM metadata for Base.
from threattrace.db.base import Base
from threattrace.db.hardening import apply_database_hardening
from threattrace.db.schema_contract import (
    METADATA_TABLE,
    SCHEMA_VERSION,
    IncompatibleSchemaError,
    contract_differences,
    contract_fingerprint,
    expected_contract,
    inspect_materialized_contract,
)
from threattrace.db.session import engine

logger = logging.getLogger(__name__)

REQUIRED_TABLES = frozenset(Base.metadata.tables)
REQUIRED_COLUMNS = {
    name: frozenset(column.name for column in table.columns)
    for name, table in Base.metadata.tables.items()
}
RECREATE_MESSAGE = (
    "Back up the database, create an empty database, and run threattrace db init again."
)


def _ensure_core_ddl(connection: Connection) -> None:
    """Create required PostgreSQL objects inside the bootstrap transaction."""
    connection.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
    connection.execute(
        text(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_type t
                    JOIN pg_namespace n ON n.oid = t.typnamespace
                    WHERE t.typname = 'analysis_state' AND n.nspname = 'public'
                ) THEN
                    CREATE TYPE public.analysis_state AS ENUM (
                        'pending','reserved','running','rerunning','reported','done','error'
                    );
                END IF;
            END$$;
            """
        )
    )
    connection.execute(
        text(
            """
            CREATE OR REPLACE FUNCTION public.set_updated_at()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
              NEW.updated_at = NOW();
              RETURN NEW;
            END;
            $$;
            """
        )
    )


def _public_tables(connection: Connection) -> set[str]:
    return set(inspect(connection).get_table_names(schema="public"))


def _read_schema_metadata(connection: Connection) -> tuple[str, str]:
    row = connection.execute(
        text(
            "SELECT schema_version, schema_fingerprint "
            f"FROM public.{METADATA_TABLE} WHERE singleton_id = 1"
        )
    ).one_or_none()
    if row is None:
        raise IncompatibleSchemaError(
            f"Schema metadata is missing. {RECREATE_MESSAGE}"
        )
    return str(row.schema_version), str(row.schema_fingerprint)


def validate_schema_integrity(
    connection: Connection, *, require_registered_fingerprint: bool
) -> str:
    """Inspect complete materialized contract and reject any incompatible drift."""
    expected = expected_contract(Base.metadata, connection.dialect)
    actual = inspect_materialized_contract(connection)
    differences = contract_differences(expected, actual)
    if differences:
        joined = "; ".join(differences)
        raise IncompatibleSchemaError(
            f"Incompatible PostgreSQL schema: {joined}. {RECREATE_MESSAGE}"
        )
    fingerprint = contract_fingerprint(actual)
    if require_registered_fingerprint:
        version, registered = _read_schema_metadata(connection)
        if version != SCHEMA_VERSION or registered != fingerprint:
            raise IncompatibleSchemaError(
                "PostgreSQL schema version or fingerprint differs from the supported "
                f"contract {SCHEMA_VERSION}. {RECREATE_MESSAGE}"
            )
    return fingerprint


def _create_fresh_schema(connection: Connection) -> None:
    _ensure_core_ddl(connection)
    Base.metadata.create_all(bind=connection)
    apply_database_hardening(connection)
    fingerprint = validate_schema_integrity(
        connection, require_registered_fingerprint=False
    )
    connection.execute(
        text(
            f"INSERT INTO public.{METADATA_TABLE} "
            "(singleton_id, schema_version, schema_fingerprint) "
            "VALUES (1, :version, :fingerprint)"
        ),
        {"version": SCHEMA_VERSION, "fingerprint": fingerprint},
    )


def create_schema() -> None:
    """Create an empty database atomically or verify an existing exact contract."""
    with engine.begin() as connection:
        existing_tables = _public_tables(connection)
        if not existing_tables:
            _create_fresh_schema(connection)
            logger.info(
                "Fresh PostgreSQL schema created",
                extra={"service": "db", "stage": "schema_created"},
            )
            return
        validate_schema_integrity(
            connection, require_registered_fingerprint=True
        )
        logger.info(
            "Existing PostgreSQL schema contract verified",
            extra={"service": "db", "stage": "schema_verified"},
        )


def initialize_database() -> None:
    create_schema()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    initialize_database()
