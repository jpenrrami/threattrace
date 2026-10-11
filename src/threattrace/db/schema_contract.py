from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from sqlalchemy import Connection, MetaData, inspect, text

SCHEMA_VERSION = "1.0.0"
METADATA_TABLE = "threattrace_schema_metadata"
REQUIRED_EXTENSIONS = frozenset({"pg_trgm"})
REQUIRED_FUNCTIONS = frozenset({"set_updated_at"})
REQUIRED_ENUMS = {
    "analysis_state": (
        "pending",
        "reserved",
        "running",
        "rerunning",
        "reported",
        "done",
        "error",
    )
}
REQUIRED_TRIGGERS = frozenset(
    {"trg_ioc_reports_updated", "trg_behavior_scores_updated"}
)
HARDENING_CHECKS = frozenset(
    {
        "ck_sample_artifacts_confidence_range",
        "ck_sample_iocs_confidence_range",
        "ck_sample_attack_techniques_confidence_range",
        "ck_behavior_scores_all_ranges",
        "ck_behavior_pattern_severity_range",
        "ck_sample_artifacts_nonempty",
        "ck_sample_iocs_nonempty",
        "ck_sample_attack_techniques_nonempty",
    }
)
HARDENING_INDEXES = {
    "idx_sample_artifacts_sample_id": ("sample_id",),
    "idx_sample_artifacts_sample_type": ("sample_id", "artifact_type"),
    "idx_sample_artifacts_source": ("source",),
    "idx_attack_techniques_sample_id": ("sample_id",),
    "idx_attack_techniques_sample_cat": ("sample_id", "category"),
    "idx_sample_iocs_sample_type_value": ("sample_id", "type", "value"),
    "idx_sample_iocs_source_type": ("source", "type"),
    "idx_behavior_scores_sample_id": ("sample_id",),
    "idx_behavior_patterns_severity": ("severity",),
    "idx_ioc_reports_sample_category_created": ("sample_category", "created_at"),
    "idx_ioc_reports_processed_report_path": ("processed_report_path",),
}
REQUIRED_EXPRESSION_INDEXES = frozenset(
    {"idx_sample_iocs_value_trgm", "idx_cape_reports_raw_json"}
)


class IncompatibleSchemaError(RuntimeError):
    pass


def _normal(value: object) -> str:
    return re.sub(r"\s+", " ", str(value).strip().lower())


def _type_name(value: object, dialect) -> str:
    compile_method = getattr(value, "compile", None)
    rendered = compile_method(dialect=dialect) if compile_method else value
    return _normal(rendered)


def expected_contract(metadata: MetaData, dialect) -> dict[str, object]:
    tables: dict[str, object] = {}
    for name, table in sorted(metadata.tables.items()):
        indexes = {}
        for index in sorted(table.indexes, key=lambda item: item.name or ""):
            if not index.name:
                continue
            columns = tuple(column.name for column in index.columns)
            indexes[index.name] = {"columns": columns, "unique": bool(index.unique)}
        tables[name] = {
            "columns": {
                column.name: {
                    "type": _type_name(column.type, dialect),
                    "nullable": bool(column.nullable),
                }
                for column in table.columns
            },
            "primary_key": tuple(column.name for column in table.primary_key.columns),
            "foreign_keys": sorted(
                (
                    tuple(element.parent.name for element in constraint.elements),
                    constraint.referred_table.name,
                    tuple(element.column.name for element in constraint.elements),
                    _normal(constraint.ondelete or ""),
                )
                for constraint in table.foreign_key_constraints
            ),
            "unique_constraints": sorted(
                {
                    tuple(column.name for column in constraint.columns)
                    for constraint in table.constraints
                    if constraint.__class__.__name__ == "UniqueConstraint"
                }
            ),
            "check_constraints": {
                constraint.name
                for constraint in table.constraints
                if constraint.__class__.__name__ == "CheckConstraint" and constraint.name
            },
            "indexes": indexes,
        }
    return {
        "tables": tables,
        "enums": REQUIRED_ENUMS,
        "extensions": REQUIRED_EXTENSIONS,
        "functions": REQUIRED_FUNCTIONS,
        "triggers": REQUIRED_TRIGGERS,
    }


def inspect_materialized_contract(connection: Connection) -> dict[str, object]:
    inspector = inspect(connection)
    dialect = connection.dialect
    tables: dict[str, object] = {}
    for name in sorted(inspector.get_table_names(schema="public")):
        primary_key = inspector.get_pk_constraint(name, schema="public")
        foreign_keys = sorted(
            (
                tuple(item.get("constrained_columns") or ()),
                str(item.get("referred_table") or ""),
                tuple(item.get("referred_columns") or ()),
                _normal((item.get("options") or {}).get("ondelete") or ""),
            )
            for item in inspector.get_foreign_keys(name, schema="public")
        )
        indexes = {}
        for item in inspector.get_indexes(name, schema="public"):
            if item.get("duplicates_constraint"):
                continue
            indexes[str(item["name"])] = {
                "columns": tuple(value for value in item.get("column_names") or () if value),
                "expressions": tuple(_normal(value) for value in item.get("expressions") or () if value),
                "unique": bool(item.get("unique")),
            }
        tables[name] = {
            "columns": {
                str(column["name"]): {
                    "type": _type_name(column["type"], dialect),
                    "nullable": bool(column["nullable"]),
                }
                for column in inspector.get_columns(name, schema="public")
            },
            "primary_key": tuple(primary_key.get("constrained_columns") or ()),
            "foreign_keys": foreign_keys,
            "unique_constraints": sorted(
                tuple(item.get("column_names") or ())
                for item in inspector.get_unique_constraints(name, schema="public")
            ),
            "check_constraints": {
                str(item["name"]): _normal(item.get("sqltext") or "")
                for item in inspector.get_check_constraints(name, schema="public")
                if item.get("name")
            },
            "indexes": indexes,
        }
    enums = {
        str(item["name"]): tuple(item.get("labels") or ())
        for item in inspector.get_enums(schema="public")
    }
    extensions = {
        name: bool(
            connection.execute(
                text("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = :name)"),
                {"name": name},
            ).scalar_one()
        )
        for name in REQUIRED_EXTENSIONS
    }
    functions = {
        name: _normal(
            connection.execute(
                text("SELECT COALESCE(pg_get_functiondef(to_regprocedure(:signature)), '')"),
                {"signature": f"public.{name}()"},
            ).scalar_one()
        )
        for name in REQUIRED_FUNCTIONS
    }
    trigger_rows = connection.execute(
        text(
            "SELECT tgname, pg_get_triggerdef(oid) FROM pg_trigger "
            "WHERE NOT tgisinternal AND tgname = ANY(:names)"
        ),
        {"names": list(REQUIRED_TRIGGERS)},
    ).all()
    triggers = {str(name): _normal(definition) for name, definition in trigger_rows}
    return {
        "tables": tables,
        "enums": enums,
        "extensions": extensions,
        "functions": functions,
        "triggers": triggers,
    }


def contract_differences(
    expected: Mapping[str, object], actual: Mapping[str, object]
) -> list[str]:
    differences: list[str] = []
    expected_tables = expected["tables"]
    actual_tables = actual["tables"]
    if set(expected_tables) != set(actual_tables):
        differences.append("table set differs")
        return differences
    for name, expected_table in expected_tables.items():
        actual_table = actual_tables[name]
        for field in ("columns", "primary_key", "foreign_keys", "unique_constraints"):
            if expected_table[field] != actual_table[field]:
                differences.append(f"{name}.{field} differs")
        expected_checks = set(expected_table["check_constraints"])
        if not expected_checks <= set(actual_table["check_constraints"]):
            differences.append(f"{name}.check_constraints differs")
        expected_indexes = expected_table["indexes"]
        actual_indexes = actual_table["indexes"]
        for index_name, expected_index in expected_indexes.items():
            actual_index = actual_indexes.get(index_name)
            if actual_index is None or (
                tuple(expected_index["columns"]) != tuple(actual_index["columns"])
                or bool(expected_index["unique"]) != bool(actual_index["unique"])
            ):
                differences.append(f"{name}.index.{index_name} differs")
    all_checks = {
        value
        for table in actual_tables.values()
        for value in table["check_constraints"]
    }
    if not HARDENING_CHECKS <= all_checks:
        differences.append("hardening check constraints differ")
    all_indexes = {
        index_name: index
        for table in actual_tables.values()
        for index_name, index in table["indexes"].items()
    }
    for index_name, columns in HARDENING_INDEXES.items():
        item = all_indexes.get(index_name)
        if item is None or tuple(item["columns"]) != columns:
            differences.append(f"hardening index {index_name} differs")
    for index_name in REQUIRED_EXPRESSION_INDEXES:
        if index_name not in all_indexes:
            differences.append(f"expression index {index_name} missing")
    if expected["enums"] != {
        name: actual["enums"].get(name) for name in expected["enums"]
    }:
        differences.append("enum contract differs")
    if not all(actual["extensions"].get(name) for name in expected["extensions"]):
        differences.append("required extension missing")
    if not all(actual["functions"].get(name) for name in expected["functions"]):
        differences.append("required function missing")
    if set(actual["triggers"]) != set(expected["triggers"]):
        differences.append("trigger contract differs")
    return differences


def contract_fingerprint(contract: Mapping[str, object]) -> str:
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":"), default=list)
    return hashlib.sha256(canonical.encode()).hexdigest()
