from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import text

from threattrace.common.logging import configure_logging, get_logger
from threattrace.config.settings import get_settings
from threattrace.db.session import session_scope

logger = get_logger(__name__)

TMP_PATTERNS = (
    "threattrace_cape_archive_test",
    "threattrace_cape_archive_batch_test",
    "threattrace_migration_*",
)
INNER_EXTENSIONS = {".json", ".log", ".txt", ".bson", ".pcap", ".evtx", ".csv", ".xml"}
SKIP_EXTENSIONS = {".zst", ".gz", ".zip", ".7z", ".rar", ".xz", ".bz2"}
INNER_ZSTD = ["zstd", "-22", "--ultra", "-T0", "--long=31"]
OUTER_ZSTD = "zstd -22 --ultra -T0 --long=31"
VERIFY_ZSTD = "zstd --long=31"
BACKUP_DIR = Path(os.environ.get("THREATTRACE_CAPE_ARCHIVE_ROOT", "runtime_storage/archives"))
CAPE_ANALYSES_DIR = Path(os.environ.get("THREATTRACE_CAPE_ANALYSES_DIR", "runtime_storage/cape_storage/analyses"))


def _safe_remove_tmp_artifacts() -> None:
    tmp_root = Path(tempfile.gettempdir())
    for pattern in TMP_PATTERNS:
        for path in tmp_root.glob(pattern):
            if not path.exists():
                continue
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)


def _print_tmp_cleanup_check() -> None:
    for pattern in TMP_PATTERNS:
        matches = sorted(Path(tempfile.gettempdir()).glob(pattern))
        if matches:
            for match in matches:
                print(match)


def _require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required tool not found in PATH: {name}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _bytes_to_mb(value: int) -> str:
    return f"{value / (1024 * 1024):.2f}"


def _percent_saved(original_bytes: int, final_bytes: int) -> float:
    if original_bytes <= 0:
        return 0.0
    return round(((original_bytes - final_bytes) / original_bytes) * 100, 2)


def _dir_size(path: Path) -> int:
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            total += item.stat().st_size
    return total


def _remove_empty_dirs(root: Path) -> int:
    removed = 0
    for current_root, dirnames, _filenames in os.walk(root, topdown=False):
        current = Path(current_root)
        for dirname in dirnames:
            candidate = current / dirname
            try:
                if candidate.exists() and candidate.is_dir() and not any(candidate.iterdir()):
                    candidate.rmdir()
                    removed += 1
            except OSError:
                continue
    return removed


def _should_inner_compress(path: Path, analysis_root: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return False
    if path.name == "MANIFEST.json":
        return False
    if path.name == "binary.symlink.txt":
        return False
    if "_associated_binary" in path.parts:
        return False
    if path.suffix.lower() in INNER_EXTENSIONS:
        return True
    if path.suffix:
        return False
    if path.stat().st_size <= 512 * 1024:
        return False

    try:
        relative = path.relative_to(analysis_root)
    except ValueError:
        return False

    if relative.parts and relative.parts[0] in {"CAPE", "files", "procdump", "selfextracted"}:
        return True

    return True


def _compress_one_file(path: Path) -> Path:
    destination = path.with_name(f"{path.name}.zst")
    subprocess.run(
        [*INNER_ZSTD, "-f", "-q", "-o", str(destination), str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    path.unlink()
    return destination


def _inner_compress_files(analysis_root: Path) -> int:
    compressed = 0
    for path in sorted(analysis_root.rglob("*")):
        if not path.is_file():
            continue
        if _should_inner_compress(path, analysis_root):
            _compress_one_file(path)
            compressed += 1
    return compressed


def _write_binary_metadata(analysis_root: Path, binary_link: Path) -> tuple[str | None, str | None]:
    packaged_relative_path: str | None = None
    original_target: str | None = None

    if not binary_link.exists() and not binary_link.is_symlink():
        return None, None

    if binary_link.is_symlink():
        original_target = os.readlink(binary_link)
        resolved_target = binary_link.resolve(strict=True)
        packaged_dir = analysis_root / "_associated_binary"
        packaged_dir.mkdir(parents=True, exist_ok=True)
        packaged_binary = packaged_dir / resolved_target.name
        shutil.copy2(resolved_target, packaged_binary)
        packaged_relative_path = str(packaged_binary.relative_to(analysis_root))
        binary_link.unlink()
        symlink_note = analysis_root / "binary.symlink.txt"
        symlink_note.write_text(
            "\n".join(
                [
                    f"original_symlink_target={original_target}",
                    f"packaged_binary={packaged_relative_path}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return original_target, packaged_relative_path

    return None, None


def _build_manifest(
    record: dict,
    archive_path: Path,
    original_target: str | None,
    packaged_binary_path: str | None,
    original_bytes: int,
    stage_bytes: int,
    final_bytes: int,
    removed_empty_dirs: int,
    inner_compressed_files: int,
    files: list[dict[str, object]],
) -> dict[str, object]:
    saved_bytes = max(original_bytes - final_bytes, 0)
    return {
        "schema": "threattrace_cape_safe_migration_v1",
        "sample_id": record["sample_id"],
        "analysis_run_id": record["analysis_run_id"],
        "cape_task_id": record["cape_task_id"],
        "sha256": record["sha256"],
        "created_at": datetime.now(UTC).isoformat(),
        "source_analysis_dir": str(record["source_analysis_dir"]),
        "archive_path": str(archive_path),
        "processed_report_path": record["processed_report_path"],
        "ioc_report_path": record["ioc_report_path"],
        "binary_symlink_target": original_target,
        "packaged_binary_path": packaged_binary_path,
        "compression": {
            "lossless": True,
            "inner": "zstd -22 --ultra -T0 --long=31",
            "outer": "tar + zstd -22 --ultra -T0 --long=31",
        },
        "stats": {
            "original_analysis_bytes": original_bytes,
            "staging_after_inner_compression_bytes": stage_bytes,
            "final_archive_bytes": final_bytes,
            "saved_bytes": saved_bytes,
            "saved_percent": _percent_saved(original_bytes, final_bytes),
            "removed_empty_dirs": removed_empty_dirs,
            "inner_compressed_files": inner_compressed_files,
        },
        "files": files,
    }


def _list_manifest_files(analysis_root: Path) -> list[dict[str, object]]:
    files: list[dict[str, object]] = []
    for path in sorted(analysis_root.rglob("*")):
        if not path.is_file():
            continue
        if path.name == "MANIFEST.json":
            continue
        files.append(
            {
                "path": str(path.relative_to(analysis_root)),
                "size": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    return files


def _write_manifest(analysis_root: Path, manifest: dict[str, object]) -> None:
    (analysis_root / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=False),
        encoding="utf-8",
    )


def _create_archive(staging_root: Path, archive_path: Path, task_dir_name: str) -> int:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["tar", "-I", OUTER_ZSTD, "-cf", str(archive_path), task_dir_name],
        check=True,
        cwd=staging_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return archive_path.stat().st_size


def _verify_archive(archive_path: Path) -> None:
    subprocess.run(
        ["zstd", "-t", "--long=31", str(archive_path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    subprocess.run(
        ["tar", "-I", VERIFY_ZSTD, "-tf", str(archive_path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _ensure_batch_safe_for_execute(session) -> None:
    count = session.execute(
        text(
            """
            SELECT COUNT(*)
            FROM analysis_runs
            WHERE state IN (
                'pending',
                'reserved',
                'running',
                'reported',
                'rerunning',
                'error'
            )
            """
        )
    ).scalar_one()
    if count:
        raise RuntimeError(
            "Batch execute blocked: non-done runs still exist "
            f"({count} rows in pending/reserved/running/reported/rerunning/error)"
        )


def _fetch_record_by_task_id(session, cape_task_id: int) -> dict | None:
    row = session.execute(
        text(
            """
            SELECT
                ar.id AS analysis_run_id,
                ar.sample_id,
                ar.cape_task_id,
                ar.state,
                cr.etl_processed,
                s.sha256,
                s.processed_report_path,
                s.ioc_report_path
            FROM analysis_runs ar
            JOIN samples s ON s.id = ar.sample_id
            LEFT JOIN cape_reports cr ON cr.analysis_run_id = ar.id
            WHERE ar.cape_task_id = :cape_task_id
            """
        ),
        {"cape_task_id": cape_task_id},
    ).mappings().one_or_none()
    return dict(row) if row else None


def _fetch_record_by_run_id(session, analysis_run_id: int) -> dict | None:
    row = session.execute(
        text(
            """
            SELECT
                ar.id AS analysis_run_id,
                ar.sample_id,
                ar.cape_task_id,
                ar.state,
                cr.etl_processed,
                s.sha256,
                s.processed_report_path,
                s.ioc_report_path
            FROM analysis_runs ar
            JOIN samples s ON s.id = ar.sample_id
            LEFT JOIN cape_reports cr ON cr.analysis_run_id = ar.id
            WHERE ar.id = :analysis_run_id
            """
        ),
        {"analysis_run_id": analysis_run_id},
    ).mappings().one_or_none()
    return dict(row) if row else None


def _fetch_batch_candidates(session, limit: int) -> list[int]:
    rows = session.execute(
        text(
            """
            SELECT ar.cape_task_id
            FROM analysis_runs ar
            JOIN cape_reports cr ON cr.analysis_run_id = ar.id
            JOIN samples s ON s.id = ar.sample_id
            JOIN ioc_reports ir ON ir.analysis_run_id = ar.id
            WHERE ar.state = 'done'
              AND ar.cape_task_id IS NOT NULL
              AND cr.etl_processed = true
              AND s.processed_report_path IS NOT NULL
              AND s.ioc_report_path IS NOT NULL
            ORDER BY ar.cape_task_id
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).all()
    return [int(row[0]) for row in rows]


def _list_existing_analysis_task_dirs(
    *,
    min_cape_task_id: int | None = None,
    max_cape_task_id: int | None = None,
) -> tuple[list[int], int]:
    numeric_ids: list[int] = []
    skipped_invalid_dir = 0

    if not CAPE_ANALYSES_DIR.exists():
        return numeric_ids, skipped_invalid_dir

    for entry in sorted(CAPE_ANALYSES_DIR.iterdir(), key=lambda path: path.name):
        if not entry.is_dir():
            continue
        try:
            task_id = int(entry.name)
        except ValueError:
            skipped_invalid_dir += 1
            continue
        if min_cape_task_id is not None and task_id < min_cape_task_id:
            continue
        if max_cape_task_id is not None and task_id > max_cape_task_id:
            continue
        numeric_ids.append(task_id)

    return numeric_ids, skipped_invalid_dir


def _validate_record(record: dict) -> dict:
    if record is None:
        raise RuntimeError("Analysis run not found")
    if record["state"] != "done":
        raise RuntimeError(f"Analysis run is not done: state={record['state']}")
    if record["cape_task_id"] is None:
        raise RuntimeError("Analysis run has no cape_task_id")
    if record["etl_processed"] is not True:
        raise RuntimeError("cape_reports.etl_processed is not true")
    if not record["processed_report_path"]:
        raise RuntimeError("samples.processed_report_path is null")
    if not record["ioc_report_path"]:
        raise RuntimeError("samples.ioc_report_path is null")

    source_analysis_dir = CAPE_ANALYSES_DIR / str(record["cape_task_id"])
    if not source_analysis_dir.is_dir():
        raise RuntimeError(f"Analysis directory missing: {source_analysis_dir}")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if not BACKUP_DIR.is_dir():
        raise RuntimeError(f"Backup directory unavailable: {BACKUP_DIR}")

    _require_tool("zstd")
    _require_tool("tar")

    record["source_analysis_dir"] = source_analysis_dir
    record["archive_name"] = (
        f"{record['sample_id']}_{record['analysis_run_id']}_{record['cape_task_id']}.tar.zst"
    )
    record["archive_path"] = BACKUP_DIR / record["archive_name"]
    return record


def _validate_record_without_dir(record: dict) -> dict:
    if record is None:
        raise RuntimeError("Analysis run not found")
    if record["state"] != "done":
        raise RuntimeError(f"Analysis run is not done: state={record['state']}")
    if record["cape_task_id"] is None:
        raise RuntimeError("Analysis run has no cape_task_id")
    if record["etl_processed"] is not True:
        raise RuntimeError("cape_reports.etl_processed is not true")
    if not record["processed_report_path"]:
        raise RuntimeError("samples.processed_report_path is null")
    if not record["ioc_report_path"]:
        raise RuntimeError("samples.ioc_report_path is null")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if not BACKUP_DIR.is_dir():
        raise RuntimeError(f"Backup directory unavailable: {BACKUP_DIR}")

    _require_tool("zstd")
    _require_tool("tar")

    record["archive_name"] = (
        f"{record['sample_id']}_{record['analysis_run_id']}_{record['cape_task_id']}.tar.zst"
    )
    record["archive_path"] = BACKUP_DIR / record["archive_name"]
    return record


def _print_single_summary(record: dict, dry_run: bool, summary: dict | None = None) -> None:
    if dry_run:
        print("safe_migration_dry_run")
        print(f"sample_id={record['sample_id']}")
        print(f"analysis_run_id={record['analysis_run_id']}")
        print(f"cape_task_id={record['cape_task_id']}")
        print(f"source={record['source_analysis_dir']}")
        print(f"archive={record['archive_path']}")
        print("would_execute=false")
        return

    print("safe_migration_summary")
    print(f"task_id={record['cape_task_id']}")
    print(f"sample_id={record['sample_id']}")
    print(f"analysis_run_id={record['analysis_run_id']}")
    print(f"cape_task_id={record['cape_task_id']}")
    print("dry_run=false")
    print(f"source={record['source_analysis_dir']}")
    print(f"archive={record['archive_path']}")
    print(f"original_mb={_bytes_to_mb(summary['original_bytes'])}")
    print(f"stage_mb={_bytes_to_mb(summary['stage_bytes'])}")
    print(f"archive_mb={_bytes_to_mb(summary['archive_bytes'])}")
    print(f"saved_percent={summary['saved_percent']:.2f}")
    print(f"removed_empty_dirs={summary['removed_empty_dirs']}")
    print(f"inner_compressed_files={summary['inner_compressed_files']}")
    print("verified=true")
    print("source_deleted=false")


def _execute_single(record: dict) -> dict:
    source_analysis_dir = Path(record["source_analysis_dir"])
    original_bytes = _dir_size(source_analysis_dir)
    staging_root = Path(
        tempfile.mkdtemp(
            prefix=f"threattrace_migration_{record['cape_task_id']}_",
            dir=tempfile.gettempdir(),
        )
    )
    stage_task_dir = staging_root / str(record["cape_task_id"])

    try:
        shutil.copytree(source_analysis_dir, stage_task_dir, symlinks=True)
        original_target, packaged_binary_path = _write_binary_metadata(stage_task_dir, stage_task_dir / "binary")
        removed_empty_dirs = _remove_empty_dirs(stage_task_dir)
        inner_compressed_files = _inner_compress_files(stage_task_dir)
        removed_empty_dirs += _remove_empty_dirs(stage_task_dir)

        files = _list_manifest_files(stage_task_dir)
        stage_bytes = _dir_size(stage_task_dir)
        archive_path = Path(record["archive_path"])

        provisional_manifest = _build_manifest(
            record=record,
            archive_path=archive_path,
            original_target=original_target,
            packaged_binary_path=packaged_binary_path,
            original_bytes=original_bytes,
            stage_bytes=stage_bytes,
            final_bytes=0,
            removed_empty_dirs=removed_empty_dirs,
            inner_compressed_files=inner_compressed_files,
            files=files,
        )
        _write_manifest(stage_task_dir, provisional_manifest)
        archive_bytes = _create_archive(staging_root, archive_path, str(record["cape_task_id"]))

        final_manifest = _build_manifest(
            record=record,
            archive_path=archive_path,
            original_target=original_target,
            packaged_binary_path=packaged_binary_path,
            original_bytes=original_bytes,
            stage_bytes=stage_bytes,
            final_bytes=archive_bytes,
            removed_empty_dirs=removed_empty_dirs,
            inner_compressed_files=inner_compressed_files,
            files=files,
        )
        _write_manifest(stage_task_dir, final_manifest)
        archive_bytes = _create_archive(staging_root, archive_path, str(record["cape_task_id"]))
        _verify_archive(archive_path)

        if not source_analysis_dir.is_dir():
            raise RuntimeError("Original analysis directory disappeared after packaging")

        return {
            "original_bytes": original_bytes,
            "stage_bytes": stage_bytes,
            "archive_bytes": archive_bytes,
            "saved_percent": _percent_saved(original_bytes, archive_bytes),
            "removed_empty_dirs": removed_empty_dirs,
            "inner_compressed_files": inner_compressed_files,
        }
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def _resolve_single_target(session, args: argparse.Namespace) -> dict:
    if args.cape_task_id is not None:
        record = _fetch_record_by_task_id(session, args.cape_task_id)
    else:
        record = _fetch_record_by_run_id(session, args.analysis_run_id)
    return _validate_record(record)


def _run_single(args: argparse.Namespace) -> int:
    with session_scope() as session:
        record = _resolve_single_target(session, args)

    if Path(record["archive_path"]).exists():
        print("safe_migration_summary")
        print(f"task_id={record['cape_task_id']}")
        print(f"sample_id={record['sample_id']}")
        print(f"analysis_run_id={record['analysis_run_id']}")
        print(f"cape_task_id={record['cape_task_id']}")
        print("already_existing=true")
        print(f"archive={record['archive_path']}")
        return 0

    if not args.execute:
        _print_single_summary(record, dry_run=True)
        return 0

    summary = _execute_single(record)
    _print_single_summary(record, dry_run=False, summary=summary)
    return 0


def _run_batch(args: argparse.Namespace) -> int:
    with session_scope() as session:
        if args.execute:
            _ensure_batch_safe_for_execute(session)
        if args.from_existing:
            candidate_ids, skipped_invalid_dir = _list_existing_analysis_task_dirs(
                min_cape_task_id=args.min_cape_task_id,
                max_cape_task_id=args.max_cape_task_id,
            )
            if args.limit is not None:
                candidate_ids = candidate_ids[:args.limit]
        else:
            candidate_ids = _fetch_batch_candidates(session, args.limit)
            skipped_invalid_dir = 0

        records: list[dict] = []
        skipped_no_db_record = 0
        skipped_missing_dir = 0
        errors = 0

        for task_id in candidate_ids:
            source_analysis_dir = CAPE_ANALYSES_DIR / str(task_id)
            if not source_analysis_dir.is_dir():
                skipped_missing_dir += 1
                continue

            record = _fetch_record_by_task_id(session, task_id)
            if record is None:
                skipped_no_db_record += 1
                continue

            try:
                validated = _validate_record_without_dir(record)
            except Exception:
                logger.exception(
                    "Safe migration candidate validation failed",
                    extra={"cape_task_id": task_id},
                )
                errors += 1
                continue

            validated["source_analysis_dir"] = source_analysis_dir
            records.append(validated)

    migrated = 0
    already_existing = 0
    errors_runtime = 0
    original_total = 0
    archive_total = 0

    for record in records:
        if Path(record["archive_path"]).exists():
            already_existing += 1
            continue
        if not args.execute:
            continue
        try:
            summary = _execute_single(record)
        except Exception:
            logger.exception(
                "Safe migration failed",
                extra={"cape_task_id": record["cape_task_id"], "analysis_run_id": record["analysis_run_id"]},
            )
            errors_runtime += 1
            continue
        migrated += 1
        original_total += summary["original_bytes"]
        archive_total += summary["archive_bytes"]

    print("safe_migration_batch_summary")
    print(f"candidates_existing_dirs={len(candidate_ids)}")
    print(f"migrated={migrated}")
    print(f"already_existing={already_existing}")
    print(f"skipped_missing_dir={skipped_missing_dir}")
    print(f"skipped_no_db_record={skipped_no_db_record}")
    print(f"skipped_invalid_dir={skipped_invalid_dir}")
    print(f"errors={errors + errors_runtime}")
    print(f"original_total_gb={original_total / (1024 ** 3):.2f}")
    print(f"archive_total_gb={archive_total / (1024 ** 3):.2f}")
    print(f"saved_percent={_percent_saved(original_total, archive_total):.2f}")
    return 0 if (errors + errors_runtime) == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create safe reversible CAPE analysis archives")
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--cape-task-id", type=int)
    selector.add_argument("--analysis-run-id", type=int)
    selector.add_argument("--limit", type=int)
    parser.add_argument("--execute", action="store_true", help="Perform the migration")
    parser.add_argument("--dry-run", action="store_true", help="Alias for no-op planning mode")
    parser.add_argument(
        "--from-existing",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="In batch mode, derive candidates from existing CAPE analysis directories",
    )
    parser.add_argument("--min-cape-task-id", type=int, default=None)
    parser.add_argument("--max-cape-task-id", type=int, default=None)
    return parser


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level)
    _safe_remove_tmp_artifacts()
    _print_tmp_cleanup_check()

    parser = build_parser()
    args = parser.parse_args()
    if args.limit is not None and args.limit <= 0:
        raise SystemExit("--limit must be > 0")
    if args.min_cape_task_id is not None and args.min_cape_task_id <= 0:
        raise SystemExit("--min-cape-task-id must be > 0")
    if args.max_cape_task_id is not None and args.max_cape_task_id <= 0:
        raise SystemExit("--max-cape-task-id must be > 0")
    if (
        args.min_cape_task_id is not None
        and args.max_cape_task_id is not None
        and args.min_cape_task_id > args.max_cape_task_id
    ):
        raise SystemExit("--min-cape-task-id must be <= --max-cape-task-id")
    if not args.execute:
        args.dry_run = True

    if args.limit is not None:
        return _run_batch(args)
    return _run_single(args)


if __name__ == "__main__":
    raise SystemExit(main())
