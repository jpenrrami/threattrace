from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import func, select

from threattrace.common.logging import configure_logging, get_logger
from threattrace.config.settings import get_settings
from threattrace.db.models import Sample
from threattrace.db.repositories import upsert_sample
from threattrace.db.session import session_scope
from threattrace.malwarebazaar.client import MalwareBazaarClient, normalize_sample

logger = get_logger(__name__)

BATCH_SIZE = 500


def _default_marker_path() -> Path:
    return get_settings().storage_root / "state" / "initial_ingest.done"


def _write_marker(path: Path, reason: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"{datetime.now(UTC).isoformat()} {reason}\n",
        encoding="utf-8",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Historical mega-ingest from MalwareBazaar for large-scale corpus creation."
    )
    parser.add_argument(
        "--recent-limit",
        type=int,
        default=None,
        help="Maximum number of recent samples to fetch.",
    )
    parser.add_argument(
        "--tag-limit",
        type=int,
        default=None,
        help="Maximum number of samples per tag source.",
    )
    parser.add_argument(
        "--tags",
        nargs="*",
        default=["ransomware", "x86", "x64"],
        help="Tag sources to include in mega-ingest.",
    )
    parser.add_argument(
        "--marker-file",
        type=Path,
        default=None,
        help="Marker file used to ensure initial ingest runs only once.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Run even if marker exists or database already contains samples.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    settings = get_settings()
    configure_logging(settings.log_level)
    marker_path = args.marker_file or _default_marker_path()

    if marker_path.exists() and not args.force:
        logger.info(
            "Initial ingest skipped because marker file already exists",
            extra={
                "service": "mega_ingest",
                "stage": "skip_marker",
                "marker_file": str(marker_path),
            },
        )
        return

    client = MalwareBazaarClient()

    recent_limit = args.recent_limit or settings.malwarebazaar_recent_limit
    tag_limit = args.tag_limit or settings.malwarebazaar_tag_limit
    selected_tags = [
        str(tag).strip().lower()
        for tag in (args.tags or ["ransomware", "x86", "x64"])
        if str(tag).strip()
    ]

    logger.info(
        "Starting mega-ingest",
        extra={
            "service": "mega_ingest",
            "stage": "start",
            "recent_limit": recent_limit,
            "tag_limit": tag_limit,
            "tags": selected_tags,
        },
    )

    with session_scope() as session:
        sample_count = session.execute(
            select(func.count(Sample.id))
        ).scalar_one()

    if sample_count > 0 and not args.force:
        _write_marker(marker_path, "existing_samples")
        logger.info(
            "Initial ingest skipped because samples already exist",
            extra={
                "service": "mega_ingest",
                "stage": "skip_existing_samples",
                "sample_count": sample_count,
                "marker_file": str(marker_path),
            },
        )
        return

    samples = client.mega_ingest_samples(
        recent_limit=recent_limit,
        tag_limit=tag_limit,
        tags=selected_tags,
    )

    inserted_count = 0
    skipped_count = 0
    error_count = 0

    with session_scope() as session:
        processed = 0
        for raw_sample in samples:
            try:
                normalized = normalize_sample(raw_sample)

                sha = getattr(normalized, "sha256", None)
                if not sha:
                    skipped_count += 1
                    continue

                existing = session.execute(
                    select(Sample.id).where(Sample.sha256 == sha)
                ).scalar_one_or_none()

                upsert_sample(session, normalized)

                if existing is None:
                    inserted_count += 1
                else:
                    skipped_count += 1

                processed += 1

                if processed % BATCH_SIZE == 0:
                    session.flush()
                    logger.info(
                        "Mega-ingest progress",
                        extra={
                            "service": "mega_ingest",
                            "stage": "progress",
                            "processed": processed,
                            "inserted": inserted_count,
                            "skipped": skipped_count,
                            "errors": error_count,
                        },
                    )

            except Exception as exc:
                error_count += 1
                logger.exception(
                    "Failed to process sample during mega-ingest",
                    extra={
                        "service": "mega_ingest",
                        "stage": "normalize_or_upsert",
                        "sample_sha256": raw_sample.get("sha256_hash")
                        or raw_sample.get("sha256"),
                        "error_message": str(exc),
                    },
                )
                continue

    logger.info(
        "Mega-ingest completed",
        extra={
            "service": "mega_ingest",
            "stage": "complete",
            "sample_count": len(samples),
            "inserted_count": inserted_count,
            "skipped_count": skipped_count,
            "error_count": error_count,
            "recent_limit": recent_limit,
            "tag_limit": tag_limit,
            "tags": selected_tags,
        },
    )
    _write_marker(marker_path, "completed")


if __name__ == "__main__":
    main()
