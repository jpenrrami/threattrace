from __future__ import annotations

import argparse

from sqlalchemy import select

from threattrace.common.logging import configure_logging, get_logger
from threattrace.config.settings import get_settings
from threattrace.db.models import Sample
from threattrace.db.repositories import upsert_sample
from threattrace.db.session import session_scope
from threattrace.malwarebazaar.client import MalwareBazaarClient, normalize_sample

logger = get_logger(__name__)

RANSOMWARE_KEYWORDS = {
    "ransom",
    "lockbit",
    "conti",
    "alphv",
    "blackcat",
    "ryuk",
    "revil",
    "sodinokibi",
    "hive",
    "maze",
    "babuk",
    "phobos",
    "dharma",
    "medusalocker",
    "ragnar",
    "avaddon",
    "clop",
    "akira",
    "crypt",
    "locker",
}

RANSOMWARE_KEYWORDS_NORM = {k.strip().lower() for k in RANSOMWARE_KEYWORDS}


def is_ransomware_candidate(sample: dict) -> bool:
    searchable_fields = []

    for field in (
        "signature",
        "file_name",
        "tags",
        "vendor_intel",
        "yara_rules",
    ):
        value = sample.get(field)

        if isinstance(value, list):
            searchable_fields.extend(str(v).lower() for v in value)
        elif isinstance(value, dict):
            searchable_fields.extend(
                str(v).lower() for v in value.values()
            )
        elif value:
            searchable_fields.append(str(value).lower())

    combined = " ".join(searchable_fields)

    return any(keyword in combined for keyword in RANSOMWARE_KEYWORDS_NORM)


def main() -> None:
    parser = argparse.ArgumentParser(description="Weekly MalwareBazaar ingestion")
    parser.add_argument("--recent-limit", type=int, default=None)
    parser.add_argument("--tag-limit", type=int, default=None)
    parser.add_argument("--family-limit", type=int, default=None)
    parser.add_argument(
        "--tags",
        nargs="*",
        default=["ransomware", "x86", "x64"],
    )
    args = parser.parse_args()

    if args.recent_limit is not None and args.recent_limit <= 0:
        raise ValueError("--recent-limit must be greater than zero")
    if args.tag_limit is not None and args.tag_limit <= 0:
        raise ValueError("--tag-limit must be greater than zero")
    if args.family_limit is not None and args.family_limit <= 0:
        raise ValueError("--family-limit must be greater than zero")

    settings = get_settings()
    configure_logging(settings.log_level)

    logger.info(
        "Launching weekly MalwareBazaar ingestion module",
        extra={
            "service": "ingest",
            "stage": "startup",
            "recent_limit": args.recent_limit,
            "tag_limit": args.tag_limit,
            "family_limit": args.family_limit,
        },
    )

    client = MalwareBazaarClient()
    recent_limit = args.recent_limit or settings.malwarebazaar_recent_limit
    tag_limit = args.tag_limit or settings.malwarebazaar_tag_limit
    selected_tags = [
        str(tag).strip().lower()
        for tag in (args.tags or ["ransomware", "x86", "x64"])
        if str(tag).strip()
    ]

    logger.info(
        "Beginning MalwareBazaar source acquisition",
        extra={
            "service": "malwarebazaar",
            "stage": "fetch",
            "recent_limit": recent_limit,
            "tag_limit": tag_limit,
            "family_limit": args.family_limit or tag_limit,
            "tag_sources": selected_tags,
        },
    )

    merged_samples = client.mega_ingest_samples(
        tags=selected_tags,
        per_tag_limit=args.family_limit or tag_limit,
        recent_limit=recent_limit,
        tag_limit=tag_limit,
    )

    merged: dict[str, dict] = {}
    non_ransomware_skipped = 0

    for item in merged_samples:
        sha256_raw = item.get("sha256_hash") or item.get("sha256")
        sha256 = (str(sha256_raw).strip().lower()) if sha256_raw else ""
        if not sha256:
            continue

        if not is_ransomware_candidate(item):
            non_ransomware_skipped += 1
            continue

        if sha256 not in merged:
            merged[sha256] = item
            continue

        existing_tags = merged[sha256].get("tags") or []
        new_tags = item.get("tags") or []

        if isinstance(existing_tags, str):
            existing_tags = [
                tag.strip().lower()
                for tag in existing_tags.split(",")
                if tag.strip()
            ]
        if isinstance(new_tags, str):
            new_tags = [
                tag.strip().lower()
                for tag in new_tags.split(",")
                if tag.strip()
            ]

        if not isinstance(existing_tags, list):
            existing_tags = list(existing_tags) if existing_tags else []
        if not isinstance(new_tags, list):
            new_tags = list(new_tags) if new_tags else []

        merged[sha256]["tags"] = sorted(
            set(existing_tags + new_tags)
        )

    logger.info(
        "MalwareBazaar sample consolidation completed",
        extra={
            "service": "ingest",
            "stage": "merge",
            "unique_samples": len(merged),
        },
    )

    logger.info(
        "Beginning normalized sample database ingestion",
        extra={
            "service": "database",
            "stage": "upsert",
            "samples_pending": len(merged),
        },
    )

    inserted_count = 0
    skipped_count = 0
    malformed_count = 0

    with session_scope() as session:
        for raw_sample in merged.values():
            try:
                normalized = normalize_sample(raw_sample)
            except ValueError as exc:
                logger.warning(
                    "Skipping malformed MalwareBazaar sample",
                    extra={
                        "service": "malwarebazaar",
                        "stage": "normalize",
                        "error": str(exc),
                        "raw_sha256": raw_sample.get("sha256_hash")
                        or raw_sample.get("sha256"),
                    },
                )
                malformed_count += 1
                continue

            try:
                existing = session.execute(
                    select(Sample.id).where(Sample.sha256 == normalized.sha256)
                ).scalar_one_or_none()
                upsert_sample(session, normalized)
                if existing is None:
                    inserted_count += 1
                else:
                    skipped_count += 1
            except Exception as exc:
                logger.error(
                    "Upsert failed",
                    extra={
                        "service": "ingest",
                        "stage": "upsert_error",
                        "sha256": normalized.sha256,
                        "error": str(exc),
                    },
                )
                continue

            total_processed = inserted_count + skipped_count + malformed_count
            if total_processed and total_processed % 100 == 0:
                logger.info(
                    "Weekly ingestion progress update",
                    extra={
                        "service": "ingest",
                        "stage": "progress",
                        "processed": total_processed,
                        "inserted": inserted_count,
                        "skipped": skipped_count,
                        "malformed": malformed_count,
                    },
                )

    logger.info(
        "Weekly MalwareBazaar ingestion completed successfully",
        extra={
            "service": "ingest",
            "stage": "complete",
            "sample_count": len(merged),
            "inserted_count": inserted_count,
            "skipped_existing_count": skipped_count,
            "malformed_count": malformed_count,
            "non_ransomware_skipped": non_ransomware_skipped,
            "recent_limit": recent_limit,
            "tag_limit": tag_limit,
            "family_limit": args.family_limit or tag_limit,
            "tag_sources": selected_tags,
        },
    )


if __name__ == "__main__":
    main()
