from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import text

from threattrace.common.pe import detect_pe_architecture
from threattrace.config.settings import get_settings
from threattrace.db.repositories import NormalizedSample, get_status_id, sanitize_json_strings, upsert_sample
from threattrace.db.session import session_scope
from threattrace.malshare.client import MalShareClient, MalShareClientError

SOURCE = "malshare"
DEFAULT_DATASET_ROLE = "validation"
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
DEFAULT_QUERY_TERMS = (
    "ransomware",
    "locker",
    "crypt",
    "ransom",
    "encryptor",
    "lockbit",
    "lockbit3",
    "akira",
    "conti",
    "blackcat",
    "alphv",
    "play",
    "royal",
    "medusa",
    "ransomhub",
    "qilin",
    "babuk",
    "hive",
    "blackbasta",
    "bianlian",
    "clop",
    "revil",
    "sodinokibi",
    "wannacry",
    "ryuk",
    "darkside",
    "locky",
    "maze",
)
PE_HINTS = ("pe32", "pe32+", "win32", "win64", "dll", "exe", "dos executable")


@dataclass(frozen=True)
class DownloadedFileInfo:
    file_type: str
    extension: str
    detected_arch: str
    is_windows_executable: bool


@dataclass(frozen=True)
class MalShareMetadataCandidate:
    hash_value: str
    hash_type: str
    source: str
    source_query: str
    dataset_role: str
    family_hint: str | None
    source_data: dict[str, Any]


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _hash_type(value: str) -> str:
    return HASH_LENGTHS.get(len(value.strip()), "unknown")


def _limit_payload(limit: int, items: list[str]) -> list[str]:
    return items[: max(0, limit)]


def _sample_path(sha256: str, extension: str) -> Path:
    settings = get_settings()
    suffix = extension if extension.startswith(".") else f".{extension}"
    return settings.malware_root / sha256[:2] / sha256[2:4] / f"{sha256}{suffix}"


def _sha256_where(hash_value: str) -> tuple[str, dict[str, Any]]:
    kind = _hash_type(hash_value)
    if kind not in {"md5", "sha1", "sha256"}:
        raise SystemExit(f"Unsupported hash value: {hash_value}")
    return f"s.{kind} = :hash_value", {"hash_value": hash_value.lower()}


def _existing_sample(hash_value: str) -> dict[str, Any] | None:
    where_sql, params = _sha256_where(hash_value)
    with session_scope() as session:
        row = session.execute(
            text(
                f"""
                SELECT s.id, s.sha256, s.md5, s.sha1, s.stored_file_path
                FROM samples s
                WHERE {where_sql}
                LIMIT 1
                """
            ),
            params,
        ).mappings().first()
        return dict(row) if row else None


def _upsert_sample_source(
    *,
    sample_id: int,
    source_sample_id: str,
    source_query: str,
    source_data: dict[str, Any],
    dataset_role: str,
    family_hint: str | None,
) -> None:
    with session_scope() as session:
        session.execute(
            text(
                """
                INSERT INTO sample_sources (
                  sample_id, source, source_sample_id, source_query,
                  source_data, dataset_role, family_hint
                ) VALUES (
                  :sample_id, :source, :source_sample_id, :source_query,
                  CAST(:source_data AS jsonb), :dataset_role, :family_hint
                )
                ON CONFLICT (sample_id, source) DO UPDATE SET
                  source_sample_id = EXCLUDED.source_sample_id,
                  source_query = EXCLUDED.source_query,
                  source_data = EXCLUDED.source_data,
                  dataset_role = EXCLUDED.dataset_role,
                  family_hint = EXCLUDED.family_hint
                """
            ),
            {
                "sample_id": sample_id,
                "source": SOURCE,
                "source_sample_id": source_sample_id,
                "source_query": source_query,
                "source_data": json.dumps(sanitize_json_strings(source_data or {})),
                "dataset_role": dataset_role,
                "family_hint": family_hint,
            },
        )


def _candidate_from_hash(
    hash_value: str,
    *,
    source_query: str,
    dataset_role: str,
    family_hint: str | None,
    source_data: dict[str, Any] | None = None,
) -> MalShareMetadataCandidate:
    return MalShareMetadataCandidate(
        hash_value=hash_value.lower(),
        hash_type=_hash_type(hash_value),
        source=SOURCE,
        source_query=source_query,
        dataset_role=dataset_role,
        family_hint=family_hint,
        source_data=source_data or {},
    )


def _split_queries(query_values: str | list[str] | None, family_hint: str | None) -> list[str]:
    terms: list[str] = []
    if isinstance(query_values, str):
        query_values = [query_values]
    for value in query_values or []:
        for item in str(value).split(","):
            term = item.strip()
            if term:
                terms.append(term)
    if family_hint:
        terms.append(family_hint.strip())
    terms.extend(DEFAULT_QUERY_TERMS)
    deduped: list[str] = []
    seen: set[str] = set()
    for term in terms:
        marker = term.lower()
        if marker and marker not in seen:
            seen.add(marker)
            deduped.append(term)
    return deduped


def _parse_hashes(values: list[str]) -> list[str]:
    hashes: list[str] = []
    for value in values:
        token = str(value).strip().lower()
        if len(token) in HASH_LENGTHS and all(ch in "0123456789abcdef" for ch in token):
            hashes.append(token)
    return hashes


def _metadata_file_type(details: dict[str, Any]) -> str:
    raw = str(
        details.get("F_TYPE")
        or details.get("file_type")
        or details.get("type")
        or ""
    ).strip().lower()
    if "pe32+" in raw:
        return "pe32+"
    if "pe32" in raw or "dll" in raw or "exe" in raw:
        return "pe32"
    if "7-zip" in raw or "7z" in raw:
        return "7z"
    if "rar" in raw:
        return "rar"
    if "zip" in raw:
        return "zip"
    if "rtf" in raw or "rich" in raw:
        return "rtf"
    return raw or "unknown"


def _details_arch(details: dict[str, Any]) -> str:
    explicit = str(details.get("arch") or details.get("architecture") or details.get("detected_arch") or "").strip().lower()
    if explicit in {"x86", "i386", "win32", "32-bit"}:
        return "x86"
    if explicit in {"x64", "amd64", "x86_64", "win64", "64-bit"}:
        return "x64"
    file_type = _metadata_file_type(details)
    if file_type == "pe32+":
        return "x64"
    if file_type == "pe32":
        return "x86"
    return "unknown"


def _details_windows_executable(details: dict[str, Any]) -> bool | None:
    raw = str(
        details.get("F_TYPE")
        or details.get("file_type")
        or details.get("type")
        or ""
    ).strip().lower()
    if not raw:
        return None
    return any(term in raw for term in PE_HINTS)


def _candidate_file_name(details: dict[str, Any], sha256: str, extension: str) -> str:
    names = details.get("FILENAMES") or []
    if isinstance(names, list) and names:
        return str(names[0]).strip() or f"{sha256}{extension}"
    return f"{sha256}{extension}"


def _inspect_downloaded_file(path: Path) -> DownloadedFileInfo:
    head = path.read_bytes()[:8]
    if head.startswith(b"MZ"):
        arch = detect_pe_architecture(path)
        return DownloadedFileInfo("exe", ".exe", arch, True)
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return DownloadedFileInfo("7z", ".7z", "unknown", False)
    if head.startswith(b"Rar!\x1a\x07"):
        return DownloadedFileInfo("rar", ".rar", "unknown", False)
    if head.startswith(b"PK\x03\x04"):
        return DownloadedFileInfo("zip", ".zip", "unknown", False)
    if head.startswith(b"{\\rtf"):
        return DownloadedFileInfo("rtf", ".rtf", "unknown", False)
    return DownloadedFileInfo("bin", ".bin", "unknown", False)


def _mark_validation_sample_pending(sample_id: int, dataset_role: str, is_windows_executable: bool) -> None:
    if dataset_role != "validation_external" or not is_windows_executable:
        return
    with session_scope() as session:
        session.execute(
            text("UPDATE samples SET status_id = :status_id WHERE id = :sample_id"),
            {
                "status_id": get_status_id(session, "pending"),
                "sample_id": sample_id,
            },
        )


def _mark_sample_excluded(sample_id: int) -> None:
    with session_scope() as session:
        session.execute(
            text("UPDATE samples SET status_id = :status_id WHERE id = :sample_id"),
            {
                "status_id": get_status_id(session, "excluded_non_ransomware"),
                "sample_id": sample_id,
            },
        )


def _repair_existing(args: argparse.Namespace) -> None:
    limit = max(0, int(args.limit or 0))
    with session_scope() as session:
        rows = session.execute(
            text(
                """
                SELECT
                  s.id AS sample_id,
                  s.sha256,
                  s.file_type,
                  s.detected_arch,
                  s.stored_file_path,
                  COALESCE(sc.code, '') AS status,
                  ss.dataset_role,
                  ss.source_data
                FROM samples s
                JOIN sample_sources ss
                  ON ss.sample_id = s.id
                 AND ss.source = :source
                LEFT JOIN status_catalog sc ON sc.id = s.status_id
                ORDER BY s.id DESC
                LIMIT :limit
                """
            ),
            {"source": SOURCE, "limit": limit or 1000},
        ).mappings().all()
        records = [dict(row) for row in rows]

    payload: dict[str, Any] = {
        "execute": bool(args.execute),
        "repair_existing": True,
        "source": SOURCE,
        "requested_limit": limit or 1000,
        "scanned": len(records),
        "repaired": [],
        "skipped": [],
        "missing": [],
    }
    for row in records:
        sample_id = int(row["sample_id"])
        stored_file_path = row.get("stored_file_path")
        if not stored_file_path:
            payload["missing"].append({"sample_id": sample_id, "reason": "missing_path"})
            continue
        path = Path(str(stored_file_path))
        if not path.exists():
            payload["missing"].append({"sample_id": sample_id, "path": str(path), "reason": "missing_file"})
            continue
        info = _inspect_downloaded_file(path)
        source_data = sanitize_json_strings(dict(row.get("source_data") or {}))
        source_data.update(
            {
                "source": SOURCE,
                "is_windows_executable": info.is_windows_executable,
                "detected_arch": info.detected_arch,
                "detected_extension": info.extension,
                "stored_file_path": str(path),
                "path_extension_mismatch": path.suffix.lower() != info.extension.lower(),
            }
        )
        desired_status = None
        if str(row.get("dataset_role") or "") == "validation_external":
            desired_status = "pending" if info.is_windows_executable else "excluded_non_ransomware"
        changed = (
            str(row.get("file_type") or "") != info.file_type
            or str(row.get("detected_arch") or "unknown") != info.detected_arch
            or ("is_windows_executable" not in dict(row.get("source_data") or {}))
            or dict(row.get("source_data") or {}).get("is_windows_executable") != info.is_windows_executable
            or source_data.get("path_extension_mismatch")
            or (
                desired_status is not None
                and str(row.get("status") or "") != desired_status
            )
        )
        result = {
            "sample_id": sample_id,
            "sha256": row.get("sha256"),
            "path": str(path),
            "file_type": info.file_type,
            "detected_arch": info.detected_arch,
            "is_windows_executable": info.is_windows_executable,
            "path_extension_mismatch": source_data["path_extension_mismatch"],
            "desired_status": desired_status,
            "changed": changed,
        }
        if not changed:
            payload["skipped"].append(result)
            continue
        if not args.execute:
            payload["repaired"].append(result)
            continue
        with session_scope() as session:
            session.execute(
                text(
                    """
                    UPDATE samples
                    SET file_type = :file_type,
                        detected_arch = :detected_arch
                    WHERE id = :sample_id
                    """
                ),
                {
                    "sample_id": sample_id,
                    "file_type": info.file_type,
                    "detected_arch": info.detected_arch,
                },
            )
            session.execute(
                text(
                    """
                    UPDATE sample_sources
                    SET source_data = CAST(:source_data AS jsonb)
                    WHERE sample_id = :sample_id
                      AND source = :source
                    """
                ),
                {
                    "sample_id": sample_id,
                    "source": SOURCE,
                    "source_data": json.dumps(source_data),
                },
            )
        if desired_status == "pending":
            _mark_validation_sample_pending(sample_id, "validation_external", True)
        elif desired_status == "excluded_non_ransomware":
            _mark_sample_excluded(sample_id)
        payload["repaired"].append(result)
    _print_json(payload)


def _discover_candidates(
    *,
    client: MalShareClient,
    query: str | None,
    limit: int,
    dataset_role: str,
    family_hint: str | None,
    arch: str | None,
    include_details: bool,
    include_non_pe: bool,
    scan_multiplier: int = 25,
    scan_limit: int | None = None,
) -> tuple[list[MalShareMetadataCandidate], dict[str, Any]]:
    queries = _split_queries(query, family_hint)
    fetch_summary: list[dict[str, Any]] = []
    hashes: list[tuple[str, str]] = []
    recent_hashes = _parse_hashes(client.get_recent_hashes())
    fetch_summary.append({"mode": "getlist", "query": "getlist", "returned": len(recent_hashes)})
    hashes.extend((value, "getlist") for value in recent_hashes)
    for term in queries:
        search_hashes = _parse_hashes(client.search(term))
        fetch_summary.append({"mode": "search", "query": term, "returned": len(search_hashes)})
        hashes.extend((value, term) for value in search_hashes)
    unique_hashes: list[tuple[str, str]] = []
    seen: set[str] = set()
    for hash_value, source_query in hashes:
        if hash_value in seen:
            continue
        seen.add(hash_value)
        unique_hashes.append((hash_value, source_query))
    effective_scan_limit = scan_limit if scan_limit and scan_limit > 0 else max(limit * max(scan_multiplier, 1), limit + 200)
    candidates: list[MalShareMetadataCandidate] = []
    rejected: list[dict[str, Any]] = []
    for hash_value, source_query in _limit_payload(effective_scan_limit, unique_hashes):
        details = client.details(hash_value)
        detected_arch = _details_arch(details)
        is_windows_executable = _details_windows_executable(details)
        if arch and detected_arch not in {"unknown", arch}:
            rejected.append({"hash_value": hash_value, "source_query": source_query, "reason": "arch_mismatch", "detected_arch": detected_arch})
            continue
        if not include_non_pe and is_windows_executable is False:
            rejected.append(
                {
                    "hash_value": hash_value,
                    "source_query": source_query,
                    "reason": "non_windows_executable",
                    "metadata_file_type": _metadata_file_type(details),
                }
            )
            continue
        candidates.append(
            _candidate_from_hash(
                hash_value,
                source_query=source_query,
                dataset_role=dataset_role,
                family_hint=family_hint or details.get("family") or details.get("type"),
                source_data=details if include_details else {
                    "F_TYPE": details.get("F_TYPE"),
                    "FILENAMES": details.get("FILENAMES"),
                    "SHA256": details.get("SHA256"),
                },
            )
        )
        if len(candidates) >= limit:
            break
    return candidates, {
        "queries": fetch_summary,
        "unique_hashes_seen": len(unique_hashes),
        "scan_limit": effective_scan_limit,
        "scan_multiplier": scan_multiplier,
        "rejected": rejected,
        "rejected_count": len(rejected),
    }


def _normalized_from_file(path: Path, source_data: dict[str, Any], family_hint: str | None, file_info: DownloadedFileInfo) -> NormalizedSample:
    data = path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
    extension = file_info.extension
    return NormalizedSample(
        sha256=sha256,
        md5=md5,
        sha1=sha1,
        file_name=_candidate_file_name(source_data, sha256, extension),
        file_type=file_info.file_type,
        file_size=len(data),
        signature=source_data.get("signature"),
        reporter=SOURCE,
        origin_country=None,
        first_seen=None,
        malwarebazaar_data={
            "source": SOURCE,
            "is_windows_executable": file_info.is_windows_executable,
            "detected_arch": file_info.detected_arch,
            "download_extension": file_info.extension,
            **sanitize_json_strings(source_data or {}),
        },
        detected_arch=file_info.detected_arch,
        tags=["ransomware"] if family_hint else [],
    )


def ingest(args: argparse.Namespace) -> None:
    if getattr(args, "repair_existing", False):
        _repair_existing(args)
        return
    settings = get_settings()
    client = MalShareClient()
    if not client.api_key:
        raise SystemExit("THREATTRACE_MALSHARE_API_KEY missing")
    execute = bool(args.execute)
    download = execute
    if execute and not args.confirm_malware_download:
        raise SystemExit("--execute requires --confirm-malware-download")
    if args.limit > settings.malshare_daily_limit:
        raise SystemExit(f"--limit exceeds THREATTRACE_MALSHARE_DAILY_LIMIT={settings.malshare_daily_limit}")

    try:
        candidates, discovery = _discover_candidates(
            client=client,
            query=args.query,
            limit=args.limit,
            dataset_role=args.dataset_role,
            family_hint=args.family_hint,
            arch=args.arch,
            include_details=args.details,
            include_non_pe=args.include_non_pe,
            scan_multiplier=int(getattr(args, "scan_multiplier", 25) or 25),
            scan_limit=getattr(args, "scan_limit", None),
        )
    except MalShareClientError as exc:
        raise SystemExit(str(exc)) from None
    payload: dict[str, Any] = {
        "execute": execute,
        "download": download,
        "source": SOURCE,
        "dataset_role": args.dataset_role,
        "arch_filter": args.arch,
        "requested_limit": args.limit,
        "query": args.query,
        "fetch_summary": discovery["queries"],
        "api_raw_candidate_count": sum(int(item["returned"]) for item in discovery["queries"]),
        "unique_hashes_seen": discovery["unique_hashes_seen"],
        "candidate_count": len(candidates),
        "candidates": [asdict(item) for item in candidates],
        "rejected": discovery["rejected"],
        "rejected_count": discovery["rejected_count"],
        "registered": [],
        "downloaded": [],
        "skipped": [],
        "failed": [],
    }
    if args.dry_run or not execute:
        _print_json(payload)
        return

    for candidate in candidates:
        existing = _existing_sample(candidate.hash_value)
        if existing:
            _upsert_sample_source(
                sample_id=int(existing["id"]),
                source_sample_id=candidate.hash_value,
                source_query=candidate.source_query,
                source_data=candidate.source_data,
                dataset_role=candidate.dataset_role,
                family_hint=candidate.family_hint,
            )
            details = candidate.source_data or {}
            _mark_validation_sample_pending(
                sample_id=int(existing["id"]),
                dataset_role=candidate.dataset_role,
                is_windows_executable=_details_windows_executable(details) is not False,
            )
            payload["registered"].append({"sample_id": existing["id"], "sha256": existing["sha256"]})
            continue
        temp_path = settings.malware_root / "malshare_downloads" / candidate.hash_value
        client.get_file(candidate.hash_value, temp_path)
        file_info = _inspect_downloaded_file(temp_path)
        if not args.include_non_pe and not file_info.is_windows_executable:
            temp_path.unlink(missing_ok=True)
            payload["skipped"].append(
                {
                    "hash_value": candidate.hash_value,
                    "reason": "downloaded_non_windows_executable",
                    "file_type": file_info.file_type,
                }
            )
            continue
        normalized = _normalized_from_file(temp_path, candidate.source_data, candidate.family_hint, file_info)
        final_path = _sample_path(normalized.sha256, file_info.extension)
        final_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path.replace(final_path)
        with session_scope() as session:
            sample = upsert_sample(session, normalized)
            sample.stored_file_path = str(final_path)
            sample.file_size = normalized.file_size
            sample.file_type = normalized.file_type
            sample.detected_arch = normalized.detected_arch or "unknown"
            session.flush()
            sample_id = int(sample.id)
        _upsert_sample_source(
            sample_id=sample_id,
            source_sample_id=candidate.hash_value,
            source_query=candidate.source_query,
            source_data={
                **candidate.source_data,
                "downloaded_sha256": normalized.sha256,
                "stored_file_path": str(final_path),
                "is_windows_executable": file_info.is_windows_executable,
                "detected_arch": file_info.detected_arch,
                "download_extension": file_info.extension,
            },
            dataset_role=candidate.dataset_role,
            family_hint=candidate.family_hint,
        )
        _mark_validation_sample_pending(
            sample_id=sample_id,
            dataset_role=candidate.dataset_role,
            is_windows_executable=file_info.is_windows_executable,
        )
        payload["downloaded"].append(
            {
                "sample_id": sample_id,
                "sha256": normalized.sha256,
                "path": str(final_path),
                "file_type": normalized.file_type,
                "detected_arch": normalized.detected_arch,
                "is_windows_executable": file_info.is_windows_executable,
            }
        )
    _print_json(payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe MalShare validation ingestion")
    parser.add_argument("--query", action="append")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--dataset-role", default=DEFAULT_DATASET_ROLE)
    parser.add_argument("--family-hint")
    parser.add_argument("--arch", choices=["x86", "x64", "unknown"])
    parser.add_argument("--include-non-pe", action="store_true")
    parser.add_argument("--scan-multiplier", type=int, default=25)
    parser.add_argument("--scan-limit", type=int)
    parser.add_argument("--details", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-malware-download", action="store_true")
    parser.add_argument("--repair-existing", action="store_true")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    ingest(args)


if __name__ == "__main__":
    main()
