from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from threattrace.config.settings import get_settings
from threattrace.db.session import session_scope
from threattrace.velociraptor.vr_config import load_vr_config


@dataclass(frozen=True)
class ResolvedSampleBinary:
    sample_id: int
    sha256: str
    source: str
    source_provenance: str
    resolved_binary_path: str
    binary_source: str
    read_only_source: bool
    file_exists: bool
    detected_arch: str = "unknown"

    def as_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "sha256": self.sha256,
            "source": self.source,
            "source_provenance": self.source_provenance,
            "resolved_binary_path": self.resolved_binary_path,
            "binary_source": self.binary_source,
            "read_only_source": self.read_only_source,
            "file_exists": self.file_exists,
            "detected_arch": self.detected_arch,
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_from_row(row: dict[str, Any]) -> tuple[str, str]:
    explicit = row.get("sample_source")
    if explicit:
        return str(explicit), "sample_sources"
    mb_data = row.get("malwarebazaar_data")
    if mb_data and str(mb_data) not in ("{}", "None"):
        if isinstance(mb_data, dict) and mb_data.get("source") == "malshare":
            return "unknown", "none"
        return "malwarebazaar_inferred", "malwarebazaar_data"
    return "unknown", "none"


def _runtime_candidates(sha256: str) -> list[tuple[str, Path]]:
    settings = get_settings()
    return [
        ("runtime_storage", settings.malware_root / sha256),
        ("runtime_storage", settings.malware_root / f"{sha256}.exe"),
        ("runtime_storage", settings.storage_root / "malware" / sha256),
        ("runtime_storage", settings.storage_root / "malware" / f"{sha256}.exe"),
    ]


def resolve_sample_binary_from_row(
    row: dict[str, Any],
    cape_binary_fallback: Path | None = None,
) -> ResolvedSampleBinary:
    sha256 = str(row.get("sha256") or "")
    sample_id = int(row.get("sample_id") or row.get("id") or 0)
    source, provenance = _source_from_row(row)
    candidates: list[tuple[str, Path, bool]] = []
    stored = row.get("stored_file_path")
    if stored:
        candidates.append(("stored_file_path", Path(str(stored)), False))
    candidates.extend((name, path, False) for name, path in _runtime_candidates(sha256))
    malshare_path = row.get("malshare_path") or row.get("source_path")
    if malshare_path:
        candidates.append(("malshare", Path(str(malshare_path)), False))
    fallback = cape_binary_fallback or load_vr_config().cape_binary_fallback
    if sha256:
        candidates.append(("cape_readonly_fallback", fallback / sha256, True))

    selected_source = candidates[0][0] if candidates else "none"
    selected_path = candidates[0][1] if candidates else Path("")
    selected_read_only = candidates[0][2] if candidates else False
    for binary_source, path, read_only in candidates:
        if path.is_file():
            selected_source = binary_source
            selected_path = path
            selected_read_only = read_only
            break

    return ResolvedSampleBinary(
        sample_id=sample_id,
        sha256=sha256,
        source=source,
        source_provenance=provenance,
        resolved_binary_path=str(selected_path),
        binary_source=selected_source,
        read_only_source=selected_read_only,
        file_exists=selected_path.is_file(),
        detected_arch=str(row.get("detected_arch") or "unknown"),
    )


def resolve_sample_binary(sample_id: int) -> ResolvedSampleBinary:
    try:
        with session_scope() as session:
            row = session.execute(
                text(
                    """
                    SELECT s.id AS sample_id, s.sha256, s.stored_file_path,
                           s.detected_arch,
                           s.malwarebazaar_data, ss.source AS sample_source,
                           ss.source_data->>'stored_file_path' AS source_path
                    FROM samples s
                    LEFT JOIN LATERAL (
                      SELECT *
                      FROM sample_sources ss
                      WHERE ss.sample_id = s.id
                      ORDER BY ss.created_at DESC, ss.id DESC
                      LIMIT 1
                    ) ss ON true
                    WHERE s.id = :sample_id
                    """
                ),
                {"sample_id": sample_id},
            ).mappings().first()
    except SQLAlchemyError as exc:
        raise RuntimeError(f"DB query failed: {exc}") from exc
    if not row:
        raise ValueError(f"Sample not found: {sample_id}")
    return resolve_sample_binary_from_row(dict(row))


def enforce_source_policy(resolved: ResolvedSampleBinary, required_source: str | None) -> None:
    if required_source is None:
        return
    if required_source == "malshare" and resolved.source_provenance != "sample_sources":
        raise ValueError("MalShare validation requires sample_sources.source='malshare'")
    if resolved.source != required_source:
        raise ValueError(f"Sample source {resolved.source!r} does not match required {required_source!r}")
