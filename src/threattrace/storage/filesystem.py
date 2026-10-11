from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path

from threattrace.common import get_logger
from threattrace.config.settings import get_settings

logger = get_logger(__name__)


def ensure_storage_dirs() -> None:
    settings = get_settings()
    settings.malware_root.mkdir(parents=True, exist_ok=True)
    settings.report_root.mkdir(parents=True, exist_ok=True)
    (settings.report_root / "raw").mkdir(parents=True, exist_ok=True)


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _safe_extension(filename: str | None) -> str:
    if not filename:
        return ".bin"
    suffix = Path(filename).suffix.lower()
    return suffix if suffix else ".bin"


def sample_storage_path(sha256: str, filename: str | None) -> Path:
    settings = get_settings()
    sha256 = sha256.strip().lower()
    if len(sha256) != 64:
        raise ValueError(f"Invalid SHA256 for sample storage: {sha256}")
    extension = _safe_extension(filename)
    return settings.malware_root / sha256[:2] / sha256[2:4] / f"{sha256}{extension}"


def report_storage_path(sha256: str) -> Path:
    settings = get_settings()
    sha256 = sha256.strip().lower()
    if len(sha256) != 64:
        raise ValueError(f"Invalid SHA256 for report storage: {sha256}")
    return settings.report_root / "raw" / f"{sha256}.json"


def extract_malware_archive(
    archive_bytes: bytes,
    password: str | None = None,
) -> tuple[bytes, str | None]:
    if not archive_bytes:
        raise ValueError("Empty archive bytes received")
    archive_password = password or get_settings().malware_archive_password
    # Fast path: standard ZIP methods supported by Python's stdlib.
    try:
        with zipfile.ZipFile(BytesIO(archive_bytes)) as archive:
            members = [
                item for item in archive.infolist()
                if not item.is_dir() and not Path(item.filename).is_absolute() and ".." not in Path(item.filename).parts
            ]
            if not members:
                raise ValueError("Malware archive is empty")
            member = members[0]
            extracted = archive.read(member, pwd=archive_password.encode("utf-8"))
            return extracted, member.filename
    except (NotImplementedError, zipfile.BadZipFile, RuntimeError):
        # Some MalwareBazaar archives use ZIP methods not supported by zipfile.
        pass

    seven_zip = shutil.which("7z") or shutil.which("7zz")
    if not seven_zip:
        raise RuntimeError("Archive requires 7z extraction but 7z is not installed on this host")

    with tempfile.TemporaryDirectory(prefix="threattrace-mbazaar-") as td:
        tmpdir = Path(td)
        archive_path = tmpdir / "sample.zip"
        archive_path.write_bytes(archive_bytes)

        # Extract everything to a temp dir; pick the first non-dir file.
        out_dir = tmpdir / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd = [seven_zip, "x", "-y", f"-p{archive_password}", f"-o{out_dir}", str(archive_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            logger.error(
                "7z extraction failed",
                extra={
                    "service": "storage",
                    "stage": "extract",
                    "stderr": proc.stderr,
                    "stdout": proc.stdout,
                },
            )
            raise RuntimeError(f"7z extraction failed: {proc.stderr.strip() or proc.stdout.strip()}")

        files = [
            p for p in out_dir.rglob("*")
            if p.is_file() and out_dir in p.resolve().parents
        ]
        if not files:
            raise RuntimeError("7z extracted no files from archive")
        first = files[0]
        data = first.read_bytes()
        if not data:
            raise RuntimeError("Extracted file is empty")
        return data, first.name


def persist_sample_file(sha256: str, file_bytes: bytes, source_name: str | None) -> Path:
    if not file_bytes:
        raise ValueError(f"Cannot persist empty sample for {sha256}")
    ensure_storage_dirs()
    destination = sample_storage_path(sha256, source_name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp_destination = destination.with_suffix(destination.suffix + ".tmp")
    tmp_destination.write_bytes(file_bytes)
    os.replace(tmp_destination, destination)
    stored_sha256 = sha256_file(destination)
    if stored_sha256.lower() != sha256.strip().lower():
        logger.error(
            "SHA256 mismatch on persisted sample",
            extra={
                "service": "storage",
                "stage": "integrity_error",
                "expected": sha256,
                "actual": stored_sha256,
                "path": str(destination),
            },
        )
        raise RuntimeError(
            f"Stored sample SHA256 mismatch: expected={sha256} got={stored_sha256}"
        )
    logger.info(
        "Sample persisted",
        extra={
            "service": "storage",
            "stage": "persist_sample",
            "sha256": sha256,
            "path": str(destination),
            "size_bytes": len(file_bytes),
        },
    )
    return destination


def _sanitize_for_json(value: object) -> object:
    if isinstance(value, dict):
        return {str(k): _sanitize_for_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_json(v) for v in value]
    if isinstance(value, str):
        return value.replace("\x00", "").replace("\u0000", "")
    return value


def persist_report_json(
    sha256: str,
    report_payload: dict,
    *,
    already_sanitized: bool = False,
) -> tuple[Path, str]:
    if not already_sanitized:
        report_payload = _sanitize_for_json(report_payload)
    ensure_storage_dirs()
    destination = report_storage_path(sha256)
    destination.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(report_payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    tmp_destination = destination.with_suffix(".tmp")
    tmp_destination.write_bytes(serialized)
    os.replace(tmp_destination, destination)
    logger.info(
        "Report persisted",
        extra={
            "service": "storage",
            "stage": "persist_report",
            "sha256": sha256,
            "path": str(destination),
            "size_bytes": len(serialized),
        },
    )
    return destination, _sha256_bytes(serialized)


def sha256_file(path: str | Path) -> str:
    """
    Returns SHA256 of an on-disk file.
    """
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"File not found for hashing: {target}")
    return _sha256_bytes(target.read_bytes())


def persist_cape_report(
    sha256: str,
    cape_task_id: int,
    report_json: dict,
    *,
    already_sanitized: bool = False,
) -> Path:
    """
    Stores CAPE report and returns report path only.
    """
    logger.info(
        "Persisting CAPE report",
        extra={
            "service": "storage",
            "sha256": sha256,
            "cape_task_id": cape_task_id,
        },
    )
    destination, _ = persist_report_json(
        sha256,
        report_json,
        already_sanitized=already_sanitized,
    )
    return destination
