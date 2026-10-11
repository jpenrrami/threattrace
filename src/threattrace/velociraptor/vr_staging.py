from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from threattrace.velociraptor.vr_binary_resolver import ResolvedSampleBinary, sha256_file
from threattrace.velociraptor.vr_config import ensure_safe_staging_bind

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StagedSample:
    staging_dir: Path
    staged_path: Path
    filename: str
    sha256: str
    hash_verified: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "staging_dir": str(self.staging_dir),
            "staged_path": str(self.staged_path),
            "filename": self.filename,
            "sha256": self.sha256,
            "hash_verified": self.hash_verified,
        }


def supported_windows_executable(path: Path) -> bool:
    suffix = path.suffix.lower()
    return suffix in {".exe", ".dll"} or path.name.lower().endswith((".exe", ".dll"))


def staged_filename(resolved: ResolvedSampleBinary, source_path: Path) -> str:
    suffix = source_path.suffix.lower()
    if suffix in {".exe", ".dll"}:
        return f"{resolved.sha256}{suffix}"
    return resolved.sha256


def stage_sample(resolved: ResolvedSampleBinary, result_dir: Path, execute: bool) -> StagedSample:
    source = Path(resolved.resolved_binary_path)
    if not source.is_file():
        raise FileNotFoundError(f"Sample binary missing: {source}")
    if not supported_windows_executable(source):
        raise ValueError("Unsupported file type for Windows execution: only .exe and .dll are supported")
    staging_dir = result_dir / "staging"
    filename = staged_filename(resolved, source)
    staged_path = staging_dir / filename
    if execute:
        staging_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, staged_path)
        staged_path.chmod(0o600)
        actual = sha256_file(staged_path)
        if actual.lower() != resolved.sha256.lower():
            raise ValueError(f"HASH_MISMATCH: staged {actual} != expected {resolved.sha256}")
        verified = True
    else:
        verified = False
    return StagedSample(staging_dir, staged_path, filename, resolved.sha256, verified)


def choose_free_port(bind_host: str, min_port: int, max_port: int) -> int:
    ensure_safe_staging_bind(bind_host)
    for port in range(min_port, max_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((bind_host, port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"No free port in {min_port}-{max_port}")


def http_server_command(bind_host: str, port: int, staging_dir: Path) -> list[str]:
    ensure_safe_staging_bind(bind_host)
    return [
        "python3",
        "-m",
        "http.server",
        str(port),
        "--bind",
        bind_host,
        "--directory",
        str(staging_dir),
    ]


class StagingHTTPServer:
    def __init__(self, bind_host: str, port: int, staging_dir: Path) -> None:
        self.command = http_server_command(bind_host, port, staging_dir)
        self.bind_host = bind_host
        self.port = port
        self.staging_dir = staging_dir
        self.process: subprocess.Popen[str] | None = None
        self.listening = False

    def __enter__(self) -> StagingHTTPServer:
        self.process = subprocess.Popen(
            self.command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.listening = wait_for_listening(self.bind_host, self.port, timeout_seconds=15.0)
        if not self.listening:
            stderr = ""
            if self.process.stderr is not None:
                try:
                    stderr = self.process.stderr.read(1000)
                except Exception as exc:
                    logger.warning("staging server stderr unavailable error=%s", exc)
            self.__exit__()
            detail = f": {stderr.strip()}" if stderr.strip() else ""
            raise RuntimeError(f"HTTP server did not listen on {self.bind_host}:{self.port}{detail}")
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)

    def as_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "pid": self.process.pid if self.process else None,
            "listening": self.listening,
        }


def is_listening(bind_host: str, port: int) -> bool:
    ensure_safe_staging_bind(bind_host)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((bind_host, port)) == 0


def wait_for_listening(bind_host: str, port: int, timeout_seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if is_listening(bind_host, port):
            return True
        time.sleep(0.1)
    return is_listening(bind_host, port)
