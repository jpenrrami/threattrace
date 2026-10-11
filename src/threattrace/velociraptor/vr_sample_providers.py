from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from threattrace.config.settings import get_settings
from threattrace.malshare.client import MalShareClient, MalShareClientError
from threattrace.malwarebazaar.client import MalwareBazaarClient
from threattrace.storage.filesystem import extract_malware_archive, sha256_file


def _provider_path(provider: str, sha256: str) -> Path:
    root = get_settings().validation_malware_dir / provider
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{sha256}.exe"


def _sample_sha256(sample: dict[str, Any]) -> str:
    return str(sample.get("sha256") or "").strip().lower()


@dataclass(frozen=True)
class ProviderPlan:
    provider: str
    available: bool
    reason: str | None = None


@dataclass(frozen=True)
class ProviderFetchResult:
    provider: str
    local_path: str | None
    retrieval_method: str
    fetched: bool
    error: str | None = None


class MalwareSampleProvider:
    name = "unknown"

    def healthcheck(self) -> ProviderPlan:
        return ProviderPlan(provider=self.name, available=True)

    def can_fetch(self, sample: dict[str, Any]) -> ProviderPlan:
        raise NotImplementedError

    def fetch(self, sample: dict[str, Any]) -> ProviderFetchResult:
        raise NotImplementedError


class LocalPathProvider(MalwareSampleProvider):
    name = "local"

    def can_fetch(self, sample: dict[str, Any]) -> ProviderPlan:
        path = Path(str(sample.get("binary_path_used") or sample.get("stored_file_path") or ""))
        if path.is_file():
            return ProviderPlan(provider=self.name, available=True)
        return ProviderPlan(provider=self.name, available=False, reason="missing_local_file")

    def fetch(self, sample: dict[str, Any]) -> ProviderFetchResult:
        plan = self.can_fetch(sample)
        path = Path(str(sample.get("binary_path_used") or sample.get("stored_file_path") or ""))
        return ProviderFetchResult(
            provider=self.name,
            local_path=str(path) if plan.available else None,
            retrieval_method="local_path",
            fetched=False,
            error=plan.reason,
        )


class MalShareProvider(MalwareSampleProvider):
    name = "malshare"

    def __init__(self, client: MalShareClient | None = None) -> None:
        self.client = client or MalShareClient()

    def healthcheck(self) -> ProviderPlan:
        if not self.client.api_key:
            return ProviderPlan(provider=self.name, available=False, reason="missing_api_key")
        return ProviderPlan(provider=self.name, available=True)

    def can_fetch(self, sample: dict[str, Any]) -> ProviderPlan:
        health = self.healthcheck()
        if not health.available:
            return health
        if str(sample.get("effective_source") or "") != "malshare":
            return ProviderPlan(provider=self.name, available=False, reason="source_not_malshare")
        if not _sample_sha256(sample):
            return ProviderPlan(provider=self.name, available=False, reason="missing_sha256")
        return ProviderPlan(provider=self.name, available=True)

    def fetch(self, sample: dict[str, Any]) -> ProviderFetchResult:
        plan = self.can_fetch(sample)
        sha256 = _sample_sha256(sample)
        if not plan.available:
            return ProviderFetchResult(self.name, None, "malshare_download", False, plan.reason)
        try:
            target = _provider_path(self.name, sha256)
            self.client.get_file(sha256, target)
            if sha256_file(target).lower() != sha256:
                raise RuntimeError("sha256_mismatch")
            return ProviderFetchResult(self.name, str(target), "malshare_download", True, None)
        except (MalShareClientError, RuntimeError) as exc:
            return ProviderFetchResult(self.name, None, "malshare_download", False, str(exc))


class MalwareBazaarProvider(MalwareSampleProvider):
    name = "malwarebazaar"

    def __init__(self, client: MalwareBazaarClient | None = None) -> None:
        self.client = client or MalwareBazaarClient()

    def healthcheck(self) -> ProviderPlan:
        return ProviderPlan(provider=self.name, available=True)

    def can_fetch(self, sample: dict[str, Any]) -> ProviderPlan:
        if _sample_sha256(sample):
            return ProviderPlan(provider=self.name, available=True)
        return ProviderPlan(provider=self.name, available=False, reason="missing_sha256")

    def fetch(self, sample: dict[str, Any]) -> ProviderFetchResult:
        plan = self.can_fetch(sample)
        sha256 = _sample_sha256(sample)
        if not plan.available:
            return ProviderFetchResult(self.name, None, "malwarebazaar_download", False, plan.reason)
        try:
            archive_bytes = self.client.download_sample_archive(sha256)
            file_bytes, _filename = extract_malware_archive(archive_bytes)
            target = _provider_path(self.name, sha256)
            target.write_bytes(file_bytes)
            target.chmod(0o600)
            if sha256_file(target).lower() != sha256:
                raise RuntimeError("sha256_mismatch")
            return ProviderFetchResult(self.name, str(target), "malwarebazaar_download", True, None)
        except Exception as exc:
            return ProviderFetchResult(self.name, None, "malwarebazaar_download", False, str(exc))
