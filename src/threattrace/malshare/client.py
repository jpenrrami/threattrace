from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from threattrace.config.settings import get_settings


@dataclass(frozen=True)
class MalShareLimit:
    raw: str
    remaining: int | None = None
    allocated: int | None = None


class MalShareClientError(RuntimeError):
    pass


class MalShareClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        settings = get_settings()
        self.api_key = api_key or settings.malshare_api_key
        self.base_url = self._normalize_base_url(base_url or settings.malshare_api_url)
        self.timeout_seconds = settings.malshare_timeout_seconds
        self.session = requests.Session()

    @staticmethod
    def _normalize_base_url(value: str) -> str:
        parsed = urlparse(value)
        if parsed.path in {"", "/"}:
            return value.rstrip("/") + "/api.php"
        return value

    def _require_api_key(self) -> str:
        if not self.api_key:
            raise RuntimeError("THREATTRACE_MALSHARE_API_KEY missing")
        return self.api_key

    def _get(self, action: str, **params: Any) -> requests.Response:
        try:
            response = self.session.get(
                self.base_url,
                params={
                    "api_key": self._require_api_key(),
                    "action": action,
                    **params,
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            status = getattr(exc.response, "status_code", None)
            raise MalShareClientError(f"MalShare {action} failed; status={status}") from None
        return response

    def _post(self, action: str, **data: Any) -> requests.Response:
        try:
            response = self.session.post(
                self.base_url,
                params={
                    "api_key": self._require_api_key(),
                    "action": action,
                },
                data=data,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            status = getattr(exc.response, "status_code", None)
            raise MalShareClientError(f"MalShare {action} failed; status={status}") from None
        return response

    def get_limit(self) -> MalShareLimit:
        raw = self._get("getlimit").text.strip()
        numbers = [int(part) for part in raw.replace("/", " ").split() if part.isdigit()]
        remaining = numbers[0] if numbers else None
        allocated = numbers[1] if len(numbers) > 1 else None
        return MalShareLimit(raw=raw, remaining=remaining, allocated=allocated)

    def search(self, query: str) -> list[str]:
        raw = self._get("search", query=query).text.strip()
        return [line.strip() for line in raw.splitlines() if line.strip()]

    def details(self, hash_value: str) -> dict[str, Any]:
        return self._get("details", hash=hash_value).json()

    def hashlookup(self, hashes: list[str]) -> dict[str, Any]:
        return self._post("hashlookup", hashes=hashes).json()

    def get_types(self) -> dict[str, Any]:
        return self._get("gettypes").json()

    def get_recent_hashes(self) -> list[str]:
        response = self._get("getlist")
        try:
            payload = response.json()
        except ValueError:
            return [line.strip() for line in response.text.splitlines() if line.strip()]
        if isinstance(payload, list):
            values: list[str] = []
            for item in payload:
                if isinstance(item, dict):
                    value = item.get("sha256") or item.get("hash") or item.get("md5")
                else:
                    value = item
                if str(value).strip():
                    values.append(str(value).strip())
            return values
        return []

    def get_recent_sources(self) -> dict[str, Any]:
        return self._get("getsources").json()

    def get_file(self, hash_value: str, output_path: Path) -> Path:
        response = self._get("getfile", hash=hash_value)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(response.content)
        output_path.chmod(0o600)
        return output_path
