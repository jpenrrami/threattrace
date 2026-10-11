from __future__ import annotations

import random
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from threattrace.common.json_config import load_json_config
from threattrace.config.settings import get_settings

ROOT_DIR = Path(__file__).resolve().parents[3]
CAPE_CLIENT_CONFIG_PATH = ROOT_DIR / "config" / "cape" / "client_rules.json"


@lru_cache(maxsize=1)
def _cape_client_config() -> dict[str, Any]:
    return load_json_config(str(CAPE_CLIENT_CONFIG_PATH))


def _exp_backoff(base: float, attempt: int, cap: float = 600.0) -> float:
    # exponential backoff with jitter
    delay = min(cap, base * (2 ** attempt))
    return delay * (0.5 + random.random() / 2.0)

class CapeClient:
    """
    CAPE API client with advanced dual-VM operational routing.

    Features:
    - Dual VM x86/x64 routing
    - Primary + fallback machine recovery
    - Tag retry fallback
    - Timeout enforcement
    - Preflight validation
    - Robust report retrieval
    - Large-scale ingestion resilience
    - HTTP retry strategy
    - API overload tolerance
    - Delayed report consistency polling
    - Session hardening
    """

    def __init__(self) -> None:
        self.settings = get_settings()
        settings = self.settings

        self.base_url = settings.cape_api_url.rstrip("/")
        self.timeout = settings.cape_timeout_seconds
        self.platform = settings.cape_platform

        self.machine_x86 = settings.cape_machine_x86
        self.machine_x64 = settings.cape_machine_x64

        self.tags_x86 = settings.cape_tags_x86
        self.tags_x64 = settings.cape_tags_x64
        self.submit_package = settings.cape_submit_package
        self.submit_options = settings.cape_submit_options
        self.submit_priority = settings.cape_submit_priority
        self.submit_custom = settings.cape_submit_custom
        self.submit_route = settings.cape_submit_route
        self.submit_clock = settings.cape_submit_clock
        self.submit_memory = settings.cape_submit_memory

        self.session = requests.Session()

        if hasattr(settings, "cape_verify_ssl"):
            self.session.verify = settings.cape_verify_ssl

        self.session.headers.update(
            {
                "User-Agent": "ThreatTrace-Ransomware-Pipeline/1.0",
                "Accept": "application/json",
            }
        )

        retry_cfg = _cape_client_config()["retry"]
        retry_strategy = Retry(
            total=int(retry_cfg["total"]),
            backoff_factor=float(retry_cfg["backoff_factor"]),
            status_forcelist=list(retry_cfg["status_forcelist"]),
            allowed_methods=list(retry_cfg["allowed_methods"]),
            raise_on_status=bool(retry_cfg["raise_on_status"]),
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if settings.cape_api_token:
            self.session.headers.update(
                {
                    "Authorization": f"Token {settings.cape_api_token}",
                }
            )

    def _url(self, endpoint: str) -> str:
        return f"{self.base_url}{endpoint}"

    def preflight_check(self) -> dict[str, Any]:
        response = self.session.get(
            self._url("/tasks/list/"),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return self._safe_json(response)

    def _submit_payload(
        self,
        machine: str,
        platform: str,
        timeout: int,
        tags: str | None = None,
    ) -> dict[str, str]:
        payload = {
            "machine": machine,
            "platform": platform,
            "timeout": str(timeout),
            "enforce_timeout": "1",
        }

        if tags:
            payload["tags"] = tags
        if self.submit_package:
            payload["package"] = self.submit_package
        if self.submit_options:
            payload["options"] = self.submit_options
        if self.submit_priority >= 0:
            payload["priority"] = str(self.submit_priority)
        if self.submit_custom:
            payload["custom"] = self.submit_custom
        if self.submit_route:
            payload["route"] = self.submit_route
        if self.submit_clock:
            payload["clock"] = self.submit_clock
        if self.submit_memory:
            payload["memory"] = "1"

        return payload

    def _perform_submission(
        self,
        file_path: Path,
        payload: dict[str, str],
    ) -> int:
        with file_path.open("rb") as handle:
            response = self.session.post(
                self._url("/tasks/create/file/"),
                files={"file": (file_path.name, handle)},
                data=payload,
                timeout=max(self.timeout, int(_cape_client_config()["submission"]["post_timeout_floor_seconds"])),
            )

        response.raise_for_status()

        payload_json = self._safe_json(response)
        task_ids = payload_json.get("data", {}).get("task_ids", [])

        if not task_ids:
            # one quick retry for transient CAPE responses
            time.sleep(float(_cape_client_config()["submission"]["empty_task_retry_sleep_seconds"]))
            with file_path.open("rb") as handle:
                response = self.session.post(
                    self._url("/tasks/create/file/"),
                    files={"file": (file_path.name, handle)},
                    data=payload,
                    timeout=max(self.timeout, int(_cape_client_config()["submission"]["post_timeout_floor_seconds"])),
                )
            response.raise_for_status()
            payload_json = self._safe_json(response)
            task_ids = payload_json.get("data", {}).get("task_ids", [])

        if not task_ids:
            raise RuntimeError(
                f"Failed CAPE submission for {file_path.name}: {payload_json}"
            )

        return int(task_ids[0])

    def submit_file(
        self,
        file_path: str | Path,
        machine: str | None = None,
        tags: str | None = None,
        platform: str | None = None,
        timeout: int | None = None,
    ) -> int:
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Sample not found: {file_path}")

        if file_path.stat().st_size == 0:
            raise RuntimeError(f"Sample file is empty: {file_path}")

        selected_machine = machine or self.machine_x86
        selected_tags = tags or self.tags_x86
        selected_platform = platform or self.platform
        selected_timeout = timeout or self.timeout

        primary_payload = self._submit_payload(
            machine=selected_machine,
            platform=selected_platform,
            timeout=selected_timeout,
            tags=selected_tags,
        )

        fallback_payload = self._submit_payload(
            machine=selected_machine,
            platform=selected_platform,
            timeout=selected_timeout,
            tags=None,
        )

        last_error: Exception | None = None

        for payload in (primary_payload, fallback_payload):
            try:
                return self._perform_submission(file_path, payload)

            except Exception as exc:
                last_error = exc
                time.sleep(float(_cape_client_config()["submission"]["payload_retry_sleep_seconds"]))

        raise RuntimeError(
            f"Failed CAPE submission after retries for {file_path.name}: {last_error}"
        )

    def submit_with_fallback(
        self,
        file_path: str | Path,
        architecture: str,
        timeout: int | None = None,
    ) -> tuple[int, str]:
        primary_machine, primary_tags = self.select_machine_for_architecture(
            architecture
        )

        try:
            task_id = self.submit_file(
                file_path=file_path,
                machine=primary_machine,
                tags=primary_tags,
                timeout=timeout,
            )
            return task_id, primary_machine

        except Exception:
            fallback_machine, fallback_tags = self.fallback_machine(
                primary_machine
            )

            task_id = self.submit_file(
                file_path=file_path,
                machine=fallback_machine,
                tags=fallback_tags,
                timeout=timeout,
            )

            return task_id, fallback_machine

    def get_task_status(self, task_id: int) -> dict[str, Any]:
        response = self.session.get(
            self._url(f"/tasks/view/{task_id}/"),
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = self._safe_json(response)

        if not payload:
            raise RuntimeError(
                f"Empty CAPE task status response for task {task_id}"
            )
        return payload

    def wait_for_report(
        self,
        task_id: int,
        max_attempts: int | None = None,
        delay_seconds: int | None = None,
    ) -> dict[str, Any]:
        """
        Waits until CAPE marks task as reported.
        Prevents premature fetch failures during heavy ingestion.
        """
        polling_cfg = _cape_client_config()["polling"]
        attempts = int(max_attempts or polling_cfg["wait_for_report_max_attempts"])
        base_delay = int(delay_seconds or polling_cfg["wait_for_report_delay_seconds"])
        for _ in range(attempts):
            task_data = self.get_task_status(task_id)

            if self.is_task_reported(task_data):
                return task_data

            status = str(
                task_data.get("data", {}).get("status", "")
            ).strip().lower()

            if status in {"failed_analysis", "failed_processing", "failed_reporting"}:
                raise RuntimeError(
                    f"CAPE task {task_id} failed with status: {status}"
                )

            time.sleep(_exp_backoff(base_delay, _, cap=float(polling_cfg["backoff_cap_seconds"])))

        raise TimeoutError(
            f"CAPE task {task_id} did not reach reported state in time"
        )

    def fetch_report(
        self,
        task_id: int,
        retries: int | None = None,
        delay_seconds: int | None = None,
    ) -> dict[str, Any]:
        """
        Robust report fetch with delayed consistency handling.
        CAPE may report task complete before report JSON is fully ready.
        """

        last_error: Exception | None = None
        polling_cfg = _cape_client_config()["polling"]
        attempts = int(retries or polling_cfg["fetch_report_retries"])
        base_delay = int(delay_seconds or polling_cfg["fetch_report_delay_seconds"])
        for _ in range(attempts):
            try:
                response = self.session.get(
                    self._url(f"/tasks/get/report/{task_id}/json/"),
                    timeout=max(self.timeout, 300),
                )

                if response.status_code == 404:
                    raise RuntimeError(f"Report not found yet for task {task_id}")

                response.raise_for_status()

                payload = self._safe_json(response)

                if isinstance(payload, dict) and payload.get("error"):
                    raise RuntimeError(payload)

                if not payload:
                    raise RuntimeError("Empty CAPE report")
                if not isinstance(payload, dict):
                    raise RuntimeError(
                        f"Invalid CAPE report format for task {task_id}"
                    )
                if "target" not in payload:
                    raise RuntimeError(
                        f"Incomplete CAPE report for task {task_id}"
                    )
                return payload
            except Exception as exc:
                last_error = exc
                time.sleep(_exp_backoff(base_delay, _, cap=float(polling_cfg["backoff_cap_seconds"])))

        raise RuntimeError(
            f"CAPE report for task {task_id} unavailable after retries: {last_error}"
        )

    def is_task_reported(self, task_data: dict[str, Any]) -> bool:
        status = str(
            task_data.get("data", {}).get("status", "")
        ).strip().lower()

        return status == "reported"

    def select_machine_for_architecture(
        self,
        architecture: str,
    ) -> tuple[str, str]:
        normalized = (architecture or "").strip().lower()

        if normalized == "x64":
            return self.machine_x64, self.tags_x64

        return self.machine_x86, self.tags_x86

    def fallback_machine(
        self,
        current_machine: str,
    ) -> tuple[str, str]:
        normalized = (current_machine or "").strip().lower()

        if normalized == self.machine_x86.lower():
            return self.machine_x64, self.tags_x64

        if normalized == self.machine_x64.lower():
            return self.machine_x86, self.tags_x86

        return self.machine_x86, self.tags_x86

    def preflight(self) -> dict[str, Any]:
        """
        Scheduler preflight:
        - Verifies CAPE API connectivity
        - Verifies machine inventory
        - Uses existing configured base_url/timeout
        """

        tasks = self.session.get(
            self._url(str(_cape_client_config()["preflight"]["tasks_endpoint"])),
            timeout=self.timeout,
        )
        tasks.raise_for_status()
        self._safe_json(tasks)

        machines = self.session.get(
            self._url(str(_cape_client_config()["preflight"]["machines_endpoint"])),
            timeout=self.timeout,
        )
        machines.raise_for_status()

        machines_data = self._safe_json(machines).get("data", [])

        if not machines_data:
            raise RuntimeError("No CAPE machines available")

        available_names = {
            machine.get("name", "").lower()
            for machine in machines_data
        }

        configured_valid = (
            self.machine_x86.lower() in available_names
            or self.machine_x64.lower() in available_names
        )

        if not configured_valid:
            raise RuntimeError(
                "Configured CAPE machines not present in CAPE inventory"
            )

        return {
            "api_ok": True,
            "machines_available": len(machines_data),
            "configured_x86": self.machine_x86,
            "configured_x64": self.machine_x64,
        }

    def health(self) -> dict[str, Any]:
        try:
            r = self.session.get(self._url("/tasks/list/"), timeout=self.timeout)
            r.raise_for_status()
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _safe_json(self, response: requests.Response) -> dict[str, Any]:

        try:
            return response.json()
        except Exception as exc:
            raise RuntimeError(
                f"Invalid JSON response from CAPE API "
                f"(status={response.status_code}): {response.text[:500]}"
            ) from exc
