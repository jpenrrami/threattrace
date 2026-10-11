from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[3]
logger = logging.getLogger(__name__)


def _load_env_file_if_present() -> None:
    """
    Lightweight .env loader (no extra dependency).

    Loads env files from the package project root and current working directory:
    - `.env`
    - `.env.local`

    Precedence:
    - existing process env wins
    - `.env.local` overrides `.env`
    """

    def parse_line(line: str) -> tuple[str, str] | None:
        s = line.strip()
        if not s or s.startswith("#"):
            return None
        if "=" not in s:
            return None
        key, value = s.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            return None
        # Remove optional surrounding quotes.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        return key, value

    loaded_from_file: set[str] = set()
    env_dirs = [PROJECT_ROOT]
    cwd = Path.cwd().resolve()
    if cwd != PROJECT_ROOT:
        env_dirs.append(cwd)

    for env_dir in env_dirs:
        for fname in (".env", ".env.local"):
            path = env_dir / fname
            if not path.exists() or not path.is_file():
                continue
            try:
                for raw in path.read_text(encoding="utf-8").splitlines():
                    parsed = parse_line(raw)
                    if not parsed:
                        continue
                    key, value = parsed
                    if key in os.environ and key not in loaded_from_file:
                        continue
                    os.environ[key] = value
                    loaded_from_file.add(key)
            except Exception as exc:
                logger.warning("environment file could not be parsed path=%s error=%s", path, exc)


def _get_env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


@dataclass(frozen=True)
class Settings:
    database_url: str
    db_pool_size: int
    db_max_overflow: int
    db_pool_timeout_seconds: int
    db_pool_use_lifo: bool
    redis_url: str
    malwarebazaar_api_url: str
    malwarebazaar_api_key: str | None
    malwarebazaar_recent_limit: int
    malwarebazaar_tag_limit: int
    malwarebazaar_min_request_interval_seconds: float
    malwarebazaar_cache_ttl_seconds: int
    malwarebazaar_max_retries: int
    malwarebazaar_downloads_per_day_limit: int
    malshare_api_url: str
    malshare_api_key: str | None
    malshare_timeout_seconds: int
    malshare_daily_limit: int
    malshare_download_dir: Path
    malshare_daily_api_limit_safety_margin: int
    validation_malware_dir: Path
    storage_root: Path
    malware_root: Path
    report_root: Path
    malware_archive_password: str
    cape_storage_path: Path
    cape_api_url: str
    cape_api_token: str | None
    cape_machine: str
    cape_machine_x86: str
    cape_machine_x64: str
    cape_platform: str
    cape_tags: str
    cape_tags_x86: str
    cape_tags_x64: str
    cape_timeout_seconds: int
    cape_submit_package: str | None
    cape_submit_options: str | None
    cape_submit_priority: int
    cape_submit_custom: str | None
    cape_submit_route: str | None
    cape_submit_clock: str | None
    cape_submit_memory: bool
    cape_poll_interval_seconds: int
    cape_poll_running_interval_seconds: int
    cape_poll_max_interval_seconds: int
    cape_max_wait_seconds: int
    daily_batch_size: int
    celery_task_soft_timeout: int
    celery_task_hard_timeout: int
    pipeline_requeue_delay_seconds: int
    pipeline_max_retries: int
    report_validation_enabled: bool
    ioc_enrichment_enabled: bool
    log_level: str
    cape_verify_ssl: bool
    vr_x64_host: str
    vr_x64_user: str
    vr_x64_password: str | None
    vr_x86_host: str
    vr_x86_user: str
    vr_x86_password: str | None
    vr_validation_snapshot: str
    vr_staging_bind_host: str
    vr_velociraptor_config: Path
    vr_velociraptor_use_sudo: bool
    vr_velociraptor_api_config: Path | None
    vr_libvirt_uri: str
    vr_wait_seconds_default: int
    vr_http_port_min: int
    vr_http_port_max: int
    vr_cape_binary_fallback: Path


# --- Validation helpers ---
def _validate_url(name: str, value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https", "redis", "postgresql", "postgresql+psycopg"}:
        raise ValueError(f"Invalid URL scheme for {name}: {value}")
    if not parsed.netloc:
        raise ValueError(f"Invalid URL netloc for {name}: {value}")
    return value.rstrip("/") if parsed.scheme in {"http", "https"} else value


def _validate_positive_int(name: str, value: int, minimum: int = 1) -> int:
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value

def _validate_float(name: str, value: float, minimum: float = 0.0) -> float:
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def _validate_path(path: Path) -> Path:
    return path.resolve()


def _validate_nonempty(name: str, value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{name} cannot be empty")
    return normalized


# Log level validation
def _validate_log_level(value: str) -> str:
    normalized = value.strip().upper()
    allowed = {
        "CRITICAL",
        "ERROR",
        "WARNING",
        "INFO",
        "DEBUG",
    }
    if normalized not in allowed:
        raise ValueError(
            f"Invalid THREATTRACE_LOG_LEVEL: {value}. Allowed: {sorted(allowed)}"
        )
    return normalized


def _parse_bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    _load_env_file_if_present()
    default_storage_root = Path.cwd() / "runtime_storage"
    storage_root = _validate_path(
        Path(_get_env("THREATTRACE_STORAGE_ROOT", str(default_storage_root)))
    )
    malware_root = _validate_path(
        Path(_get_env("THREATTRACE_MALWARE_ROOT", str(storage_root / "malware")))
    )
    report_root = _validate_path(
        Path(_get_env("THREATTRACE_REPORT_ROOT", str(storage_root / "reports")))
    )
    if malware_root == report_root:
        raise ValueError("malware_root and report_root must be different paths")
    return Settings(
        database_url=_validate_url("THREATTRACE_DATABASE_URL", _require_env("THREATTRACE_DATABASE_URL")),
        db_pool_size=_validate_positive_int(
            "THREATTRACE_DB_POOL_SIZE",
            int(_get_env("THREATTRACE_DB_POOL_SIZE", "10")),
        ),
        db_max_overflow=_validate_positive_int(
            "THREATTRACE_DB_MAX_OVERFLOW",
            int(_get_env("THREATTRACE_DB_MAX_OVERFLOW", "20")),
            minimum=0,
        ),
        db_pool_timeout_seconds=_validate_positive_int(
            "THREATTRACE_DB_POOL_TIMEOUT_SECONDS",
            int(_get_env("THREATTRACE_DB_POOL_TIMEOUT_SECONDS", "30")),
        ),
        db_pool_use_lifo=_parse_bool_env(
            "THREATTRACE_DB_POOL_USE_LIFO",
            True,
        ),
        redis_url=_validate_url(
            "THREATTRACE_REDIS_URL",
            _get_env("THREATTRACE_REDIS_URL", "redis://localhost:6379/0"),
        ),
        malwarebazaar_api_url=_validate_url("THREATTRACE_MALWAREBAZAAR_API_URL", _get_env(
            "THREATTRACE_MALWAREBAZAAR_API_URL",
            "https://mb-api.abuse.ch/api/v1/",
        )),
        malwarebazaar_api_key=(
            os.environ.get("THREATTRACE_MALWAREBAZAAR_API_KEY")
            or os.environ.get("MALWAREBAZAAR_AUTH_KEY")
            or None
        ),
        malwarebazaar_recent_limit=_validate_positive_int(
            "THREATTRACE_MALWAREBAZAAR_RECENT_LIMIT",
            int(_get_env("THREATTRACE_MALWAREBAZAAR_RECENT_LIMIT", "1000")),
        ),
        malwarebazaar_tag_limit=_validate_positive_int(
            "THREATTRACE_MALWAREBAZAAR_TAG_LIMIT",
            int(_get_env("THREATTRACE_MALWAREBAZAAR_TAG_LIMIT", "1000")),
        ),
        malwarebazaar_min_request_interval_seconds=_validate_float(
            "THREATTRACE_MALWAREBAZAAR_MIN_REQUEST_INTERVAL_SECONDS",
            float(
                _get_env(
                    "THREATTRACE_MALWAREBAZAAR_MIN_REQUEST_INTERVAL_SECONDS",
                    "1.0",
                )
            ),
            minimum=0.0,
        ),
        malwarebazaar_cache_ttl_seconds=_validate_positive_int(
            "THREATTRACE_MALWAREBAZAAR_CACHE_TTL_SECONDS",
            int(_get_env("THREATTRACE_MALWAREBAZAAR_CACHE_TTL_SECONDS", "300")),
        ),
        malwarebazaar_max_retries=_validate_positive_int(
            "THREATTRACE_MALWAREBAZAAR_MAX_RETRIES",
            int(_get_env("THREATTRACE_MALWAREBAZAAR_MAX_RETRIES", "3")),
        ),
        malwarebazaar_downloads_per_day_limit=_validate_positive_int(
            "THREATTRACE_MALWAREBAZAAR_DAILY_DOWNLOAD_LIMIT",
            int(
                os.environ.get(
                    "THREATTRACE_MALWAREBAZAAR_DAILY_DOWNLOAD_LIMIT",
                    _get_env("THREATTRACE_MALWAREBAZAAR_DOWNLOADS_PER_DAY_LIMIT", "200"),
                )
            ),
        ),
        malshare_api_url=_validate_url(
            "THREATTRACE_MALSHARE_BASE_URL",
            os.environ.get(
                "THREATTRACE_MALSHARE_BASE_URL",
                _get_env("THREATTRACE_MALSHARE_API_URL", "https://malshare.com/api.php"),
            ),
        ),
        malshare_api_key=(
            os.environ.get("THREATTRACE_MALSHARE_API_KEY")
            or os.environ.get("MALSHARE_API_KEY")
            or None
        ),
        malshare_timeout_seconds=_validate_positive_int(
            "THREATTRACE_MALSHARE_TIMEOUT_SECONDS",
            int(_get_env("THREATTRACE_MALSHARE_TIMEOUT_SECONDS", "30")),
        ),
        malshare_daily_limit=_validate_positive_int(
            "THREATTRACE_MALSHARE_DAILY_LIMIT",
            int(_get_env("THREATTRACE_MALSHARE_DAILY_LIMIT", "1000")),
        ),
        malshare_download_dir=_validate_path(
            Path(
                _get_env(
                    "THREATTRACE_MALSHARE_DOWNLOAD_DIR",
                    str(Path.cwd() / "validation_samples" / "malshare"),
                )
            )
        ),
        malshare_daily_api_limit_safety_margin=_validate_positive_int(
            "THREATTRACE_MALSHARE_DAILY_API_LIMIT_SAFETY_MARGIN",
            int(_get_env("THREATTRACE_MALSHARE_DAILY_API_LIMIT_SAFETY_MARGIN", "50")),
            minimum=0,
        ),
        validation_malware_dir=_validate_path(
            Path(
                os.environ.get(
                    "THREATTRACE_VALIDATION_MALWARE_DIR",
                    str(malware_root / "velociraptor_validation"),
                )
            )
        ),
        storage_root=storage_root,
        malware_root=malware_root,
        report_root=report_root,
        malware_archive_password=_validate_nonempty(
            "THREATTRACE_MALWARE_ARCHIVE_PASSWORD",
            _get_env("THREATTRACE_MALWARE_ARCHIVE_PASSWORD", "infected"),
        ),
        cape_api_url=_validate_url(
            "THREATTRACE_CAPE_API_URL",
            _get_env("THREATTRACE_CAPE_API_URL", "http://127.0.0.1:8080/apiv2"),
        ),
        cape_api_token=os.environ.get("THREATTRACE_CAPE_API_TOKEN") or None,
        cape_machine=_validate_nonempty(
            "THREATTRACE_CAPE_MACHINE",
            _get_env("THREATTRACE_CAPE_MACHINE", "cape-x86"),
        ),
        cape_machine_x86=_validate_nonempty(
            "THREATTRACE_CAPE_MACHINE_X86",
            _get_env("THREATTRACE_CAPE_MACHINE_X86", "cape-x86"),
        ),
        cape_machine_x64=_validate_nonempty(
            "THREATTRACE_CAPE_MACHINE_X64",
            _get_env("THREATTRACE_CAPE_MACHINE_X64", "cape-x64"),
        ),
        cape_platform=_validate_nonempty(
            "THREATTRACE_CAPE_PLATFORM",
            _get_env("THREATTRACE_CAPE_PLATFORM", "windows"),
        ),
        cape_tags=_validate_nonempty(
            "THREATTRACE_CAPE_TAGS",
            _get_env("THREATTRACE_CAPE_TAGS", "x86"),
        ),
        cape_tags_x86=_validate_nonempty(
            "THREATTRACE_CAPE_TAGS_X86",
            _get_env("THREATTRACE_CAPE_TAGS_X86", "x86"),
        ),
        cape_tags_x64=_validate_nonempty(
            "THREATTRACE_CAPE_TAGS_X64",
            _get_env("THREATTRACE_CAPE_TAGS_X64", "x64"),
        ),
        cape_timeout_seconds=_validate_positive_int(
            "THREATTRACE_CAPE_TIMEOUT_SECONDS",
            int(_get_env("THREATTRACE_CAPE_TIMEOUT_SECONDS", "300")),
        ),
        cape_submit_package=os.environ.get("THREATTRACE_CAPE_SUBMIT_PACKAGE") or None,
        cape_submit_options=os.environ.get("THREATTRACE_CAPE_SUBMIT_OPTIONS") or None,
        cape_submit_priority=_validate_positive_int(
            "THREATTRACE_CAPE_SUBMIT_PRIORITY",
            int(_get_env("THREATTRACE_CAPE_SUBMIT_PRIORITY", "1")),
            minimum=0,
        ),
        cape_submit_custom=os.environ.get("THREATTRACE_CAPE_SUBMIT_CUSTOM") or None,
        cape_submit_route=os.environ.get("THREATTRACE_CAPE_SUBMIT_ROUTE") or None,
        cape_submit_clock=os.environ.get("THREATTRACE_CAPE_SUBMIT_CLOCK") or None,
        cape_submit_memory=_parse_bool_env(
            "THREATTRACE_CAPE_SUBMIT_MEMORY",
            False,
        ),
        cape_poll_interval_seconds=_validate_positive_int(
            "THREATTRACE_CAPE_POLL_INTERVAL_SECONDS",
            int(_get_env("THREATTRACE_CAPE_POLL_INTERVAL_SECONDS", "60")),
        ),
        cape_poll_running_interval_seconds=_validate_positive_int(
            "THREATTRACE_CAPE_POLL_RUNNING_INTERVAL_SECONDS",
            int(_get_env("THREATTRACE_CAPE_POLL_RUNNING_INTERVAL_SECONDS", "45")),
        ),
        cape_poll_max_interval_seconds=_validate_positive_int(
            "THREATTRACE_CAPE_POLL_MAX_INTERVAL_SECONDS",
            int(_get_env("THREATTRACE_CAPE_POLL_MAX_INTERVAL_SECONDS", "300")),
        ),
        cape_max_wait_seconds=_validate_positive_int(
            "THREATTRACE_CAPE_MAX_WAIT_SECONDS",
            int(_get_env("THREATTRACE_CAPE_MAX_WAIT_SECONDS", "54000000")),
        ),
        daily_batch_size=_validate_positive_int(
            "THREATTRACE_DAILY_BATCH_SIZE",
            int(_get_env("THREATTRACE_DAILY_BATCH_SIZE", "500")),
        ),
        celery_task_soft_timeout=_validate_positive_int(
            "THREATTRACE_CELERY_TASK_SOFT_TIMEOUT",
            min(
                int(_get_env("THREATTRACE_CELERY_TASK_SOFT_TIMEOUT", "1800")),
                int(_get_env("THREATTRACE_CELERY_TASK_HARD_TIMEOUT", "3600")) - 1,
            ),
        ),
        celery_task_hard_timeout=_validate_positive_int(
            "THREATTRACE_CELERY_TASK_HARD_TIMEOUT",
            int(_get_env("THREATTRACE_CELERY_TASK_HARD_TIMEOUT", "3600")),
        ),
        pipeline_requeue_delay_seconds=_validate_positive_int(
            "THREATTRACE_PIPELINE_REQUEUE_DELAY_SECONDS",
            int(_get_env("THREATTRACE_PIPELINE_REQUEUE_DELAY_SECONDS", "60")),
        ),
        pipeline_max_retries=_validate_positive_int(
            "THREATTRACE_PIPELINE_MAX_RETRIES",
            int(_get_env("THREATTRACE_PIPELINE_MAX_RETRIES", "48")),
        ),
        report_validation_enabled=_parse_bool_env(
            "THREATTRACE_REPORT_VALIDATION_ENABLED",
            True,
        ),
        ioc_enrichment_enabled=_parse_bool_env(
            "THREATTRACE_IOC_ENRICHMENT_ENABLED",
            True,
        ),
        cape_storage_path=_validate_path(
            Path(_get_env("THREATTRACE_CAPE_STORAGE_PATH", str(storage_root / "cape_storage")))
        ),
        cape_verify_ssl=_parse_bool_env(
            "THREATTRACE_CAPE_VERIFY_SSL",
            False,
        ),
        log_level=_validate_log_level(_get_env("THREATTRACE_LOG_LEVEL", "INFO")),
        vr_x64_host=_validate_nonempty(
            "THREATTRACE_VR_X64_HOST",
            _get_env("THREATTRACE_VR_X64_HOST", "127.0.0.1"),
        ),
        vr_x64_user=_validate_nonempty(
            "THREATTRACE_VR_X64_USER",
            _get_env("THREATTRACE_VR_X64_USER", "Administrator"),
        ),
        vr_x64_password=os.environ.get("THREATTRACE_VR_X64_PASSWORD") or None,
        vr_x86_host=_validate_nonempty(
            "THREATTRACE_VR_X86_HOST",
            _get_env("THREATTRACE_VR_X86_HOST", "127.0.0.1"),
        ),
        vr_x86_user=_validate_nonempty(
            "THREATTRACE_VR_X86_USER",
            _get_env("THREATTRACE_VR_X86_USER", "Administrator"),
        ),
        vr_x86_password=os.environ.get("THREATTRACE_VR_X86_PASSWORD") or None,
        vr_validation_snapshot=_validate_nonempty(
            "THREATTRACE_VR_VALIDATION_SNAPSHOT",
            _get_env("THREATTRACE_VR_VALIDATION_SNAPSHOT", "baseline-snapshot"),
        ),
        vr_staging_bind_host=_validate_nonempty(
            "THREATTRACE_VR_STAGING_BIND_HOST",
            _get_env("THREATTRACE_VR_STAGING_BIND_HOST", "127.0.0.1"),
        ),
        vr_velociraptor_config=Path(
            _get_env("THREATTRACE_VR_VELOCIRAPTOR_CONFIG", "/etc/velociraptor/server.config.yaml")
        ),
        vr_velociraptor_use_sudo=_parse_bool_env(
            "THREATTRACE_VR_VELOCIRAPTOR_USE_SUDO",
            False,
        ),
        vr_velociraptor_api_config=(
            Path(os.environ["THREATTRACE_VR_VELOCIRAPTOR_API_CONFIG"])
            if os.environ.get("THREATTRACE_VR_VELOCIRAPTOR_API_CONFIG")
            else None
        ),
        vr_libvirt_uri=_validate_nonempty(
            "THREATTRACE_VR_LIBVIRT_URI",
            _get_env("THREATTRACE_VR_LIBVIRT_URI", "qemu:///system"),
        ),
        vr_wait_seconds_default=_validate_positive_int(
            "THREATTRACE_VR_WAIT_SECONDS_DEFAULT",
            int(_get_env("THREATTRACE_VR_WAIT_SECONDS_DEFAULT", "900")),
        ),
        vr_http_port_min=_validate_positive_int(
            "THREATTRACE_VR_HTTP_PORT_MIN",
            int(_get_env("THREATTRACE_VR_HTTP_PORT_MIN", "18000")),
        ),
        vr_http_port_max=_validate_positive_int(
            "THREATTRACE_VR_HTTP_PORT_MAX",
            int(_get_env("THREATTRACE_VR_HTTP_PORT_MAX", "18999")),
        ),
        vr_cape_binary_fallback=Path(
            _get_env("THREATTRACE_VR_CAPE_BINARY_FALLBACK", str(storage_root / "cape_storage" / "binaries"))
        ),

    )

def validate_runtime_configuration() -> None:
    """
    Import-time runtime validation for critical deployment safety.
    """
    settings = get_settings()

    if settings.celery_task_soft_timeout >= settings.celery_task_hard_timeout:
        raise ValueError(
            "Celery soft timeout must be lower than hard timeout"
        )

    if settings.cape_poll_interval_seconds >= settings.cape_max_wait_seconds:
        raise ValueError(
            "CAPE poll interval must be lower than max wait time"
        )
    if settings.cape_poll_running_interval_seconds >= settings.cape_max_wait_seconds:
        raise ValueError(
            "CAPE running poll interval must be lower than max wait time"
        )
    if settings.cape_poll_max_interval_seconds >= settings.cape_max_wait_seconds:
        raise ValueError(
            "CAPE max poll interval must be lower than max wait time"
        )
    if settings.cape_poll_interval_seconds > settings.cape_poll_max_interval_seconds:
        raise ValueError(
            "CAPE base poll interval must be lower than or equal to max poll interval"
        )
    if settings.cape_poll_running_interval_seconds > settings.cape_poll_max_interval_seconds:
        raise ValueError(
            "CAPE running poll interval must be lower than or equal to max poll interval"
        )
