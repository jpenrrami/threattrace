from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "***"
SECRET_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "auth_key",
    "authorization",
    "password",
    "secret",
    "token",
)

_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?key|auth[_-]?key|secret)\s*[:=]\s*([^\s,;]+)"
)
_AUTH_HEADER_RE = re.compile(r"(?i)\b(authorization:\s*(?:bearer|token)\s+)([^\s,;]+)")


def is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in SECRET_KEY_FRAGMENTS)


def redact_text(value: str) -> str:
    redacted = _ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}={REDACTED}", value)
    return _AUTH_HEADER_RE.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)


def redact_secrets(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: REDACTED if is_secret_key(str(key)) and item not in (None, "") else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
