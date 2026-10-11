from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def write_json(path: Path, payload: Any, *, default: Any = json_default) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=default) + "\n", encoding="utf-8")


def print_json(payload: Any, *, default: Any = json_default) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=default))


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return default


def read_json_dict(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    fallback = {} if default is None else dict(default)
    payload = read_json(path, fallback)
    return payload if isinstance(payload, dict) else ({} if default is None else dict(default))


def parse_json_object(text: str | None) -> dict[str, Any] | None:
    """Parse a JSON object, tolerating non-JSON text around one object."""
    raw = (text or "").strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        start, end = raw.find("{"), raw.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            payload = json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            return None
    return payload if isinstance(payload, dict) else None
