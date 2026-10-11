from __future__ import annotations

import json
from typing import Any


def coerce_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def coerce_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def dedupe_strings_lower_sorted(values: list[str]) -> list[str]:
    return sorted({value.strip().lower() for value in values if value and isinstance(value, str)})


def dedupe_strings_lower_preserve(values: list[str]) -> list[str]:
    return dedupe_strings_preserve(values, lowercase=True)


def dedupe_strings_preserve(values: list[Any], *, lowercase: bool = True) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = value.strip()
        if lowercase:
            cleaned = cleaned.lower()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result


def dedupe_preserve(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    result: list[Any] = []
    for value in values:
        try:
            marker = json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list)) else str(value)
        except TypeError:
            marker = str(value)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(value)
    return result
