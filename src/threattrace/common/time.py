from __future__ import annotations

from datetime import UTC, datetime


def utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def parse_optional_datetime(value: str | int | float | datetime | None) -> datetime | None:
    if value is None:
        return None

    # Already a datetime
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    # Epoch (seconds or milliseconds)
    if isinstance(value, (int, float)):
        try:
            # Heuristic: milliseconds if very large
            ts = float(value)
            if ts > 1e12:
                ts = ts / 1000.0
            return datetime.fromtimestamp(ts, UTC)
        except Exception:
            return None

    # String parsing
    if not isinstance(value, str):
        return None

    candidate = value.strip()
    if not candidate:
        return None

    # Normalize Zulu suffix
    candidate = candidate.replace("Z", "+00:00")

    parsers = (
        datetime.fromisoformat,
        lambda raw: datetime.strptime(raw, "%Y-%m-%d %H:%M:%S"),
        lambda raw: datetime.strptime(raw, "%Y/%m/%d %H:%M:%S"),
        lambda raw: datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S"),
    )

    for parser in parsers:
        try:
            parsed = parser(candidate)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        except (TypeError, ValueError, OverflowError):  # nosec B112: expected parser fallback
            continue

    return None
