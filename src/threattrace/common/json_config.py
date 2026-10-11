from __future__ import annotations

import json
import sys
from functools import cache
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def config_path(*parts: str) -> Path:
    relative = Path("config", *parts)
    candidates = (PROJECT_ROOT / relative, Path(sys.prefix) / relative)
    return next((path for path in candidates if path.is_file()), candidates[0])


@cache
def load_json_config(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
