
"""Common utilities for threattrace."""

from .json_config import config_path, load_json_config
from .logging import get_logger

__all__ = [
    "config_path",
    "get_logger",
    "load_json_config",
]
