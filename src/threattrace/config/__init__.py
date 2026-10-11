"""Configuration module for threattrace.

Provides centralized access to application settings.
"""

from .settings import Settings, get_settings

__all__ = [
    "Settings",
    "get_settings",
]
