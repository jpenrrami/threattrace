"""CAPE integration module.

Provides client utilities to interact with CAPE sandbox:
- Submit samples
- Poll analysis status
- Fetch reports
"""

from .client import CapeClient

__all__ = [
    "CapeClient",
]
