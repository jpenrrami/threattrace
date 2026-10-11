"""
Workers module.

Exposes Celery app for distributed execution.
Avoids importing execution logic to prevent circular dependencies.
"""

from .celery_app import celery_app

__all__ = [
    "celery_app",
]