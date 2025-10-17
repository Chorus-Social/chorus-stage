# src/chorus_stage/db/time.py
"""Time utilities for database models."""

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(UTC)
