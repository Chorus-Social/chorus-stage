"""Shared Pydantic schemas for common API elements."""
from __future__ import annotations

from pydantic import BaseModel, Field


class Cursor(BaseModel):
    """Opaque pagination cursor returned by list endpoints."""

    after: str = Field(..., description="Opaque cursor token for pagination.")
