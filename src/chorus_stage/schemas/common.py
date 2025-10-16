"""Pydantic schemas for request/response models."""
from __future__ import annotations
from pydantic import BaseModel, Field

class Cursor(BaseModel):
    after: str = Field(..., description="Opaque cursor token for pagination.")
