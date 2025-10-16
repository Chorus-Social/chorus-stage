"""Schemas supporting moderation actions."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ModerationVoteIn(BaseModel):
    """Payload for casting a moderation vote."""

    choice: int = Field(..., description="1 marks harmful, 0 marks not harmful.")
