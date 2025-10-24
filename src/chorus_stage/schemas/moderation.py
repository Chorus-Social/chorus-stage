# src/chorus_stage/schemas/moderation.py
"""Moderation-related Pydantic schemas."""


from pydantic import BaseModel, Field


class ModerationAction(BaseModel):
    """Schema for triggering moderation actions."""

    post_id: int
    is_harmful: bool = Field(..., description="True if post is harmful")
    pow_token: str = Field(..., description="Proof of work token")

class ModerationCaseResponse(BaseModel):
    """Schema for moderation case information returned by the API."""

    post_id: int
    community_id: int | None
    state: int
    opened_order_index: int
    closed_order_index: int | None
    # Additional moderation metadata could be added here
