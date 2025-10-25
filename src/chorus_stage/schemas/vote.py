# src/chorus_stage/schemas/vote.py
"""Vote-related Pydantic schemas."""

from typing import Literal

from pydantic import BaseModel, Field


class VoteCreate(BaseModel):
    """Schema for creating a new vote."""

    post_id: int
    direction: Literal[-1, 1] = Field(..., description="1 for upvote, -1 for downvote")
    pow_nonce: str
    client_nonce: str
    hash_algorithm: str = Field(
        "blake3",
        description="Hash algorithm used for proof of work (blake3 or sha256)",
    )
