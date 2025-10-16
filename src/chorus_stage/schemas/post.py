"""Schemas representing posts in the API layer."""
from __future__ import annotations

from pydantic import BaseModel, Field


class PostCreate(BaseModel):
    """Payload submitted by clients to create a post."""

    body_md: str = Field(..., min_length=1, max_length=4000)
    proof_nonce: int
    proof_payload_sha256_hex: str
    signature_hex: str
    author_pubkey_hex: str


class PostOut(BaseModel):
    """Representation of a post returned to callers."""

    id: int
    # Order index is used for deterministic feed sorting.
    order_index: int
    body_md: str
    author_pubkey_hex: str
