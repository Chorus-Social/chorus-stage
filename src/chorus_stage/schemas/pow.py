"""Schemas related to proof-of-work challenges."""
from __future__ import annotations

from pydantic import BaseModel


class PowChallengeOut(BaseModel):
    """API response payload for issuing a proof-of-work challenge."""

    action: str
    salt_hex: str
    target_bits: int
    issued_at_ms: int
