from __future__ import annotations
from pydantic import BaseModel

class PowChallengeOut(BaseModel):
    action: str
    salt_hex: str
    target_bits: int
    issued_at_ms: int
