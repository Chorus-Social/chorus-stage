"""PoW endpoints.

These endpoints are intentionally simple. State like replay caches or rate-limits
can be layered in later.
"""
from __future__ import annotations
from fastapi import APIRouter
import binascii
from chorus_stage.schemas.pow import PowChallengeOut
from chorus_stage.services.pow_service import issue_challenge, Action

router = APIRouter()

@router.get("/challenge", response_model=PowChallengeOut)
async def get_challenge(action: Action = "post", target_bits: int = 16) -> PowChallengeOut:
    ch = issue_challenge(action, target_bits)
    return PowChallengeOut(
        action=ch.action,
        salt_hex=binascii.hexlify(ch.salt).decode(),
        target_bits=ch.target_bits,
        issued_at_ms=ch.issued_at_ms,
    )
