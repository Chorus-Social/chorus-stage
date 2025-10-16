"""PoW endpoints.

These endpoints are intentionally simple. State like replay caches or rate-limits
can be layered in later.
"""
from __future__ import annotations
from fastapi import APIRouter
import binascii
from chorus.schemas.pow import PowChallengeOut
from chorus.services.pow_service import issue_challenge

router = APIRouter()

@router.get("/challenge", response_model=PowChallengeOut)
async def get_challenge(action: str = "post", target_bits: int = 16) -> PowChallengeOut:
    ch = issue_challenge(action, target_bits)
    return PowChallengeOut(action=ch.action, salt_hex=binascii.hexlify(ch.salt).decode(), target_bits=ch.target_bits, issued_at_ms=ch.issued_at_ms)
