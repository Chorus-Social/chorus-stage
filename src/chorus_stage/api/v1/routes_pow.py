"""Proof-of-work API endpoints.

This module exposes a minimal interface for issuing proof-of-work challenges
to clients. The implementation intentionally stays lightweight; additional
concerns such as replay tracking or rate limiting can be layered on elsewhere
in the stack.
"""
from __future__ import annotations

from fastapi import APIRouter

from chorus_stage.schemas.pow import PowChallengeOut
from chorus_stage.services.pow_service import Action, issue_challenge

router = APIRouter()


DEFAULT_ACTION: Action = "post"
DEFAULT_TARGET_BITS: int = 16


@router.get("/challenge", response_model=PowChallengeOut)
async def get_challenge(
    action: Action = DEFAULT_ACTION, target_bits: int = DEFAULT_TARGET_BITS
) -> PowChallengeOut:
    """Issue a proof-of-work challenge for a client to solve.

    Args:
        action: The domain-specific action the proof-of-work guards.
        target_bits: Difficulty expressed as the target number of leading zero bits.

    Returns:
        A `PowChallengeOut` payload that can be returned directly by FastAPI.
    """
    challenge = issue_challenge(action, target_bits)
    return PowChallengeOut(
        action=challenge.action,
        # Encode the random salt as hex to keep the response JSON friendly.
        salt_hex=challenge.salt.hex(),
        target_bits=challenge.target_bits,
        issued_at_ms=challenge.issued_at_ms,
    )
