"""Service helpers for issuing and validating proof-of-work challenges."""
from __future__ import annotations

import binascii
from typing import Literal

from chorus_stage.core.pow import PowChallenge, generate_challenge, validate_solution

Action = Literal["post", "vote", "read"]

__all__ = ["Action", "issue_challenge", "is_solution_valid"]


def issue_challenge(action: Action, target_bits: int) -> PowChallenge:
    """Create a proof-of-work challenge envelope for clients.

    Args:
        action: The domain-specific action being guarded.
        target_bits: Difficulty expressed as the count of leading zero bits required.

    Returns:
        A `PowChallenge` that can be sent to clients.

    Notes:
        This function is intentionally stateless; replay tracking belongs in the API layer.
    """
    return generate_challenge(action, target_bits=target_bits)


def is_solution_valid(challenge: PowChallenge, payload_sha256_hex: str, nonce: int) -> bool:
    """Validate a proof-of-work solution.

    Args:
        challenge: The challenge instance originally issued to the client.
        payload_sha256_hex: Hex-encoded SHA-256 digest of the canonical request payload.
        nonce: Nonce chosen by the client.

    Returns:
        True if the solution meets the difficulty requirements; False otherwise.
    """
    try:
        digest = binascii.unhexlify(payload_sha256_hex)
    except binascii.Error:
        return False
    return validate_solution(challenge, digest, nonce)
