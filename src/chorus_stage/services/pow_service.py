"""PoW issuance and validation service."""
from __future__ import annotations
import binascii, hashlib
from typing import Literal
from chorus.core.pow import PowChallenge, generate_challenge, validate_solution

Action = Literal["post", "vote", "read"]

def issue_challenge(action: Action, target_bits: int) -> PowChallenge:
    """Create a PoW challenge envelope for clients.

    This is a pure function; storing replay protections belongs at the API layer.
    """
    return generate_challenge(action, target_bits=target_bits)

def is_solution_valid(challenge: PowChallenge, payload_sha256_hex: str, nonce: int) -> bool:
    """Return True if solution is valid for given challenge and payload digest (hex)."""
    try:
        digest = binascii.unhexlify(payload_sha256_hex)
    except binascii.Error:
        return False
    return validate_solution(challenge, digest, nonce)
