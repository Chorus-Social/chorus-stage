"""Proof-of-Work helpers.

This module defines small puzzle challenges to throttle spammy actions.

Contracts are designed LeetCode-style for incremental implementation.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Literal

Action = Literal["post", "vote", "read"]

@dataclass(frozen=True)
class PowChallenge:
    """A PoW challenge envelope.

    Attributes
    ----------
    action : Action
        The action being protected (post, vote, read).
    salt : bytes
        Server-provided random salt.
    target_bits : int
        Number of leading zero bits required in the hash.
    issued_at_ms : int
        Milliseconds since epoch when the challenge was issued.
    """
    action: Action
    salt: bytes
    target_bits: int
    issued_at_ms: int

    @property
    def salt_hex(self) -> str:
        """Return the salt encoded as hexadecimal."""
        return self.salt.hex()

def generate_challenge(action: Action, target_bits: int | None = None) -> PowChallenge:
    """Generate a new proof-of-work challenge for an action.

    Args:
        action: The action the challenge will protect.
        target_bits: Optional override for the default difficulty.

    Returns:
        Challenge parameters that can be sent to the client.

    Notes:
        Salts must remain unguessable and this helper stays stateless; replay tracking
        can be implemented in higher layers.
    """
    salt = os.urandom(16)
    tb = target_bits if target_bits is not None else 16
    return PowChallenge(action=action, salt=salt, target_bits=tb, issued_at_ms=int(time.time()*1000))

def validate_solution(challenge: PowChallenge, payload_digest: bytes, nonce: int) -> bool:
    """Validate a proposed proof-of-work solution.

    Args:
        challenge: Previously issued challenge instance.
        payload_digest: SHA-256 digest of the canonical request payload (32 bytes).
        nonce: Unsigned integer chosen by the client.

    Returns:
        True if `sha256(salt | payload_digest | nonce_le64)` has at least
        `challenge.target_bits` leading zero bits; False otherwise.
    """
    if len(payload_digest) != 32:
        return False
    if not (0 <= challenge.target_bits <= 256):
        return False

    nonce_bytes = nonce.to_bytes(8, "little", signed=False)
    h = hashlib.sha256(challenge.salt + payload_digest + nonce_bytes).digest()

    # Count leading zero bits
    zeros = 0
    for byte in h:
        if byte == 0:
            zeros += 8
            continue
        # Count bits in first non-zero byte
        for bit in range(7, -1, -1):
            if (byte >> bit) & 1 == 0:
                zeros += 1
            else:
                break
        break
    return zeros >= challenge.target_bits
