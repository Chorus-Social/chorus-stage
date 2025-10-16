"""Proof-of-Work helpers.

This module defines small puzzle challenges to throttle spammy actions.

Contracts are designed LeetCode-style for incremental implementation.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Literal, Tuple
import os, time, hashlib

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

def generate_challenge(action: Action, target_bits: int | None = None) -> PowChallenge:
    """Generate a new PoW challenge for `action`.

    Parameters
    ----------
    action : Action
        The action type.
    target_bits : int | None
        Override default difficulty for testing.

    Returns
    -------
    PowChallenge
        Challenge parameters to send to the client.

    Notes
    -----
    - Salt must be unguessable.
    - Do not store server state here; we validate later with a replay cache.
    """
    salt = os.urandom(16)
    tb = target_bits if target_bits is not None else 16
    return PowChallenge(action=action, salt=salt, target_bits=tb, issued_at_ms=int(time.time()*1000))

def validate_solution(challenge: PowChallenge, payload_digest: bytes, nonce: int) -> bool:
    """Validate a proposed PoW solution.

    Contract
    --------
    Inputs:
        - challenge: previously issued challenge
        - payload_digest: SHA-256 digest of the canonical request payload (32 bytes)
        - nonce: unsigned integer chosen by the client

    Output:
        - bool: True if sha256(salt | payload_digest | nonce_le64) has at least
                `challenge.target_bits` leading zero bits.

    Edge cases:
        - payload_digest must be 32 bytes
        - target_bits > 256 is invalid
        - nonce can be 0

    Complexity goal:
        - O(1) verification time, no loops beyond the single hash.
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
