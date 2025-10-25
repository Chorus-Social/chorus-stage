"""Proof-of-Work helpers.

This module defines small puzzle challenges to throttle spammy actions.

Contracts are designed LeetCode-style for incremental implementation.
"""
from __future__ import annotations

import hashlib
from typing import Literal

import blake3

Action = Literal["post", "vote", "read", "register"]
DEFAULT_TARGET_BITS = 16
BLAKE3_DIGEST_BYTES = 32
SHA256_DIGEST_BYTES = 32
MAX_TARGET_BITS = 256
NONCE_SIZE_BYTES = 8
MILLISECONDS_PER_SECOND = 1000

def validate_solution(
    salt_bytes: bytes,
    payload_digest: bytes,
    nonce: int,
    target_bits: int,
    hash_algorithm: str = "blake3",
) -> bool:
    """Validate a proposed proof-of-work solution.

    Args:
        salt_bytes: Server-provided random salt or deterministic challenge identifier.
        payload_digest: Hash digest of the canonical request payload (32 bytes).
        nonce: Unsigned integer chosen by the client.
        target_bits: Number of leading zero bits required in the hash.
        hash_algorithm: Hash algorithm to use ("blake3" or "sha256").

    Returns:
        True if the hash of `salt_bytes | payload_digest | nonce_le64` has at least
        `target_bits` leading zero bits; False otherwise.
    """
    expected_digest_size = (
        BLAKE3_DIGEST_BYTES if hash_algorithm == "blake3" else SHA256_DIGEST_BYTES
    )
    if len(payload_digest) != expected_digest_size:
        return False
    if not (0 <= target_bits <= MAX_TARGET_BITS):
        return False

    nonce_bytes = nonce.to_bytes(NONCE_SIZE_BYTES, "little", signed=False)
    input_bytes = bytearray()
    input_bytes.extend(salt_bytes)
    input_bytes.extend(payload_digest)
    input_bytes.extend(nonce_bytes)

    # Use the specified hash algorithm
    if hash_algorithm == "sha256":
        h = hashlib.sha256(bytes(input_bytes)).digest()
    else:  # Default to blake3
        h = blake3(bytes(input_bytes)).digest()

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
                break # Found first non-zero bit
        break # Exit outer loop after processing the first non-zero byte
    return zeros >= target_bits
