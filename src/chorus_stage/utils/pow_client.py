"""Client-side proof-of-work utilities for web frontends.

This module provides utilities for computing proof-of-work in web browsers,
with automatic fallback from Blake3 to SHA-256 when Blake3 is not available.
"""

from __future__ import annotations

import hashlib
from typing import Literal

try:
    import blake3
    BLAKE3_AVAILABLE = True
except ImportError:
    blake3 = None  # type: ignore
    BLAKE3_AVAILABLE = False

HashAlgorithm = Literal["blake3", "sha256"]


def compute_payload_digest(
    action: str,
    pubkey_hex: str,
    challenge_str: str,
    hash_algorithm: HashAlgorithm = "blake3"
) -> bytes:
    """Compute the payload digest for proof-of-work.

    Args:
        action: The action being performed (e.g., "post", "vote")
        pubkey_hex: Hex-encoded public key
        challenge_str: Challenge string from server
        hash_algorithm: Hash algorithm to use

    Returns:
        Digest bytes (32 bytes for both Blake3 and SHA-256)

    Raises:
        ValueError: If Blake3 is requested but not available
    """
    combined_payload = f"{action}:{pubkey_hex}:{challenge_str}".encode()

    if hash_algorithm == "blake3":
        if not BLAKE3_AVAILABLE or blake3 is None:
            raise ValueError("Blake3 is not available. Use SHA-256 as fallback.")
        return blake3.blake3(combined_payload).digest()
    elif hash_algorithm == "sha256":
        return hashlib.sha256(combined_payload).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")


def compute_pow_hash(
    salt_bytes: bytes,
    payload_digest: bytes,
    nonce: int,
    hash_algorithm: HashAlgorithm = "blake3"
) -> bytes:
    """Compute the final proof-of-work hash.

    Args:
        salt_bytes: Server-provided salt
        payload_digest: Pre-computed payload digest
        nonce: Client-chosen nonce
        hash_algorithm: Hash algorithm to use

    Returns:
        Final hash bytes

    Raises:
        ValueError: If Blake3 is requested but not available
    """
    nonce_bytes = nonce.to_bytes(8, "little", signed=False)
    input_bytes = bytearray()
    input_bytes.extend(salt_bytes)
    input_bytes.extend(payload_digest)
    input_bytes.extend(nonce_bytes)

    if hash_algorithm == "blake3":
        if not BLAKE3_AVAILABLE or blake3 is None:
            raise ValueError("Blake3 is not available. Use SHA-256 as fallback.")
        return blake3.blake3(bytes(input_bytes)).digest()
    elif hash_algorithm == "sha256":
        return hashlib.sha256(bytes(input_bytes)).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")


def count_leading_zero_bits(hash_bytes: bytes) -> int:
    """Count the number of leading zero bits in a hash.

    Args:
        hash_bytes: Hash bytes to analyze

    Returns:
        Number of leading zero bits
    """
    zeros = 0
    for byte in hash_bytes:
        if byte == 0:
            zeros += 8
            continue
        # Count bits in first non-zero byte
        for bit in range(7, -1, -1):
            if (byte >> bit) & 1 == 0:
                zeros += 1
            else:
                break  # Found first non-zero bit
        break  # Exit outer loop after processing the first non-zero byte
    return zeros


def find_pow_solution(
    action: str,
    pubkey_hex: str,
    challenge_str: str,
    target_bits: int,
    hash_algorithm: HashAlgorithm = "blake3",
    max_attempts: int = 1000000,
) -> tuple[int, bool]:
    """Find a proof-of-work solution by brute force.

    Args:
        action: The action being performed
        pubkey_hex: Hex-encoded public key
        challenge_str: Challenge string from server
        target_bits: Required number of leading zero bits
        hash_algorithm: Hash algorithm to use
        max_attempts: Maximum number of attempts before giving up

    Returns:
        Tuple of (nonce, success) where success indicates if a solution was found

    Raises:
        ValueError: If Blake3 is requested but not available
    """
    salt_bytes = bytes.fromhex(challenge_str)
    payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, hash_algorithm)

    for nonce in range(max_attempts):
        hash_result = compute_pow_hash(salt_bytes, payload_digest, nonce, hash_algorithm)
        if count_leading_zero_bits(hash_result) >= target_bits:
            return nonce, True

    return 0, False


def get_available_hash_algorithms() -> list[HashAlgorithm]:
    """Get list of available hash algorithms.

    Returns:
        List of available hash algorithms, with SHA-256 always available
    """
    algorithms: list[HashAlgorithm] = ["sha256"]
    if BLAKE3_AVAILABLE:
        algorithms.insert(0, "blake3")
    return algorithms


def get_preferred_hash_algorithm() -> HashAlgorithm:
    """Get the preferred hash algorithm (Blake3 if available, otherwise SHA-256).

    Returns:
        Preferred hash algorithm
    """
    return "blake3" if BLAKE3_AVAILABLE else "sha256"
