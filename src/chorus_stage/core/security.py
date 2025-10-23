"""Signature utilities built on Ed25519 primitives."""
from __future__ import annotations

import binascii
import hashlib

from nacl.signing import VerifyKey


def verify_signature(pubkey_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verify an Ed25519 signature.

    Args:
        pubkey_hex: Hex-encoded 32-byte public key.
        message: Exact bytes that were signed on the client.
        signature_hex: Hex-encoded 64-byte signature.

    Returns:
        True if the signature is valid for `message` under `pubkey_hex`; False otherwise.
    """
    try:
        pubkey = VerifyKey(binascii.unhexlify(pubkey_hex))
        signature = binascii.unhexlify(signature_hex)
        pubkey.verify(message, signature)
        return True
    except Exception:
        return False


def hash_key(user_key: str) -> str:
    """Return a SHA-256 hash of the provided user key."""
    return hashlib.sha256(user_key.encode("utf-8")).hexdigest()
