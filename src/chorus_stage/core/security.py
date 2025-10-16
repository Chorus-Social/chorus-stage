"""Signature utilities (Ed25519).

All functions are deterministic and side-effect free.
"""
from __future__ import annotations
from typing import Optional
import hashlib
import binascii
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

def verify_signature(pubkey_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verify an Ed25519 signature.

    Parameters
    ----------
    pubkey_hex : str
        Hex-encoded 32-byte public key.
    message : bytes
        The exact bytes that were signed on the client.
    signature_hex : str
        Hex-encoded 64-byte signature.

    Returns
    -------
    bool
        True if the signature is valid for `message` under `pubkey_hex`.

    Edge cases
    ----------
    - Reject non-hex or wrong length inputs.
    - Treat exceptions as verification failure.
    """
    try:
        pubkey = VerifyKey(binascii.unhexlify(pubkey_hex))
        signature = binascii.unhexlify(signature_hex)
        pubkey.verify(message, signature)
        return True
    except Exception:
        return False

def hash_key(user_key: str) -> str:
    return hashlib.sha256(user_key.encode("utf-8")).hexdigest()