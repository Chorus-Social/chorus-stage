"""High-level signing workflows used by the API layer."""
from __future__ import annotations

from chorus_stage.core.security import verify_signature


def verify_request_signature(pubkey_hex: str, payload_bytes: bytes, signature_hex: str) -> bool:
    """Validate that a request signature matches the payload under a public key.

    Args:
        pubkey_hex: Hex-encoded public key provided by the client.
        payload_bytes: Canonical payload bytes that were allegedly signed.
        signature_hex: Hex-encoded signature to verify.

    Returns:
        True if the signature is valid for the given payload and key; False otherwise.
    """
    return verify_signature(pubkey_hex, payload_bytes, signature_hex)
