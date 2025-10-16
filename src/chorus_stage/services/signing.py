"""High-level signing workflows.

These wrap `core.security` for API-layer use.
"""
from __future__ import annotations
from chorus.core.security import verify_signature

def verify_request_signature(pubkey_hex: str, payload_bytes: bytes, signature_hex: str) -> bool:
    """Return True if the request `signature_hex` is valid for `payload_bytes` under `pubkey_hex`."""
    return verify_signature(pubkey_hex, payload_bytes, signature_hex)
