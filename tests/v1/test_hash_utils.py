# mypy: ignore-errors
"""Tests for hashing utilities."""

from __future__ import annotations

from chorus_stage.utils import hash as hash_utils

DIGEST_LENGTH = 32
HEX_DIGEST_LENGTH = 64


def test_blake3_digest_default_path() -> None:
    """Ensure the default digest produces 32 bytes."""
    digest = hash_utils.blake3_digest(b"default")
    assert isinstance(digest, bytes)
    assert len(digest) == DIGEST_LENGTH


def test_blake3_digest_fallback(monkeypatch) -> None:
    """Ensure the fallback path still returns a 32-byte digest."""
    monkeypatch.setattr(hash_utils, "_blake3", None)
    digest = hash_utils.blake3_digest(b"fallback")
    assert isinstance(digest, bytes)
    assert len(digest) == DIGEST_LENGTH


def test_blake3_hexdigest(monkeypatch) -> None:
    """Ensure hex digests return 64-character strings."""
    monkeypatch.setattr(hash_utils, "_blake3", None)
    hexdigest = hash_utils.blake3_hexdigest(b"hex")
    assert isinstance(hexdigest, str)
    assert len(hexdigest) == HEX_DIGEST_LENGTH
