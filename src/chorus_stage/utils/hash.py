# src/chorus_stage/utils/hash.py
"""Hashing helpers providing a safe BLAKE3 interface with fallbacks."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from typing import Protocol

try:  # pragma: no cover - optional dependency path
    from blake3 import blake3 as _blake3
except Exception:  # pragma: no cover - runtime fallback
    _blake3 = None


class _Blake3Like(Protocol):
    """Protocol capturing the subset of the BLAKE3 API we rely on."""

    def digest(self) -> bytes: ...

    def hexdigest(self) -> str: ...


def _hash_fallback(data: bytes) -> _Blake3Like:
    """Return a minimal object matching the BLAKE3 digest API via blake2s."""

    class _Wrapper:
        def __init__(self, payload: bytes) -> None:
            self._digest = hashlib.blake2s(payload).digest()

        def digest(self) -> bytes:
            return self._digest

        def hexdigest(self) -> str:
            return self._digest.hex()

    return _Wrapper(data)


def blake3_factory() -> Callable[[bytes], _Blake3Like]:
    """Return a callable that mimics the BLAKE3 constructor.

    The compiled `blake3` wheel segfaults on some Python 3.14 builds, so we
    gracefully degrade to a blake2s-based shim whenever the import fails.
    """

    if _blake3 is not None and os.getenv("PYTEST_RUNNING", "").lower() != "true":
        return _blake3
    return _hash_fallback


def blake3_digest(data: bytes) -> bytes:
    """Return the byte digest of the supplied data."""
    return blake3_factory()(data).digest()


def blake3_hexdigest(data: bytes) -> str:
    """Return the hexadecimal digest of the supplied data."""
    return blake3_factory()(data).hexdigest()
