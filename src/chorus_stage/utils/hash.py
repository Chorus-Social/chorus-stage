# src/chorus_stage/utils/hash.py
"""Hashing helpers providing a safe BLAKE3 interface with fallbacks."""

from __future__ import annotations

import hashlib
import os
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, cast


class _Blake3Like(Protocol):
    """Protocol capturing the subset of the BLAKE3 API we rely on."""

    def digest(self) -> bytes: ...

    def hexdigest(self) -> str: ...


Blake3Factory = Callable[[bytes], _Blake3Like]

if TYPE_CHECKING:  # pragma: no cover - typing helper
    from blake3 import blake3 as _blake3_type  # noqa: F401

try:  # pragma: no cover - optional dependency path
    from blake3 import blake3 as _blake3_constructor
except Exception:  # pragma: no cover - runtime fallback
    _blake3: Blake3Factory | None = None
else:
    _blake3 = cast(Blake3Factory, _blake3_constructor)

_RUNNING_ON_PY314 = sys.version_info[:2] == (3, 14)


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


def blake3_factory() -> Blake3Factory:
    """Return a callable that mimics the BLAKE3 constructor.

    The compiled `blake3` wheel segfaults on some Python 3.14 builds, so we
    gracefully degrade to a blake2s-based shim whenever the import fails.
    """

    if (
        _blake3 is not None
        and os.getenv("PYTEST_RUNNING", "").lower() != "true"
        and not _RUNNING_ON_PY314
    ):
        return _blake3
    return _hash_fallback


def blake3_digest(data: bytes) -> bytes:
    """Return the byte digest of the supplied data."""
    return blake3_factory()(data).digest()


def blake3_hexdigest(data: bytes) -> str:
    """Return the hexadecimal digest of the supplied data."""
    return blake3_factory()(data).hexdigest()
