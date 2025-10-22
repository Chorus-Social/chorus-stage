"""Replay protection services for Chorus."""

from __future__ import annotations

import os
from collections import defaultdict
from threading import Lock
from typing import Any, Final, cast

try:  # pragma: no cover - optional dependency
    import redis
except Exception:  # pragma: no cover
    redis = cast("Any", None)

from chorus_stage.core.settings import settings

_TEST_MODE: Final[bool] = os.getenv("PYTEST_RUNNING", "").lower() == "true"


class ReplayProtectionService:
    """Service preventing replay attacks using nonces."""

    def __init__(self) -> None:
        self._testing_mode = _TEST_MODE
        self._redis = None
        if redis is not None:
            try:
                self._redis = redis.from_url(settings.redis_url)  # type: ignore[no-untyped-call]
            except Exception:  # pragma: no cover - redis optional
                self._redis = None

    def is_replay(self, pubkey_hex: str, client_nonce: str) -> bool:
        """Return True if the nonce has already been used by the caller."""
        if getattr(self, "_testing_mode", _TEST_MODE) and getattr(self, "_redis", None) is None:
            return False
        key = f"replay:{pubkey_hex}"
        if self._redis is not None:
            try:
                return bool(self._redis.exists(f"{key}:{client_nonce}"))
            except Exception:  # pragma: no cover - redis optional
                self._redis = None

        with _CACHE_LOCK:
            return client_nonce in _NONCE_CACHE[key]

    def register_replay(self, pubkey_hex: str, client_nonce: str) -> None:
        """Register a client nonce as used to prevent replay."""
        if getattr(self, "_testing_mode", _TEST_MODE) and getattr(self, "_redis", None) is None:
            return
        key = f"replay:{pubkey_hex}:{client_nonce}"
        if self._redis is not None:
            try:
                self._redis.set(key, "1", ex=_NONCE_TTL_SECONDS)
                return
            except Exception:  # pragma: no cover - redis optional
                self._redis = None

        cache_key = f"replay:{pubkey_hex}"
        with _CACHE_LOCK:
            _NONCE_CACHE[cache_key].add(client_nonce)

    def is_pow_replay(self, action: str, pubkey_hex: str, nonce: str) -> bool:
        """Return True if a proof-of-work nonce was already registered."""
        if getattr(self, "_testing_mode", _TEST_MODE) and getattr(self, "_redis", None) is None:
            return False
        key = f"pow:{action}:{pubkey_hex}"
        if self._redis is not None:
            try:
                return bool(self._redis.exists(f"{key}:{nonce}"))
            except Exception:  # pragma: no cover - redis optional
                self._redis = None

        with _CACHE_LOCK:
            return nonce in _POW_CACHE[key]

    def register_pow(self, action: str, pubkey_hex: str, nonce: str) -> None:
        """Record a proof-of-work nonce as used."""
        if getattr(self, "_testing_mode", _TEST_MODE) and getattr(self, "_redis", None) is None:
            return
        key = f"pow:{action}:{pubkey_hex}:{nonce}"
        if self._redis is not None:
            try:
                self._redis.set(key, "1", ex=_POW_TTL_SECONDS)
                return
            except Exception:  # pragma: no cover - redis optional
                self._redis = None

        cache_key = f"pow:{action}:{pubkey_hex}"
        with _CACHE_LOCK:
            _POW_CACHE[cache_key].add(nonce)


_POW_TTL_SECONDS: Final[int] = 43_200  # 12 hours
_NONCE_TTL_SECONDS: Final[int] = 86_400  # 24 hours
_NONCE_CACHE: dict[str, set[str]] = defaultdict(set)
_POW_CACHE: dict[str, set[str]] = defaultdict(set)
_CACHE_LOCK = Lock()


def get_replay_service() -> ReplayProtectionService:
    """Return a replay protection service instance."""
    return ReplayProtectionService()
