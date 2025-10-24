"""Replay protection services for Chorus."""

from __future__ import annotations

import os
import time
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

    # --- Adaptive PoW lease helpers -------------------------------------------------
    def grant_pow_lease(self, pubkey_hex: str, *, actions: int, ttl_seconds: int) -> None:
        """Grant a short-lived allowance of PoW-free actions for a user.

        Backed by Redis if available; falls back to an in-process cache for tests.
        """
        if actions <= 0 or ttl_seconds <= 0:
            return
        key = f"powlease:{pubkey_hex}"
        if self._redis is not None:
            try:
                # Set value and expiry atomically
                pipe = self._redis.pipeline()
                pipe.set(key, int(actions))
                pipe.expire(key, int(ttl_seconds))
                pipe.execute()
                return
            except Exception:  # pragma: no cover - redis optional
                self._redis = None

        expiry = int(time.time()) + int(ttl_seconds)
        with _CACHE_LOCK:
            _LEASE_CACHE[key] = [int(actions), expiry]

    def consume_pow_lease(self, pubkey_hex: str) -> bool:
        """Consume a single action from a user's PoW lease if available.

        Returns True if a lease exists and was decremented, False otherwise.
        """
        key = f"powlease:{pubkey_hex}"
        if self._redis is not None:
            try:
                # Use DECR to consume atomically; ensure non-negative behavior
                remaining = self._redis.decr(key)
                if remaining is None:
                    return False
                if remaining >= 0:
                    # Key exists and we consumed one
                    return True
                # We over-decremented a non-existing key or it hit negative; reset to 0
                self._redis.set(key, 0)
                return False
            except Exception:  # pragma: no cover - redis optional
                self._redis = None

        now = int(time.time())
        with _CACHE_LOCK:
            entry = _LEASE_CACHE.get(key)
            if not entry:
                return False
            remaining, expiry = entry
            if expiry < now or remaining <= 0:
                _LEASE_CACHE.pop(key, None)
                return False
            entry[0] = remaining - 1
            return True

    # --- Generic cooldown helpers ---------------------------------------------------
    def _is_cooldown(self, key: str) -> bool:
        """Return True if a cooldown key is currently active (exists)."""
        if self._redis is not None:
            try:
                return bool(self._redis.exists(key))
            except Exception:  # pragma: no cover
                self._redis = None
        now = int(time.time())
        with _CACHE_LOCK:
            expiry = _COOLDOWN_CACHE.get(key)
            if expiry is None:
                return False
            if expiry < now:
                _COOLDOWN_CACHE.pop(key, None)
                return False
            return True

    def _set_cooldown(self, key: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        if self._redis is not None:
            try:
                self._redis.set(key, "1", ex=int(ttl_seconds))
                return
            except Exception:  # pragma: no cover
                self._redis = None
        with _CACHE_LOCK:
            _COOLDOWN_CACHE[key] = int(time.time()) + int(ttl_seconds)

    # --- Specific cooldowns ---------------------------------------------------------
    def is_harmful_vote_cooldown_author(self, voter_pubkey_hex: str, author_user_hex: str) -> bool:
        return self._is_cooldown(f"hcool:a:{voter_pubkey_hex}:{author_user_hex}")

    def set_harmful_vote_cooldown_author(
        self, voter_pubkey_hex: str, author_user_hex: str, ttl_seconds: int
    ) -> None:
        self._set_cooldown(f"hcool:a:{voter_pubkey_hex}:{author_user_hex}", ttl_seconds)

    def is_harmful_vote_cooldown_post(self, voter_pubkey_hex: str, post_id: int) -> bool:
        return self._is_cooldown(f"hcool:p:{voter_pubkey_hex}:{post_id}")

    def set_harmful_vote_cooldown_post(
        self, voter_pubkey_hex: str, post_id: int, ttl_seconds: int
    ) -> None:
        self._set_cooldown(f"hcool:p:{voter_pubkey_hex}:{post_id}", ttl_seconds)

    def is_moderation_trigger_cooldown(self, user_hex: str) -> bool:
        return self._is_cooldown(f"modtrig:{user_hex}")

    def set_moderation_trigger_cooldown(self, user_hex: str, ttl_seconds: int) -> None:
        self._set_cooldown(f"modtrig:{user_hex}", ttl_seconds)


_POW_TTL_SECONDS: Final[int] = 43_200  # 12 hours
_NONCE_TTL_SECONDS: Final[int] = 86_400  # 24 hours
_NONCE_CACHE: dict[str, set[str]] = defaultdict(set)
_POW_CACHE: dict[str, set[str]] = defaultdict(set)
_LEASE_CACHE: dict[str, list[int]] = {}
_COOLDOWN_CACHE: dict[str, int] = {}
_CACHE_LOCK = Lock()


def get_replay_service() -> ReplayProtectionService:
    """Return a replay protection service instance."""
    return ReplayProtectionService()
