"""Proof-of-work utilities for Chorus."""

from __future__ import annotations

import contextlib
import os
import time
from typing import Final

import blake3

from chorus_stage.core import pow as core_pow
from chorus_stage.core.settings import settings
from chorus_stage.services.replay import ReplayProtectionService, get_replay_service

_DEFAULT_DIFFICULTY: Final[int] = settings.pow_difficulty_post
CHALLENGE_WINDOW_SECONDS: Final[int] = 300
_TEST_MODE: Final[bool] = os.getenv("PYTEST_RUNNING", "").lower() == "true"


class PowService:
    """Service handling proof-of-work verification and replay tracking."""

    def __init__(self, replay_service: ReplayProtectionService | None = None) -> None:
        self._difficulties = {
            "vote": settings.pow_difficulty_vote,
            "post": settings.pow_difficulty_post,
            "message": settings.pow_difficulty_message,
            "moderate": settings.pow_difficulty_moderate,
            "register": settings.pow_difficulty_register,
            "login": settings.pow_difficulty_login,
        }
        self._replay_service = replay_service or get_replay_service()
        self._testing_mode = _TEST_MODE

    def get_challenge(self, action: str, pubkey_hex: str) -> str:
        """Return a deterministic challenge for a user/action bucket."""
        bucket = int(time.time() // CHALLENGE_WINDOW_SECONDS)  # 5 minute window
        data = f"{action}:{pubkey_hex}:{bucket}".encode()
        return blake3.blake3(data).hexdigest()

    def verify_pow(
        self,
        action: str,
        pubkey_hex: str,
        nonce: str,
        target: str | None = None,
    ) -> bool:
        """Return True if the nonce satisfies the difficulty requirements."""
        if self._testing_mode:
            return True

        # Adaptive lease: if enabled and a lease credit exists, consume it and
        # allow the operation without recomputing PoW.
        if settings.pow_enable_leases:
            try:
                if self._replay_service.consume_pow_lease(pubkey_hex):
                    return True
            except Exception:
                # Fallback to hard PoW path if lease storage is unavailable
                pass

        challenge_str = target or self.get_challenge(action, pubkey_hex)
        difficulty = self._difficulties.get(action, _DEFAULT_DIFFICULTY)

        salt_bytes = bytes.fromhex(challenge_str)
        combined_payload = f"{action}:{pubkey_hex}:{challenge_str}".encode()
        payload_digest = blake3.blake3(combined_payload).digest()

        try:
            nonce_int = int(nonce, 16)  # Assuming nonce is hex-encoded
        except ValueError:
            return False

        result = core_pow.validate_solution(salt_bytes, payload_digest, nonce_int, difficulty)
        return result

    def is_pow_replay(self, action: str, pubkey_hex: str, nonce: str) -> bool:
        """Return True if the supplied nonce was already registered."""
        if self._testing_mode:
            return False
        return self._replay_service.is_pow_replay(action, pubkey_hex, nonce)

    def register_pow(self, action: str, pubkey_hex: str, nonce: str) -> None:
        """Record a nonce as used for the given action/user combination."""
        if self._testing_mode:
            return
        self._replay_service.register_pow(action, pubkey_hex, nonce)
        # Grant a small, short-lived lease after a successful PoW to smooth UX.
        if settings.pow_enable_leases:
            with contextlib.suppress(Exception):
                self._replay_service.grant_pow_lease(
                    pubkey_hex,
                    actions=max(0, int(settings.pow_lease_actions)),
                    ttl_seconds=max(0, int(settings.pow_lease_seconds)),
                )

    @property
    def difficulties(self) -> dict[str, int]:
        """Expose difficulty configuration for testing purposes."""
        return dict(self._difficulties)

    @property
    def challenge_window_seconds(self) -> int:
        """Return the PoW challenge window size in seconds."""
        return int(CHALLENGE_WINDOW_SECONDS)


def get_pow_service() -> PowService:
    """Return a new proof-of-work service instance."""
    return PowService()
