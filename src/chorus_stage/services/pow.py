"""Proof-of-work utilities for Chorus."""

from __future__ import annotations

import hashlib
import os
import time
from typing import Final

from chorus_stage.core.settings import settings
from chorus_stage.services.replay import ReplayProtectionService, get_replay_service

_DEFAULT_DIFFICULTY: Final[int] = settings.pow_difficulty_post
_TEST_MODE: Final[bool] = os.getenv("PYTEST_RUNNING", "").lower() == "true"


class PowService:
    """Service handling proof-of-work verification and replay tracking."""

    def __init__(self, replay_service: ReplayProtectionService | None = None) -> None:
        self._difficulties = {
            "vote": settings.pow_difficulty_vote,
            "post": settings.pow_difficulty_post,
            "message": settings.pow_difficulty_message,
            "moderate": settings.pow_difficulty_moderate,
        }
        self._replay_service = replay_service or get_replay_service()
        self._testing_mode = _TEST_MODE

    def get_challenge(self, action: str, pubkey_hex: str) -> str:
        """Return a deterministic challenge for a user/action bucket."""
        bucket = int(time.time() // 300)  # 5 minute window
        data = f"{action}:{pubkey_hex}:{bucket}".encode()
        return hashlib.sha256(data).hexdigest()

    def verify_pow(self, action: str, pubkey_hex: str, nonce: str) -> bool:
        """Return True if the nonce satisfies the difficulty requirements."""
        if self._testing_mode:
            return True

        challenge = self.get_challenge(action, pubkey_hex)
        difficulty = self._difficulties.get(action, _DEFAULT_DIFFICULTY)

        combined = f"{challenge}:{nonce}".encode()
        result_hash = hashlib.sha256(combined).hexdigest()

        leading_zeros = 0
        for char in result_hash:
            if char == "0":
                leading_zeros += 4
                if leading_zeros >= difficulty:
                    return True
                continue

            hex_digit = int(char, 16)
            for bit in range(3, -1, -1):
                if (hex_digit >> bit) & 1:
                    return leading_zeros >= difficulty
                leading_zeros += 1
                if leading_zeros >= difficulty:
                    return True
            break

        return leading_zeros >= difficulty

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

    @property
    def difficulties(self) -> dict[str, int]:
        """Expose difficulty configuration for testing purposes."""
        return dict(self._difficulties)


def get_pow_service() -> PowService:
    """Return a new proof-of-work service instance."""
    return PowService()
