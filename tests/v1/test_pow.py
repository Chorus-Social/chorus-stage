# tests/v1/test_pow.py
"""Tests for Proof-of-Work utilities."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import blake3

import pytest

from chorus_stage.core import pow as core_pow
from chorus_stage.core.settings import settings
from chorus_stage.services.pow import PowService


@pytest.fixture
def mock_replay_service():
    """Mock ReplayProtectionService for PowService."""
    mock = MagicMock()
    mock.is_pow_replay.return_value = False
    mock.consume_pow_lease.return_value = False
    return mock


@pytest.fixture
def pow_service(mock_replay_service):
    """PowService instance with mocked replay service."""
    pow_service = PowService(replay_service=mock_replay_service)
    pow_service._testing_mode = False  # Ensure replay service is called in tests
    return pow_service



def test_core_pow_validate_solution_valid():
    """Test core_pow.validate_solution with a valid solution."""
    # This is a simplified test; a real PoW solution would be found by a client
    salt_bytes = bytes.fromhex("1" * 64)  # Use non-null bytes
    target_bits = 1
    payload_digest = b"\x01" * 32  # Example non-null digest

    # Find a nonce that satisfies the difficulty
    found_nonce = -1
    for i in range(100000):  # Iterate to find a valid nonce
        if core_pow.validate_solution(salt_bytes, payload_digest, i, target_bits):
            found_nonce = i
            break
    assert found_nonce != -1, "Failed to find a valid nonce for the test"

    assert core_pow.validate_solution(salt_bytes, payload_digest, found_nonce, target_bits)


def test_core_pow_validate_solution_invalid_nonce():
    """Test core_pow.validate_solution with an invalid nonce."""
    salt_bytes = bytes.fromhex("1" * 64)  # Use non-null bytes
    target_bits = 1
    payload_digest = b"\x01" * 32
    nonce = 12345  # An arbitrary invalid nonce

    assert not core_pow.validate_solution(salt_bytes, payload_digest, nonce, target_bits)


def test_core_pow_validate_solution_insufficient_zeros():
    """Test core_pow.validate_solution with insufficient leading zeros."""
    salt_bytes = bytes.fromhex("1" * 64)  # Use non-null bytes
    target_bits = 256  # Very high difficulty
    payload_digest = b"\x01" * 32
    nonce = 0

    assert not core_pow.validate_solution(salt_bytes, payload_digest, nonce, target_bits)


def test_core_pow_validate_solution_incorrect_payload_digest_length():
    """Test core_pow.validate_solution with incorrect payload digest length."""
    salt_bytes = bytes.fromhex("1" * 64)  # Use non-null bytes
    target_bits = 1
    payload_digest = b"short"  # Incorrect length
    nonce = 0

    assert not core_pow.validate_solution(salt_bytes, payload_digest, nonce, target_bits)


def test_pow_service_get_challenge(pow_service):
    """Test PowService.get_challenge."""
    action = "register"
    pubkey_hex = "a" * 64
    challenge1 = pow_service.get_challenge(action, pubkey_hex)
    challenge2 = pow_service.get_challenge(action, pubkey_hex)
    assert challenge1 == challenge2  # Should be deterministic within window

    # Simulate time passing to change the bucket
    original_challenge_window = pow_service.challenge_window_seconds
    # Temporarily modify the constant for testing purposes
    # This is a bit hacky, but necessary to test the time-based bucket change
    # In a real scenario, you might mock time.time()
    import chorus_stage.services.pow as services_pow
    services_pow.CHALLENGE_WINDOW_SECONDS = 1  # Temporarily reduce window
    time.sleep(1.1)
    challenge3 = pow_service.get_challenge(action, pubkey_hex)
    assert challenge1 != challenge3
    services_pow.CHALLENGE_WINDOW_SECONDS = original_challenge_window  # Restore


def test_pow_service_verify_pow_valid(pow_service):
    """Test PowService.verify_pow with a valid solution."""
    settings.pow_difficulty_register = 1  # Set low difficulty for testing
    action = "register"
    pubkey_hex = "b" * 64
    challenge_str = pow_service.get_challenge(action, pubkey_hex)

    # Find a nonce that satisfies the difficulty
    found_nonce_hex = ""
    for i in range(1_000_000):
        nonce_hex = hex(i)[2:]
        if pow_service.verify_pow(action, pubkey_hex, nonce_hex, challenge_str):
            found_nonce_hex = nonce_hex
            break
    assert found_nonce_hex != "", "Failed to find a valid nonce for PowService test"

    assert pow_service.verify_pow(action, pubkey_hex, found_nonce_hex, challenge_str)


def test_pow_service_verify_pow_invalid_nonce(pow_service):
    """Test PowService.verify_pow with an invalid nonce."""
    settings.pow_difficulty_register = 1
    action = "register"
    pubkey_hex = "c" * 64
    challenge_str = pow_service.get_challenge(action, pubkey_hex)
    invalid_nonce_hex = "deadbeef"
    assert not pow_service.verify_pow(action, pubkey_hex, invalid_nonce_hex, challenge_str)


def test_pow_service_verify_pow_insufficient_difficulty(pow_service):
    """Test PowService.verify_pow with insufficient difficulty."""
    settings.pow_difficulty_register = 256  # Very high difficulty
    action = "register"
    pubkey_hex = "d" * 64
    challenge_str = pow_service.get_challenge(action, pubkey_hex)
    nonce_hex = "0"  # Unlikely to meet high difficulty
    assert not pow_service.verify_pow(action, pubkey_hex, nonce_hex, challenge_str)


def test_pow_service_is_pow_replay(pow_service, mock_replay_service):
    """Test PowService.is_pow_replay."""
    action = "register"
    pubkey_hex = "e" * 64
    nonce_hex = "123"
    mock_replay_service.is_pow_replay.return_value = True
    assert pow_service.is_pow_replay(action, pubkey_hex, nonce_hex)
    mock_replay_service.is_pow_replay.assert_called_once_with(action, pubkey_hex, nonce_hex)


def test_pow_service_register_pow(pow_service, mock_replay_service):
    """Test PowService.register_pow."""
    action = "register"
    pubkey_hex = "f" * 64
    nonce_hex = "456"
    pow_service.register_pow(action, pubkey_hex, nonce_hex)
    mock_replay_service.register_pow.assert_called_once_with(action, pubkey_hex, nonce_hex)
    mock_replay_service.grant_pow_lease.assert_called_once()
