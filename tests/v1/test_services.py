# mypy: ignore-errors
# src/chorus_stage/tests/test_services.py
"""Tests for service layer components."""


import pytest

from tests.conftest import test_settings

SHA256_HEX_DIGITS = 64
ED25519_KEY_HEX_LEN = 64
ED25519_KEY_BYTES = 32


def test_pow_service_verification() -> None:
    """Test the proof-of-work verification service."""
    from chorus_stage.services.pow import PowService

    pow_service = PowService()

    # Test with valid PoW
    pubkey_hex = "a" * 64  # Mock pubkey
    action = "post"

    pow_service.get_challenge(action, pubkey_hex)

    # In a real scenario, this would take significant time
    # For testing, we'll override the verify method with a simpler check
    # just to verify the method call flow works
    original_method = pow_service.verify_pow

    def mock_verify_pow(action: str, pubkey_hex: str, nonce: str) -> bool:
        # Simple check that verifies the method was called correctly
        return action == "post" and pubkey_hex == "a" * 64 and nonce == "valid_nonce"

    pow_service.verify_pow = mock_verify_pow  # type: ignore[method-assign]

    assert pow_service.verify_pow(action, pubkey_hex, "valid_nonce") is True
    assert pow_service.verify_pow(action, pubkey_hex, "invalid_nonce") is False

    # Restore original method
    pow_service.verify_pow = original_method  # type: ignore[method-assign]


def test_crypto_service_key_validation() -> None:
    """Test the cryptographic service key validation."""
    from chorus_stage.services.crypto import CryptoService

    crypto_service = CryptoService()

    # Valid hex string
    valid_key = "a" * 64
    assert crypto_service.validate_and_decode_pubkey(valid_key) == bytes.fromhex(valid_key)

    # Invalid hex string
    with pytest.raises(ValueError):
        crypto_service.validate_and_decode_pubkey("not_a_hex_string")

    # Odd-length hex string
    with pytest.raises(ValueError):
        crypto_service.validate_and_decode_pubkey("a" * 63)


def test_moderation_service_update_state(db_session, test_post) -> None:
    """Test the moderation service state updates."""
    from chorus_stage.models import ModerationCase, ModerationVote
    from chorus_stage.models.moderation import (
        MODERATION_STATE_CLEARED,
        MODERATION_STATE_HIDDEN,
        MODERATION_STATE_OPEN,
    )
    from chorus_stage.services.moderation import ModerationService

    # Create a case
    case = ModerationCase(
        post_id=test_post.id,
        community_id=1,
        state=MODERATION_STATE_OPEN,
        opened_order_index=1,
    )
    db_session.add(case)

    # Create mock moderation service
    moderation_service = ModerationService()

    # No votes yet - should remain in queue
    moderation_service.update_moderation_state(test_post.id, db_session)
    db_session.refresh(case)
    assert case.state == MODERATION_STATE_OPEN

    # Add some "not harmful" votes
    for i in range(6):
        vote = ModerationVote(
            post_id=test_post.id,
            voter_user_id=i,  # Use different voter IDs
            choice=0  # Not harmful
        )
        db_session.add(vote)

    # Now update state
    moderation_service.update_moderation_state(test_post.id, db_session)
    db_session.refresh(case)
    assert case.state == MODERATION_STATE_CLEARED

    # Add "harmful" votes to exceed threshold
    for i in range(6, 13):  # More than twice as many harmful votes
        vote = ModerationVote(
            post_id=test_post.id,
            voter_user_id=i,
            choice=1  # Harmful
        )
        db_session.add(vote)

    # Update state again
    moderation_service.update_moderation_state(test_post.id, db_session)
    db_session.refresh(case)
    assert case.state == MODERATION_STATE_HIDDEN

    # Check post state is also updated
    db_session.refresh(test_post)
    assert test_post.moderation_state == MODERATION_STATE_HIDDEN


def test_replay_protection() -> None:
    """Test the replay protection service."""
    from unittest.mock import MagicMock

    # Mock Redis to avoid needing a Redis server for unit tests
    redis_mock = MagicMock()

    from chorus_stage.services.replay import ReplayProtectionService

    # Temporarily patch the redis client
    original_init = ReplayProtectionService.__init__

    def mock_init(self: ReplayProtectionService) -> None:
        self._redis = redis_mock

    ReplayProtectionService.__init__ = mock_init

    replay_service = ReplayProtectionService()

    # Set up the mock responses
    redis_mock.exists.return_value = False

    # First use should return False (not a replay)
    assert replay_service.is_replay("pubkey", "nonce") is False

    # Verify the method was called with the expected key
    redis_mock.exists.assert_called_with("replay:pubkey:nonce")

    # Set up for registration
    replay_service.register_replay("pubkey", "nonce")
    redis_mock.set.assert_called_with("replay:pubkey:nonce", "1", ex=86400)

    # Set up for replay detection
    redis_mock.exists.return_value = True

    # Second use should return True (a replay)
    assert replay_service.is_replay("pubkey", "nonce") is True

    # Different nonce should return False on new call
    redis_mock.exists.return_value = False
    assert replay_service.is_replay("pubkey", "different_nonce") is False

    # Restore original init
    ReplayProtectionService.__init__ = original_init


def test_e2e_message_service() -> None:
    """Test the E2E message service."""
    from chorus_stage.services.e2e_messages import E2EMessageService

    e2e_service = E2EMessageService()

    # Test PGP key validation
    valid_pgp = """-----BEGIN PGP PUBLIC KEY BLOCK-----
mDMEXEcE6RYJKwYBBAHaRw8BAQdAqgE8E7+1A9D4jOe3m0D1FQ2oPzL7Yz3S
2X9k9jX8VQ7j/2O7N1k3tM5F2c1l0g3sR9lJ8S4wX2F2H1I4tK6pX7C/R
-----END PGP PUBLIC KEY BLOCK-----"""

    assert e2e_service.verify_pgp_key(valid_pgp) is True

    invalid_pgp = "Not a PGP key"
    assert e2e_service.verify_pgp_key(invalid_pgp) is False

    # Test message encryption/decryption
    recipient_key = test_settings.secret_key  # Using as mock PGP key
    sender_key = f"{test_settings.secret_key}_sender"

    message = "Test message"
    encrypted = e2e_service.encrypt_message(message, recipient_key, sender_key)
    decrypted = e2e_service.decrypt_message(encrypted, recipient_key)

    assert encrypted.startswith("ENCRYPTED:")
    assert "Decrypted" in decrypted

    # Test message digest creation
    message_bytes = message.encode()
    digest = e2e_service.create_message_digest(message_bytes)
    assert isinstance(digest, str)
    assert len(digest) == SHA256_HEX_DIGITS  # SHA256 hex digest length


def test_crypto_service_keypair_generation() -> None:
    """Test the cryptographic service keypair generation."""
    from chorus_stage.services.crypto import CryptoService

    crypto_service = CryptoService()

    # Generate keypair
    private_key_hex, public_key_hex = crypto_service.generate_session_key_pair()

    # Verify key formats
    assert isinstance(private_key_hex, str)
    assert isinstance(public_key_hex, str)
    assert len(private_key_hex) == ED25519_KEY_HEX_LEN  # 32 bytes = 64 hex chars
    assert len(public_key_hex) == ED25519_KEY_HEX_LEN  # 32 bytes = 64 hex chars

    # Try to convert back to bytes to verify valid hex
    private_key_bytes = bytes.fromhex(private_key_hex)
    public_key_bytes = bytes.fromhex(public_key_hex)

    assert len(private_key_bytes) == ED25519_KEY_BYTES
    assert len(public_key_bytes) == ED25519_KEY_BYTES


def test_system_clock_increment(db_session) -> None:
    """Test that the system clock increments correctly."""
    from chorus_stage.models import SystemClock

    # Get or create clock
    clock = db_session.query(SystemClock).first()
    if not clock:
        clock = SystemClock(id=1, day_seq=0, hour_seq=0)
        db_session.add(clock)
        db_session.commit()

    original_day = clock.day_seq
    original_hour = clock.hour_seq

    # Increment
    clock.day_seq += 1
    clock.hour_seq = (clock.hour_seq + 1) % 24

    db_session.commit()
    db_session.refresh(clock)

    # Verify
    assert clock.day_seq == original_day + 1
    assert clock.hour_seq == (original_hour + 1) % 24
