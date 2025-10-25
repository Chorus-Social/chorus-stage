# tests/v1/test_simple_utils.py
"""Simple unit tests that don't require database setup."""

import pytest

from chorus_stage.utils.pow_client import compute_payload_digest, compute_pow_hash


class TestSimpleUtils:
    """Test simple utility functions without database dependencies."""

    def test_compute_payload_digest_sha256(self):
        """Test payload digest computation with SHA-256."""
        result = compute_payload_digest("test_action", "test_pubkey", "test_challenge", "sha256")
        
        assert isinstance(result, bytes)
        assert len(result) == 32
        assert result.hex() == "bac6fbf144cfebe5a6cd62a64298889b926f99089fa01cfb800a174dd603bb25"

    def test_compute_payload_digest_blake3(self):
        """Test payload digest computation with BLAKE3."""
        result = compute_payload_digest("test_action", "test_pubkey", "test_challenge", "blake3")
        
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_compute_payload_digest_unsupported_algorithm(self):
        """Test payload digest computation with unsupported algorithm."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            compute_payload_digest("test", "test", "test", "md5")

    def test_compute_pow_hash_sha256(self):
        """Test PoW hash computation with SHA-256."""
        result = compute_pow_hash(b"test_salt_32_bytes_long", b"test_payload_digest_32", 12345, "sha256")
        
        assert isinstance(result, bytes)
        assert len(result) == 32
        assert result.hex() == "b26000d0e28f242b888fb91f2e159240c89c0b06961ebbe3056e56b0c64ee269"

    def test_compute_pow_hash_blake3(self):
        """Test PoW hash computation with BLAKE3."""
        result = compute_pow_hash(b"test_salt_32_bytes_long", b"test_payload_digest_32", 12345, "blake3")
        
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_compute_pow_hash_unsupported_algorithm(self):
        """Test PoW hash computation with unsupported algorithm."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            compute_pow_hash(b"test", b"test", 123, "md5")

    def test_deterministic_results(self):
        """Test that functions produce deterministic results."""
        result1 = compute_payload_digest("test", "test", "test", "sha256")
        result2 = compute_payload_digest("test", "test", "test", "sha256")
        assert result1 == result2
        
        result3 = compute_pow_hash(b"test", b"test", 123, "sha256")
        result4 = compute_pow_hash(b"test", b"test", 123, "sha256")
        assert result3 == result4

    def test_different_inputs_produce_different_results(self):
        """Test that different inputs produce different results."""
        base_result = compute_payload_digest("test", "test", "test", "sha256")
        
        # Different action
        result1 = compute_payload_digest("different", "test", "test", "sha256")
        assert result1 != base_result
        
        # Different pubkey
        result2 = compute_payload_digest("test", "different", "test", "sha256")
        assert result2 != base_result
        
        # Different challenge
        result3 = compute_payload_digest("test", "test", "different", "sha256")
        assert result3 != base_result
