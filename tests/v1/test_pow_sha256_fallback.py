"""Tests for SHA-256 fallback in proof-of-work implementation."""

import hashlib
from unittest.mock import patch

import pytest

from chorus_stage.core import pow as core_pow
from chorus_stage.services.pow import PowService
from chorus_stage.utils.pow_client import (
    compute_payload_digest,
    compute_pow_hash,
    count_leading_zero_bits,
    get_available_hash_algorithms,
    get_preferred_hash_algorithm,
)


class TestSHA256Fallback:
    """Test SHA-256 fallback functionality."""

    def test_validate_solution_sha256(self):
        """Test that validate_solution works with SHA-256."""
        salt_bytes = b"test_salt"
        payload_digest = hashlib.sha256(b"test_payload").digest()
        nonce = 12345
        target_bits = 8  # Low difficulty for testing
        
        # Test SHA-256
        result = core_pow.validate_solution(
            salt_bytes, payload_digest, nonce, target_bits, "sha256"
        )
        assert isinstance(result, bool)
        
        # Test Blake3 (if available)
        result_blake3 = core_pow.validate_solution(
            salt_bytes, payload_digest, nonce, target_bits, "blake3"
        )
        assert isinstance(result_blake3, bool)

    def test_pow_service_sha256(self):
        """Test that PowService works with SHA-256."""
        pow_service = PowService()
        
        # Test with SHA-256
        result = pow_service.verify_pow(
            "post",
            "test_pubkey",
            "12345",
            hash_algorithm="sha256"
        )
        # Should return False for invalid nonce, but not raise exception
        assert isinstance(result, bool)

    def test_payload_digest_sha256(self):
        """Test payload digest computation with SHA-256."""
        digest = compute_payload_digest(
            "post", "test_pubkey", "test_challenge", "sha256"
        )
        assert len(digest) == 32  # SHA-256 produces 32 bytes
        assert isinstance(digest, bytes)

    def test_pow_hash_sha256(self):
        """Test PoW hash computation with SHA-256."""
        salt_bytes = b"test_salt"
        payload_digest = hashlib.sha256(b"test_payload").digest()
        nonce = 12345
        
        hash_result = compute_pow_hash(salt_bytes, payload_digest, nonce, "sha256")
        assert len(hash_result) == 32
        assert isinstance(hash_result, bytes)

    def test_count_leading_zero_bits(self):
        """Test leading zero bit counting."""
        # Test with all zeros
        all_zeros = b"\x00" * 4
        assert count_leading_zero_bits(all_zeros) == 32
        
        # Test with some zeros
        some_zeros = b"\x00\x00\x01\x02"
        assert count_leading_zero_bits(some_zeros) == 16
        
        # Test with no leading zeros
        no_zeros = b"\x01\x02\x03\x04"
        assert count_leading_zero_bits(no_zeros) == 0

    def test_available_algorithms(self):
        """Test getting available hash algorithms."""
        algorithms = get_available_hash_algorithms()
        assert "sha256" in algorithms
        assert len(algorithms) >= 1
        assert all(alg in ["blake3", "sha256"] for alg in algorithms)

    def test_preferred_algorithm(self):
        """Test getting preferred hash algorithm."""
        preferred = get_preferred_hash_algorithm()
        assert preferred in ["blake3", "sha256"]

    @patch('chorus_stage.utils.pow_client.BLAKE3_AVAILABLE', False)
    def test_blake3_unavailable_fallback(self):
        """Test behavior when Blake3 is not available."""
        # Should raise error when trying to use Blake3
        with pytest.raises(ValueError, match="Blake3 is not available"):
            compute_payload_digest("post", "test", "challenge", "blake3")
        
        # SHA-256 should still work
        digest = compute_payload_digest("post", "test", "challenge", "sha256")
        assert len(digest) == 32

    def test_algorithm_compatibility(self):
        """Test that both algorithms produce valid results."""
        action = "post"
        pubkey_hex = "test_pubkey"
        challenge_str = "test_challenge"
        
        # Test SHA-256
        sha256_digest = compute_payload_digest(
            action, pubkey_hex, challenge_str, "sha256"
        )
        assert len(sha256_digest) == 32
        
        # Test Blake3 (if available)
        try:
            blake3_digest = compute_payload_digest(
                action, pubkey_hex, challenge_str, "blake3"
            )
            assert len(blake3_digest) == 32
        except ValueError:
            # Blake3 not available, which is expected in some environments
            pass

    def test_digest_size_validation(self):
        """Test that digest size validation works correctly."""
        # Test with correct size (32 bytes)
        salt_bytes = b"test_salt"
        payload_digest = b"\x00" * 32  # 32 bytes
        nonce = 12345
        target_bits = 8
        
        result = core_pow.validate_solution(
            salt_bytes, payload_digest, nonce, target_bits, "sha256"
        )
        assert isinstance(result, bool)
        
        # Test with incorrect size
        wrong_size_digest = b"\x00" * 16  # 16 bytes (wrong size)
        result_wrong = core_pow.validate_solution(
            salt_bytes, wrong_size_digest, nonce, target_bits, "sha256"
        )
        assert result_wrong is False
