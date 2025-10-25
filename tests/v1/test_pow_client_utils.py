# tests/v1/test_pow_client_utils.py
"""Tests for PoW client utility functions."""

import hashlib
from unittest.mock import patch

import pytest

from chorus_stage.utils.pow_client import (
    compute_payload_digest,
    compute_pow_hash,
    find_pow_solution,
)


class TestComputePayloadDigest:
    """Test the compute_payload_digest function."""

    def test_compute_payload_digest_blake3(self):
        """Test payload digest computation with BLAKE3."""
        action = "test_action"
        pubkey_hex = "test_pubkey_hex"
        challenge_str = "test_challenge"
        
        result = compute_payload_digest(action, pubkey_hex, challenge_str, "blake3")
        
        # Should return bytes
        assert isinstance(result, bytes)
        assert len(result) == 32  # BLAKE3 produces 32-byte digest

    def test_compute_payload_digest_sha256(self):
        """Test payload digest computation with SHA-256."""
        action = "test_action"
        pubkey_hex = "test_pubkey_hex"
        challenge_str = "test_challenge"
        
        result = compute_payload_digest(action, pubkey_hex, challenge_str, "sha256")
        
        # Should return bytes
        assert isinstance(result, bytes)
        assert len(result) == 32  # SHA-256 produces 32-byte digest

    def test_compute_payload_digest_unsupported_algorithm(self):
        """Test payload digest computation with unsupported algorithm."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            compute_payload_digest("test", "test", "test", "md5")

    def test_compute_payload_digest_blake3_unavailable(self):
        """Test payload digest computation when BLAKE3 is unavailable."""
        with patch('chorus_stage.utils.pow_client.BLAKE3_AVAILABLE', False):
            with pytest.raises(ValueError, match="Blake3 is not available"):
                compute_payload_digest("test", "test", "test", "blake3")

    def test_compute_payload_digest_deterministic(self):
        """Test that payload digest computation is deterministic."""
        action = "test_action"
        pubkey_hex = "test_pubkey_hex"
        challenge_str = "test_challenge"
        
        result1 = compute_payload_digest(action, pubkey_hex, challenge_str, "sha256")
        result2 = compute_payload_digest(action, pubkey_hex, challenge_str, "sha256")
        
        assert result1 == result2

    def test_compute_payload_digest_different_inputs(self):
        """Test that different inputs produce different digests."""
        base_action = "test_action"
        base_pubkey = "test_pubkey_hex"
        base_challenge = "test_challenge"
        
        base_result = compute_payload_digest(base_action, base_pubkey, base_challenge, "sha256")
        
        # Different action
        result1 = compute_payload_digest("different_action", base_pubkey, base_challenge, "sha256")
        assert result1 != base_result
        
        # Different pubkey
        result2 = compute_payload_digest(base_action, "different_pubkey", base_challenge, "sha256")
        assert result2 != base_result
        
        # Different challenge
        result3 = compute_payload_digest(base_action, base_pubkey, "different_challenge", "sha256")
        assert result3 != base_result


class TestComputePowHash:
    """Test the compute_pow_hash function."""

    def test_compute_pow_hash_blake3(self):
        """Test PoW hash computation with BLAKE3."""
        salt_bytes = b"test_salt_32_bytes_long"
        payload_digest = b"test_payload_digest_32"
        nonce = 12345
        
        result = compute_pow_hash(salt_bytes, payload_digest, nonce, "blake3")
        
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_compute_pow_hash_sha256(self):
        """Test PoW hash computation with SHA-256."""
        salt_bytes = b"test_salt_32_bytes_long"
        payload_digest = b"test_payload_digest_32"
        nonce = 12345
        
        result = compute_pow_hash(salt_bytes, payload_digest, nonce, "sha256")
        
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_compute_pow_hash_unsupported_algorithm(self):
        """Test PoW hash computation with unsupported algorithm."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            compute_pow_hash(b"test", b"test", 123, "md5")

    def test_compute_pow_hash_blake3_unavailable(self):
        """Test PoW hash computation when BLAKE3 is unavailable."""
        with patch('chorus_stage.utils.pow_client.BLAKE3_AVAILABLE', False):
            with pytest.raises(ValueError, match="Blake3 is not available"):
                compute_pow_hash(b"test", b"test", 123, "blake3")

    def test_compute_pow_hash_deterministic(self):
        """Test that PoW hash computation is deterministic."""
        salt_bytes = b"test_salt_32_bytes_long"
        payload_digest = b"test_payload_digest_32"
        nonce = 12345
        
        result1 = compute_pow_hash(salt_bytes, payload_digest, nonce, "sha256")
        result2 = compute_pow_hash(salt_bytes, payload_digest, nonce, "sha256")
        
        assert result1 == result2

    def test_compute_pow_hash_different_nonce(self):
        """Test that different nonces produce different hashes."""
        salt_bytes = b"test_salt_32_bytes_long"
        payload_digest = b"test_payload_digest_32"
        
        result1 = compute_pow_hash(salt_bytes, payload_digest, 12345, "sha256")
        result2 = compute_pow_hash(salt_bytes, payload_digest, 54321, "sha256")
        
        assert result1 != result2


class TestFindPowSolution:
    """Test the find_pow_solution function."""

    def test_find_pow_solution_success(self):
        """Test successful PoW solution finding."""
        action = "test_action"
        pubkey_hex = "test_pubkey_hex"
        challenge_str = "test_challenge"
        target_bits = 4  # Low difficulty for testing
        hash_algorithm = "sha256"
        max_attempts = 1000
        
        nonce, success = find_pow_solution(
            action, pubkey_hex, challenge_str, target_bits, hash_algorithm, max_attempts
        )
        
        assert success is True
        assert isinstance(nonce, int)
        assert nonce >= 0

    def test_find_pow_solution_high_difficulty(self):
        """Test PoW solution finding with high difficulty (should fail)."""
        action = "test_action"
        pubkey_hex = "test_pubkey_hex"
        challenge_str = "test_challenge"
        target_bits = 32  # Very high difficulty
        hash_algorithm = "sha256"
        max_attempts = 100  # Low max attempts
        
        nonce, success = find_pow_solution(
            action, pubkey_hex, challenge_str, target_bits, hash_algorithm, max_attempts
        )
        
        assert success is False
        assert isinstance(nonce, int)

    def test_find_pow_solution_blake3(self):
        """Test PoW solution finding with BLAKE3."""
        action = "test_action"
        pubkey_hex = "test_pubkey_hex"
        challenge_str = "test_challenge"
        target_bits = 4
        hash_algorithm = "blake3"
        max_attempts = 1000
        
        nonce, success = find_pow_solution(
            action, pubkey_hex, challenge_str, target_bits, hash_algorithm, max_attempts
        )
        
        assert success is True
        assert isinstance(nonce, int)

    def test_find_pow_solution_unsupported_algorithm(self):
        """Test PoW solution finding with unsupported algorithm."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            find_pow_solution("test", "test", "test", 4, "md5", 100)

    def test_find_pow_solution_blake3_unavailable(self):
        """Test PoW solution finding when BLAKE3 is unavailable."""
        with patch('chorus_stage.utils.pow_client.BLAKE3_AVAILABLE', False):
            with pytest.raises(ValueError, match="Blake3 is not available"):
                find_pow_solution("test", "test", "test", 4, "blake3", 100)

    def test_find_pow_solution_zero_max_attempts(self):
        """Test PoW solution finding with zero max attempts."""
        action = "test_action"
        pubkey_hex = "test_pubkey_hex"
        challenge_str = "test_challenge"
        target_bits = 4
        hash_algorithm = "sha256"
        max_attempts = 0
        
        nonce, success = find_pow_solution(
            action, pubkey_hex, challenge_str, target_bits, hash_algorithm, max_attempts
        )
        
        assert success is False
        assert nonce == 0

    def test_find_pow_solution_verification(self):
        """Test that found PoW solution actually satisfies the difficulty requirement."""
        action = "test_action"
        pubkey_hex = "test_pubkey_hex"
        challenge_str = "test_challenge"
        target_bits = 8
        hash_algorithm = "sha256"
        max_attempts = 10000
        
        nonce, success = find_pow_solution(
            action, pubkey_hex, challenge_str, target_bits, hash_algorithm, max_attempts
        )
        
        if success:
            # Verify the solution
            payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, hash_algorithm)
            pow_hash = compute_pow_hash(payload_digest, payload_digest, nonce, hash_algorithm)
            
            # Count leading zero bits
            leading_zeros = 0
            for byte in pow_hash:
                if byte == 0:
                    leading_zeros += 8
                else:
                    leading_zeros += bin(byte)[2:].zfill(8).index('1')
                    break
            
            assert leading_zeros >= target_bits

    def test_find_pow_solution_different_inputs(self):
        """Test that different inputs produce different solutions."""
        base_action = "test_action"
        base_pubkey = "test_pubkey_hex"
        base_challenge = "test_challenge"
        target_bits = 4
        hash_algorithm = "sha256"
        max_attempts = 1000
        
        base_nonce, base_success = find_pow_solution(
            base_action, base_pubkey, base_challenge, target_bits, hash_algorithm, max_attempts
        )
        
        # Different action should produce different nonce
        nonce1, success1 = find_pow_solution(
            "different_action", base_pubkey, base_challenge, target_bits, hash_algorithm, max_attempts
        )
        if base_success and success1:
            assert base_nonce != nonce1

    def test_find_pow_solution_consistency(self):
        """Test that the same inputs produce the same solution."""
        action = "test_action"
        pubkey_hex = "test_pubkey_hex"
        challenge_str = "test_challenge"
        target_bits = 4
        hash_algorithm = "sha256"
        max_attempts = 1000
        
        nonce1, success1 = find_pow_solution(
            action, pubkey_hex, challenge_str, target_bits, hash_algorithm, max_attempts
        )
        nonce2, success2 = find_pow_solution(
            action, pubkey_hex, challenge_str, target_bits, hash_algorithm, max_attempts
        )
        
        # Results should be consistent
        assert success1 == success2
        if success1:
            assert nonce1 == nonce2
