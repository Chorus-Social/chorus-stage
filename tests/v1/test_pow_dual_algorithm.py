"""Test that demonstrates both BLAKE3 and SHA-256 PoW functionality.

This test shows how to request, solve, and respond to the API with both
BLAKE3 and SHA-256 proof-of-work algorithms.
"""

import pytest

from chorus_stage.core import pow as core_pow
from chorus_stage.services.pow import PowService
from chorus_stage.utils.pow_client import (
    compute_payload_digest,
    compute_pow_hash,
    count_leading_zero_bits,
    find_pow_solution,
    get_available_hash_algorithms,
)


class TestDualAlgorithmPoW:
    """Test both BLAKE3 and SHA-256 PoW algorithms."""

    @pytest.fixture
    def pow_service(self):
        """Create a PowService instance for testing."""
        return PowService()

    def test_algorithm_availability(self):
        """Test that both algorithms are available."""
        algorithms = get_available_hash_algorithms()
        assert "sha256" in algorithms, "SHA-256 should always be available"
        assert len(algorithms) >= 1, "At least one algorithm should be available"
        
        # Print available algorithms for debugging
        print(f"Available algorithms: {algorithms}")

    def test_blake3_pow_solution(self):
        """Test BLAKE3 PoW solution finding and validation."""
        if "blake3" not in get_available_hash_algorithms():
            pytest.skip("BLAKE3 not available")
        
        action = "post"
        pubkey_hex = "test_pubkey_hex"
        challenge_str = "1" * 64  # 32 bytes in hex
        target_bits = 8  # Low difficulty for testing
        
        # Find BLAKE3 solution
        nonce, success = find_pow_solution(
            action=action,
            pubkey_hex=pubkey_hex,
            challenge_str=challenge_str,
            target_bits=target_bits,
            hash_algorithm="blake3",
            max_attempts=50000
        )
        
        assert success, "Failed to find BLAKE3 PoW solution"
        print(f"BLAKE3 solution found: nonce={nonce}")
        
        # Verify the solution using core validation
        salt_bytes = bytes.fromhex(challenge_str)
        payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, "blake3")
        
        is_valid = core_pow.validate_solution(
            salt_bytes, payload_digest, nonce, target_bits, "blake3"
        )
        assert is_valid, "BLAKE3 solution should be valid"
        
        # Verify manually
        hash_result = compute_pow_hash(salt_bytes, payload_digest, nonce, "blake3")
        leading_zeros = count_leading_zero_bits(hash_result)
        assert leading_zeros >= target_bits, f"BLAKE3 solution has {leading_zeros} leading zeros, need {target_bits}"
        print(f"BLAKE3 hash has {leading_zeros} leading zero bits")

    def test_sha256_pow_solution(self):
        """Test SHA-256 PoW solution finding and validation."""
        action = "vote"
        pubkey_hex = "test_pubkey_hex_2"
        challenge_str = "2" * 64  # 32 bytes in hex
        target_bits = 8  # Low difficulty for testing
        
        # Find SHA-256 solution
        nonce, success = find_pow_solution(
            action=action,
            pubkey_hex=pubkey_hex,
            challenge_str=challenge_str,
            target_bits=target_bits,
            hash_algorithm="sha256",
            max_attempts=50000
        )
        
        assert success, "Failed to find SHA-256 PoW solution"
        print(f"SHA-256 solution found: nonce={nonce}")
        
        # Verify the solution using core validation
        salt_bytes = bytes.fromhex(challenge_str)
        payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, "sha256")
        
        is_valid = core_pow.validate_solution(
            salt_bytes, payload_digest, nonce, target_bits, "sha256"
        )
        assert is_valid, "SHA-256 solution should be valid"
        
        # Verify manually
        hash_result = compute_pow_hash(salt_bytes, payload_digest, nonce, "sha256")
        leading_zeros = count_leading_zero_bits(hash_result)
        assert leading_zeros >= target_bits, f"SHA-256 solution has {leading_zeros} leading zeros, need {target_bits}"
        print(f"SHA-256 hash has {leading_zeros} leading zero bits")

    def test_pow_service_blake3(self, pow_service):
        """Test PowService with BLAKE3 algorithm."""
        if "blake3" not in get_available_hash_algorithms():
            pytest.skip("BLAKE3 not available")
        
        action = "message"
        pubkey_hex = "test_pubkey_hex_3"
        
        # Get challenge from service
        challenge_str = pow_service.get_challenge(action, pubkey_hex)
        print(f"BLAKE3 challenge: {challenge_str}")
        
        # Find solution
        nonce, success = find_pow_solution(
            action=action,
            pubkey_hex=pubkey_hex,
            challenge_str=challenge_str,
            target_bits=pow_service.difficulties.get("message", 15),
            hash_algorithm="blake3",
            max_attempts=10000
        )
        
        if success:
            # Test with PowService
            is_valid = pow_service.verify_pow(
                action, pubkey_hex, hex(nonce)[2:], challenge_str, "blake3"
            )
            assert is_valid, "PowService should validate BLAKE3 solution"
            print(f"BLAKE3 PowService validation: {is_valid}")

    def test_pow_service_sha256(self, pow_service):
        """Test PowService with SHA-256 algorithm."""
        action = "moderate"
        pubkey_hex = "test_pubkey_hex_4"
        
        # Get challenge from service
        challenge_str = pow_service.get_challenge(action, pubkey_hex)
        print(f"SHA-256 challenge: {challenge_str}")
        
        # Find solution
        nonce, success = find_pow_solution(
            action=action,
            pubkey_hex=pubkey_hex,
            challenge_str=challenge_str,
            target_bits=pow_service.difficulties.get("moderate", 15),
            hash_algorithm="sha256",
            max_attempts=10000
        )
        
        if success:
            # Test with PowService
            is_valid = pow_service.verify_pow(
                action, pubkey_hex, hex(nonce)[2:], challenge_str, "sha256"
            )
            assert is_valid, "PowService should validate SHA-256 solution"
            print(f"SHA-256 PowService validation: {is_valid}")

    def test_algorithm_comparison(self):
        """Compare BLAKE3 and SHA-256 performance and results."""
        action = "post"
        pubkey_hex = "comparison_test"
        challenge_str = "3" * 64
        target_bits = 6  # Very low difficulty for comparison
        
        results = {}
        
        success_blake3 = False
        # Test BLAKE3 if available
        if "blake3" in get_available_hash_algorithms():
            nonce_blake3, success_blake3 = find_pow_solution(
                action, pubkey_hex, challenge_str, target_bits, "blake3", 10000
            )
            if success_blake3:
                salt_bytes = bytes.fromhex(challenge_str)
                payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, "blake3")
                hash_result = compute_pow_hash(salt_bytes, payload_digest, nonce_blake3, "blake3")
                results["blake3"] = {
                    "nonce": nonce_blake3,
                    "leading_zeros": count_leading_zero_bits(hash_result),
                    "hash_hex": hash_result.hex()[:16] + "..."
                }
                print(f"BLAKE3: nonce={nonce_blake3}, zeros={results['blake3']['leading_zeros']}")
        
        # Test SHA-256
        nonce_sha256, success_sha256 = find_pow_solution(
            action, pubkey_hex, challenge_str, target_bits, "sha256", 10000
        )
        if success_sha256:
            salt_bytes = bytes.fromhex(challenge_str)
            payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, "sha256")
            hash_result = compute_pow_hash(salt_bytes, payload_digest, nonce_sha256, "sha256")
            results["sha256"] = {
                "nonce": nonce_sha256,
                "leading_zeros": count_leading_zero_bits(hash_result),
                "hash_hex": hash_result.hex()[:16] + "..."
            }
            print(f"SHA-256: nonce={nonce_sha256}, zeros={results['sha256']['leading_zeros']}")
        
        # Both should succeed with low difficulty
        assert success_sha256, "SHA-256 should always work"
        if "blake3" in get_available_hash_algorithms():
            assert success_blake3, "BLAKE3 should work when available"
        
        # Both should meet the target
        if "blake3" in results:
            assert results["blake3"]["leading_zeros"] >= target_bits
        assert results["sha256"]["leading_zeros"] >= target_bits
        
        print(f"Algorithm comparison results: {results}")

    def test_api_request_simulation(self):
        """Simulate API request/response flow with both algorithms."""
        # Simulate different user actions
        actions = ["register", "login", "post", "vote", "message"]
        
        for action in actions:
            print(f"\nTesting {action} with both algorithms:")
            
            # Test BLAKE3 if available
            if "blake3" in get_available_hash_algorithms():
                self._simulate_api_request(action, "blake3")
            
            # Test SHA-256
            self._simulate_api_request(action, "sha256")

    def _simulate_api_request(self, action: str, algorithm: str):
        """Simulate a complete API request flow."""
        pubkey_hex = f"test_pubkey_{action}_{algorithm}"
        challenge_str = "4" * 64
        target_bits = 6  # Low difficulty for testing
        
        print(f"  {algorithm.upper()}: Finding PoW solution for {action}...")
        
        # Find solution
        nonce, success = find_pow_solution(
            action=action,
            pubkey_hex=pubkey_hex,
            challenge_str=challenge_str,
            target_bits=target_bits,
            hash_algorithm=algorithm,  # type: ignore
            max_attempts=5000
        )
        
        if success:
            # Simulate API request payload
            request_payload = {
                "action": action,
                "pubkey_hex": pubkey_hex,
                "pow_nonce": hex(nonce)[2:],
                "pow_difficulty": target_bits,
                "hash_algorithm": algorithm,
                "challenge": challenge_str
            }
            
            # Simulate server validation
            salt_bytes = bytes.fromhex(challenge_str)
            payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, algorithm)  # type: ignore
            is_valid = core_pow.validate_solution(
                salt_bytes, payload_digest, nonce, target_bits, algorithm
            )
            
            print(f"    ✅ {algorithm.upper()} solution valid: {is_valid}")
            print(f"    📦 Request payload: {request_payload}")
        else:
            print(f"    ❌ {algorithm.upper()} solution not found within attempts")
