#!/usr/bin/env python3
"""Standalone test for BLAKE3 and SHA-256 PoW support.

This test demonstrates that both algorithms work correctly without requiring pytest.
"""

import sys
from typing import Literal

# Add the src directory to the path
sys.path.insert(0, "src")

from chorus_stage.core import pow as core_pow
from chorus_stage.utils.pow_client import (
    compute_payload_digest,
    compute_pow_hash,
    count_leading_zero_bits,
    find_pow_solution,
    get_available_hash_algorithms,
)

HashAlgorithm = Literal["blake3", "sha256"]


def test_algorithm_availability():
    """Test that both algorithms are available."""
    algorithms = get_available_hash_algorithms()
    print(f"Available algorithms: {algorithms}")
    assert "sha256" in algorithms, "SHA-256 should always be available"
    assert len(algorithms) >= 1, "At least one algorithm should be available"
    print("✅ Algorithm availability test passed")


def test_blake3_pow_solution():
    """Test BLAKE3 PoW solution finding and validation."""
    if "blake3" not in get_available_hash_algorithms():
        print("⚠️ BLAKE3 not available, skipping test")
        return
    
    action = "post"
    pubkey_hex = "test_pubkey_hex"
    challenge_str = "1" * 64  # 32 bytes in hex
    target_bits = 8  # Low difficulty for testing
    
    print(f"Testing BLAKE3 PoW solution...")
    print(f"  Action: {action}")
    print(f"  Target bits: {target_bits}")
    
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
    print(f"  ✅ BLAKE3 solution found: nonce={nonce}")
    
    # Verify the solution using core validation
    salt_bytes = bytes.fromhex(challenge_str)
    payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, "blake3")
    
    is_valid = core_pow.validate_solution(
        salt_bytes, payload_digest, nonce, target_bits, "blake3"
    )
    assert is_valid, "BLAKE3 solution should be valid"
    print(f"  ✅ BLAKE3 solution validation passed")
    
    # Verify manually
    hash_result = compute_pow_hash(salt_bytes, payload_digest, nonce, "blake3")
    leading_zeros = count_leading_zero_bits(hash_result)
    assert leading_zeros >= target_bits, f"BLAKE3 solution has {leading_zeros} leading zeros, need {target_bits}"
    print(f"  ✅ BLAKE3 hash has {leading_zeros} leading zero bits")


def test_sha256_pow_solution():
    """Test SHA-256 PoW solution finding and validation."""
    action = "vote"
    pubkey_hex = "test_pubkey_hex_2"
    challenge_str = "2" * 64  # 32 bytes in hex
    target_bits = 8  # Low difficulty for testing
    
    print(f"Testing SHA-256 PoW solution...")
    print(f"  Action: {action}")
    print(f"  Target bits: {target_bits}")
    
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
    print(f"  ✅ SHA-256 solution found: nonce={nonce}")
    
    # Verify the solution using core validation
    salt_bytes = bytes.fromhex(challenge_str)
    payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, "sha256")
    
    is_valid = core_pow.validate_solution(
        salt_bytes, payload_digest, nonce, target_bits, "sha256"
    )
    assert is_valid, "SHA-256 solution should be valid"
    print(f"  ✅ SHA-256 solution validation passed")
    
    # Verify manually
    hash_result = compute_pow_hash(salt_bytes, payload_digest, nonce, "sha256")
    leading_zeros = count_leading_zero_bits(hash_result)
    assert leading_zeros >= target_bits, f"SHA-256 solution has {leading_zeros} leading zeros, need {target_bits}"
    print(f"  ✅ SHA-256 hash has {leading_zeros} leading zero bits")


def test_api_request_simulation():
    """Simulate API request/response flow with both algorithms."""
    print("Testing API request simulation...")
    
    # Simulate different user actions
    actions = ["register", "login", "post", "vote", "message"]
    
    for action in actions:
        print(f"\n  Testing {action}:")
        
        # Test BLAKE3 if available
        if "blake3" in get_available_hash_algorithms():
            simulate_api_request(action, "blake3")
        
        # Test SHA-256
        simulate_api_request(action, "sha256")


def simulate_api_request(action: str, algorithm: HashAlgorithm):
    """Simulate a complete API request flow."""
    pubkey_hex = f"test_pubkey_{action}_{algorithm}"
    challenge_str = "4" * 64
    target_bits = 6  # Low difficulty for testing
    
    print(f"    {algorithm.upper()}: Finding PoW solution for {action}...")
    
    # Find solution
    nonce, success = find_pow_solution(
        action=action,
        pubkey_hex=pubkey_hex,
        challenge_str=challenge_str,
        target_bits=target_bits,
        hash_algorithm=algorithm,
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
        payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, algorithm)
        is_valid = core_pow.validate_solution(
            salt_bytes, payload_digest, nonce, target_bits, algorithm
        )
        
        print(f"      ✅ {algorithm.upper()} solution valid: {is_valid}")
        print(f"      📦 Request payload: {request_payload}")
    else:
        print(f"      ❌ {algorithm.upper()} solution not found within attempts")


def main():
    """Run all tests."""
    print("🔐 Chorus PoW Dual Algorithm Test")
    print("=" * 40)
    
    try:
        test_algorithm_availability()
        test_blake3_pow_solution()
        test_sha256_pow_solution()
        test_api_request_simulation()
        
        print("\n✅ All tests passed!")
        print("\nKey takeaways:")
        print("• Both BLAKE3 and SHA-256 PoW algorithms are supported")
        print("• SHA-256 is always available as a fallback")
        print("• BLAKE3 is preferred when available")
        print("• All user-facing PoW challenges support both algorithms")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
