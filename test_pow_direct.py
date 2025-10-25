#!/usr/bin/env python3
"""
Direct test of SHA-256 and BLAKE3 PoW functionality without pytest.
This script demonstrates both algorithms working with the API.
"""

import sys
import os
import asyncio
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from chorus_stage.utils.pow_client import (
    find_pow_solution,
    compute_payload_digest,
    count_leading_zero_bits,
)
from chorus_stage.core.pow import validate_solution


async def test_algorithm(algorithm: str, difficulty: int = 4) -> bool:
    """Test a specific PoW algorithm."""
    print(f"\n🧪 Testing {algorithm.upper()} PoW...")
    
    # Test data
    action = "test"
    pubkey_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    challenge_str = "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef123456"
    
    try:
        # Compute payload digest
        payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, algorithm)
        print(f"  📊 Payload digest: {payload_digest[:16].hex()}...")
        
        # Find PoW solution
        print(f"  🔍 Finding solution with difficulty {difficulty}...")
        nonce, success = find_pow_solution(action, pubkey_hex, challenge_str, difficulty, algorithm)
        
        if success:
            print(f"  ✅ Solution found: nonce={nonce}")
            
            # Verify solution by computing the hash
            from chorus_stage.utils.pow_client import compute_pow_hash
            salt_bytes = bytes.fromhex(challenge_str)
            final_hash = compute_pow_hash(salt_bytes, payload_digest, nonce, algorithm)
            leading_zeros = count_leading_zero_bits(final_hash)
            print(f"  📈 Leading zeros: {leading_zeros}")
            print(f"  🔐 Validation: {'✅ PASS' if leading_zeros >= difficulty else '❌ FAIL'}")
            
            return leading_zeros >= difficulty
        else:
            print(f"  ❌ No solution found after maximum attempts")
            return False
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False


async def test_api_simulation() -> None:
    """Simulate API request with both algorithms."""
    print("\n🌐 API Request Simulation...")
    
    # Test data for API simulation
    action = "register"
    pubkey_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    challenge_str = "cafebabe1234567890abcdef1234567890abcdef1234567890abcdef123456"
    
    algorithms = ["blake3", "sha256"]
    
    for algorithm in algorithms:
        print(f"\n  🔄 Testing {algorithm.upper()} API simulation...")
        
        try:
            # Compute payload digest (what the API would do)
            payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, algorithm)
            
            # Find solution (what client would do)
            nonce, success = find_pow_solution(action, pubkey_hex, challenge_str, 4, algorithm)
            
            if success:
                # Verify (what API would do)
                from chorus_stage.utils.pow_client import compute_pow_hash
                salt_bytes = bytes.fromhex(challenge_str)
                final_hash = compute_pow_hash(salt_bytes, payload_digest, nonce, algorithm)
                leading_zeros = count_leading_zero_bits(final_hash)
                is_valid = leading_zeros >= 4
                
                print(f"    📊 Payload: {payload_digest[:16].hex()}...")
                print(f"    🔑 Nonce: {nonce}")
                print(f"    📈 Leading zeros: {leading_zeros}")
                print(f"    ✅ Valid: {'YES' if is_valid else 'NO'}")
            else:
                print(f"    ❌ No solution found")
            
        except Exception as e:
            print(f"    ❌ Error: {e}")


async def main() -> None:
    """Main test function."""
    print("🚀 Chorus Stage PoW Algorithm Test")
    print("=" * 50)
    
    # Test both algorithms
    algorithms = ["blake3", "sha256"]
    results = {}
    
    for algorithm in algorithms:
        results[algorithm] = await test_algorithm(algorithm)
    
    # Test API simulation
    await test_api_simulation()
    
    # Summary
    print("\n📋 Test Summary")
    print("=" * 30)
    for algorithm, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {algorithm.upper()}: {status}")
    
    all_passed = all(results.values())
    print(f"\n🎯 Overall: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    
    return all_passed


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
