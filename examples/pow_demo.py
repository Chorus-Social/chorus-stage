#!/usr/bin/env python3
"""Demonstration of BLAKE3 and SHA-256 PoW support in Chorus API.

This script shows how to:
1. Request a PoW challenge from the API
2. Solve the challenge using either BLAKE3 or SHA-256
3. Submit the solution back to the API

Usage:
    python examples/pow_demo.py
"""

import hashlib
import json
import sys
from typing import Any, Dict, Literal

# Add the src directory to the path so we can import chorus_stage modules
sys.path.insert(0, "src")

from chorus_stage.utils.pow_client import (
    find_pow_solution,
    get_available_hash_algorithms,
    get_preferred_hash_algorithm,
)

HashAlgorithm = Literal["blake3", "sha256"]


def demonstrate_pow_workflow() -> None:
    """Demonstrate the complete PoW workflow with both algorithms."""
    print("🔐 Chorus PoW Algorithm Support Demonstration")
    print("=" * 50)
    
    # Check available algorithms
    algorithms = get_available_hash_algorithms()
    preferred = get_preferred_hash_algorithm()
    
    print(f"Available algorithms: {algorithms}")
    print(f"Preferred algorithm: {preferred}")
    print()
    
    # Test parameters
    action = "post"
    pubkey_hex = "demo_pubkey_1234567890abcdef"
    challenge_str = "1" * 64  # 32 bytes in hex
    target_bits = 8  # Low difficulty for demo
    
    print(f"Action: {action}")
    print(f"Public key: {pubkey_hex}")
    print(f"Challenge: {challenge_str}")
    print(f"Target bits: {target_bits}")
    print()
    
    # Test BLAKE3 if available
    if "blake3" in algorithms:
        print("🔵 Testing BLAKE3 PoW:")
        test_algorithm("blake3", action, pubkey_hex, challenge_str, target_bits)
        print()
    
    # Test SHA-256
    print("🟡 Testing SHA-256 PoW:")
    test_algorithm("sha256", action, pubkey_hex, challenge_str, target_bits)
    print()
    
    # Show API request examples
    print("📡 API Request Examples:")
    show_api_examples()


def test_algorithm(algorithm: HashAlgorithm, action: str, pubkey_hex: str, challenge_str: str, target_bits: int) -> bool:
    """Test a specific algorithm."""
    print(f"  Finding {algorithm.upper()} solution...")
    
    # Find PoW solution
    nonce, success = find_pow_solution(
        action=action,
        pubkey_hex=pubkey_hex,
        challenge_str=challenge_str,
        target_bits=target_bits,
        hash_algorithm=algorithm,
        max_attempts=10000
    )
    
    if success:
        print(f"  ✅ Solution found: nonce={nonce}")
        
        # Create API request payload
        payload = create_api_payload(action, pubkey_hex, nonce, target_bits, challenge_str, algorithm)
        print(f"  📦 API payload: {json.dumps(payload, indent=2)}")
        
        return True
    else:
        print(f"  ❌ No solution found within attempts")
        return False


def create_api_payload(action: str, pubkey_hex: str, nonce: int, difficulty: int, challenge: str, algorithm: HashAlgorithm) -> Dict[str, Any]:
    """Create an API request payload for the given parameters."""
    if action in ["register", "login"]:
        return {
            "pubkey": pubkey_hex,
            "pow": {
                "nonce": hex(nonce)[2:],
                "difficulty": difficulty,
                "target": challenge,
                "hash_algorithm": algorithm
            },
            "proof": {
                "challenge": "base64_encoded_challenge",
                "signature": "base64_encoded_signature"
            }
        }
    elif action == "post":
        return {
            "content_md": "Hello, Chorus!",
            "pow_nonce": hex(nonce)[2:],
            "pow_difficulty": difficulty,
            "pow_hash_algorithm": algorithm,
            "content_hash": hashlib.sha256(b"Hello, Chorus!").hexdigest()
        }
    elif action == "vote":
        return {
            "post_id": 1,
            "direction": 1,
            "pow_nonce": hex(nonce)[2:],
            "client_nonce": "client_nonce_123",
            "hash_algorithm": algorithm
        }
    elif action == "message":
        return {
            "ciphertext": "base64_encoded_encrypted_message",
            "recipient_pubkey_hex": "recipient_pubkey_hex",
            "pow_nonce": hex(nonce)[2:],
            "hash_algorithm": algorithm
        }
    else:
        return {
            "action": action,
            "pow_nonce": hex(nonce)[2:],
            "hash_algorithm": algorithm
        }


def show_api_examples() -> None:
    """Show example API requests for different endpoints."""
    examples = {
        "Registration": {
            "endpoint": "POST /api/v1/auth/register",
            "description": "Register a new user with PoW",
            "payload": {
                "pubkey": "base64_encoded_public_key",
                "display_name": "User Name",
                "pow": {
                    "nonce": "hex_nonce",
                    "difficulty": 15,
                    "target": "challenge_string",
                    "hash_algorithm": "blake3"  # or "sha256"
                },
                "proof": {
                    "challenge": "base64_challenge",
                    "signature": "base64_signature"
                }
            }
        },
        "Post Creation": {
            "endpoint": "POST /api/v1/posts/",
            "description": "Create a new post with PoW",
            "payload": {
                "content_md": "Post content in markdown",
                "pow_nonce": "hex_nonce",
                "pow_difficulty": 15,
                "pow_hash_algorithm": "blake3",  # or "sha256"
                "content_hash": "sha256_hash_of_content"
            }
        },
        "Voting": {
            "endpoint": "POST /api/v1/votes/",
            "description": "Cast a vote with PoW",
            "payload": {
                "post_id": 123,
                "direction": 1,
                "pow_nonce": "hex_nonce",
                "client_nonce": "client_nonce",
                "hash_algorithm": "blake3"  # or "sha256"
            }
        },
        "Direct Messaging": {
            "endpoint": "POST /api/v1/messages/",
            "description": "Send a direct message with PoW",
            "payload": {
                "ciphertext": "base64_encrypted_message",
                "recipient_pubkey_hex": "recipient_public_key_hex",
                "pow_nonce": "hex_nonce",
                "hash_algorithm": "blake3"  # or "sha256"
            }
        }
    }
    
    for name, example in examples.items():
        print(f"\n📋 {name}:")
        print(f"  {example['endpoint']}")
        print(f"  {example['description']}")
        print(f"  Payload: {json.dumps(example['payload'], indent=4)}")


def show_algorithm_comparison() -> None:
    """Show comparison between BLAKE3 and SHA-256."""
    print("\n🔍 Algorithm Comparison:")
    print("=" * 30)
    
    comparison = {
        "BLAKE3": {
            "speed": "Faster",
            "security": "Modern, secure",
            "availability": "Requires blake3 package",
            "use_case": "Preferred when available"
        },
        "SHA-256": {
            "speed": "Standard speed",
            "security": "Well-established, secure",
            "availability": "Always available (built-in)",
            "use_case": "Fallback when BLAKE3 unavailable"
        }
    }
    
    for algorithm, properties in comparison.items():
        print(f"\n{algorithm}:")
        for property_name, value in properties.items():
            print(f"  {property_name.title()}: {value}")


if __name__ == "__main__":
    try:
        demonstrate_pow_workflow()
        show_algorithm_comparison()
        
        print("\n✅ Demonstration complete!")
        print("\nKey takeaways:")
        print("• Both BLAKE3 and SHA-256 are supported")
        print("• BLAKE3 is preferred when available")
        print("• SHA-256 serves as a reliable fallback")
        print("• All user-facing PoW challenges support both algorithms")
        
    except Exception as e:
        print(f"❌ Error during demonstration: {e}")
        sys.exit(1)
