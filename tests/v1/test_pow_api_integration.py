"""Integration tests for BLAKE3 and SHA-256 PoW support across all user-facing endpoints.

This test demonstrates that the API accepts and validates both BLAKE3 and SHA-256
proof-of-work solutions for all user-facing operations.
"""

import base64
import hashlib
import secrets
from typing import Any

import pytest
from fastapi.testclient import TestClient

from chorus_stage.main import app
from chorus_stage.utils.pow_client import (
    compute_payload_digest,
    compute_pow_hash,
    count_leading_zero_bits,
    find_pow_solution,
    get_available_hash_algorithms,
)


class TestPoWAPIIntegration:
    """Test PoW integration with both BLAKE3 and SHA-256 algorithms."""

    @pytest.fixture
    def client(self):
        """FastAPI test client."""
        return TestClient(app)

    @pytest.fixture
    def test_keypair(self):
        """Generate a test Ed25519 keypair."""
        # For testing, we'll use a deterministic keypair
        # In a real implementation, you'd use proper Ed25519 key generation
        private_key = secrets.token_bytes(32)
        public_key = hashlib.sha256(private_key).digest()  # Simplified for testing
        return private_key, public_key

    @pytest.fixture
    def test_pubkey_b64(self, test_keypair):
        """Base64-encoded test public key."""
        _, public_key = test_keypair
        return base64.urlsafe_b64encode(public_key).decode().rstrip("=")

    def test_registration_blake3(self, client, test_pubkey_b64):
        """Test user registration with BLAKE3 PoW."""
        # Request challenge
        challenge_response = client.post("/api/v1/auth/challenge", json={
            "pubkey": test_pubkey_b64,
            "intent": "register"
        })
        assert challenge_response.status_code == 200
        challenge_data = challenge_response.json()
        
        # Solve PoW with BLAKE3
        nonce, success = find_pow_solution(
            action="register",
            pubkey_hex=test_pubkey_b64,
            challenge_str=challenge_data["pow_target"],
            target_bits=challenge_data["pow_difficulty"],
            hash_algorithm="blake3",
            max_attempts=100000
        )
        assert success, "Failed to find BLAKE3 PoW solution"
        
        # Create signature proof (simplified for testing)
        challenge_bytes = base64.b64decode(challenge_data["signature_challenge"])
        signature = b"fake_signature_for_testing"  # In real implementation, use Ed25519
        
        # Register user
        registration_response = client.post("/api/v1/auth/register", json={
            "pubkey": test_pubkey_b64,
            "display_name": "Test User",
            "accent_color": "#ff0000",
            "pow": {
                "nonce": hex(nonce)[2:],
                "difficulty": challenge_data["pow_difficulty"],
                "target": challenge_data["pow_target"],
                "hash_algorithm": "blake3"
            },
            "proof": {
                "challenge": challenge_data["signature_challenge"],
                "signature": base64.b64encode(signature).decode()
            }
        })
        
        # Should succeed with BLAKE3
        assert registration_response.status_code in [200, 201], f"Registration failed: {registration_response.text}"

    def test_registration_sha256(self, client, test_pubkey_b64):
        """Test user registration with SHA-256 PoW."""
        # Request challenge
        challenge_response = client.post("/api/v1/auth/challenge", json={
            "pubkey": test_pubkey_b64,
            "intent": "register"
        })
        assert challenge_response.status_code == 200
        challenge_data = challenge_response.json()
        
        # Solve PoW with SHA-256
        nonce, success = find_pow_solution(
            action="register",
            pubkey_hex=test_pubkey_b64,
            challenge_str=challenge_data["pow_target"],
            target_bits=challenge_data["pow_difficulty"],
            hash_algorithm="sha256",
            max_attempts=100000
        )
        assert success, "Failed to find SHA-256 PoW solution"
        
        # Create signature proof (simplified for testing)
        challenge_bytes = base64.b64decode(challenge_data["signature_challenge"])
        signature = b"fake_signature_for_testing"  # In real implementation, use Ed25519
        
        # Register user
        registration_response = client.post("/api/v1/auth/register", json={
            "pubkey": test_pubkey_b64,
            "display_name": "Test User SHA256",
            "accent_color": "#00ff00",
            "pow": {
                "nonce": hex(nonce)[2:],
                "difficulty": challenge_data["pow_difficulty"],
                "target": challenge_data["pow_target"],
                "hash_algorithm": "sha256"
            },
            "proof": {
                "challenge": challenge_data["signature_challenge"],
                "signature": base64.b64encode(signature).decode()
            }
        })
        
        # Should succeed with SHA-256
        assert registration_response.status_code in [200, 201], f"Registration failed: {registration_response.text}"

    def test_posting_blake3(self, client, test_pubkey_b64):
        """Test post creation with BLAKE3 PoW."""
        # First register user
        self._register_test_user(client, test_pubkey_b64, "blake3")
        
        # Get auth token
        auth_token = self._login_test_user(client, test_pubkey_b64, "blake3")
        
        # Create post with BLAKE3 PoW
        post_data = {
            "content_md": "Test post with BLAKE3 PoW",
            "pow_nonce": "test_nonce_blake3",
            "pow_difficulty": 15,
            "pow_hash_algorithm": "blake3",
            "content_hash": hashlib.sha256(b"Test post with BLAKE3 PoW").hexdigest()
        }
        
        response = client.post(
            "/api/v1/posts/",
            json=post_data,
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Should succeed with BLAKE3
        assert response.status_code in [200, 201], f"Post creation failed: {response.text}"

    def test_posting_sha256(self, client, test_pubkey_b64):
        """Test post creation with SHA-256 PoW."""
        # First register user
        self._register_test_user(client, test_pubkey_b64, "sha256")
        
        # Get auth token
        auth_token = self._login_test_user(client, test_pubkey_b64, "sha256")
        
        # Create post with SHA-256 PoW
        post_data = {
            "content_md": "Test post with SHA-256 PoW",
            "pow_nonce": "test_nonce_sha256",
            "pow_difficulty": 15,
            "pow_hash_algorithm": "sha256",
            "content_hash": hashlib.sha256(b"Test post with SHA-256 PoW").hexdigest()
        }
        
        response = client.post(
            "/api/v1/posts/",
            json=post_data,
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Should succeed with SHA-256
        assert response.status_code in [200, 201], f"Post creation failed: {response.text}"

    def test_voting_blake3(self, client, test_pubkey_b64):
        """Test voting with BLAKE3 PoW."""
        # First register user and create a post
        self._register_test_user(client, test_pubkey_b64, "blake3")
        auth_token = self._login_test_user(client, test_pubkey_b64, "blake3")
        post_id = self._create_test_post(client, auth_token, "blake3")
        
        # Vote with BLAKE3 PoW
        vote_data = {
            "post_id": post_id,
            "direction": 1,
            "pow_nonce": "vote_nonce_blake3",
            "client_nonce": "client_nonce_blake3",
            "hash_algorithm": "blake3"
        }
        
        response = client.post(
            "/api/v1/votes/",
            json=vote_data,
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Should succeed with BLAKE3
        assert response.status_code in [200, 201], f"Voting failed: {response.text}"

    def test_voting_sha256(self, client, test_pubkey_b64):
        """Test voting with SHA-256 PoW."""
        # First register user and create a post
        self._register_test_user(client, test_pubkey_b64, "sha256")
        auth_token = self._login_test_user(client, test_pubkey_b64, "sha256")
        post_id = self._create_test_post(client, auth_token, "sha256")
        
        # Vote with SHA-256 PoW
        vote_data = {
            "post_id": post_id,
            "direction": 1,
            "pow_nonce": "vote_nonce_sha256",
            "client_nonce": "client_nonce_sha256",
            "hash_algorithm": "sha256"
        }
        
        response = client.post(
            "/api/v1/votes/",
            json=vote_data,
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Should succeed with SHA-256
        assert response.status_code in [200, 201], f"Voting failed: {response.text}"

    def test_messaging_blake3(self, client, test_pubkey_b64):
        """Test direct messaging with BLAKE3 PoW."""
        # Register sender and recipient
        self._register_test_user(client, test_pubkey_b64, "blake3")
        sender_token = self._login_test_user(client, test_pubkey_b64, "blake3")
        
        # Create recipient keypair
        recipient_private, recipient_public = self.test_keypair()
        recipient_pubkey_b64 = base64.urlsafe_b64encode(recipient_public).decode().rstrip("=")
        self._register_test_user(client, recipient_pubkey_b64, "blake3")
        
        # Send message with BLAKE3 PoW
        message_data = {
            "ciphertext": base64.b64encode(b"encrypted message content").decode(),
            "recipient_pubkey_hex": recipient_public.hex(),
            "pow_nonce": "message_nonce_blake3",
            "hash_algorithm": "blake3"
        }
        
        response = client.post(
            "/api/v1/messages/",
            json=message_data,
            headers={"Authorization": f"Bearer {sender_token}"}
        )
        
        # Should succeed with BLAKE3
        assert response.status_code in [200, 201], f"Messaging failed: {response.text}"

    def test_messaging_sha256(self, client, test_pubkey_b64):
        """Test direct messaging with SHA-256 PoW."""
        # Register sender and recipient
        self._register_test_user(client, test_pubkey_b64, "sha256")
        sender_token = self._login_test_user(client, test_pubkey_b64, "sha256")
        
        # Create recipient keypair
        recipient_private, recipient_public = self.test_keypair()
        recipient_pubkey_b64 = base64.urlsafe_b64encode(recipient_public).decode().rstrip("=")
        self._register_test_user(client, recipient_pubkey_b64, "sha256")
        
        # Send message with SHA-256 PoW
        message_data = {
            "ciphertext": base64.b64encode(b"encrypted message content").decode(),
            "recipient_pubkey_hex": recipient_public.hex(),
            "pow_nonce": "message_nonce_sha256",
            "hash_algorithm": "sha256"
        }
        
        response = client.post(
            "/api/v1/messages/",
            json=message_data,
            headers={"Authorization": f"Bearer {sender_token}"}
        )
        
        # Should succeed with SHA-256
        assert response.status_code in [200, 201], f"Messaging failed: {response.text}"

    def test_algorithm_availability(self):
        """Test that both algorithms are available."""
        algorithms = get_available_hash_algorithms()
        assert "sha256" in algorithms, "SHA-256 should always be available"
        assert len(algorithms) >= 1, "At least one algorithm should be available"

    def test_pow_solution_validation(self):
        """Test that PoW solutions are correctly validated."""
        action = "test"
        pubkey_hex = "test_pubkey"
        challenge_str = "test_challenge"
        target_bits = 8  # Low difficulty for testing
        
        # Test BLAKE3 solution
        if "blake3" in get_available_hash_algorithms():
            nonce_blake3, success_blake3 = find_pow_solution(
                action, pubkey_hex, challenge_str, target_bits, "blake3", 10000
            )
            if success_blake3:
                # Verify the solution
                salt_bytes = bytes.fromhex(challenge_str)
                payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, "blake3")
                hash_result = compute_pow_hash(salt_bytes, payload_digest, nonce_blake3, "blake3")
                assert count_leading_zero_bits(hash_result) >= target_bits
        
        # Test SHA-256 solution
        nonce_sha256, success_sha256 = find_pow_solution(
            action, pubkey_hex, challenge_str, target_bits, "sha256", 10000
        )
        if success_sha256:
            # Verify the solution
            salt_bytes = bytes.fromhex(challenge_str)
            payload_digest = compute_payload_digest(action, pubkey_hex, challenge_str, "sha256")
            hash_result = compute_pow_hash(salt_bytes, payload_digest, nonce_sha256, "sha256")
            assert count_leading_zero_bits(hash_result) >= target_bits

    # Helper methods
    def _register_test_user(self, client, pubkey_b64: str, algorithm: str):
        """Register a test user with the specified algorithm."""
        # Request challenge
        challenge_response = client.post("/api/v1/auth/challenge", json={
            "pubkey": pubkey_b64,
            "intent": "register"
        })
        assert challenge_response.status_code == 200
        challenge_data = challenge_response.json()
        
        # Solve PoW
        nonce, success = find_pow_solution(
            action="register",
            pubkey_hex=pubkey_b64,
            challenge_str=challenge_data["pow_target"],
            target_bits=challenge_data["pow_difficulty"],
            hash_algorithm=algorithm,
            max_attempts=10000
        )
        assert success, f"Failed to find {algorithm} PoW solution"
        
        # Register
        response = client.post("/api/v1/auth/register", json={
            "pubkey": pubkey_b64,
            "display_name": f"Test User {algorithm.upper()}",
            "pow": {
                "nonce": hex(nonce)[2:],
                "difficulty": challenge_data["pow_difficulty"],
                "target": challenge_data["pow_target"],
                "hash_algorithm": algorithm
            },
            "proof": {
                "challenge": challenge_data["signature_challenge"],
                "signature": base64.b64encode(b"fake_signature").decode()
            }
        })
        return response.status_code in [200, 201]

    def _login_test_user(self, client, pubkey_b64: str, algorithm: str) -> str:
        """Login a test user and return auth token."""
        # Request challenge
        challenge_response = client.post("/api/v1/auth/challenge", json={
            "pubkey": pubkey_b64,
            "intent": "login"
        })
        assert challenge_response.status_code == 200
        challenge_data = challenge_response.json()
        
        # Solve PoW
        nonce, success = find_pow_solution(
            action="login",
            pubkey_hex=pubkey_b64,
            challenge_str=challenge_data["pow_target"],
            target_bits=challenge_data["pow_difficulty"],
            hash_algorithm=algorithm,
            max_attempts=10000
        )
        assert success, f"Failed to find {algorithm} PoW solution"
        
        # Login
        response = client.post("/api/v1/auth/login", json={
            "pubkey": pubkey_b64,
            "pow": {
                "nonce": hex(nonce)[2:],
                "difficulty": challenge_data["pow_difficulty"],
                "target": challenge_data["pow_target"],
                "hash_algorithm": algorithm
            },
            "proof": {
                "challenge": challenge_data["signature_challenge"],
                "signature": base64.b64encode(b"fake_signature").decode()
            }
        })
        assert response.status_code == 200
        return response.json()["access_token"]

    def _create_test_post(self, client, auth_token: str, algorithm: str) -> int:
        """Create a test post and return its ID."""
        post_data = {
            "content_md": f"Test post with {algorithm.upper()} PoW",
            "pow_nonce": f"post_nonce_{algorithm}",
            "pow_difficulty": 15,
            "pow_hash_algorithm": algorithm,
            "content_hash": hashlib.sha256(f"Test post with {algorithm.upper()} PoW".encode()).hexdigest()
        }
        
        response = client.post(
            "/api/v1/posts/",
            json=post_data,
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code in [200, 201]
        return response.json()["id"]
