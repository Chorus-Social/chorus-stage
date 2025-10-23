# mypy: ignore-errors
# src/chorus_stage/tests/v1/test_auth.py
"""Tests for authentication endpoints."""

from __future__ import annotations

import base64

from fastapi import status

from chorus_stage.core.settings import settings
from tests.conftest import build_register_payload


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _decode_b64(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _issue_client_challenge(client, pubkey_b64: str, intent: str) -> dict:
    response = client.post(
        "/api/v1/auth/challenge",
        json={"pubkey": pubkey_b64, "intent": intent},
    )
    assert response.status_code == status.HTTP_200_OK
    return response.json()


def _build_login_payload(test_user_data, challenge_payload: dict, nonce: str = "test") -> dict:
    challenge_bytes = _decode_b64(challenge_payload["signature_challenge"])
    signature = test_user_data["private_key"].sign(challenge_bytes).signature  # type: ignore[attr-defined]
    return {
        "pubkey": test_user_data["pubkey_b64"],
        "pow": {
            "nonce": nonce,
            "difficulty": challenge_payload["pow_difficulty"],
            "target": challenge_payload["pow_target"],
        },
        "proof": {
            "challenge": challenge_payload["signature_challenge"],
            "signature": _b64(signature),
        },
    }


def test_register_user_success(client, test_user_data, db_session) -> None:
    """Test successful user registration."""
    payload = build_register_payload(test_user_data)
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()

    assert data["created"] is True
    assert data["user_id"] == _b64(test_user_data["user_id"])


def test_register_user_invalid_key(client) -> None:
    """Test registration with invalid public key."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "pubkey": "invalid_key",
            "display_name": "Invalid User",
            "pow": {
                "nonce": "deadbeef",
                "difficulty": settings.pow_difficulty_register,
                "target": "cafebabe",
            },
            "proof": {
                "challenge": _b64(b"bad-challenge"),
                "signature": _b64(b"\x00" * 64),
            },
        },
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid public key format" in response.json()["detail"]


def test_register_duplicate_key(client, test_user_data, db_session) -> None:
    """Test registration idempotency when the key already exists."""
    client.post("/api/v1/auth/register", json=build_register_payload(test_user_data))
    response = client.post("/api/v1/auth/register", json=build_register_payload(test_user_data))
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["created"] is False
    assert data["user_id"] == _b64(test_user_data["user_id"])


def test_login_success(client, test_user, test_user_data, db_session) -> None:
    """Test successful login with Ed25519 signature."""
    challenge_payload = _issue_client_challenge(client, test_user_data["pubkey_b64"], "login")
    payload = _build_login_payload(test_user_data, challenge_payload, nonce="login_nonce")

    response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "session_nonce" in data


def test_login_invalid_user(client, test_user_data) -> None:
    """Test login with non-existent user."""
    challenge_payload = _issue_client_challenge(client, test_user_data["pubkey_b64"], "login")
    payload = _build_login_payload(test_user_data, challenge_payload, nonce="missing_user_nonce")

    response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "User not found" in response.json()["detail"]


def test_login_invalid_signature(client, test_user, test_user_data) -> None:
    """Test login with invalid (non-base64) signature."""
    challenge_payload = _issue_client_challenge(client, test_user_data["pubkey_b64"], "login")
    payload = _build_login_payload(test_user_data, challenge_payload)
    payload["proof"]["signature"] = "not-base64"

    response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Authentication failed" in response.json()["detail"]


def test_login_wrong_signature(client, test_user, test_user_data) -> None:
    """Test login with wrong signature for the challenge."""
    challenge_payload = _issue_client_challenge(client, test_user_data["pubkey_b64"], "login")
    payload = _build_login_payload(test_user_data, challenge_payload)
    payload["proof"]["signature"] = _b64(
        test_user_data["private_key"].sign(b"different-message").signature  # type: ignore[attr-defined]
    )

    response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Authentication failed" in response.json()["detail"]
