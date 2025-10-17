# mypy: ignore-errors
# src/chorus_stage/tests/v1/test_auth.py
"""Tests for authentication endpoints."""

from fastapi import status
from jose import jwt


def test_register_user_success(client, test_user_data, db_session) -> None:
    """Test successful user registration."""
    response = client.post(
        "/api/v1/auth/register",
        json=test_user_data["user_identity"]
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()

    assert "access_token" in data
    assert "user" in data
    assert data["user"]["display_name"] == test_user_data["user_identity"]["display_name"]

    # Verify token is valid
    token_data = jwt.get_unverified_claims(data["access_token"])
    assert "sub" in token_data


def test_register_user_invalid_key(client) -> None:
    """Test registration with invalid public key."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "ed25519_pubkey": "invalid_key",
            "display_name": "Invalid User"
        }
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid public key format" in response.json()["detail"]


def test_register_duplicate_key(client, test_user_data, db_session) -> None:
    """Test registration with a duplicate public key."""
    # First registration should succeed
    client.post(
        "/api/v1/auth/register",
        json=test_user_data["user_identity"]
    )

    # Second registration with the same key should fail
    response = client.post(
        "/api/v1/auth/register",
        json=test_user_data["user_identity"]
    )
    assert response.status_code == status.HTTP_409_CONFLICT
    assert "already registered" in response.json()["detail"]


def test_login_success(client, test_user, test_user_data, db_session) -> None:
    """Test successful login with Ed25519 signature."""
    # Generate signature for a nonce
    nonce = "test_nonce_value"
    signature = test_user_data["private_key"].sign(nonce.encode()).hex()

    response = client.post(
        "/api/v1/auth/login",
        params={
            "ed25519_pubkey": test_user_data["pubkey_hex"],
        },
        headers={
            "signature": signature
        }
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "session_nonce" in data


def test_login_invalid_user(client, test_user_data) -> None:
    """Test login with non-existent user."""
    nonce = "test_nonce_value"
    signature = test_user_data["private_key"].sign(nonce.encode()).hex()

    response = client.post(
        "/api/v1/auth/login",
        params={
            "ed25519_pubkey": test_user_data["pubkey_hex"],
        },
        headers={
            "signature": signature
        }
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "User not found" in response.json()["detail"]


def test_login_invalid_signature(client, test_user, test_user_data) -> None:
    """Test login with invalid signature."""
    nonce = "test_nonce_value"

    response = client.post(
        "/api/v1/auth/login",
        params={
            "ed25519_pubkey": test_user_data["pubkey_hex"],
        },
        headers={
            "signature": "invalid_signature"
        }
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid signature format" in response.json()["detail"]


def test_login_wrong_signature(client, test_user, test_user_data) -> None:
    """Test login with wrong signature for the nonce."""
    nonce = "test_nonce_value"
    # Sign a different message to create an invalid signature
    wrong_signature = test_user_data["private_key"].sign(b"different_message").hex()

    response = client.post(
        "/api/v1/auth/login",
        params={
            "ed25519_pubkey": test_user_data["pubkey_hex"],
        },
        headers={
            "signature": wrong_signature
        }
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Authentication failed" in response.json()["detail"]


def test_register_user_with_pgp_key(client, test_user_data, db_session) -> None:
    """Test user registration with a PGP public key."""
    pgp_key = """-----BEGIN PGP PUBLIC KEY BLOCK-----
mDMEXEcE6RYJKwYBBAHaRw8BAQdAqgE8E7+1A9D4jOe3m0D1FQ2oPzL7Yz3S
2X9k9jX8VQ7j/2O7N1k3tM5F2c1l0g3sR9lJ8S4wX2F2H1I4tK6pX7C/R
-----END PGP PUBLIC KEY BLOCK-----"""

    user_data = test_user_data["user_identity"].copy()
    user_data["pgp_public_key_asc"] = pgp_key

    response = client.post(
        "/api/v1/auth/register",
        json=user_data
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["user"]["pgp_public_key"] is True
