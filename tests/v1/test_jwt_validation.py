# tests/v1/test_jwt_validation.py
"""Tests for JWT token validation edge cases and security."""

import base64
from unittest.mock import patch

import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient
from jose import jwt

from chorus_stage.api.v1.dependencies import get_current_user
from chorus_stage.core.settings import settings


def _b64(data: bytes) -> str:
    """Helper to encode bytes to base64."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class TestJWTValidationEdgeCases:
    """Test JWT validation edge cases and security scenarios."""

    def test_jwt_without_bearer_prefix(self, client):
        """Test that requests without Bearer prefix are rejected."""
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": "InvalidToken123"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_empty_token(self, client):
        """Test that empty JWT tokens are rejected."""
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": "Bearer "}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_malformed_token(self, client):
        """Test that malformed JWT tokens are rejected."""
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": "Bearer not.a.valid.jwt"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_wrong_secret(self, client, test_user):
        """Test that JWT tokens signed with wrong secret are rejected."""
        # Create a JWT with wrong secret
        wrong_secret = "wrong_secret_key"
        token = jwt.encode(
            {"sub": _b64(test_user.user_id), "iat": 1234567890, "exp": 1234567890 + 3600},
            wrong_secret,
            algorithm=settings.jwt_algorithm,
        )
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_wrong_algorithm(self, client, test_user):
        """Test that JWT tokens with wrong algorithm are rejected."""
        # Create a JWT with wrong algorithm
        token = jwt.encode(
            {"sub": _b64(test_user.user_id), "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm="HS512",  # Wrong algorithm
        )
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_expired_token(self, client, test_user):
        """Test that expired JWT tokens are rejected."""
        # Create an expired JWT
        token = jwt.encode(
            {"sub": _b64(test_user.user_id), "iat": 1234567890, "exp": 1234567890 - 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_future_issued_time(self, client, test_user):
        """Test that JWT tokens with future issued time are rejected."""
        import time
        
        # Create a JWT with future iat
        future_time = int(time.time()) + 3600
        token = jwt.encode(
            {"sub": _b64(test_user.user_id), "iat": future_time, "exp": future_time + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_missing_subject(self, client):
        """Test that JWT tokens without subject claim are rejected."""
        token = jwt.encode(
            {"iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_invalid_subject_encoding(self, client):
        """Test that JWT tokens with invalid subject encoding are rejected."""
        token = jwt.encode(
            {"sub": "invalid_base64!", "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_none_subject(self, client):
        """Test that JWT tokens with None subject are rejected."""
        token = jwt.encode(
            {"sub": None, "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_empty_subject(self, client):
        """Test that JWT tokens with empty subject are rejected."""
        token = jwt.encode(
            {"sub": "", "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_nonexistent_user(self, client):
        """Test that JWT tokens for non-existent users are rejected."""
        fake_user_id = b"fake_user_id_32_bytes_long"
        token = jwt.encode(
            {"sub": _b64(fake_user_id), "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_extra_claims(self, client, test_user):
        """Test that JWT tokens with extra claims are accepted."""
        # Create a JWT with extra claims
        token = jwt.encode(
            {
                "sub": _b64(test_user.user_id),
                "iat": 1234567890,
                "exp": 1234567890 + 3600,
                "extra_claim": "extra_value",
                "admin": True
            },
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == status.HTTP_200_OK

    def test_jwt_case_sensitivity(self, client, test_user):
        """Test that JWT validation is case sensitive for Bearer scheme."""
        token = jwt.encode(
            {"sub": _b64(test_user.user_id), "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        # Test different case variations
        for auth_header in [
            f"bearer {token}",  # lowercase
            f"BEARER {token}",  # uppercase
            f"Bearer{token}",   # no space
            f"Bearer  {token}", # double space
        ]:
            response = client.get(
                "/api/v1/users/me",
                headers={"Authorization": auth_header}
            )
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_whitespace(self, client, test_user):
        """Test that JWT tokens with leading/trailing whitespace are handled."""
        token = jwt.encode(
            {"sub": _b64(test_user.user_id), "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        # Test with whitespace
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer  {token}  "}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_multiple_authorization_headers(self, client, test_user):
        """Test behavior with multiple Authorization headers."""
        token = jwt.encode(
            {"sub": _b64(test_user.user_id), "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        # FastAPI should use the first Authorization header
        response = client.get(
            "/api/v1/users/me",
            headers=[
                ("Authorization", f"Bearer {token}"),
                ("Authorization", "Bearer invalid_token")
            ]
        )
        assert response.status_code == status.HTTP_200_OK

    def test_jwt_without_authorization_header(self, client):
        """Test that requests without Authorization header are rejected."""
        response = client.get("/api/v1/users/me")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_corrupted_payload(self, client):
        """Test that JWT tokens with corrupted payload are rejected."""
        # Create a JWT and corrupt the payload
        token = jwt.encode(
            {"sub": "test", "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        # Corrupt the payload by changing characters
        parts = token.split('.')
        corrupted_payload = parts[1][:-5] + "XXXXX"  # Corrupt the payload
        corrupted_token = f"{parts[0]}.{corrupted_payload}.{parts[2]}"
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {corrupted_token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_with_corrupted_signature(self, client):
        """Test that JWT tokens with corrupted signature are rejected."""
        # Create a JWT and corrupt the signature
        token = jwt.encode(
            {"sub": "test", "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        # Corrupt the signature by changing characters
        parts = token.split('.')
        corrupted_signature = parts[2][:-5] + "XXXXX"  # Corrupt the signature
        corrupted_token = f"{parts[0]}.{parts[1]}.{corrupted_signature}"
        
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {corrupted_token}"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestJWTTokenSecurity:
    """Test JWT token security aspects."""

    def test_jwt_token_not_logged_in_response(self, client):
        """Test that JWT tokens are not included in error responses."""
        response = client.get("/api/v1/users/me")
        
        # Ensure no sensitive information is leaked in error responses
        assert "token" not in response.text.lower()
        assert "jwt" not in response.text.lower()
        assert "bearer" not in response.text.lower()

    def test_jwt_token_validation_timing(self, client, test_user):
        """Test that JWT validation timing is consistent."""
        import time
        
        # Test with valid token
        token = jwt.encode(
            {"sub": _b64(test_user.user_id), "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        start_time = time.time()
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        valid_time = time.time() - start_time
        
        # Test with invalid token
        start_time = time.time()
        response = client.get(
            "/api/v1/users/me",
            headers={"Authorization": "Bearer invalid_token"}
        )
        invalid_time = time.time() - start_time
        
        # Both should complete quickly and not leak timing information
        assert valid_time < 1.0
        assert invalid_time < 1.0
        assert abs(valid_time - invalid_time) < 0.5  # Should be similar timing
