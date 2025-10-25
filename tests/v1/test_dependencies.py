# tests/v1/test_dependencies.py
"""Tests for API dependencies module."""

import base64
from unittest.mock import patch

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from jose import JWTError

from chorus_stage.api.v1.dependencies import (
    CurrentUserDep,
    SessionDep,
    _decode_user_id,
    get_current_user,
)
from chorus_stage.core.settings import settings
from chorus_stage.models import User


def _b64(data: bytes) -> str:
    """Helper to encode bytes to base64."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class TestDecodeUserId:
    """Test the _decode_user_id helper function."""

    def test_decode_valid_user_id(self):
        """Test decoding a valid base64 user ID."""
        user_id_bytes = b"test_user_id_32_bytes_long"
        encoded = _b64(user_id_bytes)
        
        result = _decode_user_id(encoded)
        assert result == user_id_bytes

    def test_decode_user_id_with_padding(self):
        """Test decoding a user ID that needs padding."""
        user_id_bytes = b"test_user_id_31_bytes"
        encoded = base64.urlsafe_b64encode(user_id_bytes).decode()
        # Remove padding to test padding restoration
        encoded_no_padding = encoded.rstrip("=")
        
        result = _decode_user_id(encoded_no_padding)
        assert result == user_id_bytes

    def test_decode_invalid_user_id(self):
        """Test decoding an invalid base64 user ID raises exception."""
        with pytest.raises(HTTPException) as exc_info:
            _decode_user_id("invalid_base64!")
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in exc_info.value.detail


class TestGetCurrentUser:
    """Test the get_current_user dependency function."""

    def test_get_current_user_success(self, db_session, test_user):
        """Test successful user retrieval with valid JWT."""
        # Create a valid JWT token
        from chorus_stage.api.v1.endpoints.auth import create_access_token
        token = create_access_token(test_user.user_id)
        
        # Mock the credentials
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        
        # Call the function
        result = get_current_user(credentials, db_session)
        
        assert result == test_user
        assert result.user_id == test_user.user_id

    def test_get_current_user_invalid_jwt(self, db_session):
        """Test get_current_user with invalid JWT token."""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid_token")
        
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials, db_session)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in exc_info.value.detail

    def test_get_current_user_missing_subject(self, db_session):
        """Test get_current_user with JWT missing subject claim."""
        # Create a JWT without 'sub' claim
        from jose import jwt
        token = jwt.encode(
            {"iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials, db_session)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in exc_info.value.detail

    def test_get_current_user_nonexistent_user(self, db_session):
        """Test get_current_user with valid JWT but user doesn't exist in DB."""
        # Create a JWT for a user that doesn't exist in the database
        from jose import jwt
        fake_user_id = b"fake_user_id_32_bytes_long"
        token = jwt.encode(
            {"sub": _b64(fake_user_id), "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials, db_session)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "User not found" in exc_info.value.detail

    def test_get_current_user_jwt_decode_error(self, db_session):
        """Test get_current_user with JWT decode error."""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="malformed.jwt.token")
        
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials, db_session)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in exc_info.value.detail

    def test_get_current_user_wrong_algorithm(self, db_session, test_user):
        """Test get_current_user with JWT signed with wrong algorithm."""
        from jose import jwt
        token = jwt.encode(
            {"sub": _b64(test_user.user_id), "iat": 1234567890, "exp": 1234567890 + 3600},
            settings.secret_key,
            algorithm="HS512",  # Wrong algorithm
        )
        
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials, db_session)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in exc_info.value.detail

    def test_get_current_user_expired_token(self, db_session, test_user):
        """Test get_current_user with expired JWT token."""
        from jose import jwt
        import time
        
        # Create an expired token
        token = jwt.encode(
            {"sub": _b64(test_user.user_id), "iat": 1234567890, "exp": 1234567890 - 3600},
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials, db_session)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in exc_info.value.detail


class TestTypeAliases:
    """Test that type aliases are properly defined."""
    
    def test_session_dep_type_alias(self):
        """Test SessionDep type alias is properly defined."""
        # This is more of a compile-time check, but we can verify the import works
        assert SessionDep is not None
        
    def test_current_user_dep_type_alias(self):
        """Test CurrentUserDep type alias is properly defined."""
        # This is more of a compile-time check, but we can verify the import works
        assert CurrentUserDep is not None
