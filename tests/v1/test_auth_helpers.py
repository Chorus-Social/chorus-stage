# tests/v1/test_auth_helpers.py
"""Tests for auth helper functions."""

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from chorus_stage.api.v1.endpoints.auth import (
    _create_or_update_user,
    _federate_user_registration,
    _get_creation_day_from_bridge,
)
from chorus_stage.core.settings import settings
from chorus_stage.models import User, UserState


def _b64(data: bytes) -> str:
    """Helper to encode bytes to base64."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class TestGetCreationDayFromBridge:
    """Test the _get_creation_day_from_bridge helper function."""

    @pytest.mark.asyncio
    async def test_bridge_disabled_returns_zero(self):
        """Test that when bridge is disabled, returns 0."""
        with patch.object(settings, 'bridge_enabled', False):
            result = await _get_creation_day_from_bridge()
            assert result == 0

    @pytest.mark.asyncio
    async def test_bridge_enabled_success(self):
        """Test successful day proof fetching from bridge."""
        mock_day_proof = MagicMock()
        mock_day_proof.day_number = 42
        
        mock_bridge_client = AsyncMock()
        mock_bridge_client.fetch_day_proof.return_value = mock_day_proof
        
        with patch.object(settings, 'bridge_enabled', True), \
             patch('chorus_stage.api.v1.endpoints.auth.get_bridge_client', return_value=mock_bridge_client):
            
            result = await _get_creation_day_from_bridge()
            assert result == 42
            mock_bridge_client.fetch_day_proof.assert_called_once_with(day=0)

    @pytest.mark.asyncio
    async def test_bridge_enabled_no_day_proof(self):
        """Test when bridge is enabled but returns no day proof."""
        mock_bridge_client = AsyncMock()
        mock_bridge_client.fetch_day_proof.return_value = None
        
        with patch.object(settings, 'bridge_enabled', True), \
             patch('chorus_stage.api.v1.endpoints.auth.get_bridge_client', return_value=mock_bridge_client):
            
            result = await _get_creation_day_from_bridge()
            assert result == 0

    @pytest.mark.asyncio
    async def test_bridge_disabled_error(self):
        """Test when bridge is disabled via BridgeDisabledError."""
        mock_bridge_client = AsyncMock()
        from chorus_stage.services.bridge import BridgeDisabledError
        mock_bridge_client.fetch_day_proof.side_effect = BridgeDisabledError("Bridge disabled")
        
        with patch.object(settings, 'bridge_enabled', True), \
             patch('chorus_stage.api.v1.endpoints.auth.get_bridge_client', return_value=mock_bridge_client):
            
            result = await _get_creation_day_from_bridge()
            assert result == 0

    @pytest.mark.asyncio
    async def test_bridge_other_error(self):
        """Test when bridge throws other exception."""
        mock_bridge_client = AsyncMock()
        mock_bridge_client.fetch_day_proof.side_effect = Exception("Network error")
        
        with patch.object(settings, 'bridge_enabled', True), \
             patch('chorus_stage.api.v1.endpoints.auth.get_bridge_client', return_value=mock_bridge_client), \
             patch('builtins.print') as mock_print:
            
            result = await _get_creation_day_from_bridge()
            assert result == 0
            mock_print.assert_called_once()


class TestCreateOrUpdateUser:
    """Test the _create_or_update_user helper function."""

    def test_create_new_user(self, db_session):
        """Test creating a new user."""
        from chorus_stage.schemas.user import RegisterRequest
        
        pubkey_bytes = b"test_pubkey_32_bytes_long"
        user_hash = b"test_user_hash_32_bytes"
        creation_day = 42
        
        payload = RegisterRequest(
            pubkey=_b64(pubkey_bytes),
            display_name="Test User",
            accent_color="#FF5733",
            pow={"nonce": "test", "difficulty": 15, "target": "test"},
            proof={"challenge": "test", "signature": "test"}
        )
        
        user, created = _create_or_update_user(db_session, pubkey_bytes, user_hash, payload, creation_day)
        
        assert created is True
        assert user.user_id == user_hash
        assert user.pubkey == pubkey_bytes
        assert user.display_name == "Test User"
        assert user.accent_color == "#FF5733"
        assert user.creation_day == 42
        assert user.state is not None
        assert user.state.user_id == user_hash

    def test_update_existing_user(self, db_session, test_user):
        """Test updating an existing user."""
        from chorus_stage.schemas.user import RegisterRequest
        
        user_hash = b"test_user_hash_32_bytes"
        creation_day = 42
        
        payload = RegisterRequest(
            pubkey=_b64(test_user.pubkey),
            display_name="Updated Name",
            accent_color="#00FF00",
            pow={"nonce": "test", "difficulty": 15, "target": "test"},
            proof={"challenge": "test", "signature": "test"}
        )
        
        user, created = _create_or_update_user(db_session, test_user.pubkey, user_hash, payload, creation_day)
        
        assert created is False
        assert user == test_user
        assert user.display_name == "Updated Name"
        assert user.accent_color == "#00FF00"

    def test_update_existing_user_without_state(self, db_session):
        """Test updating user that doesn't have state."""
        from chorus_stage.schemas.user import RegisterRequest
        
        # Create user without state
        pubkey_bytes = b"test_pubkey_32_bytes_long"
        user_hash = b"test_user_hash_32_bytes"
        user = User(
            user_id=user_hash,
            pubkey=pubkey_bytes,
            display_name="Original Name",
            accent_color="#FF0000",
            creation_day=0,
        )
        db_session.add(user)
        db_session.commit()
        
        payload = RegisterRequest(
            pubkey=_b64(pubkey_bytes),
            display_name="Updated Name",
            accent_color="#00FF00",
            pow={"nonce": "test", "difficulty": 15, "target": "test"},
            proof={"challenge": "test", "signature": "test"}
        )
        
        user, created = _create_or_update_user(db_session, pubkey_bytes, user_hash, payload, 42)
        
        assert created is False
        assert user.display_name == "Updated Name"
        assert user.accent_color == "#00FF00"
        assert user.state is not None
        assert user.state.user_id == user_hash


class TestFederateUserRegistration:
    """Test the _federate_user_registration helper function."""

    @pytest.mark.asyncio
    async def test_bridge_disabled(self, db_session):
        """Test federation when bridge is disabled."""
        with patch.object(settings, 'bridge_enabled', False):
            await _federate_user_registration(b"user_hash", b"pubkey", 42, db_session)
            # Should complete without error

    @pytest.mark.asyncio
    async def test_bridge_enabled_success(self, db_session):
        """Test successful federation."""
        mock_bridge_client = AsyncMock()
        mock_envelope = b"federation_envelope_data"
        mock_bridge_client.create_user_registration_envelope.return_value = mock_envelope
        
        with patch.object(settings, 'bridge_enabled', True), \
             patch('chorus_stage.api.v1.endpoints.auth.get_bridge_client', return_value=mock_bridge_client):
            
            await _federate_user_registration(b"user_hash", b"pubkey", 42, db_session)
            
            mock_bridge_client.create_user_registration_envelope.assert_called_once()
            mock_bridge_client.send_federation_envelope.assert_called_once()

    @pytest.mark.asyncio
    async def test_bridge_disabled_error(self, db_session):
        """Test federation when bridge throws BridgeDisabledError."""
        from chorus_stage.services.bridge import BridgeDisabledError
        
        mock_bridge_client = AsyncMock()
        mock_bridge_client.create_user_registration_envelope.side_effect = BridgeDisabledError("Bridge disabled")
        
        with patch.object(settings, 'bridge_enabled', True), \
             patch('chorus_stage.api.v1.endpoints.auth.get_bridge_client', return_value=mock_bridge_client), \
             patch('builtins.print') as mock_print:
            
            await _federate_user_registration(b"user_hash", b"pubkey", 42, db_session)
            
            mock_print.assert_called_once_with("Bridge is disabled, user registration not federated.")

    @pytest.mark.asyncio
    async def test_bridge_other_error(self, db_session):
        """Test federation when bridge throws other exception."""
        mock_bridge_client = AsyncMock()
        mock_bridge_client.create_user_registration_envelope.side_effect = Exception("Network error")
        
        with patch.object(settings, 'bridge_enabled', True), \
             patch('chorus_stage.api.v1.endpoints.auth.get_bridge_client', return_value=mock_bridge_client), \
             patch('builtins.print') as mock_print:
            
            await _federate_user_registration(b"user_hash", b"pubkey", 42, db_session)
            
            mock_print.assert_called_once()
