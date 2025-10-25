# tests/v1/test_posts_helpers.py
"""Tests for post helper functions."""

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from chorus_stage.api.v1.endpoints.posts import (
    _create_federation_envelope,
    _get_community_info,
    _get_parent_post,
    _handle_bridge_registration,
    _validate_content_hash,
    _validate_post_pow,
)
from chorus_stage.models import Community, Post, SystemClock, User
from chorus_stage.schemas.post import PostCreate


class TestValidatePostPow:
    """Test the _validate_post_pow helper function."""

    def test_validate_pow_success(self, test_user, mock_pow_service):
        """Test successful PoW validation."""
        post_data = PostCreate(
            content_md="Test content",
            content_hash=hashlib.sha256(b"Test content").hexdigest(),
            pow_nonce="test_nonce",
            pow_difficulty=20,
            pow_hash_algorithm="blake3"
        )
        
        # Mock pow service to return success
        mock_pow_service.difficulties = {"post": 20}
        mock_pow_service.is_pow_replay.return_value = False
        mock_pow_service.verify_pow.return_value = True
        
        # Should not raise exception
        _validate_post_pow(post_data, test_user, mock_pow_service)

    def test_validate_pow_insufficient_difficulty(self, test_user, mock_pow_service):
        """Test PoW validation with insufficient difficulty."""
        post_data = PostCreate(
            content_md="Test content",
            content_hash=hashlib.sha256(b"Test content").hexdigest(),
            pow_nonce="test_nonce",
            pow_difficulty=15,  # Lower than required
            pow_hash_algorithm="blake3"
        )
        
        mock_pow_service.difficulties = {"post": 20}
        
        with pytest.raises(HTTPException) as exc_info:
            _validate_post_pow(post_data, test_user, mock_pow_service)
        
        assert exc_info.value.status_code == 400
        assert "Insufficient proof-of-work difficulty" in exc_info.value.detail

    def test_validate_pow_replay_detected(self, test_user, mock_pow_service):
        """Test PoW validation with replay detection."""
        post_data = PostCreate(
            content_md="Test content",
            content_hash=hashlib.sha256(b"Test content").hexdigest(),
            pow_nonce="test_nonce",
            pow_difficulty=20,
            pow_hash_algorithm="blake3"
        )
        
        mock_pow_service.difficulties = {"post": 20}
        mock_pow_service.is_pow_replay.return_value = True  # Replay detected
        
        with pytest.raises(HTTPException) as exc_info:
            _validate_post_pow(post_data, test_user, mock_pow_service)
        
        assert exc_info.value.status_code == 429
        assert "Proof of work nonce has already been used" in exc_info.value.detail

    def test_validate_pow_invalid_proof(self, test_user, mock_pow_service):
        """Test PoW validation with invalid proof."""
        post_data = PostCreate(
            content_md="Test content",
            content_hash=hashlib.sha256(b"Test content").hexdigest(),
            pow_nonce="test_nonce",
            pow_difficulty=20,
            pow_hash_algorithm="blake3"
        )
        
        mock_pow_service.difficulties = {"post": 20}
        mock_pow_service.is_pow_replay.return_value = False
        mock_pow_service.verify_pow.return_value = False  # Invalid proof
        
        with pytest.raises(HTTPException) as exc_info:
            _validate_post_pow(post_data, test_user, mock_pow_service)
        
        assert exc_info.value.status_code == 400
        assert "Invalid proof of work" in exc_info.value.detail


class TestValidateContentHash:
    """Test the _validate_content_hash helper function."""

    def test_validate_content_hash_success(self):
        """Test successful content hash validation."""
        content = "Test content"
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        post_data = PostCreate(
            content_md=content,
            content_hash=content_hash,
            pow_nonce="test",
            pow_difficulty=20,
            pow_hash_algorithm="blake3"
        )
        
        result = _validate_content_hash(post_data)
        assert result == hashlib.sha256(content.encode()).digest()

    def test_validate_content_hash_mismatch(self):
        """Test content hash validation with mismatched hash."""
        content = "Test content"
        wrong_hash = hashlib.sha256(b"Different content").hexdigest()
        
        post_data = PostCreate(
            content_md=content,
            content_hash=wrong_hash,
            pow_nonce="test",
            pow_difficulty=20,
            pow_hash_algorithm="blake3"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            _validate_content_hash(post_data)
        
        assert exc_info.value.status_code == 400
        assert "Content hash does not match content" in exc_info.value.detail

    def test_validate_content_hash_invalid_hex(self):
        """Test content hash validation with invalid hex."""
        post_data = PostCreate(
            content_md="Test content",
            content_hash="invalid_hex_string",
            pow_nonce="test",
            pow_difficulty=20,
            pow_hash_algorithm="blake3"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            _validate_content_hash(post_data)
        
        assert exc_info.value.status_code == 400
        assert "Content hash does not match content" in exc_info.value.detail


class TestGetParentPost:
    """Test the _get_parent_post helper function."""

    def test_get_parent_post_none(self, db_session):
        """Test getting parent post when parent_post_id is None."""
        parent, parent_federation_id = _get_parent_post(db_session, None)
        
        assert parent is None
        assert parent_federation_id is None

    def test_get_parent_post_success(self, db_session, test_user):
        """Test successful parent post retrieval."""
        # Create a parent post
        parent_post = Post(
            order_index=1,
            author_user_id=test_user.user_id,
            author_pubkey=test_user.pubkey,
            body_md="Parent post",
            content_hash=b"parent_hash",
            moderation_state=0,
            harmful_vote_count=0,
        )
        db_session.add(parent_post)
        db_session.commit()
        db_session.refresh(parent_post)
        
        parent, parent_federation_id = _get_parent_post(db_session, parent_post.id)
        
        assert parent == parent_post
        assert parent_federation_id is None

    def test_get_parent_post_with_federation_id(self, db_session, test_user):
        """Test parent post retrieval with federation ID."""
        # Create a parent post with federation ID
        federation_id = b"federation_post_id"
        parent_post = Post(
            order_index=1,
            author_user_id=test_user.user_id,
            author_pubkey=test_user.pubkey,
            body_md="Parent post",
            content_hash=b"parent_hash",
            moderation_state=0,
            harmful_vote_count=0,
            federation_post_id=federation_id,
        )
        db_session.add(parent_post)
        db_session.commit()
        db_session.refresh(parent_post)
        
        parent, parent_federation_id = _get_parent_post(db_session, parent_post.id)
        
        assert parent == parent_post
        assert parent_federation_id == federation_id.hex()

    def test_get_parent_post_not_found(self, db_session):
        """Test parent post retrieval when post doesn't exist."""
        with pytest.raises(HTTPException) as exc_info:
            _get_parent_post(db_session, 99999)
        
        assert exc_info.value.status_code == 404
        assert "Parent post not found" in exc_info.value.detail

    def test_get_parent_post_deleted(self, db_session, test_user):
        """Test parent post retrieval when post is deleted."""
        # Create a deleted parent post
        parent_post = Post(
            order_index=1,
            author_user_id=test_user.user_id,
            author_pubkey=test_user.pubkey,
            body_md="Parent post",
            content_hash=b"parent_hash",
            moderation_state=0,
            harmful_vote_count=0,
            deleted=True,
        )
        db_session.add(parent_post)
        db_session.commit()
        db_session.refresh(parent_post)
        
        with pytest.raises(HTTPException) as exc_info:
            _get_parent_post(db_session, parent_post.id)
        
        assert exc_info.value.status_code == 404
        assert "Parent post not found" in exc_info.value.detail


class TestGetCommunityInfo:
    """Test the _get_community_info helper function."""

    def test_get_community_info_none(self, db_session):
        """Test getting community info when community_slug is None."""
        community_id, community_slug = _get_community_info(db_session, None)
        
        assert community_id is None
        assert community_slug is None

    def test_get_community_info_success(self, db_session):
        """Test successful community info retrieval."""
        # Create a community
        community = Community(
            internal_slug="test-community",
            display_name="Test Community",
            description_md="Test description",
            is_profile_like=False,
            order_index=1,
        )
        db_session.add(community)
        db_session.commit()
        db_session.refresh(community)
        
        community_id, community_slug = _get_community_info(db_session, "test-community")
        
        assert community_id == community.id
        assert community_slug == "test-community"

    def test_get_community_info_not_found(self, db_session):
        """Test community info retrieval when community doesn't exist."""
        with pytest.raises(HTTPException) as exc_info:
            _get_community_info(db_session, "nonexistent-community")
        
        assert exc_info.value.status_code == 404
        assert "Community not found" in exc_info.value.detail


class TestHandleBridgeRegistration:
    """Test the _handle_bridge_registration helper function."""

    @pytest.mark.asyncio
    async def test_bridge_registration_success(self, test_user):
        """Test successful bridge registration."""
        mock_bridge_client = AsyncMock()
        mock_result = MagicMock()
        mock_result.order_index = 42
        mock_result.post_id = b"federation_post_id"
        mock_result.origin_instance = "test-instance"
        mock_bridge_client.register_post.return_value = mock_result
        
        post_data = PostCreate(
            content_md="Test content",
            content_hash=hashlib.sha256(b"Test content").hexdigest(),
            pow_nonce="test_nonce",
            pow_difficulty=20,
            pow_hash_algorithm="blake3"
        )
        
        result = await _handle_bridge_registration(
            mock_bridge_client, test_user, b"computed_hash", post_data, "test-community", "parent_id"
        )
        
        assert result == (42, b"federation_post_id", "test-instance")
        mock_bridge_client.register_post.assert_called_once()

    @pytest.mark.asyncio
    async def test_bridge_registration_disabled(self, test_user):
        """Test bridge registration when bridge is disabled."""
        from chorus_stage.services.bridge import BridgeDisabledError
        
        mock_bridge_client = AsyncMock()
        mock_bridge_client.register_post.side_effect = BridgeDisabledError("Bridge disabled")
        
        post_data = PostCreate(
            content_md="Test content",
            content_hash=hashlib.sha256(b"Test content").hexdigest(),
            pow_nonce="test_nonce",
            pow_difficulty=20,
            pow_hash_algorithm="blake3"
        )
        
        result = await _handle_bridge_registration(
            mock_bridge_client, test_user, b"computed_hash", post_data, "test-community", "parent_id"
        )
        
        assert result == (None, None, None)

    @pytest.mark.asyncio
    async def test_bridge_registration_error(self, test_user):
        """Test bridge registration with bridge error."""
        from chorus_stage.services.bridge import BridgeError
        
        mock_bridge_client = AsyncMock()
        mock_bridge_client.register_post.side_effect = BridgeError("Bridge error")
        
        post_data = PostCreate(
            content_md="Test content",
            content_hash=hashlib.sha256(b"Test content").hexdigest(),
            pow_nonce="test_nonce",
            pow_difficulty=20,
            pow_hash_algorithm="blake3"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await _handle_bridge_registration(
                mock_bridge_client, test_user, b"computed_hash", post_data, "test-community", "parent_id"
            )
        
        assert exc_info.value.status_code == 503
        assert "Bridge registration failed" in exc_info.value.detail


class TestCreateFederationEnvelope:
    """Test the _create_federation_envelope helper function."""

    @pytest.mark.asyncio
    async def test_federation_envelope_bridge_disabled(self, db_session, test_user):
        """Test federation envelope creation when bridge is disabled."""
        mock_bridge_client = AsyncMock()
        mock_bridge_client.enabled = False
        
        clock = SystemClock(id=1, day_seq=1, hour_seq=0)
        
        await _create_federation_envelope(
            mock_bridge_client, test_user, b"computed_hash", 42, clock, b"federation_id", db_session
        )
        
        # Should complete without error and not call bridge methods
        mock_bridge_client.send_federation_envelope.assert_not_called()

    @pytest.mark.asyncio
    async def test_federation_envelope_success(self, db_session, test_user):
        """Test successful federation envelope creation."""
        mock_bridge_client = AsyncMock()
        mock_bridge_client.enabled = True
        
        clock = SystemClock(id=1, day_seq=1, hour_seq=0)
        
        with patch('chorus_stage.api.v1.endpoints.posts.secrets') as mock_secrets, \
             patch('chorus_stage.api.v1.endpoints.posts.time') as mock_time:
            
            mock_secrets.token_hex.return_value = "test_token"
            mock_time.time.return_value = 1234567890
            
            await _create_federation_envelope(
                mock_bridge_client, test_user, b"computed_hash", 42, clock, b"federation_id", db_session
            )
            
            mock_bridge_client.send_federation_envelope.assert_called_once()

    @pytest.mark.asyncio
    async def test_federation_envelope_protobuf_error(self, db_session, test_user):
        """Test federation envelope creation with protobuf error."""
        mock_bridge_client = AsyncMock()
        mock_bridge_client.enabled = True
        
        clock = SystemClock(id=1, day_seq=1, hour_seq=0)
        
        with patch('chorus_stage.api.v1.endpoints.posts.federation_pb2') as mock_pb2, \
             patch('builtins.print') as mock_print:
            
            # Simulate AttributeError when accessing protobuf classes
            mock_pb2.PostAnnouncement = None
            mock_pb2.FederationEnvelope = None
            
            await _create_federation_envelope(
                mock_bridge_client, test_user, b"computed_hash", 42, clock, b"federation_id", db_session
            )
            
            mock_print.assert_called_once_with("Warning: Protobuf classes not available, skipping federation")
