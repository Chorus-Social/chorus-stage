import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from chorus_stage.core.settings import settings
from chorus_stage.models import Post, User
from chorus_stage.services.bridge import BridgeClient, BridgePostRegistration, BridgePostSubmission
from chorus_stage.api.v1.endpoints.auth import create_access_token
import hashlib
import base64

@pytest.fixture
def mock_bridge_client():
    mock_client = AsyncMock(spec=BridgeClient)
    mock_client.enabled = True
    mock_client.register_post.return_value = BridgePostRegistration(
        order_index=999,
        post_id=b"federation_post_id_from_bridge",
        origin_instance="bridge.chorus.test",
        day_number=123
    )
    with patch("chorus_stage.services.bridge.get_bridge_client", return_value=mock_client):
        yield mock_client

@pytest.fixture
def test_user_with_creation_day(db_session: Session) -> User:
    user = User(
        user_id=b"\x01" * 32,
        pubkey=b"\x02" * 32,
        display_name="Test User",
        accent_color="#123456",
        creation_day=100 # Example creation day
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture
def auth_token_for_test_user(test_user_with_creation_day: User) -> dict[str, str]:
    token = create_access_token(test_user_with_creation_day.user_id)
    return {"Authorization": f"Bearer {token}"}

@pytest.mark.asyncio
async def test_create_post_with_bridge_enabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    mock_pow_service,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = True

    content_md = "Test post content for bridge"
    content_hash = hashlib.sha256(content_md.encode()).hexdigest()
    pow_nonce = "test_pow_nonce"

    payload = {
        "content_md": content_md,
        "content_hash": content_hash,
        "pow_nonce": pow_nonce,
        "pow_difficulty": 20,
        "parent_post_id": None,
        "community_internal_slug": None,
    }

    with (
        patch("chorus_stage.api.v1.endpoints.posts.get_pow_service", return_value=mock_pow_service),
        patch("chorus_stage.api.v1.endpoints.posts.get_current_user", return_value=test_user_with_creation_day),
    ):

        response = client.post("/api/v1/posts/", json=payload, headers=auth_token_for_test_user)

        assert response.status_code == 201
        data = response.json()

        # Verify BridgeClient.register_post was called with correct arguments
        mock_bridge_client.register_post.assert_called_once()
        called_submission: BridgePostSubmission = mock_bridge_client.register_post.call_args[0][0]
        assert called_submission.author_pubkey_hex == test_user_with_creation_day.pubkey.hex()
        assert called_submission.content_hash_hex == content_hash
        assert called_submission.body_md == content_md
        assert called_submission.pow_nonce == pow_nonce

        # Verify post was created with data from bridge registration
        assert data["order_index"] == 999
        assert data["federation_post_id"] == b"federation_post_id_from_bridge".hex()
        assert data["federation_origin"] == "bridge.chorus.test"

        # Verify post in DB
        post = db_session.query(Post).filter(Post.content_hash == bytes.fromhex(content_hash)).first()
        assert post is not None
        assert post.order_index == 999
        assert post.federation_post_id == b"federation_post_id_from_bridge"
        assert post.federation_origin == "bridge.chorus.test"

        # Verify ActivityPub export was called
        mock_bridge_client.export_activitypub.assert_called_once()
        called_export_payload = mock_bridge_client.export_activitypub.call_args[0][0]
        assert called_export_payload["chorus_post"]["post_id"] == post.content_hash.hex()
        assert called_export_payload["chorus_post"]["author_pubkey_hash"] == test_user_with_creation_day.pubkey.hex()
        assert called_export_payload["chorus_post"]["body_md"] == content_md
        assert called_export_payload["chorus_post"]["day_number"] == post.order_index
        assert called_export_payload["chorus_post"]["community"] is None
        assert called_export_payload["signature"] == "placeholder_signature"

    settings.bridge_enabled = original_bridge_enabled

@pytest.mark.asyncio
async def test_create_post_with_bridge_disabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    mock_pow_service,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = False
    mock_bridge_client.enabled = False

    content_md = "Test post content without bridge"
    content_hash = hashlib.sha256(content_md.encode()).hexdigest()
    pow_nonce = "test_pow_nonce_disabled"

    payload = {
        "content_md": content_md,
        "content_hash": content_hash,
        "pow_nonce": pow_nonce,
        "pow_difficulty": 20,
        "parent_post_id": None,
        "community_internal_slug": None,
    }

    with (
        patch("chorus_stage.api.v1.endpoints.posts.get_pow_service", return_value=mock_pow_service),
        patch("chorus_stage.api.v1.endpoints.posts.get_current_user", return_value=test_user_with_creation_day),
        patch("chorus_stage.api.v1.endpoints.posts.get_system_clock") as mock_get_system_clock,
    ):
        mock_clock = AsyncMock()
        mock_clock.day_seq = 500 # Simulate local clock
        mock_get_system_clock.return_value = mock_clock

        response = client.post("/api/v1/posts/", json=payload, headers=auth_token_for_test_user)

        assert response.status_code == 201
        data = response.json()

        # Verify BridgeClient.register_post was NOT called
        mock_bridge_client.register_post.assert_not_called()
        mock_bridge_client.export_activitypub.assert_not_called()

        # Verify post was created with local data
        assert data["order_index"] == 500
        assert data["federation_post_id"] is None
        assert data["federation_origin"] is None

        # Verify post in DB
        post = db_session.query(Post).filter(Post.content_hash == bytes.fromhex(content_hash)).first()
        assert post is not None
        assert post.order_index == 500
        assert post.federation_post_id is None
        assert post.federation_origin is None

    settings.bridge_enabled = original_bridge_enabled
    mock_bridge_client.enabled = True