
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from chorus_stage.core.settings import settings
from chorus_stage.models import Post, User, ModerationCase, ModerationVote
from chorus_stage.services.bridge import BridgeClient
from chorus_stage.api.v1.endpoints.auth import create_access_token
import hashlib

@pytest.fixture
def mock_bridge_client():
    mock_client = AsyncMock(spec=BridgeClient)
    mock_client.enabled = True
    mock_client.anchor_moderation_event.return_value = True
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

@pytest.fixture
def test_post_for_moderation(db_session: Session, test_user_with_creation_day: User) -> Post:
    post = Post(
        order_index=1,
        author_user_id=test_user_with_creation_day.user_id,
        author_pubkey=test_user_with_creation_day.pubkey,
        body_md="Content to be moderated",
        content_hash=hashlib.sha256(b"Content to be moderated").digest(),
        moderation_state=0,
        harmful_vote_count=0,
    )
    db_session.add(post)
    db_session.commit()
    db_session.refresh(post)
    return post

@pytest.fixture
def moderation_case_for_post(db_session: Session, test_post_for_moderation: Post) -> ModerationCase:
    case = ModerationCase(
        post_id=test_post_for_moderation.id,
        community_id=1, # Assuming a default community exists
        state=0,
        opened_order_index=1,
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case

@pytest.mark.asyncio
async def test_vote_on_moderation_with_bridge_enabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
    test_post_for_moderation: Post,
    moderation_case_for_post: ModerationCase,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = True

    with (
        patch("chorus_stage.api.v1.endpoints.moderation.get_current_user", return_value=test_user_with_creation_day),
        patch("chorus_stage.api.v1.endpoints.moderation.ModerationService.update_moderation_state", return_value=None),
    ):

        response = client.post(
            f"/api/v1/moderation/vote?post_id={test_post_for_moderation.id}&is_harmful=true",
            headers=auth_token_for_test_user
        )

        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "vote_recorded"

        # Verify BridgeClient.anchor_moderation_event was called with correct arguments
        mock_bridge_client.anchor_moderation_event.assert_called_once()
        called_event_data = mock_bridge_client.anchor_moderation_event.call_args[0][0]
        assert called_event_data["post_id"] == test_post_for_moderation.id
        assert called_event_data["voter_user_id"] == test_user_with_creation_day.user_id.hex()
        assert called_event_data["choice"] == 1 # is_harmful=true

    settings.bridge_enabled = original_bridge_enabled

@pytest.mark.asyncio
async def test_vote_on_moderation_with_bridge_disabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
    test_post_for_moderation: Post,
    moderation_case_for_post: ModerationCase,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = False
    mock_bridge_client.enabled = False

    with (
        patch("chorus_stage.api.v1.endpoints.moderation.get_current_user", return_value=test_user_with_creation_day),
        patch("chorus_stage.api.v1.endpoints.moderation.ModerationService.update_moderation_state", return_value=None),
    ):

        response = client.post(
            f"/api/v1/moderation/vote?post_id={test_post_for_moderation.id}&is_harmful=false",
            headers=auth_token_for_test_user
        )

        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "vote_recorded"

        # Verify BridgeClient.anchor_moderation_event was NOT called
        mock_bridge_client.anchor_moderation_event.assert_not_called()

    settings.bridge_enabled = original_bridge_enabled
    mock_bridge_client.enabled = True
