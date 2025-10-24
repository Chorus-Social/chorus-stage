
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from chorus_stage.core.settings import settings
from chorus_stage.models import User, Community, SystemClock, CommunityMember
from chorus_stage.services.bridge import BridgeClient
from chorus_stage.api.v1.endpoints.auth import create_access_token
import json
import time
import itertools

_mock_day_seq_counter = itertools.count(100)

@pytest.fixture
def mock_bridge_client():
    mock_client = AsyncMock(spec=BridgeClient)
    mock_client.enabled = True
    mock_client.send_federation_envelope.return_value = True
    mock_client.create_community_envelope.return_value = b"serialized_community_envelope_bytes"
    mock_client.create_community_join_envelope.return_value = b"serialized_community_join_envelope_bytes" # Add this mock
    mock_client.create_community_leave_envelope.side_effect = AsyncMock(return_value=b"serialized_community_leave_envelope_bytes")
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
def mock_system_clock():
    clock = SystemClock(id=1, day_seq=next(_mock_day_seq_counter), hour_seq=0)
    with patch("chorus_stage.api.v1.endpoints.posts.get_system_clock", return_value=clock):
        yield clock

@pytest.fixture
def test_community(db_session: Session, mock_system_clock: SystemClock) -> Community:
    community = Community(
        internal_slug="test-community-slug",
        display_name="Test Community Name",
        description_md="Test Description",
        is_profile_like=False,
        order_index=mock_system_clock.day_seq,
    )
    db_session.add(community)
    db_session.commit()
    db_session.refresh(community)
    return community

@pytest.fixture
def test_community_member(db_session: Session, test_user_with_creation_day: User, test_community: Community) -> CommunityMember:
    from chorus_stage.models import CommunityMember
    member = CommunityMember(
        community_id=test_community.id,
        user_id=test_user_with_creation_day.user_id
    )
    db_session.add(member)
    db_session.commit()
    db_session.refresh(member)
    return member

@pytest.mark.asyncio
async def test_create_community_with_bridge_enabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
    mock_system_clock: SystemClock,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = True

    community_data = {
        "internal_slug": "test-community",
        "display_name": "Test Community",
        "description_md": "A community for testing",
    }

    with patch("chorus_stage.api.v1.endpoints.communities.get_current_user", return_value=test_user_with_creation_day):
        response = client.post("/api/v1/communities/", json=community_data, headers=auth_token_for_test_user)

        assert response.status_code == 201
        data = response.json()
        assert data["internal_slug"] == "test-community"

        # Verify BridgeClient.create_community_envelope was called with correct arguments
        mock_bridge_client.create_community_envelope.assert_called_once_with(
            community_id=data["id"],
            internal_slug=community_data["internal_slug"],
            display_name=community_data["display_name"],
            creation_day=data["order_index"],
            idempotency_key=f"community-create-{data['id']}-{data['order_index']}",
        )

        # Verify BridgeClient.send_federation_envelope was called with the result of create_community_envelope
        mock_bridge_client.send_federation_envelope.assert_called_once_with(
            b"serialized_community_envelope_bytes", # The dummy bytes returned by create_community_envelope mock
            idempotency_key=f"community-create-{data['id']}-{data['order_index']}",
        )

    settings.bridge_enabled = original_bridge_enabled

@pytest.mark.asyncio
async def test_create_community_with_bridge_disabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
    mock_system_clock: SystemClock,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = False
    mock_bridge_client.enabled = False

    community_data = {
        "internal_slug": "test-community-no-bridge",
        "display_name": "Test Community No Bridge",
        "description_md": "A community for testing without bridge",
    }

    with patch("chorus_stage.api.v1.endpoints.communities.get_current_user", return_value=test_user_with_creation_day):
        response = client.post("/api/v1/communities/", json=community_data, headers=auth_token_for_test_user)

        assert response.status_code == 201
        data = response.json()
        assert data["internal_slug"] == "test-community-no-bridge"

        # Verify BridgeClient.send_federation_envelope was NOT called
        mock_bridge_client.send_federation_envelope.assert_not_called()

    settings.bridge_enabled = original_bridge_enabled
    mock_bridge_client.enabled = True

@pytest.mark.asyncio
async def test_join_community_with_bridge_enabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
    mock_system_clock: SystemClock,
    test_community: Community,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = True

    with patch("chorus_stage.api.v1.endpoints.communities.get_current_user", return_value=test_user_with_creation_day):
        response = client.post(
            f"/api/v1/communities/{test_community.id}/join",
            headers=auth_token_for_test_user
        )

        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "joined"

        # Verify BridgeClient.create_community_join_envelope was called with correct arguments
        mock_bridge_client.create_community_join_envelope.assert_called_once_with(
            community_id=test_community.id,
            user_id_hex=test_user_with_creation_day.user_id.hex(),
            day_seq=mock_system_clock.day_seq,
            idempotency_key=f"community-join-{test_community.id}-{test_user_with_creation_day.user_id.hex()}-{mock_system_clock.day_seq}",
        )

        # Verify BridgeClient.send_federation_envelope was called with the result of create_community_join_envelope
        mock_bridge_client.send_federation_envelope.assert_called_once_with(
            b"serialized_community_join_envelope_bytes", # The dummy bytes returned by create_community_join_envelope mock
            idempotency_key=f"community-join-{test_community.id}-{test_user_with_creation_day.user_id.hex()}-{mock_system_clock.day_seq}",
        )

    settings.bridge_enabled = original_bridge_enabled

@pytest.mark.asyncio
async def test_join_community_with_bridge_disabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
    mock_system_clock: SystemClock,
    test_community: Community,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = False
    mock_bridge_client.enabled = False

    with patch("chorus_stage.api.v1.endpoints.communities.get_current_user", return_value=test_user_with_creation_day):
        response = client.post(
            f"/api/v1/communities/{test_community.id}/join",
            headers=auth_token_for_test_user
        )

        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "joined"

        # Verify BridgeClient.send_federation_envelope was NOT called
        mock_bridge_client.send_federation_envelope.assert_not_called()

    settings.bridge_enabled = original_bridge_enabled
    mock_bridge_client.enabled = True

@pytest.mark.asyncio
async def test_leave_community_with_bridge_enabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
    mock_system_clock: SystemClock,
    test_community: Community,
    test_community_member: CommunityMember,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = True

    with patch("chorus_stage.api.v1.endpoints.communities.get_current_user", return_value=test_user_with_creation_day):
        response = client.delete(
            f"/api/v1/communities/{test_community.id}/leave",
            headers=auth_token_for_test_user
        )

        assert response.status_code == 204

        # Verify BridgeClient.create_community_leave_envelope was called with correct arguments
        mock_bridge_client.create_community_leave_envelope.assert_called_once_with(
            community_id=test_community.id,
            user_id_hex=test_user_with_creation_day.user_id.hex(),
            day_seq=mock_system_clock.day_seq,
            idempotency_key=f"community-leave-{test_community.id}-{test_user_with_creation_day.user_id.hex()}-{mock_system_clock.day_seq}",
        )

        # Verify BridgeClient.send_federation_envelope was called with the result of create_community_leave_envelope
        mock_bridge_client.send_federation_envelope.assert_called_once_with(
            b"serialized_community_leave_envelope_bytes", # The dummy bytes returned by create_community_leave_envelope mock
            idempotency_key=f"community-leave-{test_community.id}-{test_user_with_creation_day.user_id.hex()}-{mock_system_clock.day_seq}",
        )

    settings.bridge_enabled = original_bridge_enabled

@pytest.mark.asyncio
async def test_leave_community_with_bridge_disabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
    mock_system_clock: SystemClock,
    test_community: Community,
    test_community_member: CommunityMember,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = False
    mock_bridge_client.enabled = False

    with patch("chorus_stage.api.v1.endpoints.communities.get_current_user", return_value=test_user_with_creation_day):
        response = client.delete(
            f"/api/v1/communities/{test_community.id}/leave",
            headers=auth_token_for_test_user
        )

        assert response.status_code == 204

        # Verify BridgeClient.send_federation_envelope was NOT called
        mock_bridge_client.send_federation_envelope.assert_not_called()

    settings.bridge_enabled = original_bridge_enabled
    mock_bridge_client.enabled = True
