
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from chorus_stage.core.settings import settings
from chorus_stage.models import User, DirectMessage, SystemClock
from chorus_stage.services.bridge import BridgeClient
from chorus_stage.api.v1.endpoints.auth import create_access_token
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
from chorus_stage.core.settings import settings
import hashlib
import base64
import itertools

_mock_day_seq_counter = itertools.count(100)

@pytest.fixture
def mock_bridge_client():
    mock_client = AsyncMock(spec=BridgeClient)
    mock_client.enabled = True
    mock_client.send_federation_envelope.return_value = True
    mock_client.create_direct_message_sent_envelope.return_value = b"serialized_dm_sent_envelope_bytes" # Add this mock
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
def other_user_with_creation_day(db_session: Session) -> User:
    user = User(
        user_id=b"\x03" * 32,
        pubkey=b"\x04" * 32,
        display_name="Other User",
        accent_color="#654321",
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
    with patch("chorus_stage.api.v1.endpoints.messages.get_system_clock", return_value=clock):
        yield clock

@pytest.mark.asyncio
async def test_send_message_with_bridge_enabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
    other_user_with_creation_day: User,
    mock_system_clock: SystemClock,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = True

    message_data = {
        "recipient_pubkey_hex": other_user_with_creation_day.pubkey.hex(),
        "ciphertext": base64.b64encode(b"encrypted_message").decode(),
        "header_blob": None,
        "pow_nonce": "test_nonce",
    }

    with (
        patch("chorus_stage.api.v1.endpoints.messages.get_current_user", return_value=test_user_with_creation_day),
        patch("chorus_stage.api.v1.endpoints.messages.PowService.verify_pow", return_value=True),
        patch("chorus_stage.api.v1.endpoints.messages.PowService.is_pow_replay", return_value=False),
        patch("chorus_stage.api.v1.endpoints.messages.PowService.register_pow", return_value=None),
    ):
        response = client.post("/api/v1/messages/", json=message_data, headers=auth_token_for_test_user)

        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "message_sent"

        # Verify BridgeClient.create_direct_message_sent_envelope was called with correct arguments
        mock_bridge_client.create_direct_message_sent_envelope.assert_called_once_with(
            message_id=data["message_id"],
            sender_user_id_hex=test_user_with_creation_day.user_id.hex(),
            recipient_user_id_hex=other_user_with_creation_day.user_id.hex(),
            day_seq=mock_system_clock.day_seq + 1,
            idempotency_key=f"dm-sent-{data['message_id']}-{test_user_with_creation_day.user_id.hex()}-{mock_system_clock.day_seq + 1}",
        )

        # Verify BridgeClient.send_federation_envelope was called with the result of create_direct_message_sent_envelope
        mock_bridge_client.send_federation_envelope.assert_called_once_with(
            b"serialized_dm_sent_envelope_bytes", # The dummy bytes returned by create_direct_message_sent_envelope mock
            idempotency_key=f"dm-sent-{data['message_id']}-{test_user_with_creation_day.user_id.hex()}-{mock_system_clock.day_seq + 1}",
        )

    settings.bridge_enabled = original_bridge_enabled

@pytest.mark.asyncio
async def test_send_message_with_bridge_disabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    auth_token_for_test_user: dict[str, str],
    test_user_with_creation_day: User,
    other_user_with_creation_day: User,
    mock_system_clock: SystemClock,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = False
    mock_bridge_client.enabled = False

    message_data = {
        "recipient_pubkey_hex": other_user_with_creation_day.pubkey.hex(),
        "ciphertext": base64.b64encode(b"encrypted_message_no_bridge").decode(),
        "header_blob": None,
        "pow_nonce": "test_nonce_no_bridge",
    }

    with (
        patch("chorus_stage.api.v1.endpoints.messages.get_current_user", return_value=test_user_with_creation_day),
        patch("chorus_stage.api.v1.endpoints.messages.PowService.verify_pow", return_value=True),
        patch("chorus_stage.api.v1.endpoints.messages.PowService.is_pow_replay", return_value=False),
        patch("chorus_stage.api.v1.endpoints.messages.PowService.register_pow", return_value=None),
    ):
        response = client.post("/api/v1/messages/", json=message_data, headers=auth_token_for_test_user)

        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "message_sent"

        # Verify BridgeClient.send_federation_envelope was NOT called
        mock_bridge_client.send_federation_envelope.assert_not_called()

    settings.bridge_enabled = original_bridge_enabled
    mock_bridge_client.enabled = True
