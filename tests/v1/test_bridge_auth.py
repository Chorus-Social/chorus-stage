
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from chorus_stage.core.settings import settings
from chorus_stage.models import User
from chorus_stage.services.bridge import BridgeDayProof, BridgeClient

# Assuming `app` is imported from main.py for TestClient
# For testing purposes, we might need a way to get the app instance
# or directly test the endpoint function with mocked dependencies.
# Given the instruction "never run the main.py or start the uvicorn server",
# we will directly test the endpoint function with mocked dependencies.

# We need to mock the get_bridge_client function
@pytest.fixture
def mock_bridge_client():
    mock_client = AsyncMock(spec=BridgeClient)
    mock_client.enabled = True
    mock_client.fetch_day_proof.return_value = BridgeDayProof(
        day_number=123,
        proof=b"mock_proof",
        proof_hash=b"mock_proof_hash",
        canonical=True
    )
    with patch("chorus_stage.api.v1.endpoints.auth.get_bridge_client", return_value=mock_client):
        yield mock_client

async def test_register_user_with_bridge_enabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient, # Assuming test_client fixture is available
    mock_pow_service, # Assuming mock_pow_service fixture is available
    mock_replay_service, # Assuming mock_replay_service fixture is available
):
    # Temporarily enable bridge for this test
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = True

    # Mock dependencies for the register_user endpoint
    with patch("chorus_stage.api.v1.endpoints.auth.get_pow_service", return_value=mock_pow_service), \
         patch("chorus_stage.api.v1.endpoints.auth.get_replay_service", return_value=mock_replay_service):

        # Prepare registration payload
        pubkey = "a" * 64 # Example public key hex
        payload = {
            "pubkey": pubkey,
            "display_name": "test_user",
            "accent_color": "#FFFFFF",
            "pow": {
                "nonce": "test_nonce",
                "difficulty": 20,
                "target": "test_target"
            },
            "proof": {
                "challenge": "test_challenge",
                "signature": "test_signature"
            }
        }

        # Mock crypto_service.validate_and_decode_pubkey and verify_signature_bytes
        with patch("chorus_stage.api.v1.endpoints.auth.crypto_service.validate_and_decode_pubkey", return_value=bytes.fromhex(pubkey)), \
             patch("chorus_stage.api.v1.endpoints.auth.crypto_service.validate_auth_challenge", return_value="challenge_nonce_hex"), \
             patch("chorus_stage.api.v1.endpoints.auth.crypto_service.verify_signature_bytes", return_value=True):

            response = client.post("/api/v1/auth/register", json=payload)

            assert response.status_code == 201
            data = response.json()
            assert data["created"] is True

            # Verify that fetch_day_proof was called
            mock_bridge_client.fetch_day_proof.assert_called_once_with(day=0)

            # Verify that the user was created with the correct creation_day
            user = db_session.query(User).filter(User.pubkey == bytes.fromhex(pubkey)).first()
            assert user is not None
            assert user.creation_day == 123 # From mock_bridge_client.fetch_day_proof.return_value

    # Restore original settings
    settings.bridge_enabled = original_bridge_enabled

@pytest.mark.asyncio
async def test_register_user_with_bridge_disabled(
    db_session: Session,
    mock_bridge_client: AsyncMock,
    client: TestClient,
    mock_pow_service,
    mock_replay_service,
):
    # Ensure bridge is disabled for this test
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = False
    mock_bridge_client.enabled = False # Ensure the mock also reflects disabled state

    with patch("chorus_stage.api.v1.endpoints.auth.get_pow_service", return_value=mock_pow_service), \
         patch("chorus_stage.api.v1.endpoints.auth.get_replay_service", return_value=mock_replay_service):

        pubkey = "b" * 64
        payload = {
            "pubkey": pubkey,
            "display_name": "test_user_no_bridge",
            "accent_color": "#000000",
            "pow": {
                "nonce": "test_nonce_no_bridge",
                "difficulty": 20,
                "target": "test_target_no_bridge"
            },
            "proof": {
                "challenge": "test_challenge_no_bridge",
                "signature": "test_signature_no_bridge"
            }
        }

        with patch("chorus_stage.api.v1.endpoints.auth.crypto_service.validate_and_decode_pubkey", return_value=bytes.fromhex(pubkey)), \
             patch("chorus_stage.api.v1.endpoints.auth.crypto_service.validate_auth_challenge", return_value="challenge_nonce_hex_no_bridge"), \
             patch("chorus_stage.api.v1.endpoints.auth.crypto_service.verify_signature_bytes", return_value=True):

            response = client.post("/api/v1/auth/register", json=payload)

            assert response.status_code == 201
            data = response.json()
            assert data["created"] is True

            # Verify that fetch_day_proof was NOT called
            mock_bridge_client.fetch_day_proof.assert_not_called()

            # Verify that the user was created with the default creation_day (0)
            user = db_session.query(User).filter(User.pubkey == bytes.fromhex(pubkey)).first()
            assert user is not None
            assert user.creation_day == 0

    settings.bridge_enabled = original_bridge_enabled
    mock_bridge_client.enabled = True # Restore mock state
