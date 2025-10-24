import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.models import FederationOutbound
from chorus_stage.services.bridge import BridgeClient, BridgeDisabledError
from chorus_stage.services.bridge_sync import BridgeSyncWorker


@pytest.fixture
def mock_bridge_client_for_outbound():
    client = AsyncMock(spec=BridgeClient)
    client.enabled = True
    client.retry_federation_envelope.return_value = True  # Default to success
    return client


@pytest.fixture
def mock_session_local_for_outbound(mocker, db_session: Session):
    # Patch SessionLocal to return our actual db_session when called as a context manager
    mock_sl = mocker.patch('chorus_stage.db.session.SessionLocal')
    mock_sl.return_value.__enter__.return_value = db_session
    mock_sl.return_value.__exit__.return_value = None
    return mock_sl


@pytest.mark.asyncio
async def test_process_outbound_events_success(
    db_session: Session,
    mock_bridge_client_for_outbound: AsyncMock,
):
    # Ensure bridge is enabled for this test
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = True

    # Create some pending outbound events
    event1 = FederationOutbound(
        event_type="TestEvent",
        event_hash="a" * 64,
        payload=b"payload1",
        status="pending",
        retry_count=0,
    )
    event2 = FederationOutbound(
        event_type="TestEvent",
        event_hash="b" * 64,
        payload=b"payload2",
        status="pending",
        retry_count=0,
    )
    db_session.add_all([event1, event2])
    db_session.flush()

    worker = BridgeSyncWorker(client=mock_bridge_client_for_outbound, db_session=db_session)
    await worker._process_outbound_events()
    db_session.commit() # Commit changes made by _process_outbound_events

    # Assert that retry_federation_envelope was called for each pending event
    mock_bridge_client_for_outbound.retry_federation_envelope.assert_has_calls([
        (b"payload1", "a" * 64),
        (b"payload2", "b" * 64),
    ])

    # Refresh events from DB and check their status
    db_session.refresh(event1)
    db_session.refresh(event2)
    assert event1.status == "accepted"
    assert event2.status == "accepted"
    assert event1.retry_count == 0
    assert event2.retry_count == 0

    settings.bridge_enabled = original_bridge_enabled


@pytest.mark.asyncio
async def test_process_outbound_events_failure_and_retry(
    db_session: Session,
    mock_bridge_client_for_outbound: AsyncMock,
    mock_session_local_for_outbound: MagicMock,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = True
    original_max_retries = settings.bridge_outbound_max_retries
    settings.bridge_outbound_max_retries = 2

    # Configure retry_federation_envelope to fail twice, then succeed
    mock_bridge_client_for_outbound.retry_federation_envelope.side_effect = [
        False,  # First attempt fails
        False,  # Second attempt fails
        True,   # Third attempt succeeds
    ]

    event = FederationOutbound(
        event_type="TestEvent",
        event_hash="c" * 64,
        payload=b"payload3",
        status="pending",
        retry_count=0,
    )
    db_session.add(event)
    db_session.flush()

    worker = BridgeSyncWorker(client=mock_bridge_client_for_outbound)

    # First processing attempt (retry_count = 1)
    await worker._process_outbound_events()
    db_session.commit() # Commit changes made by _process_outbound_events
    db_session.refresh(event)
    assert event.status == "pending"
    assert event.retry_count == 1

    # Second processing attempt (retry_count = 2)
    await worker._process_outbound_events()
    db_session.refresh(event)
    assert event.status == "pending"
    assert event.retry_count == 2

    # Third processing attempt (retry_count = 2, max_retries = 2, so it should fail)
    await worker._process_outbound_events()
    db_session.refresh(event)
    assert event.status == "failed"
    assert event.retry_count == 2

    settings.bridge_enabled = original_bridge_enabled
    settings.bridge_outbound_max_retries = original_max_retries


@pytest.mark.asyncio
async def test_process_outbound_events_bridge_disabled(
    db_session: Session,
    mock_bridge_client_for_outbound: AsyncMock,
    mock_session_local_for_outbound: MagicMock,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = False
    mock_bridge_client_for_outbound.enabled = False

    event = FederationOutbound(
        event_type="TestEvent",
        event_hash="d" * 64,
        payload=b"payload4",
        status="pending",
        retry_count=0,
    )
    db_session.add(event)
    db_session.flush()

    worker = BridgeSyncWorker(client=mock_bridge_client_for_outbound)
    await worker._process_outbound_events()

    # Should not attempt to send if bridge is disabled
    mock_bridge_client_for_outbound.retry_federation_envelope.assert_not_called()
    db_session.refresh(event)
    assert event.status == "pending"  # Status should remain unchanged

    settings.bridge_enabled = original_bridge_enabled
    mock_bridge_client_for_outbound.enabled = True


@pytest.mark.asyncio
async def test_process_outbound_events_exception_handling(
    db_session: Session,
    mock_bridge_client_for_outbound: AsyncMock,
    mock_session_local_for_outbound: MagicMock,
):
    original_bridge_enabled = settings.bridge_enabled
    settings.bridge_enabled = True
    original_max_retries = settings.bridge_outbound_max_retries
    settings.bridge_outbound_max_retries = 1

    mock_bridge_client_for_outbound.retry_federation_envelope.side_effect = Exception("Network error")

    event = FederationOutbound(
        event_type="TestEvent",
        event_hash="e" * 64,
        payload=b"payload5",
        status="pending",
        retry_count=0,
    )
    db_session.add(event)
    db_session.flush()

    worker = BridgeSyncWorker(client=mock_bridge_client_for_outbound)
    await worker._process_outbound_events()

    db_session.refresh(event)
    assert event.status == "failed"
    assert event.retry_count == 1

    settings.bridge_enabled = original_bridge_enabled
    settings.bridge_outbound_max_retries = original_max_retries
