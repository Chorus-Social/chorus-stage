import asyncio
from unittest.mock import AsyncMock, MagicMock
import pytest

# Mock the SystemClock model for testing purposes
class MockSystemClock:
    def __init__(self, id=1, day_seq=0, hour_seq=0):
        self.id = id
        self.day_seq = day_seq
        self.hour_seq = hour_seq

# Import necessary modules after patching
from chorus_stage.services.bridge_sync import BridgeSyncWorker, BridgeSyncState
from chorus_stage.services.bridge import BridgeClient, BridgeDayProof
from chorus_stage.models import SystemClock

@pytest.fixture(autouse=True)
def mock_system_clock_model(mocker):
    mocker.patch('chorus_stage.models.SystemClock', new=MockSystemClock)
    yield

@pytest.fixture
def mock_bridge_client():
    client = AsyncMock(spec=BridgeClient)
    client.enabled = True
    client.fetch_day_proof.return_value = BridgeDayProof(
        day_number=100,
        proof=b"test_proof",
        proof_hash=b"test_proof_hash",
        canonical=True
    )
    client.pull_events.return_value = MagicMock(events=[], cursor=None)
    return client

@pytest.fixture
def mock_session(mocker):
    session = mocker.MagicMock()
    mock_query_obj = mocker.MagicMock()
    mock_query_obj.first.return_value = None # Default: no SystemClock initially
    session.query.return_value = mock_query_obj
    return session

@pytest.fixture
def mock_session_local(mocker, mock_session):
    # Patch SessionLocal to return our mock_session when called as a context manager
    mock_sl = mocker.patch('chorus_stage.db.session.SessionLocal', return_value=mocker.MagicMock())
    mock_sl.return_value.__enter__.return_value = mock_session
    mock_sl.return_value.__exit__.return_value = None
    return mock_sl

@pytest.fixture(autouse=True)
def reset_mock_session_and_query(mock_session):
    # Reset the mock_session and mock_query_obj before each test
    mock_session.reset_mock()
    mock_session.query.return_value.first.return_value = None
    yield

@pytest.mark.asyncio
async def test_bridge_sync_worker_fetches_day_proof_and_updates_clock(mock_bridge_client, mock_session, mock_session_local):
    worker = BridgeSyncWorker(client=mock_bridge_client)

    # Call the new method directly
    await worker._fetch_and_apply_day_proof()

    # Assert fetch_day_proof was called
    mock_bridge_client.fetch_day_proof.assert_called_once_with(0) # Initial local day is 0

    # Assert SystemClock was created and updated
    mock_session.add.assert_called_once()
    added_clock = mock_session.add.call_args[0][0]
    assert isinstance(added_clock, MockSystemClock) # Assert against MockSystemClock
    assert added_clock.day_seq == 100
    mock_session.commit.assert_called_once()

@pytest.mark.asyncio
async def test_bridge_sync_worker_updates_existing_clock(mock_bridge_client, mock_session, mock_session_local):
    # Set up an existing SystemClock
    existing_clock = MockSystemClock(id=1, day_seq=50, hour_seq=0)
    mock_session.query.return_value.first.return_value = existing_clock

    worker = BridgeSyncWorker(client=mock_bridge_client)

    # Call the new method directly
    await worker._fetch_and_apply_day_proof()

    # Assert fetch_day_proof was called with the existing day
    mock_bridge_client.fetch_day_proof.assert_called_once_with(50)

    # Assert SystemClock was updated
    assert existing_clock.day_seq == 100
    mock_session.commit.assert_called_once()