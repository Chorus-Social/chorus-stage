"""Tests for system and transparency endpoints."""

import hashlib
from unittest.mock import AsyncMock, patch

from fastapi import status
from fastapi.testclient import TestClient

# Test constants
EXPECTED_REQUEST_COUNT = 100
EXPECTED_SUCCESS_RATE = 95.0


def test_system_config(client: TestClient) -> None:
    """Test system configuration endpoint."""
    r = client.get("/api/v1/system/config")
    assert r.status_code == status.HTTP_200_OK
    data = r.json()
    assert "app" in data and "pow" in data and "moderation" in data
    assert "difficulties" in data["pow"]
    assert "leases" in data["pow"]
    assert "cooldowns" in data["moderation"]


def test_system_clock(client: TestClient) -> None:
    """Test system clock endpoint."""
    r = client.get("/api/v1/system/clock")
    assert r.status_code == status.HTTP_200_OK
    data = r.json()
    assert "day_seq" in data and "hour_seq" in data


def test_moderation_stats(
    client: TestClient, auth_token: dict[str, str], other_auth_token: dict[str, str]
) -> None:
    """Test moderation statistics endpoint."""
    # Create a couple of posts and votes to produce stats

    def mkc(content: str) -> tuple[str, str]:
        return content, hashlib.sha256(content.encode()).hexdigest()

    c1, h1 = mkc("Stat Post 1")
    r = client.post(
        "/api/v1/posts/",
        json={"content_md": c1, "pow_nonce": "s1", "pow_difficulty": 20, "content_hash": h1},
        headers=other_auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED
    p1 = r.json()["id"]

    c2, h2 = mkc("Stat Post 2")
    r = client.post(
        "/api/v1/posts/",
        json={"content_md": c2, "pow_nonce": "s2", "pow_difficulty": 20, "content_hash": h2},
        headers=other_auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED
    p2 = r.json()["id"]

    # Cast a harmful and a not-harmful vote
    r = client.post(
        "/api/v1/votes/",
        json={"post_id": p1, "direction": -1, "pow_nonce": "sv1", "client_nonce": "sc1"},
        headers=auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED

    r = client.post(
        "/api/v1/votes/",
        json={"post_id": p2, "direction": 1, "pow_nonce": "sv2", "client_nonce": "sc2"},
        headers=auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED

    # Fetch stats
    r = client.get("/api/v1/system/moderation-stats")
    assert r.status_code == status.HTTP_200_OK
    stats = r.json()
    assert "cases" in stats and "votes" in stats and "top_flagged_posts" in stats
    assert isinstance(stats["votes"]["harmful"], int)


def test_bridge_health_disabled(client: TestClient) -> None:
    """Test Bridge health endpoint when Bridge is disabled."""
    r = client.get("/api/v1/system/bridge/health")
    assert r.status_code == status.HTTP_200_OK
    data = r.json()
    assert data["status"] == "disabled"
    assert data["enabled"] is False


def test_bridge_metrics_disabled(client: TestClient) -> None:
    """Test Bridge metrics endpoint when Bridge is disabled."""
    r = client.get("/api/v1/system/bridge/metrics")
    assert r.status_code == status.HTTP_200_OK
    data = r.json()
    assert data["enabled"] is False


@patch("chorus_stage.services.bridge.get_bridge_client")
def test_bridge_health_enabled(mock_get_bridge_client: AsyncMock, client: TestClient) -> None:
    """Test Bridge health endpoint when Bridge is enabled."""
    # Mock Bridge client
    mock_client = AsyncMock()
    mock_client.health_check.return_value = {
        "status": "healthy",
        "enabled": True,
        "response_time_ms": 50.0,
        "bridge_status": {"version": "1.0.0"},
        "circuit_breaker": {
            "state": "closed",
            "failure_count": 0,
            "success_count": 10,
            "last_failure_time": 0.0,
            "is_open": False
        }
    }
    mock_get_bridge_client.return_value = mock_client

    # Mock bridge_enabled to return True
    with patch("chorus_stage.services.bridge.bridge_enabled", return_value=True):
        r = client.get("/api/v1/system/bridge/health")
        assert r.status_code == status.HTTP_200_OK
        data = r.json()
        assert data["status"] == "healthy"
        assert data["enabled"] is True
        assert "circuit_breaker" in data


@patch("chorus_stage.services.bridge.get_bridge_client")
def test_bridge_metrics_enabled(mock_get_bridge_client: AsyncMock, client: TestClient) -> None:
    """Test Bridge metrics endpoint when Bridge is enabled."""
    # Mock Bridge client
    mock_client = AsyncMock()
    mock_client.get_metrics.return_value = {
        "request_count": 100,
        "success_count": 95,
        "error_count": 5,
        "success_rate": 95.0,
        "average_response_time": 150.0,
        "min_response_time": 50.0,
        "max_response_time": 500.0,
        "error_counts_by_type": {"http_500": 3, "network_error": 2},
        "endpoint_counts": {"GET /health": 10, "POST /api/bridge/federation/send": 90}
    }
    mock_get_bridge_client.return_value = mock_client

    # Mock bridge_enabled to return True
    with patch("chorus_stage.services.bridge.bridge_enabled", return_value=True):
        r = client.get("/api/v1/system/bridge/metrics")
        assert r.status_code == status.HTTP_200_OK
        data = r.json()
        assert data["request_count"] == EXPECTED_REQUEST_COUNT
        assert data["success_rate"] == EXPECTED_SUCCESS_RATE
        assert "error_counts_by_type" in data
        assert "endpoint_counts" in data
