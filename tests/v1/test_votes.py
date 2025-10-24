# mypy: ignore-errors
# src/chorus_stage/tests/v1/test_votes.py
"""Tests for vote-related endpoints."""

from unittest.mock import patch

import pytest
from fastapi import status

pytestmark = pytest.mark.usefixtures("mock_pow_service", "mock_replay_service")


def test_cast_upvote(client, auth_token, test_post) -> None:
    """Test casting an upvote on a post."""
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": test_post.id,
            "direction": 1,
            "pow_nonce": "test_nonce",
            "client_nonce": "client_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED


def test_cast_downvote(client, auth_token, test_post) -> None:
    """Test casting a downvote on a post."""
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": test_post.id,
            "direction": -1,
            "pow_nonce": "test_nonce",
            "client_nonce": "client_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED


def test_vote_invalid_direction(client, auth_token, test_post) -> None:
    """Test voting with invalid direction."""
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": test_post.id,
            "direction": 2,  # Invalid direction
            "pow_nonce": "test_nonce",
            "client_nonce": "client_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_vote_nonexistent_post(client, auth_token) -> None:
    """Test voting on a non-existent post."""
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": 99999,  # Non-existent post
            "direction": 1,
            "pow_nonce": "test_nonce",
            "client_nonce": "client_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_replay_vote(client, auth_token, test_post) -> None:
    """Test that voting with the same nonce is rejected."""
    # First vote should succeed
    with patch("chorus_stage.services.replay.ReplayProtectionService") as mock_replay:
        mock_replay.return_value.is_replay.return_value = False

        response = client.post(
            "/api/v1/votes/",
            json={
                "post_id": test_post.id,
                "direction": 1,
                "pow_nonce": "test_nonce",
                "client_nonce": "client_nonce"
            },
            headers=auth_token
        )
        assert response.status_code == status.HTTP_201_CREATED

        # Second vote with the same nonce should fail
        mock_replay.return_value.is_replay.return_value = True

        response = client.post(
            "/api/v1/votes/",
            json={
                "post_id": test_post.id,
                "direction": -1,  # Even changing direction shouldn't allow replay
                "pow_nonce": "test_nonce",
                "client_nonce": "client_nonce"
            },
            headers=auth_token
        )
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "already been processed" in response.json()["detail"]


def test_change_vote_direction(client, auth_token, test_post) -> None:
    """Test changing the direction of a vote."""
    # Cast an upvote
    client.post(
        "/api/v1/votes/",
        json={
            "post_id": test_post.id,
            "direction": 1,
            "pow_nonce": "test_nonce_1",
            "client_nonce": "client_nonce_1"
        },
        headers=auth_token
    )

    # Change to downvote with new nonce
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": test_post.id,
            "direction": -1,
            "pow_nonce": "test_nonce_2",
            "client_nonce": "client_nonce_2"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Check vote direction
    response = client.get(f"/api/v1/votes/{test_post.id}/my-vote", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["direction"] == -1


def test_remove_vote(client, auth_token, test_post) -> None:
    """Test removing a vote by voting the same direction again."""
    # Cast an upvote
    client.post(
        "/api/v1/votes/",
        json={
            "post_id": test_post.id,
            "direction": 1,
            "pow_nonce": "test_nonce_1",
            "client_nonce": "client_nonce_1"
        },
        headers=auth_token
    )

    # Vote the same direction again to remove
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": test_post.id,
            "direction": 1,  # Same direction
            "pow_nonce": "test_nonce_2",
            "client_nonce": "client_nonce_2"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Check vote was removed
    response = client.get(f"/api/v1/votes/{test_post.id}/my-vote", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["direction"] == 0  # 0 means no vote


def test_vote_on_same_post_multiple_times(client, auth_token, test_post) -> None:
    """Test that voting multiple times on the same post updates the vote."""
    # First upvote
    client.post(
        "/api/v1/votes/",
        json={
            "post_id": test_post.id,
            "direction": 1,
            "pow_nonce": "test_nonce_1",
            "client_nonce": "client_nonce_1"
        },
        headers=auth_token
    )

    # Check vote was cast
    response = client.get(f"/api/v1/votes/{test_post.id}/my-vote", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["direction"] == 1

    # Second post with different direction
    client.post(
        "/api/v1/votes/",
        json={
            "post_id": test_post.id,
            "direction": -1,
            "pow_nonce": "test_nonce_2",
            "client_nonce": "client_nonce_2"
        },
        headers=auth_token
    )

    # Check vote was updated
    response = client.get(f"/api/v1/votes/{test_post.id}/my-vote", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["direction"] == -1


def _mk_content(i: int) -> tuple[str, str]:
    import hashlib
    content = f"Post {i} content"
    return content, hashlib.sha256(content.encode()).hexdigest()


def test_harmful_vote_author_cooldown(client, auth_token, other_auth_token) -> None:
    """Second harmful vote against same author is rate-limited."""
    # Create two posts by the same author (other user)
    c1, h1 = _mk_content(1)
    r = client.post(
        "/api/v1/posts/",
        json={"content_md": c1, "pow_nonce": "n1", "pow_difficulty": 20, "content_hash": h1},
        headers=other_auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED
    p1 = r.json()["id"]

    c2, h2 = _mk_content(2)
    r = client.post(
        "/api/v1/posts/",
        json={"content_md": c2, "pow_nonce": "n2", "pow_difficulty": 20, "content_hash": h2},
        headers=other_auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED
    p2 = r.json()["id"]

    # First harmful vote by current user succeeds
    r = client.post(
        "/api/v1/votes/",
        json={"post_id": p1, "direction": -1, "pow_nonce": "v1", "client_nonce": "c1"},
        headers=auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED

    # Second harmful vote against same author should hit cooldown
    r = client.post(
        "/api/v1/votes/",
        json={"post_id": p2, "direction": -1, "pow_nonce": "v2", "client_nonce": "c2"},
        headers=auth_token,
    )
    assert r.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "cool-down" in r.json()["detail"]


def test_harmful_vote_post_cooldown(client, auth_token, test_post) -> None:
    """Harmful votes on the same post are rate-limited."""
    r = client.post(
        "/api/v1/votes/",
        json={"post_id": test_post.id, "direction": -1, "pow_nonce": "v3", "client_nonce": "c3"},
        headers=auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED

    r = client.post(
        "/api/v1/votes/",
        json={"post_id": test_post.id, "direction": -1, "pow_nonce": "v4", "client_nonce": "c4"},
        headers=auth_token,
    )
    assert r.status_code == status.HTTP_429_TOO_MANY_REQUESTS
