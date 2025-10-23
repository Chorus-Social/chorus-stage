# mypy: ignore-errors
# src/chorus_stage/tests/v1/test_moderation.py
"""Tests for moderation-related endpoints."""

from fastapi import status
from pytest import FixtureRequest

from chorus_stage.models.moderation import MODERATION_STATE_OPEN


def test_trigger_moderation(client, test_user, auth_token, test_post, db_session) -> None:
    """Test triggering moderation for a post."""
    # Ensure user has moderation tokens
    test_user.state.mod_tokens_remaining = 3
    db_session.commit()

    response = client.post(
        "/api/v1/moderation/trigger",
        params={"post_id": test_post.id},
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "case_id" in data
    assert data["status"] == "moderation_triggered"


def test_trigger_moderation_no_tokens(client, test_user, auth_token, test_post, db_session) -> None:
    """Test triggering moderation with no tokens."""
    # Set tokens to 0
    test_user.state.mod_tokens_remaining = 0
    db_session.commit()

    response = client.post(
        "/api/v1/moderation/trigger",
        params={"post_id": test_post.id},
        headers=auth_token
    )
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "No moderation tokens" in response.json()["detail"]


def test_trigger_moderation_same_post_twice(
    client,
    test_user,
    auth_token,
    test_post,
    db_session,
) -> None:
    """Test triggering moderation twice for the same post on the same day."""
    # Ensure user has tokens
    test_user.state.mod_tokens_remaining = 3
    db_session.commit()

    # First trigger
    response = client.post(
        "/api/v1/moderation/trigger",
        params={"post_id": test_post.id},
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Second trigger on the same day
    response = client.post(
        "/api/v1/moderation/trigger",
        params={"post_id": test_post.id},
        headers=auth_token
    )
    # Should return 429 but indicate it was already triggered today
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "already triggered moderation" in response.json()["detail"]


def test_vote_on_moderation(client, test_user, auth_token, test_post, db_session) -> None:
    """Test voting on moderation for a post."""
    response = client.post(
        "/api/v1/moderation/vote",
        params={"post_id": test_post.id, "is_harmful": True},
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["status"] == "vote_recorded"


def test_vote_on_moderation_not_harmful(
    client,
    test_user,
    auth_token,
    test_post,
    db_session,
) -> None:
    """Test voting not harmful on moderation for a post."""
    response = client.post(
        "/api/v1/moderation/vote",
        params={"post_id": test_post.id, "is_harmful": False},
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["status"] == "vote_recorded"


def test_change_moderation_vote(client, test_user, auth_token, test_post, db_session) -> None:
    """Test changing a moderation vote."""
    # Initial harmful vote
    client.post(
        "/api/v1/moderation/vote",
        params={"post_id": test_post.id, "is_harmful": True},
        headers=auth_token
    )

    # Change to not harmful
    response = client.post(
        "/api/v1/moderation/vote",
        params={"post_id": test_post.id, "is_harmful": False},
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["status"] == "vote_recorded"


def test_moderation_queue(client, db_session, test_post) -> None:
    """Test getting the moderation queue."""
    response = client.get("/api/v1/moderation/queue")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)


def test_get_moderation_history(client, test_user, auth_token, test_post, db_session) -> None:
    """Test getting a user's moderation history."""
    from chorus_stage.models import ModerationCase

    # Create a moderation case for the test post
    case = ModerationCase(
        post_id=test_post.id,
        community_id=1,
        state=MODERATION_STATE_OPEN,
        opened_order_index=1
    )
    db_session.add(case)
    db_session.commit()

    response = client.get("/api/v1/moderation/history", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)


def test_moderation_flow_with_multiple_votes(
    client,
    test_user,
    test_post,
    request: FixtureRequest,
) -> None:
    """Test a full moderation flow with multiple users voting."""
    auth_token = request.getfixturevalue("auth_token")
    other_auth_token = request.getfixturevalue("other_auth_token")
    db_session = request.getfixturevalue("db_session")

    test_user.state.mod_tokens_remaining = 3
    db_session.commit()

    response = client.post(
        "/api/v1/moderation/trigger",
        params={"post_id": test_post.id},
        headers=auth_token,
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = client.post(
        "/api/v1/moderation/vote",
        params={"post_id": test_post.id, "is_harmful": True},
        headers=auth_token,
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = client.post(
        "/api/v1/modération/vote",
        params={"post_id": test_post.id, "is_harmful": True},
        headers=other_auth_token,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND  # Wrong URL for typographical test

    response = client.post(
        "/api/v1/moderation/vote",
        params={"post_id": test_post.id, "is_harmful": True},
        headers=other_auth_token,
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = client.post(
        "/api/v1/moderation/vote",
        params={"post_id": test_post.id, "is_harmful": False},
        headers=auth_token,
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = client.get("/api/v1/moderation/queue")
    assert response.status_code == status.HTTP_200_OK
    queue = response.json()
    assert any(p["id"] == test_post.id for p in queue)
