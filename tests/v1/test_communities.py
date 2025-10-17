# mypy: ignore-errors
# src/chorus_stage/tests/v1/test_communities.py
"""Tests for community-related endpoints."""

from fastapi import status


def test_list_communities(client, community, db_session) -> None:
    """Test listing all communities."""
    response = client.get("/api/v1/communities/")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert any(c["id"] == community.id for c in data)
    assert any(c["internal_slug"] == community.internal_slug for c in data)


def test_get_community(client, community, db_session) -> None:
    """Test getting a specific community."""
    response = client.get(f"/api/v1/communities/{community.id}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == community.id
    assert data["internal_slug"] == community.internal_slug


def test_get_nonexistent_community(client) -> None:
    """Test getting a non-existent community."""
    response = client.get("/api/v1/communities/99999")
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_create_community(client, test_user, auth_token, mock_pow_service, db_session) -> None:
    """Test creating a new community."""
    response = client.post(
        "/api/v1/communities/",
        json={
            "internal_slug": "new-test",
            "display_name": "New Test Community",
            "description_md": "A new test community"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["internal_slug"] == "new-test"
    assert data["display_name"] == "New Test Community"
    assert data["description_md"] == "A new test community"


def test_create_duplicate_community(client, test_user, auth_token, community, db_session) -> None:
    """Test creating a community with a duplicate slug."""
    response = client.post(
        "/api/v1/communities/",
        json={
            "internal_slug": community.internal_slug,  # Same slug
            "display_name": "Different Name"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_409_CONFLICT
    assert "already exists" in response.json()["detail"]


def test_join_community(client, test_user, auth_token, community, db_session) -> None:
    """Test joining a community."""
    response = client.post(
        f"/api/v1/communities/{community.id}/join",
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["status"] == "joined"


def test_join_same_community_twice(client, test_user, auth_token, community, db_session) -> None:
    """Test joining a community twice."""
    # First join should succeed
    client.post(f"/api/v1/communities/{community.id}/join", headers=auth_token)

    # Second join should fail
    response = client.post(
        f"/api/v1/communities/{community.id}/join",
        headers=auth_token
    )
    assert response.status_code == status.HTTP_409_CONFLICT
    assert "Already a member" in response.json()["detail"]


def test_leave_community(client, test_user, auth_token, community, db_session) -> None:
    """Test leaving a community."""
    # Join first
    client.post(f"/api/v1/communities/{community.id}/join", headers=auth_token)

    # Then leave
    response = client.delete(f"/api/v1/communities/{community.id}/leave", headers=auth_token)
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_leave_community_not_joined(client, test_user, auth_token, community, db_session) -> None:
    """Test leaving a community the user hasn't joined."""
    response = client.delete(
        f"/api/v1/communities/{community.id}/leave",
        headers=auth_token
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "Not a member" in response.json()["detail"]


def test_get_community_posts(client, db_session, test_user, test_post, community) -> None:
    """Test getting posts from a specific community."""
    # Add post to community
    test_post.community_id = community.id
    db_session.commit()

    response = client.get(f"/api/v1/communities/{community.id}/posts")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert any(p["id"] == test_post.id for p in data)


def test_multiple_users_in_community(client, test_user, other_user, auth_token, other_auth_token, community, db_session) -> None:
    """Test multiple users joining the same community."""
    # First user joins
    client.post(f"/api/v1/communities/{community.id}/join", headers=auth_token)

    # Second user joins
    response = client.post(f"/api/v1/communities/{community.id}/join", headers=other_auth_token)
    assert response.status_code == status.HTTP_201_CREATED

    # Both users can leave independently
    client.delete(f"/api/v1/communities/{community.id}/leave", headers=auth_token)
    client.delete(f"/api/v1/communities/{community.id}/leave", headers=other_auth_token)
