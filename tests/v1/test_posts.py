# mypy: ignore-errors
# src/chorus_stage/tests/v1/test_posts.py
"""Tests for post-related endpoints."""

import base64
import hashlib

import pytest
from fastapi import status

pytestmark = pytest.mark.usefixtures("mock_pow_service")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def test_create_post_success(client, test_user, auth_token) -> None:
    """Test successful post creation."""
    content = "Test post content"
    content_hash = hashlib.sha256(content.encode()).hexdigest()

    response = client.post(
        "/api/v1/posts/",
        json={
            "content_md": content,
            "pow_nonce": "test_nonce",
            "pow_difficulty": 20,
            "content_hash": content_hash
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["body_md"] == content
    assert data["author_user_id"] == _b64(test_user.user_id)
    assert data["content_hash"] == content_hash


def test_create_post_invalid_pow(client, test_user, auth_token) -> None:
    """Test post creation fails when difficulty is insufficient."""
    content = "Test post content"
    content_hash = hashlib.sha256(content.encode()).hexdigest()

    response = client.post(
        "/api/v1/posts/",
        json={
            "content_md": content,
            "pow_nonce": "test_nonce",
            "pow_difficulty": 19,
            "content_hash": content_hash
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Insufficient proof-of-work" in response.json()["detail"]


def test_create_post_invalid_hash(client, test_user, auth_token) -> None:
    """Test post creation with invalid content hash."""
    content = "Test post content"
    invalid_hash = "invalid_hash_value"

    response = client.post(
        "/api/v1/posts/",
        json={
            "content_md": content,
            "pow_nonce": "test_nonce",
            "pow_difficulty": 20,
            "content_hash": invalid_hash
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Content hash does not match" in response.json()["detail"]


def test_create_post_in_community(client, test_user, auth_token, community) -> None:
    """Test creating a post within a specific community."""
    content = "Test post in community"
    content_hash = hashlib.sha256(content.encode()).hexdigest()

    response = client.post(
        "/api/v1/posts/",
        json={
            "content_md": content,
            "pow_nonce": "test_nonce",
            "pow_difficulty": 20,
            "content_hash": content_hash,
            "community_internal_slug": "test"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["body_md"] == content
    assert data["community_id"] == community.id


def test_create_post_in_nonexistent_community(client, test_user, auth_token) -> None:
    """Test creating a post in a non-existent community."""
    content = "Test post in nonexistent community"
    content_hash = hashlib.sha256(content.encode()).hexdigest()

    response = client.post(
        "/api/v1/posts/",
        json={
            "content_md": content,
            "pow_nonce": "test_nonce",
            "pow_difficulty": 20,
            "content_hash": content_hash,
            "community_internal_slug": "nonexistent"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "Community not found" in response.json()["detail"]


def test_get_posts(client, test_post) -> None:
    """Test retrieving a list of posts."""
    response = client.get("/api/v1/posts/")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    if data:  # If there are any posts
        assert "id" in data[0]
        assert "body_md" in data[0]


def test_get_specific_post(client, test_post) -> None:
    """Test retrieving a specific post by ID."""
    response = client.get(f"/api/v1/posts/{test_post.id}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == test_post.id
    assert data["body_md"] == test_post.body_md


def test_get_nonexistent_post(client) -> None:
    """Test retrieving a non-existent post."""
    response = client.get("/api/v1/posts/99999")
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_get_post_children(client, db_session, test_user, test_post, setup_system_clock) -> None:
    """Test retrieving replies to a post."""

    from chorus_stage.models import Post

    # Create a reply to the test post
    content = "Reply to test post"
    content_hash = hashlib.sha256(content.encode()).digest()

    reply = Post(
        order_index=2,
        author_user_id=test_user.user_id,
        author_pubkey=test_user.pubkey,
        parent_post_id=test_post.id,
        body_md=content,
        content_hash=content_hash,
        moderation_state=0
    )
    db_session.add(reply)
    db_session.commit()

    response = client.get(f"/api/v1/posts/{test_post.id}/children")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    # All returned posts should have parent_post_id = test_post.id
    assert all(post["parent_post_id"] == test_post.id for post in data)


def test_delete_own_post(client, test_user, auth_token, test_post, db_session) -> None:
    """Test deleting a post by the author."""
    # Ensure the test post belongs to the test user
    test_post.author_user_id = test_user.user_id
    db_session.commit()

    response = client.delete(f"/api/v1/posts/{test_post.id}", headers=auth_token)
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_delete_other_post(client, test_user, other_auth_token, test_post, db_session) -> None:
    """Test deleting a post by someone other than the author."""
    # Ensure the test post belongs to the test user, not the other user
    test_post.author_user_id = test_user.user_id
    db_session.commit()

    response = client.delete(f"/api/v1/posts/{test_post.id}", headers=other_auth_token)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "own posts" in response.json()["detail"]


def test_delete_nonexistent_post(client, auth_token) -> None:
    """Test deleting a non-existent post."""
    response = client.delete("/api/v1/posts/99999", headers=auth_token)
    assert response.status_code == status.HTTP_404_NOT_FOUND
