"""Tests for user transparency endpoints."""

import base64

from fastapi import status


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def test_user_summary_and_recent_posts(client, test_user, auth_token, test_post) -> None:
    user_b64 = _b64(test_user.user_id)

    r = client.get(f"/api/v1/users/{user_b64}/summary")
    assert r.status_code == status.HTTP_200_OK
    data = r.json()
    assert data["user_id"] == user_b64
    assert "posts" in data and "moderation" in data

    r = client.get(f"/api/v1/users/{user_b64}/recent-posts")
    assert r.status_code == status.HTTP_200_OK
    posts = r.json()
    assert isinstance(posts, list)
    if posts:
        assert "id" in posts[0]


def test_user_communities(client, test_user, auth_token, community) -> None:
    # Create a post in community
    import hashlib

    content = "Hello Community"
    h = hashlib.sha256(content.encode()).hexdigest()
    r = client.post(
        "/api/v1/posts/",
        json={
            "content_md": content,
            "pow_nonce": "uc1",
            "pow_difficulty": 20,
            "content_hash": h,
            "community_internal_slug": community.internal_slug,
        },
        headers=auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED

    user_b64 = _b64(test_user.user_id)
    r = client.get(f"/api/v1/users/{user_b64}/communities")
    assert r.status_code == status.HTTP_200_OK
    rows = r.json()
    assert any(row["community_id"] == community.id for row in rows)
