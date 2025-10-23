# mypy: ignore-errors
# src/chorus_stage/tests/v1/test_integration.py
"""Integration tests that verify multiple components work together."""

import base64
import hashlib
from typing import Any

import pytest
from fastapi import status

from chorus_stage.models.moderation import (
    MODERATION_STATE_CLEARED,
    MODERATION_STATE_OPEN,
)
from tests.conftest import build_register_payload

VISIBLE_OR_QUEUE_STATES = {MODERATION_STATE_OPEN, MODERATION_STATE_CLEARED}
MIN_TWO_POSTS = 2

pytestmark = pytest.mark.usefixtures("mock_pow_service", "mock_replay_service")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _decode_b64(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _issue_challenge(client, pubkey_b64: str, intent: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/challenge",
        json={"pubkey": pubkey_b64, "intent": intent},
    )
    assert response.status_code == status.HTTP_200_OK
    return response.json()


def _build_login_payload(
    identity: dict[str, Any],
    challenge: dict[str, str],
    nonce: str,
) -> dict[str, Any]:
    challenge_bytes = _decode_b64(challenge["signature_challenge"])
    signature = identity["private_key"].sign(challenge_bytes).signature  # type: ignore[attr-defined]
    return {
        "pubkey": identity["pubkey_b64"],
        "pow": {
            "nonce": nonce,
            "difficulty": challenge["pow_difficulty"],
            "target": challenge["pow_target"],
        },
        "proof": {
            "challenge": challenge["signature_challenge"],
            "signature": _b64(signature),
        },
    }


def test_full_post_flow(client, test_user, auth_token, db_session) -> None:
    """Test the complete flow of creating a post, voting, and moderating."""
    # Create a post
    content = "This is a test post for the full flow"
    content_hash = hashlib.sha256(content.encode()).hexdigest()

    response = client.post(
        "/api/v1/posts/",
        json={
            "content_md": content,
            "pow_nonce": "test_post_nonce",
            "pow_difficulty": 20,
            "content_hash": content_hash
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    post_id = response.json()["id"]

    # Vote on the post (upvote)
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": post_id,
            "direction": 1,
            "pow_nonce": "test_vote_nonce",
            "client_nonce": "test_client_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Check our vote
    response = client.get(f"/api/v1/votes/{post_id}/my-vote", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["direction"] == 1

    # Change vote to downvote
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": post_id,
            "direction": -1,
            "pow_nonce": "test_vote_nonce_2",
            "client_nonce": "test_client_nonce_2"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Trigger moderation
    test_user.state.mod_tokens_remaining = 3
    db_session.commit()

    response = client.post(
        "/api/v1/moderation/trigger",
        params={"post_id": post_id},
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Vote on moderation (not harmful)
    response = client.post(
        "/api/v1/moderation/vote",
        params={"post_id": post_id, "is_harmful": False},
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Check post is still visible
    response = client.get(f"/api/v1/posts/{post_id}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["moderation_state"] in VISIBLE_OR_QUEUE_STATES


def test_community_and_posts_flow(client, test_user, auth_token) -> None:
    """Test creating a community and posting to it."""
    # Create a community
    response = client.post(
        "/api/v1/communities/",
        json={
            "internal_slug": "flow-test",
            "display_name": "Flow Test Community",
            "description_md": "A community for testing the full flow"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    community_id = response.json()["id"]

    # Join the community
    response = client.post(
        f"/api/v1/communities/{community_id}/join",
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Create a post in the community
    content = "This is a test post in the flow test community"
    content_hash = hashlib.sha256(content.encode()).hexdigest()

    response = client.post(
        "/api/v1/posts/",
        json={
            "content_md": content,
            "pow_nonce": "test_post_nonce",
            "pow_difficulty": 20,
            "content_hash": content_hash,
            "community_internal_slug": "flow-test"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    post_id = response.json()["id"]

    # Check the post appears in the community
    response = client.get(f"/api/v1/communities/{community_id}/posts")
    assert response.status_code == status.HTTP_200_OK
    posts = response.json()
    assert len(posts) >= 1
    assert any(p["id"] == post_id for p in posts)

    # Leave the community
    response = client.delete(f"/api/v1/communities/{community_id}/leave", headers=auth_token)
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_messaging_flow(client, test_user, other_user, auth_token, other_auth_token) -> None:
    """Test the messaging flow between users."""
    # Send a message from test_user to other_user
    ciphertext = base64.b64encode(b"encrypted_message_content").decode()

    response = client.post(
        "/api/v1/messages/",
        json={
            "ciphertext": ciphertext,
            "recipient_pubkey_hex": other_user.pubkey.hex(),
            "pow_nonce": "test_message_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    message_id = response.json()["message_id"]

    # Check it appears in other_user's inbox
    response = client.get("/api/v1/messages/inbox", headers=other_auth_token)
    assert response.status_code == status.HTTP_200_OK
    messages = response.json()
    assert len(messages) >= 1
    assert any(msg["id"] == message_id for msg in messages)

    # Check it appears in test_user's sent messages
    response = client.get("/api/v1/messages/sent", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    messages = response.json()
    assert len(messages) >= 1
    assert any(msg["id"] == message_id for msg in messages)

    # Mark the message as read by other_user
    response = client.put(f"/api/v1/messages/{message_id}/read", headers=other_auth_token)
    assert response.status_code == status.HTTP_200_OK


def test_multiple_users_community_interaction(
    client,
    test_user,
    other_user,
    auth_token,
    other_auth_token,
) -> None:
    """Test multiple users interacting within a community."""
    # Create a community
    response = client.post(
        "/api/v1/communities/",
        json={
            "internal_slug": "multi-test",
            "display_name": "Multi-User Test Community",
            "description_md": "A community for testing multiple users"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    community_id = response.json()["id"]

    # Both users join the community
    client.post(f"/api/v1/communities/{community_id}/join", headers=auth_token)
    client.post(f"/api/v1/communities/{community_id}/join", headers=other_auth_token)

    # Test user creates a post
    content = "Post by test user"
    content_hash = hashlib.sha256(content.encode()).hexdigest()

    response = client.post(
        "/api/v1/posts/",
        json={
            "content_md": content,
            "pow_nonce": "test_post_nonce_1",
            "pow_difficulty": 20,
            "content_hash": content_hash,
            "community_internal_slug": "multi-test"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    post_id_1 = response.json()["id"]

    # Other user creates a post
    content2 = "Post by other user"
    content_hash2 = hashlib.sha256(content2.encode()).hexdigest()

    response = client.post(
        "/api/v1/posts/",
        json={
            "content_md": content2,
            "pow_nonce": "test_post_nonce_2",
            "pow_difficulty": 20,
            "content_hash": content_hash2,
            "community_internal_slug": "multi-test"
        },
        headers=other_auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    post_id_2 = response.json()["id"]

    # Test user votes on other user's post
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": post_id_2,
            "direction": 1,
            "pow_nonce": "test_vote_nonce",
            "client_nonce": "test_client_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Check community posts include both posts
    response = client.get(f"/api/v1/communities/{community_id}/posts")
    assert response.status_code == status.HTTP_200_OK
    posts = response.json()
    assert len(posts) >= MIN_TWO_POSTS
    post_ids = [p["id"] for p in posts]
    assert post_id_1 in post_ids
    assert post_id_2 in post_ids


def test_complete_anonymous_flow(client, test_user_data, other_user_data) -> None:
    """Test a complete anonymous user flow without JWT tokens."""
    # Register test user
    response = client.post(
        "/api/v1/auth/register",
        json=build_register_payload(test_user_data)
    )
    assert response.status_code == status.HTTP_201_CREATED
    test_login_challenge = _issue_challenge(client, test_user_data["pubkey_b64"], "login")
    login_payload = _build_login_payload(test_user_data, test_login_challenge, "anon-login-1")
    login_resp = client.post("/api/v1/auth/login", json=login_payload)
    assert login_resp.status_code == status.HTTP_200_OK
    test_token = login_resp.json()["access_token"]
    test_auth_header = {"Authorization": f"Bearer {test_token}"}

    # Register other user
    response = client.post(
        "/api/v1/auth/register",
        json=build_register_payload(other_user_data)
    )
    assert response.status_code == status.HTTP_201_CREATED
    other_login_challenge = _issue_challenge(client, other_user_data["pubkey_b64"], "login")
    other_login_payload = _build_login_payload(
        other_user_data,
        other_login_challenge,
        "anon-login-2",
    )
    other_login = client.post("/api/v1/auth/login", json=other_login_payload)
    assert other_login.status_code == status.HTTP_200_OK
    other_token = other_login.json()["access_token"]
    other_auth_header = {"Authorization": f"Bearer {other_token}"}

    # Test user creates a community
    response = client.post(
        "/api/v1/communities/",
        json={
            "internal_slug": "anonymous-test",
            "display_name": "Anonymous Test Community"
        },
        headers=test_auth_header
    )
    assert response.status_code == status.HTTP_201_CREATED
    community_id = response.json()["id"]

    # Both users join
    client.post(f"/api/v1/communities/{community_id}/join", headers=test_auth_header)
    client.post(f"/api/v1/communities/{community_id}/join", headers=other_auth_header)

    # Other user creates a post
    response = client.post(
        "/api/v1/posts/",
        json={
            "content_md": "Anonymous post content",
            "pow_nonce": "test_post_nonce",
            "pow_difficulty": 20,
            "content_hash": hashlib.sha256(b"Anonymous post content").hexdigest(),
            "community_internal_slug": "anonymous-test"
        },
        headers=other_auth_header
    )
    assert response.status_code == status.HTTP_201_CREATED
    post_id = response.json()["id"]

    # Test user votes on the post
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": post_id,
            "direction": 1,
            "pow_nonce": "test_vote_nonce",
            "client_nonce": "test_client_nonce"
        },
        headers=test_auth_header
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Other user sends a message to test user
    ciphertext = base64.b64encode(b"Encrypted message between users").decode()

    response = client.post(
        "/api/v1/messages/",
        json={
            "ciphertext": ciphertext,
            "recipient_pubkey_hex": test_user_data["pubkey_hex"],
            "pow_nonce": "test_message_nonce"
        },
        headers=other_auth_header
    )
    assert response.status_code == status.HTTP_201_CREATED

    # Test user checks their inbox
    response = client.get("/api/v1/messages/inbox", headers=test_auth_header)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) >= 1

    # Test user leaves the community
    response = client.delete(f"/api/v1/communities/{community_id}/leave", headers=test_auth_header)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # Other user is still in community
    response = client.get(f"/api/v1/communities/{community_id}/posts", headers=other_auth_header)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) >= 1


def test_api_error_handling(client, auth_token) -> None:
    """Test that API properly handles various error cases."""
    # Invalid JSON
    response = client.post(
        "/api/v1/posts/",
        data="invalid json",
        headers={**auth_token, "Content-Type": "application/json"}
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Missing required fields
    response = client.post(
        "/api/v1/posts/",
        json={},
        headers=auth_token
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Invalid field value
    response = client.post(
        "/api/v1/votes/",
        json={
            "post_id": 1,
            "direction": 2,  # Invalid direction
            "pow_nonce": "test",
            "client_nonce": "test"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
