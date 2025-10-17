# mypy: ignore-errors
# src/chorus_stage/tests/v1/test_messages.py
"""Tests for message-related endpoints."""

import base64

from fastapi import status


def test_send_message(client, test_user, other_user, auth_token, mock_pow_service, db_session) -> None:
    """Test sending a direct message."""
    ciphertext = base64.b64encode(b"encrypted_message_content").decode()

    response = client.post(
        "/api/v1/messages/",
        json={
            "ciphertext": ciphertext,
            "recipient_pubkey_hex": other_user.ed25519_pubkey.hex(),
            "header_blob": None,
            "pow_nonce": "test_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "message_id" in data
    assert data["status"] == "message_sent"


def test_send_message_to_nonexistent_user(client, test_user, auth_token, mock_pow_service, db_session) -> None:
    """Test sending a message to a non-existent user."""
    ciphertext = base64.b64encode(b"encrypted_message_content").decode()

    response = client.post(
        "/api/v1/messages/",
        json={
            "ciphertext": ciphertext,
            "recipient_pubkey_hex": "00" * 32,  # Non-existent pubkey
            "header_blob": None,
            "pow_nonce": "test_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "Recipient not found" in response.json()["detail"]


def test_send_message_invalid_pubkey(client, test_user, auth_token, mock_pow_service, db_session) -> None:
    """Test sending a message with an invalid public key."""
    ciphertext = base64.b64encode(b"encrypted_message_content").decode()

    response = client.post(
        "/api/v1/messages/",
        json={
            "ciphertext": ciphertext,
            "recipient_pubkey_hex": "invalid_key",
            "header_blob": None,
            "pow_nonce": "test_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid recipient public key" in response.json()["detail"]


def test_send_message_invalid_ciphertext(client, test_user, other_user, auth_token, mock_pow_service, db_session) -> None:
    """Test sending a message with invalid ciphertext."""
    response = client.post(
        "/api/v1/messages/",
        json={
            "ciphertext": "not_base64",
            "recipient_pubkey_hex": other_user.ed25519_pubkey.hex(),
            "header_blob": None,
            "pow_nonce": "test_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Ciphertext must be valid base64" in response.json()["detail"]


def test_send_message_with_header(client, test_user, other_user, auth_token, mock_pow_service, db_session) -> None:
    """Test sending a message with header blob."""
    ciphertext = base64.b64encode(b"encrypted_message_content").decode()
    header_blob = base64.b64encode(b"encryption_header").decode()

    response = client.post(
        "/api/v1/messages/",
        json={
            "ciphertext": ciphertext,
            "recipient_pubkey_hex": other_user.ed25519_pubkey.hex(),
            "header_blob": header_blob,
            "pow_nonce": "test_nonce"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "message_id" in data


def test_get_inbox(client, test_user, auth_token, direct_message, db_session) -> None:
    """Test getting a user's message inbox."""
    response = client.get("/api/v1/messages/inbox", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    # Check that message fields are base64 encoded in response
    assert isinstance(data[0]["ciphertext"], str)
    if data[0]["header_blob"]:
        assert isinstance(data[0]["header_blob"], str)


def test_get_sent_messages(client, other_user, other_auth_token, direct_message, db_session) -> None:
    """Test getting messages sent by a user."""
    response = client.get("/api/v1/messages/sent", headers=other_auth_token)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    # Check that message fields are base64 encoded in response
    assert isinstance(data[0]["ciphertext"], str)


def test_mark_message_read(client, test_user, auth_token, direct_message, db_session) -> None:
    """Test marking a message as read."""
    response = client.put(
        f"/api/v1/messages/{direct_message.id}/read",
        headers=auth_token
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "marked_as_read"


def test_mark_message_read_sender(client, other_user, other_auth_token, direct_message, db_session) -> None:
    """Test that the sender can't mark a message as read."""
    response = client.put(
        f"/api/v1/messages/{direct_message.id}/read",
        headers=other_auth_token
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_message_reply_flow(client, test_user, other_user, auth_token, other_auth_token, mock_pow_service, db_session) -> None:
    """Test a full message conversation flow."""
    # User 1 sends a message to User 2
    ciphertext = base64.b64encode(b"Hello from User 1").decode()

    response = client.post(
        "/api/v1/messages/",
        json={
            "ciphertext": ciphertext,
            "recipient_pubkey_hex": other_user.ed25519_pubkey.hex(),
            "header_blob": None,
            "pow_nonce": "test_nonce_1"
        },
        headers=auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    message_id_1 = response.json()["message_id"]

    # User 2 reads the message
    response = client.put(
        f"/api/v1/messages/{message_id_1}/read",
        headers=other_auth_token
    )
    assert response.status_code == status.HTTP_200_OK

    # User 2 sends a reply to User 1
    reply_ciphertext = base64.b64encode(b"Reply from User 2").decode()

    response = client.post(
        "/api/v1/messages/",
        json={
            "ciphertext": reply_ciphertext,
            "recipient_pubkey_hex": test_user.ed25519_pubkey.hex(),
            "header_blob": None,
            "pow_nonce": "test_nonce_2"
        },
        headers=other_auth_token
    )
    assert response.status_code == status.HTTP_201_CREATED
    message_id_2 = response.json()["message_id"]

    # Check User 1's inbox contains the reply (but not their own message)
    response = client.get("/api/v1/messages/inbox", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    messages = response.json()
    reply_found = False
    msg_found = False

    for msg in messages:
        if msg["id"] == message_id_2:
            reply_found = True
        if msg["id"] == message_id_1:
            msg_found = True

    assert reply_found is True
    assert msg_found is False  # Own message shouldn't be in inbox


def test_empty_inbox(client, test_user, auth_token, db_session) -> None:
    """Test getting an empty inbox."""
    # Ensure no messages are sent to this user
    response = client.get("/api/v1/messages/inbox", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []


def test_message_flow_with_pagination(client, test_user, other_user, auth_token, mock_pow_service, db_session) -> None:
    """Test message retrieval with pagination."""
    # Send multiple messages
    message_ids = []
    for i in range(10):
        ciphertext = base64.b64encode(f"Message {i}".encode()).decode()

        response = client.post(
            "/api/v1/messages/",
            json={
                "ciphertext": ciphertext,
                "recipient_pubkey_hex": other_user.ed25519_pubkey.hex(),
                "header_blob": None,
                "pow_nonce": f"test_nonce_{i}"
            },
            headers=auth_token
        )
        message_ids.append(response.json()["message_id"])

    # Get first page
    response = client.get("/api/v1/messages/sent?limit=5", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    first_page = response.json()
    assert len(first_page) == 5

    # Get second page using the order_index of the last message
    last_order_index = first_page[-1]["order_index"]
    response = client.get(f"/api/v1/messages/sent?limit=5&before={last_order_index}", headers=auth_token)
    assert response.status_code == status.HTTP_200_OK
    second_page = response.json()
    assert len(second_page) == 5

    # Verify no overlap between pages
    first_page_ids = [msg["id"] for msg in first_page]
    second_page_ids = [msg["id"] for msg in second_page]
    assert set(first_page_ids).isdisjoint(set(second_page_ids))

    # All message IDs should be covered
    all_ids = first_page_ids + second_page_ids
    assert set(all_ids) == set(message_ids[:5] + message_ids[5:])
