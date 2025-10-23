# src/chorus_stage/api/v1/endpoints/messages.py
"""Direct message endpoints for the Chorus API."""

from __future__ import annotations

import base64
import binascii
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

from chorus_stage.db.session import get_db
from chorus_stage.models import DirectMessage, User
from chorus_stage.schemas.direct_message import DirectMessageCreate
from chorus_stage.services.pow import PowService, get_pow_service

from .posts import get_current_user, get_system_clock

router = APIRouter(prefix="/messages", tags=["messages"])


def get_pow_service_dep() -> PowService:
    """Return the shared proof-of-work service."""
    return get_pow_service()


SessionDep = Annotated[Session, Depends(get_db)]
CurrentUserDep = Annotated[User, Depends(get_current_user)]
PowServiceDep = Annotated[PowService, Depends(get_pow_service_dep)]


def _encode_user_id(user_id: bytes) -> str:
    return base64.urlsafe_b64encode(user_id).decode().rstrip("=")


def _serialize_message(message: DirectMessage) -> dict[str, Any]:
    """Serialize a DirectMessage instance into API payload form."""
    return {
        "id": message.id,
        "order_index": int(message.order_index),
        "sender_user_id": _encode_user_id(message.sender_user_id),
        "recipient_user_id": _encode_user_id(message.recipient_user_id),
        "ciphertext": base64.b64encode(message.ciphertext).decode(),
        "header_blob": (
            base64.b64encode(message.header_blob).decode()
            if message.header_blob
            else None
        ),
        "delivered": message.delivered,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def send_message(
    message_data: DirectMessageCreate,
    current_user: CurrentUserDep,
    db: SessionDep,
    pow_service: PowServiceDep,
) -> dict[str, Any]:
    """Send an end-to-end encrypted direct message."""
    try:
        recipient_pubkey = bytes.fromhex(message_data.recipient_pubkey_hex)
    except ValueError as exc:  # pragma: no cover - validation should catch
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid recipient public key format",
        ) from exc

    recipient = (
        db.query(User)
        .filter(User.pubkey == recipient_pubkey)
        .first()
    )

    if recipient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found",
        )

    sender_pubkey_hex = current_user.pubkey.hex()

    if not pow_service.verify_pow("message", sender_pubkey_hex, message_data.pow_nonce):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid proof of work for sending a message",
        )

    if pow_service.is_pow_replay("message", sender_pubkey_hex, message_data.pow_nonce):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Proof of work has been used before",
        )

    pow_service.register_pow("message", sender_pubkey_hex, message_data.pow_nonce)

    clock = get_system_clock(db)

    try:
        ciphertext = base64.b64decode(message_data.ciphertext, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ciphertext must be valid base64",
        ) from exc

    header_blob: bytes | None = None
    if message_data.header_blob is not None:
        try:
            header_blob = base64.b64decode(message_data.header_blob, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Header blob must be valid base64",
            ) from exc

    new_message = DirectMessage(
        order_index=clock.day_seq,
        sender_user_id=current_user.user_id,
        recipient_user_id=recipient.user_id,
        ciphertext=ciphertext,
        header_blob=header_blob,
        delivered=False,
    )

    clock.day_seq += 1
    db.add(new_message)
    db.commit()
    db.refresh(new_message)

    return {"status": "message_sent", "message_id": new_message.id}


@router.get("/inbox")
async def get_inbox(
    current_user: CurrentUserDep,
    db: SessionDep,
    limit: int = Query(50, le=100),
    before: int | None = Query(None),
) -> list[dict[str, Any]]:
    """Get encrypted messages for current user (as recipient)."""
    query = db.query(DirectMessage).filter(
        DirectMessage.recipient_user_id == current_user.user_id
    )

    if before is not None:
        query = query.filter(DirectMessage.order_index < before)

    messages = query.order_by(desc(DirectMessage.order_index)).limit(limit).all()
    return [_serialize_message(message) for message in messages]


@router.get("/sent")
async def get_sent_messages(
    current_user: CurrentUserDep,
    db: SessionDep,
    limit: int = Query(50, le=100),
    before: int | None = Query(None),
) -> list[dict[str, Any]]:
    """Get encrypted messages sent by current user."""
    query = db.query(DirectMessage).filter(
        DirectMessage.sender_user_id == current_user.user_id
    )

    if before is not None:
        query = query.filter(DirectMessage.order_index < before)

    messages = query.order_by(desc(DirectMessage.order_index)).limit(limit).all()
    return [_serialize_message(message) for message in messages]


@router.put("/{message_id}/read")
async def mark_message_read(
    message_id: int,
    current_user: CurrentUserDep,
    db: SessionDep,
) -> dict[str, str]:
    """Mark a direct message as read/delivered."""
    message = (
        db.query(DirectMessage)
        .filter(
            DirectMessage.id == message_id,
            DirectMessage.recipient_user_id == current_user.user_id,
        )
        .first()
    )

    if message is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    message.delivered = True
    db.commit()

    return {"status": "marked_as_read"}
