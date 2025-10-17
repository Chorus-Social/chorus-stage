# src/chorus_stage/schemas/direct_message.py
"""Direct message-related Pydantic schemas."""

import base64

from pydantic import BaseModel, ConfigDict, Field, field_serializer


class DirectMessageCreate(BaseModel):
    """Schema for creating a new direct message."""

    ciphertext: str = Field(..., description="Base64-encoded PGP-encrypted message content")
    recipient_pubkey_hex: str = Field(..., description="Hex-encoded public key of recipient")
    header_blob: str | None = Field(None, description="Optional base64-encoded encryption header")
    pow_nonce: str = Field(..., description="Proof of work nonce")


class DirectMessageResponse(BaseModel):
    """Schema for direct message information returned by the API."""

    id: int
    order_index: int
    sender_user_id: int
    recipient_user_id: int
    ciphertext: str
    header_blob: str | None
    delivered: bool

    @field_serializer("ciphertext")
    def serialize_ciphertext(self, value: bytes | str) -> str:
        """Encode the binary ciphertext as base64."""
        if isinstance(value, bytes):
            return base64.b64encode(value).decode()
        return value

    @field_serializer("header_blob")
    def serialize_header_blob(self, value: bytes | str | None) -> str | None:
        """Encode the binary header blob as base64."""
        if value is None:
            return None
        if isinstance(value, bytes):
            return base64.b64encode(value).decode()
        return value

    model_config = ConfigDict(from_attributes=True)
