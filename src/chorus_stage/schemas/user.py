"""User-related Pydantic schemas."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PowEnvelope(BaseModel):
    """Payload describing the proof-of-work presented during authentication."""

    nonce: str = Field(..., description="Client-computed PoW nonce")
    difficulty: int = Field(..., ge=1, description="Difficulty (leading zero bits) satisfied")
    target: str = Field(..., description="Opaque PoW challenge identifier")


class SignatureProof(BaseModel):
    """Proof that the client controls the submitted public key."""

    challenge: str = Field(..., description="Opaque challenge string (base64 encoded)")
    signature: str = Field(..., description="Signature over the challenge")


class ChallengeRequest(BaseModel):
    """Request to obtain a registration/login challenge."""

    pubkey: str = Field(..., description="Base64-encoded Ed25519 public key (32 bytes)")
    intent: Literal["register", "login"] = Field(..., description="Handshake intent")


class ChallengeResponse(BaseModel):
    """Challenge payload returned to clients before authentication."""

    pow_target: str = Field(..., description="Server-supplied PoW challenge identifier")
    pow_difficulty: int = Field(..., description="Difficulty clients must satisfy")
    signature_challenge: str = Field(..., description="Base64 challenge that must be signed")


class RegisterRequest(BaseModel):
    """Schema for anonymous key registration."""

    pubkey: str = Field(..., description="Base64-encoded Ed25519 public key (32 bytes)")
    display_name: str | None = Field(None, description="Optional persona label")
    accent_color: str | None = Field(None, description="Optional client-specified accent color")
    pow: PowEnvelope
    proof: SignatureProof


class RegisterResponse(BaseModel):
    """Registration response containing the derived anonymous identifier."""

    user_id: str = Field(..., description="URL-safe base64 encoded BLAKE3 digest of the public key")
    created: bool = Field(..., description="True if a new record was inserted")

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    """Schema for login submissions."""

    pubkey: str = Field(..., description="Base64-encoded Ed25519 public key (32 bytes)")
    pow: PowEnvelope
    proof: SignatureProof


class LoginResponse(BaseModel):
    """Response returned after successful login."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(..., description="Token type (typically 'bearer')")
    session_nonce: str = Field(..., description="Ephemeral nonce for client session binding")
