"""User-related Pydantic schemas."""

from pydantic import BaseModel, ConfigDict, Field, model_validator


class UserIdentity(BaseModel):
    """Schema for user registration/identity verification."""

    ed25519_pubkey: str = Field(..., description="Hex-encoded Ed25519 public key")
    display_name: str | None = Field(None, description="Optional display name")
    preferred_name: str | None = Field(None)
    pronouns: str | None = Field(None)
    gender_identity: str | None = Field(None)
    sexual_orientation: str | None = Field(None)
    bio: str | None = Field(None)
    pgp_public_key_asc: str | None = Field(
        None,
        description="Optional PGP public key in ASCII armor format",
    )

    model_config = ConfigDict(arbitrary_types_allowed=True)


class UserResponse(BaseModel):
    """Schema for user information returned by the API."""

    id: int
    ed25519_pubkey: str = Field(..., description="Hex-encoded Ed25519 public key")
    display_name: str | None
    preferred_name: str | None
    pronouns: str | None
    gender_identity: str | None
    sexual_orientation: str | None
    bio: str | None
    pgp_public_key: bool = Field(..., description="Whether user has a PGP public key")
    mod_tokens_remaining: int
    deleted: bool

    @model_validator(mode="before")
    @classmethod
    def _normalize_fields(cls, data: object) -> object:
        if isinstance(data, dict):
            pubkey = data.get("ed25519_pubkey")
            if isinstance(pubkey, (bytes, bytearray)):
                data["ed25519_pubkey"] = pubkey.hex()

            pgp_flag = data.get("pgp_public_key")
            if isinstance(pgp_flag, (bytes, bytearray)) or pgp_flag is not None and not isinstance(pgp_flag, bool):
                data["pgp_public_key"] = bool(pgp_flag)

        return data

    model_config = ConfigDict(from_attributes=True)
