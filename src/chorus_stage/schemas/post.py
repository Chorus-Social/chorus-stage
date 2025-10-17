# src/chorus_stage/schemas/post.py
"""Post-related Pydantic schemas."""

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PostCreate(BaseModel):
    """Schema for creating a new post."""

    content_md: str = Field(..., min_length=1, max_length=5000, description="Markdown content")
    parent_post_id: int | None = Field(None, description="Parent post ID for comments")
    community_internal_slug: str | None = Field(None, description="Community slug")
    pow_nonce: str = Field(..., description="Proof of work nonce")
    pow_difficulty: int = Field(
        ...,
        ge=15,
        description="Proof of work difficulty",
    )
    content_hash: str = Field(..., description="Hash of the content for integrity verification")


class PostResponse(BaseModel):
    """Schema for post information returned by the API."""

    id: int
    order_index: int
    author_user_id: int | None
    author_pubkey: str
    parent_post_id: int | None
    community_id: int | None
    body_md: str
    content_hash: str
    moderation_state: int
    harmful_vote_count: int
    upvotes: int
    downvotes: int
    deleted: bool

    @model_validator(mode="before")
    @classmethod
    def _decode_binary_fields(cls, data: object) -> object:
        if not isinstance(data, dict):
            extracted: dict[str, object | None] = {}
            for field_name in cls.model_fields:
                extracted[field_name] = getattr(data, field_name, None)
            data = extracted

        author = data.get("author_pubkey")
        if isinstance(author, bytes | bytearray):
            data["author_pubkey"] = author.hex()

        content_hash = data.get("content_hash")
        if isinstance(content_hash, bytes | bytearray):
            data["content_hash"] = content_hash.hex()

        return data

    model_config = ConfigDict(from_attributes=True)
