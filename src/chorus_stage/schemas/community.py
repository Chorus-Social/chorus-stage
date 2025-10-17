# src/chorus_stage/schemas/community.py
"""Community-related Pydantic schemas."""


from pydantic import BaseModel


class CommunityCreate(BaseModel):
    """Schema for creating a new community."""

    internal_slug: str
    display_name: str
    description_md: str | None = None

class CommunityResponse(BaseModel):
    """Schema for community information returned by the API."""

    id: int
    internal_slug: str
    display_name: str
    description_md: str | None
    is_profile_like: bool
    order_index: int
