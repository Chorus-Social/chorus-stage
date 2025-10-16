"""Schemas describing user entities and payloads."""
from __future__ import annotations

from pydantic import BaseModel


class UserBase(BaseModel):
    """Common fields shared across user payloads."""

    display_name: str | None = None


class UserCreate(UserBase):
    """Payload for creating a user; the authentication key arrives separately."""


class UserUpdate(UserBase):
    """Partial update payload; unset fields are ignored."""


class UserOut(UserBase):
    """Representation of a persisted user."""

    id: int

    class Config:
        # Enable compatibility with ORM objects.
        from_attributes = True
