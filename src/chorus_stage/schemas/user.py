from __future__ import annotations
from pydantic import BaseModel

class UserBase(BaseModel):
    display_name: str | None = None

class UserCreate(UserBase):
    """Payload for creating a user. Keys are provided separately for hashing."""

class UserUpdate(UserBase):
    """Partial update. Unset fields are ignored."""

class UserOut(UserBase):
    id: int

    class Config:
        from_attributes = True  # Pydantic v2: replaces orm_mode