"""CRUD-style helpers for managing users."""
from __future__ import annotations

from typing import Sequence

from sqlalchemy.orm import Session

from chorus_stage.core import security
from chorus_stage.models.user import User
from chorus_stage.schemas.user import UserCreate, UserUpdate

__all__ = [
    "get_user",
    "get_users",
    "create_user",
    "update_user",
    "delete_user",
]


def get_user(db: Session, user_id: int) -> User | None:
    """Return a single user by primary key."""
    return db.query(User).filter(User.id == user_id).first()


def get_users(db: Session, skip: int = 0, limit: int = 100) -> Sequence[User]:
    """Return users with simple offset-based pagination."""
    return db.query(User).offset(skip).limit(limit).all()


def create_user(db: Session, user: UserCreate, user_key: str) -> User:
    """Persist a new user with a hashed authentication key."""
    hashed_key = security.hash_key(user_key)
    db_user = User(user_key=hashed_key, display_name=user.display_name)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user(db: Session, db_user: User, update_data: UserUpdate) -> User:
    """Apply partial updates to an existing user."""
    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(db_user, key, value)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def delete_user(db: Session, db_user: User) -> User:
    """Remove a user from the database and return the deleted instance."""
    db.delete(db_user)
    db.commit()
    return db_user
