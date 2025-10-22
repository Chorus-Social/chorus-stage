# src/chorus_stage/models/user.py
"""SQLAlchemy models for anonymous user identities."""

from __future__ import annotations

import base64

from sqlalchemy import BigInteger, ForeignKey, Integer, LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from chorus_stage.db.session import Base


class User(Base):
    """Anonymous identity keyed by the hash of an Ed25519 public key."""

    __tablename__ = "anon_key"

    user_id: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    pubkey: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    accent_color: Mapped[str | None] = mapped_column(Text, nullable=True)

    state: Mapped[UserState] = relationship(
        "UserState",
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
    )

    @property
    def pubkey_hex(self) -> str:
        """Return the user's public key as a hex string."""
        return self.pubkey.hex()

    @property
    def user_id_hex(self) -> str:
        """Return the user identifier as a hex string."""
        return self.user_id.hex()

    @property
    def user_id_b64(self) -> str:
        """Return the user identifier encoded in URL-safe base64."""
        return base64.urlsafe_b64encode(self.user_id).decode().rstrip("=")

    # Provide legacy attribute name compatibility.
    id = synonym("user_id")


class UserState(Base):
    """Per-user mutable state kept separate from identity metadata."""

    __tablename__ = "user_state"

    user_id: Mapped[bytes] = mapped_column(
        LargeBinary(32),
        ForeignKey("anon_key.user_id", ondelete="CASCADE"),
        primary_key=True,
    )
    mod_tokens_remaining: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    mod_tokens_day_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    user: Mapped[User] = relationship("User", back_populates="state")
