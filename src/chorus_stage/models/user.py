"""SQLAlchemy model definitions for users."""
from sqlalchemy import BigInteger, LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column

from chorus_stage.db.session import Base


class User(Base):
    """Persistent representation of a user account."""

    __tablename__ = "user_account"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Ed25519 identity (public) used to sign requests.
    ed25519_pubkey: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    # Optional display persona fields.
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    preferred_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    pronouns: Mapped[str | None] = mapped_column(Text, nullable=True)
    gender_identity: Mapped[str | None] = mapped_column(Text, nullable=True)
    sexual_orientation: Mapped[str | None] = mapped_column(Text, nullable=True)
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)

    # PGP for client E2E payload delivery (armored).
    pgp_public_key_asc: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Moderation token bookkeeping (privacy-preserving).
    mod_tokens_remaining: Mapped[int] = mapped_column(default=3, nullable=False)
    mod_tokens_day_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    # Optional: soft deletion without removing signatures.
    deleted: Mapped[bool] = mapped_column(default=False, nullable=False)
