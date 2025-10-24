# src/chorus_stage/models/moderation.py
"""Models tracking moderation cases and associated actions."""

from sqlalchemy import BigInteger, ForeignKey, LargeBinary, Numeric, SmallInteger
from sqlalchemy.orm import Mapped, mapped_column

from chorus_stage.db.session import Base

MODERATION_STATE_OPEN = 0
MODERATION_STATE_CLEARED = 1
MODERATION_STATE_HIDDEN = 2


class ModerationCase(Base):
    """State machine representing the moderation status of a post."""

    __tablename__ = "moderation_case"

    # One case per post currently in queue; reopening replaces the state as needed.
    post_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("post.id", ondelete="CASCADE"),
        primary_key=True,
    )
    community_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("community.id"),
        nullable=False,
    )
    # 0 = open, 1 = cleared (not harmful), 2 = hidden (harmful).
    state: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=MODERATION_STATE_OPEN)
    # Snapshot numbers for audit without relying on timestamps.
    opened_order_index: Mapped[int] = mapped_column(Numeric(38, 0), nullable=False)
    closed_order_index: Mapped[int | None] = mapped_column(Numeric(38, 0), nullable=True)

class ModerationVote(Base):
    """Votes cast by community members when moderating a piece of content."""

    __tablename__ = "moderation_vote"

    post_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("moderation_case.post_id", ondelete="CASCADE"),
        primary_key=True,
    )
    voter_user_id: Mapped[bytes] = mapped_column(
        LargeBinary(32),
        primary_key=True,
    )
    # 1 = harmful, 0 = not harmful.
    choice: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    weight: Mapped[float] = mapped_column(Numeric(8, 4), nullable=False, default=1.0)

class ModerationTrigger(Base):
    """Audit record showing that a user spent a token to flag a post."""

    __tablename__ = "moderation_trigger"

    post_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("post.id", ondelete="CASCADE"),
        primary_key=True
    )
    trigger_user_id: Mapped[bytes] = mapped_column(
        LargeBinary(32),
        ForeignKey("anon_key.user_id"),
        primary_key=True,
    )
    day_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
