# src/chorus_stage/models/vote.py
"""Models capturing voting interactions on posts."""

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Index, Numeric, SmallInteger
from sqlalchemy.orm import Mapped, mapped_column

from chorus_stage.db.session import Base
from chorus_stage.db.time import utcnow


class PostVote(Base):
    """Per-user vote on a post.

    Votes are weighted to establish content quality signals while
    preserving voter anonymity.
    """

    __tablename__ = "post_vote"
    __table_args__ = (
        CheckConstraint("direction IN (1, -1)", name="ck_post_vote_direction"),
        Index("ix_post_vote_post_id", "post_id"),
    )

    post_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("post.id", ondelete="CASCADE"),
        primary_key=True,
    )

    voter_user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("user_account.id"),
        primary_key=True,
    )

    # Composite primary key prevents duplicate votes from the same user.

    # 1 = upvote, -1 = downvote.
    direction: Mapped[int] = mapped_column(SmallInteger, nullable=False)

    # Future-proof for reputation models; default weight = 1.0.
    weight: Mapped[float] = mapped_column(Numeric(8, 4), nullable=False, default=1.0)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
