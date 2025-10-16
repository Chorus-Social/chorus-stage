# models/vote.py
from __future__ import annotations
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import BigInteger, SmallInteger, Numeric, ForeignKey, CheckConstraint, Index
from chorus_stage.db.session import Base

class PostVote(Base):
    """Per-user vote on a post.

    Notes
    -----
    - Composite PK (post_id, voter_user_id) prevents duplicate votes.
    - `direction` is constrained to {1, -1}.
    - `weight` reserved for future reputation weighting.
    - No timestamps by design; recency windows use order_index on `post`.
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

    # 1 = upvote, -1 = downvote
    direction: Mapped[int] = mapped_column(SmallInteger, nullable=False)

    # Future-proof for reputation models; default weight = 1.0
    weight: Mapped[float] = mapped_column(Numeric(8, 4), nullable=False, default=1.0)