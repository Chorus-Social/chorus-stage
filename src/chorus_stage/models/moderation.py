# models/moderation.py
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import BigInteger, Text, SmallInteger, ForeignKey, Numeric
from chorus_stage.db.session import Base

class ModerationCase(Base):
    __tablename__ = "moderation_case"

    # One case per post currently in queue; re-open by replacing state as needed
    post_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("post.id", ondelete="CASCADE"), primary_key=True)
    community_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("community.id"), nullable=False)
    # 0 = open, 1 = cleared (not harmful), 2 = hidden (harmful)
    state: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    # Snapshot numbers for audit; not timestamps
    opened_order_index: Mapped[int] = mapped_column(Numeric(38,0), nullable=False)

class ModerationVote(Base):
    __tablename__ = "moderation_vote"

    post_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("moderation_case.post_id", ondelete="CASCADE"), primary_key=True)
    voter_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_account.id"), primary_key=True)
    # 1 harmful, 0 not harmful
    choice: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    weight: Mapped[float] = mapped_column(Numeric(8,4), nullable=False, default=1.0)

class ModerationTrigger(Base):
    """
    Records that a user spent a token to send a post to moderation.
    No timestamps: we log day_seq used and the consuming user.
    """
    __tablename__ = "moderation_trigger"

    post_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("post.id", ondelete="CASCADE"), primary_key=True)
    trigger_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_account.id"), primary_key=True)
    day_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)