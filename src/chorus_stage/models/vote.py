"""SQLAlchemy models for votes and moderation logs."""
from __future__ import annotations
from sqlalchemy import BigInteger, Column, ForeignKey, SmallInteger, Numeric, Text
from chorus.db.session import Base

class Vote(Base):
    __tablename__ = "vote"
    post_id = Column(BigInteger, ForeignKey("post.id", ondelete="CASCADE"), primary_key=True)
    voter_pubkey = Column("voter_pubkey", type_=bytes, primary_key=True)  # store as bytea
    choice = Column(SmallInteger, nullable=False)  # 1 harmful, 0 not
    weight = Column(Numeric(8,4), nullable=False, default=1.0)

class ModerationAction(Base):
    __tablename__ = "moderation_action"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    post_id = Column(BigInteger, ForeignKey("post.id"))
    action = Column(SmallInteger, nullable=False)  # 0 soft_hide, 1 hard_remove
    reason = Column(Text, nullable=False)
    threshold_snapshot = Column(Text, nullable=False)  # json
    created_seq = Column(BigInteger, nullable=False)
