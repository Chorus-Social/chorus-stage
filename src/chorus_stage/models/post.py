"""SQLAlchemy models for posts and related entities."""
from __future__ import annotations
from sqlalchemy import BigInteger, Column, ForeignKey, Boolean, Text, LargeBinary, Numeric
from sqlalchemy.orm import relationship
from chorus.db.session import Base

class AnonKey(Base):
    __tablename__ = "anon_key"
    pubkey = Column(LargeBinary, primary_key=True)   # 32 bytes
    display_name = Column(Text, nullable=True)
    accent_color = Column(Text, nullable=True)
    created_seq = Column(BigInteger, nullable=False)

class Post(Base):
    __tablename__ = "post"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    author_pubkey = Column(LargeBinary, ForeignKey("anon_key.pubkey"), nullable=False)
    body_md = Column(Text, nullable=False)
    content_hash = Column(LargeBinary, nullable=False)
    order_index = Column(Numeric(38, 0), nullable=False, unique=True)
    deleted = Column(Boolean, nullable=False, default=False)
