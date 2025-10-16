# models/community.py
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import BigInteger, Text, Boolean
from chorus_stage.db.session import Base

class Community(Base):
    __tablename__ = "community"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    internal_slug: Mapped[str] = mapped_column(Text, unique=True, nullable=False)  # your internal id/handle
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    description_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Treat like a user profile functionally
    is_profile_like: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # For deterministic ordering of community creation if needed
    order_index: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)

class CommunityMember(Base):
    __tablename__ = "community_member"

    community_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # No timestamps. Presence implies membership.