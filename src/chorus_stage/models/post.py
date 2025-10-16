"""SQLAlchemy models for posts and related attributes."""
from sqlalchemy import BigInteger, ForeignKey, LargeBinary, Numeric, Text
from sqlalchemy.orm import Mapped, mapped_column

from chorus_stage.db.session import Base


class Post(Base):
    """Primary content entity produced by users."""

    __tablename__ = "post"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # Global monotonic index for sorting without relying on timestamps.
    order_index: Mapped[int] = mapped_column(Numeric(38, 0), nullable=False, unique=True)
    author_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_account.id"), nullable=False)

    # Parent chain for comments; top-level posts have parent_post_id = NULL.
    parent_post_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("post.id"), nullable=True)

    # Every post belongs to a community (including user profile communities).
    community_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("community.id"), nullable=False)

    # Text only; links are literal URLs inside markdown.
    body_md: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Moderation state machine codes:
    # 0 = visible, 1 = in_queue (excluded from home feed), 2 = hidden (threshold met).
    moderation_state: Mapped[int] = mapped_column(default=0, nullable=False)

    deleted: Mapped[bool] = mapped_column(default=False, nullable=False)
