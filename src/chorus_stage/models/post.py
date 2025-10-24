# src/chorus_stage/models/post.py
"""SQLAlchemy models for posts and related attributes."""

from sqlalchemy import BigInteger, ForeignKey, Integer, LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column

from chorus_stage.db.session import Base


class Post(Base):
    """Primary content entity produced by users.

    Posts are the central content type in Chorus, organized in a global
    deterministic order without timestamps to protect against timing analysis.
    """

    __tablename__ = "post"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Global monotonic index for sorting without relying on timestamps.
    order_index: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    author_user_id: Mapped[bytes | None] = mapped_column(
        LargeBinary(32),
        ForeignKey("anon_key.user_id"),
        nullable=True,
    )
    author_pubkey: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Global identifier assigned by the bridge; may be null for legacy/local rows.
    federation_post_id: Mapped[bytes | None] = mapped_column(
        LargeBinary(32),
        nullable=True,
        unique=True,
    )
    federation_origin: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Parent chain for comments; top-level posts have parent_post_id = NULL.
    parent_post_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("post.id"),
        nullable=True,
    )

    # Every post belongs to a community (including user profile communities).
    community_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("community.id"),
        nullable=True,
    )

    # Text only; links are literal URLs inside markdown.
    body_md: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Moderation state machine codes:
    # 0 = visible, 1 = in_queue (excluded from home feed), 2 = hidden (threshold met).
    moderation_state: Mapped[int] = mapped_column(default=0, nullable=False)
    harmful_vote_count: Mapped[int] = mapped_column(default=0, nullable=False)
    upvotes: Mapped[int] = mapped_column(default=0, nullable=False)
    downvotes: Mapped[int] = mapped_column(default=0, nullable=False)

    deleted: Mapped[bool] = mapped_column(default=False, nullable=False)
