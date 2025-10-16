# models/post.py
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import BigInteger, Text, LargeBinary, Numeric, Boolean, ForeignKey
from chorus_stage.db.session import Base

class Post(Base):
    __tablename__ = "post"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    order_index: Mapped[int] = mapped_column(Numeric(38,0), nullable=False, unique=True)  # global monotonic
    author_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_account.id"), nullable=False)

    # Parent chain for comments; top-level posts have parent_post_id = NULL
    parent_post_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("post.id"), nullable=True)

    # Required: every post belongs to a community (can also be a user’s profile-community)
    community_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("community.id"), nullable=False)

    # Text only; links are just literal URLs inside markdown
    body_md: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Moderation state machine
    # 0 = visible, 1 = in_queue (excluded from home feed), 2 = hidden (threshold met)
    moderation_state: Mapped[int] = mapped_column(default=0, nullable=False)

    deleted: Mapped[bool] = mapped_column(default=False, nullable=False)