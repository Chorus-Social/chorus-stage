"""Data access helpers for working with posts."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from chorus_stage.models.moderation import MODERATION_STATE_HIDDEN
from chorus_stage.models.post import Post

__all__ = ["PostRepository"]


class PostRepository:
    """Thin wrapper around database access for post entities."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the repository with an async SQLAlchemy session."""
        self.session = session

    async def get_by_id(self, post_id: int) -> Post | None:
        """Return a post by identifier."""
        result = await self.session.execute(select(Post).where(Post.id == post_id))
        return result.scalars().first()

    async def list_recent(self, limit: int) -> list[Post]:
        """Return posts sorted by descending order index."""
        result = await self.session.execute(
            select(Post)
            .where(Post.deleted.is_(False))
            .order_by(Post.order_index.desc())
            .limit(limit)
        )
        return list(result.scalars())

    async def list_visible(self, limit: int | None = None) -> list[Post]:
        """Return posts that are not hidden by moderation."""
        stmt = select(Post).where(
            Post.deleted.is_(False),
            Post.moderation_state != MODERATION_STATE_HIDDEN,
        )
        stmt = stmt.order_by(Post.order_index.desc())
        if limit is not None:
            stmt = stmt.limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars())

    async def create(
        self,
        *,
        author_pubkey: bytes,
        body_md: str,
        content_hash: bytes,
        order_index: int,
    ) -> Post:
        """Insert a new post and return the persisted ORM instance.

        Args:
            author_pubkey: Raw author public key bytes (should be 32 bytes).
            body_md: Markdown body content.
            content_hash: SHA-256 digest of the body for deduplication.
            order_index: Monotonic ordering index supplied by the service layer.
        """
        post = Post(
            author_pubkey=author_pubkey,
            body_md=body_md,
            content_hash=content_hash,
            order_index=order_index,
        )
        self.session.add(post)
        await self.session.flush()
        return post

    async def increment_harmful_votes(self, post_id: int, delta: int = 1) -> Post | None:
        """Increment the harmful vote counter for a post."""
        post = await self.get_by_id(post_id)
        if post is None:
            return None
        post.harmful_vote_count += delta
        await self.session.flush()
        return post
