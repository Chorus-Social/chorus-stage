"""Data access helpers for posts."""
from __future__ import annotations
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from chorus.models.post import Post

class PostRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, post_id: int) -> Post | None:
        """Fetch a post by id. Returns None if not found."""
        res = await self.session.execute(select(Post).where(Post.id == post_id))
        return res.scalars().first()

    async def create(self, *, author_pubkey: bytes, body_md: str, content_hash: bytes, order_index: int) -> Post:
        """Insert a new post and return it.

        Pre-conditions:
        - `author_pubkey` is 32 bytes
        - `order_index` is monotonically increasing (enforced by caller)
        """
        p = Post(author_pubkey=author_pubkey, body_md=body_md, content_hash=content_hash, order_index=order_index)
        self.session.add(p)
        await self.session.flush()
        return p
