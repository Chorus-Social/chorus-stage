"""Feed endpoints for listing posts in various orders."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from chorus_stage.db.session import get_session
from chorus_stage.repositories.post_repo import PostRepository
from chorus_stage.schemas.post import PostOut
from chorus_stage.services.post_service import to_post_out

router = APIRouter(tags=["feed"])


@router.get("/rising", response_model=list[PostOut])
async def get_rising_feed(
    limit: int = Query(10, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> list[PostOut]:
    """Return a slice of the most recent posts."""
    repo = PostRepository(session)
    posts = await repo.list_visible(limit)
    return [to_post_out(post) for post in posts]


@router.get("/home", response_model=list[PostOut])
async def get_home_feed(
    limit: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> list[PostOut]:
    """Return posts suitable for the home feed."""
    repo = PostRepository(session)
    posts = await repo.list_visible(limit)
    return [to_post_out(post) for post in posts]
