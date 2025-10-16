"""Endpoints for lightweight moderation flows."""
from __future__ import annotations

import math

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from chorus_stage.core import settings as core_settings
from chorus_stage.db.session import get_session
from chorus_stage.repositories.post_repo import PostRepository
from chorus_stage.schemas.moderation import ModerationVoteIn

router = APIRouter(tags=["moderation"])


def _hide_threshold_votes(total_population: int = 100) -> int:
    """Compute the vote count needed to hide content."""
    threshold = getattr(core_settings, "HARMFUL_HIDE_THRESHOLD", 0.5)
    return max(1, math.ceil(threshold * total_population))


@router.post("/{post_id}/vote", status_code=status.HTTP_202_ACCEPTED)
async def cast_moderation_vote(
    post_id: int,
    payload: ModerationVoteIn,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Record a moderation vote and hide the post if a simple threshold is met."""
    if payload.choice not in (0, 1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid vote choice")

    repo = PostRepository(session)
    post = await repo.get_by_id(post_id)
    if post is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    if payload.choice == 1:
        post = await repo.increment_harmful_votes(post_id)
        threshold_votes = _hide_threshold_votes()
        if post and post.harmful_vote_count >= threshold_votes:
            post.moderation_state = 2
            await session.flush()

    await session.commit()
    return {"status": "accepted"}
