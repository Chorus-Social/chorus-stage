"""Moderation-related endpoints for the Chorus API."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from chorus_stage.db.session import get_db
from chorus_stage.models import (
    ModerationCase,
    ModerationTrigger,
    ModerationVote,
    Post,
    User,
)
from chorus_stage.models.moderation import MODERATION_STATE_OPEN
from chorus_stage.schemas.post import PostResponse
from chorus_stage.services.moderation import ModerationService

from .posts import get_current_user, get_system_clock

router = APIRouter(prefix="/moderation", tags=["moderation"])
moderation_service = ModerationService()
SessionDep = Annotated[Session, Depends(get_db)]
CurrentUserDep = Annotated[User, Depends(get_current_user)]


@router.get("/queue", response_model=list[PostResponse])
async def get_moderation_queue(
    db: SessionDep,
    limit: int = Query(50, le=100),
    before: int | None = Query(None),
) -> list[Post]:
    """Get posts currently in the moderation queue."""
    query = db.query(ModerationCase).filter(ModerationCase.state == MODERATION_STATE_OPEN)

    if before is not None:
        query = query.filter(ModerationCase.opened_order_index < before)

    cases = query.order_by(ModerationCase.opened_order_index).limit(limit).all()
    case_ids = [case.post_id for case in cases]

    if not case_ids:
        return []

    return (
        db.query(Post)
        .filter(Post.id.in_(case_ids), Post.deleted.is_(False))
        .all()
    )


@router.post("/trigger", status_code=status.HTTP_201_CREATED)
async def trigger_moderation(
    post_id: int,
    current_user: CurrentUserDep,
    db: SessionDep,
) -> dict[str, int | str]:
    """Trigger moderation for a post using a moderation token."""
    post = (
        db.query(Post)
        .filter(Post.id == post_id, Post.deleted.is_(False))
        .first()
    )

    if post is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found",
        )

    if not moderation_service.can_trigger_moderation(current_user.user_id, post_id, db):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="You have already triggered moderation for this post today",
        )

    if not moderation_service.consume_moderation_token(current_user.user_id, db):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="No moderation tokens remaining",
        )

    case = db.query(ModerationCase).filter(ModerationCase.post_id == post_id).first()
    trigger_day_seq = 0

    if case is None:
        clock = get_system_clock(db)
        trigger_day_seq = clock.day_seq
        case = ModerationCase(
            post_id=post_id,
            community_id=post.community_id or 1,
            state=MODERATION_STATE_OPEN,
            opened_order_index=clock.day_seq,
        )
        clock.day_seq += 1
        db.add(case)
        db.commit()
        db.refresh(case)
    else:
        trigger_day_seq = int(case.opened_order_index)

    trigger = ModerationTrigger(
        post_id=post_id,
        trigger_user_id=current_user.user_id,
        day_seq=trigger_day_seq,
    )
    db.add(trigger)
    db.commit()

    return {"status": "moderation_triggered", "case_id": case.post_id}


@router.post("/vote", status_code=status.HTTP_201_CREATED)
async def vote_on_moderation(
    post_id: int,
    current_user: CurrentUserDep,
    db: SessionDep,
    is_harmful: bool = Query(..., description="Whether the post is considered harmful"),
) -> dict[str, str]:
    """Vote on whether a post is harmful."""
    post = (
        db.query(Post)
        .filter(Post.id == post_id, Post.deleted.is_(False))
        .first()
    )

    if post is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found",
        )

    case = db.query(ModerationCase).filter(ModerationCase.post_id == post_id).first()
    if case is None:
        clock = get_system_clock(db)
        case = ModerationCase(
            post_id=post_id,
            community_id=post.community_id or 1,
            state=MODERATION_STATE_OPEN,
            opened_order_index=clock.day_seq,
        )
        clock.day_seq += 1
        db.add(case)
        db.commit()
        db.refresh(case)

    existing_vote = (
        db.query(ModerationVote)
        .filter(
            ModerationVote.post_id == post_id,
            ModerationVote.voter_user_id == current_user.user_id,
        )
        .first()
    )

    choice = 1 if is_harmful else 0
    if existing_vote:
        existing_vote.choice = choice
    else:
        db.add(
            ModerationVote(
                post_id=post_id,
                voter_user_id=current_user.user_id,
                choice=choice,
                weight=1.0,
            )
        )

    moderation_service.update_moderation_state(post_id, db)
    db.commit()

    return {"status": "vote_recorded"}


@router.get("/history")
async def get_moderation_history(
    current_user: CurrentUserDep,
    db: SessionDep,
    limit: int = Query(50, le=100),
    before: int | None = Query(None),
) -> list[dict[str, int]]:
    """Get moderation history for posts authored by the current user."""
    query = (
        db.query(ModerationCase)
        .join(Post)
        .filter(Post.author_user_id == current_user.user_id, Post.deleted.is_(False))
    )

    if before is not None:
        query = query.filter(ModerationCase.opened_order_index < before)

    cases = query.order_by(ModerationCase.opened_order_index.desc()).limit(limit).all()
    return [
        {
            "post_id": case.post_id,
            "state": case.state,
            "opened_order_index": int(case.opened_order_index),
        }
        for case in cases
    ]
