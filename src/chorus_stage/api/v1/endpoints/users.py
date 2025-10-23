"""User transparency endpoints (anonymized summaries)."""

from __future__ import annotations

import base64
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from chorus_stage.db.session import get_db
from chorus_stage.models import (
    Community,
    ModerationCase,
    ModerationTrigger,
    ModerationVote,
    Post,
    PostVote,
    User,
    UserState,
)

router = APIRouter(prefix="/users", tags=["users", "transparency"])

SessionDep = Annotated[Session, Depends(get_db)]


def _decode_user_id(subject: str) -> bytes:
    padding = "=" * (-len(subject) % 4)
    try:
        return base64.urlsafe_b64decode(subject + padding)
    except Exception as err:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user identifier encoding",
        ) from err


@router.get("/{user_id}/summary")
async def get_user_summary(user_id: str, db: SessionDep) -> dict[str, Any]:
    """Return an anonymized overview of a user's activity.

    Input is URL-safe base64 of user_id (BLAKE3(pubkey)).
    """
    user_id_bytes = _decode_user_id(user_id)
    user = db.query(User).filter(User.user_id == user_id_bytes).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Posts and comments
    total_posts = (
        db.query(func.count()).select_from(Post).filter(Post.author_user_id == user_id_bytes).scalar() or 0
    )
    total_comments = (
        db.query(func.count())
        .select_from(Post)
        .filter(Post.author_user_id == user_id_bytes, Post.parent_post_id.isnot(None))
        .scalar()
        or 0
    )
    # Vote activity cast by the user
    upvotes_cast = (
        db.query(func.count())
        .select_from(PostVote)
        .filter(PostVote.voter_user_id == user_id_bytes, PostVote.direction == 1)
        .scalar()
        or 0
    )
    downvotes_cast = (
        db.query(func.count())
        .select_from(PostVote)
        .filter(PostVote.voter_user_id == user_id_bytes, PostVote.direction == -1)
        .scalar()
        or 0
    )
    # Moderation participation (cast by the user)
    mod_votes_harmful = (
        db.query(func.count())
        .select_from(ModerationVote)
        .filter(ModerationVote.voter_user_id == user_id_bytes, ModerationVote.choice == 1)
        .scalar()
        or 0
    )
    mod_votes_not = (
        db.query(func.count())
        .select_from(ModerationVote)
        .filter(ModerationVote.voter_user_id == user_id_bytes, ModerationVote.choice == 0)
        .scalar()
        or 0
    )
    # Moderation triggers spent
    mod_triggers = (
        db.query(func.count())
        .select_from(ModerationTrigger)
        .filter(ModerationTrigger.trigger_user_id == user_id_bytes)
        .scalar()
        or 0
    )
    # Tokens remaining (informative, not identifying)
    state = db.query(UserState).filter(UserState.user_id == user_id_bytes).first()
    tokens_remaining = int(state.mod_tokens_remaining) if state else 0

    # Number of communities they posted in
    communities_count = (
        db.query(func.count(func.distinct(Post.community_id)))
        .filter(Post.author_user_id == user_id_bytes, Post.community_id.isnot(None))
        .scalar()
        or 0
    )

    return {
        "user_id": user_id,
        "profile": {
            "display_name": user.display_name,
            "accent_color": user.accent_color,
        },
        "posts": {"total": int(total_posts), "comments": int(total_comments)},
        "votes_cast": {"up": int(upvotes_cast), "down": int(downvotes_cast)},
        "moderation": {
            "votes": {"harmful": int(mod_votes_harmful), "not_harmful": int(mod_votes_not)},
            "triggers": int(mod_triggers),
            "tokens_remaining": tokens_remaining,
        },
        "communities": {"count": int(communities_count)},
    }


@router.get("/{user_id}/recent-posts")
async def get_user_recent_posts(
    user_id: str,
    db: SessionDep,
    limit: int = Query(20, le=100),
    before: int | None = Query(None),
) -> list[dict[str, Any]]:
    """List recent posts authored by the user (anonymized fields only)."""
    user_id_bytes = _decode_user_id(user_id)
    query = db.query(Post).filter(Post.author_user_id == user_id_bytes, Post.deleted.is_(False))
    if before is not None:
        query = query.filter(Post.order_index < before)
    from sqlalchemy import desc

    posts = (
        query.order_by(desc(Post.order_index)).limit(limit).all()
    )
    # Minimal fields for overview
    results: list[dict[str, Any]] = []
    for p in posts:
        results.append(
            {
                "id": p.id,
                "order_index": int(p.order_index),
                "community_id": p.community_id,
                "moderation_state": p.moderation_state,
                "upvotes": p.upvotes,
                "downvotes": p.downvotes,
            }
        )
    return results


@router.get("/{user_id}/communities")
async def get_user_communities(
    user_id: str,
    db: SessionDep,
) -> list[dict[str, Any]]:
    """Return communities a user has posted in with post counts.

    Cross-community linking is inherent to a given user_id; users wanting siloed
    personas should use distinct keys per context.
    """
    user_id_bytes = _decode_user_id(user_id)
    rows = (
        db.query(Community.id, Community.internal_slug, func.count(Post.id))
        .join(Post, Post.community_id == Community.id)
        .filter(Post.author_user_id == user_id_bytes, Community.id.isnot(None))
        .group_by(Community.id, Community.internal_slug)
        .order_by(func.count(Post.id).desc())
        .all()
    )
    return [
        {"community_id": cid, "internal_slug": slug, "posts": int(cnt or 0)}
        for (cid, slug, cnt) in rows
    ]

