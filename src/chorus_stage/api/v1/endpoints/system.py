"""System and transparency endpoints for Chorus API."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.db.session import get_db
from chorus_stage.models import Community, ModerationCase, ModerationVote, Post, SystemClock
from chorus_stage.services.pow import PowService, get_pow_service

router = APIRouter(prefix="/system", tags=["system", "transparency"])


def get_pow_service_dep() -> PowService:
    return get_pow_service()


SessionDep = Annotated[Session, Depends(get_db)]
PowServiceDep = Annotated[PowService, Depends(get_pow_service_dep)]


@router.get("/config")
async def get_public_config(pow_service: PowServiceDep) -> dict[str, object]:
    """Return a sanitized snapshot of public runtime configuration.

    Excludes secrets and connection strings; suitable for transparency UIs.
    """
    return {
        "app": {
            "name": settings.app_name,
            "version": settings.app_version,
            "jwt_algorithm": settings.jwt_algorithm,
            "access_token_expire_minutes": settings.access_token_expire_minutes,
            "debug": settings.debug,
        },
        "pow": {
            "difficulties": pow_service.difficulties,
            "challenge_window_seconds": pow_service.challenge_window_seconds,
            "leases": {
                "enabled": settings.pow_enable_leases,
                "seconds": settings.pow_lease_seconds,
                "actions": settings.pow_lease_actions,
            },
        },
        "moderation": {
            "thresholds": settings.moderation_thresholds,
            "min_community_size": settings.moderation_min_community_size,
            "cooldowns": {
                "harmful_vote_author_seconds": settings.harmful_vote_author_cooldown_seconds,
                "harmful_vote_post_seconds": settings.harmful_vote_post_cooldown_seconds,
                "trigger_seconds": settings.moderation_trigger_cooldown_seconds,
            },
        },
    }


@router.get("/clock")
async def get_clock(db: SessionDep) -> dict[str, int]:
    """Expose the monotonic system clock for transparency and tooling."""
    clock = db.query(SystemClock).first()
    if not clock:
        clock = SystemClock(id=1, day_seq=0, hour_seq=0)
        db.add(clock)
        db.commit()
        db.refresh(clock)
    return {"day_seq": int(clock.day_seq), "hour_seq": int(clock.hour_seq)}


@router.get("/moderation-stats")
async def get_moderation_stats(db: SessionDep) -> dict[str, object]:
    """Return aggregated moderation statistics without revealing identities."""
    total_cases = db.query(func.count()).select_from(ModerationCase).scalar() or 0
    open_cases = (
        db.query(func.count())
        .select_from(ModerationCase)
        .filter(ModerationCase.state == 0)
        .scalar()
        or 0
    )
    cleared_cases = (
        db.query(func.count())
        .select_from(ModerationCase)
        .filter(ModerationCase.state == 1)
        .scalar()
        or 0
    )
    hidden_cases = (
        db.query(func.count())
        .select_from(ModerationCase)
        .filter(ModerationCase.state == 2)
        .scalar()
        or 0
    )

    harmful_votes = (
        db.query(func.count())
        .select_from(ModerationVote)
        .filter(ModerationVote.choice == 1)
        .scalar()
        or 0
    )
    not_harmful_votes = (
        db.query(func.count())
        .select_from(ModerationVote)
        .filter(ModerationVote.choice == 0)
        .scalar()
        or 0
    )

    # Per-community case counts
    community_rows = (
        db.query(
            Community.id,
            Community.internal_slug,
            func.count(ModerationCase.post_id),
        )
        .join(ModerationCase, ModerationCase.community_id == Community.id, isouter=True)
        .group_by(Community.id, Community.internal_slug)
        .all()
    )
    per_community = [
        {
            "community_id": cid,
            "internal_slug": slug,
            "cases": int(count or 0),
        }
        for (cid, slug, count) in community_rows
    ]

    # Top flagged posts (by harmful votes tracked on Post)
    top_posts = (
        db.query(Post.id, Post.harmful_vote_count, Post.moderation_state)
        .filter(Post.deleted.is_(False))
        .order_by(Post.harmful_vote_count.desc())
        .limit(10)
        .all()
    )
    top_flagged_posts = [
        {
            "post_id": pid,
            "harmful_vote_count": int(hcount or 0),
            "moderation_state": int(state or 0),
        }
        for (pid, hcount, state) in top_posts
    ]

    return {
        "cases": {
            "total": int(total_cases),
            "open": int(open_cases),
            "cleared": int(cleared_cases),
            "hidden": int(hidden_cases),
        },
        "votes": {
            "harmful": int(harmful_votes),
            "not_harmful": int(not_harmful_votes),
        },
        "per_community": per_community,
        "top_flagged_posts": top_flagged_posts,
    }


@router.get("/activity-stats")
async def get_activity_stats(db: SessionDep) -> dict[str, int]:
    """Network-wide activity counters (anonymized)."""
    users = db.query(func.count()).select_from(User).scalar() or 0
    posts = db.query(func.count()).select_from(Post).scalar() or 0
    votes = db.query(func.count()).select_from(PostVote).scalar() or 0
    messages = db.query(func.count()).select_from(DirectMessage).scalar() or 0
    communities = db.query(func.count()).select_from(Community).scalar() or 0
    return {
        "users": int(users),
        "communities": int(communities),
        "posts": int(posts),
        "votes": int(votes),
        "messages": int(messages),
    }
from chorus_stage.models import User, PostVote, DirectMessage
