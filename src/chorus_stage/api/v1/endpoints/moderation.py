"""Moderation-related endpoints for the Chorus API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import Integer, func
from sqlalchemy.orm import Session
from sqlalchemy.sql import functions

from chorus_stage.api.v1.dependencies import CurrentUserDep, SessionDep
from chorus_stage.core.settings import settings
from chorus_stage.models import (
    Community,
    ModerationCase,
    ModerationTrigger,
    ModerationVote,
    Post,
)
from chorus_stage.models.moderation import MODERATION_STATE_OPEN
from chorus_stage.schemas.post import PostResponse
from chorus_stage.services.bridge import BridgeDisabledError, BridgeError, get_bridge_client
from chorus_stage.services.moderation import ModerationService
from chorus_stage.services.replay import get_replay_service

from .posts import get_system_clock

# Moderation case states
MODERATION_STATE_PENDING = 1
MODERATION_STATE_CLOSED = 2

router = APIRouter(prefix="/moderation", tags=["moderation"])
moderation_service = ModerationService()


def _ensure_default_community(db: Session) -> int:
    """Ensure a fallback community exists for moderation bookkeeping."""

    default_slug = "global-feed"
    community = (
        db.query(Community)
        .filter(Community.internal_slug == default_slug)
        .first()
    )
    if community:
        return community.id

    clock = get_system_clock(db)
    community = Community(
        internal_slug=default_slug,
        display_name="Global Feed",
        description_md=None,
        is_profile_like=False,
        order_index=clock.day_seq,
    )
    clock.day_seq += 1
    db.add(community)
    db.commit()
    db.refresh(community)
    return community.id


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

    replay_service = get_replay_service()
    user_hex = current_user.user_id.hex()
    if replay_service.is_moderation_trigger_cooldown(user_hex):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many moderation triggers; please slow down",
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
        community_id = post.community_id or _ensure_default_community(db)
        case = ModerationCase(
            post_id=post_id,
            community_id=community_id,
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
    # Apply small trigger cool-down after success
    replay_service.set_moderation_trigger_cooldown(
        user_hex,
        settings.moderation_trigger_cooldown_seconds,
    )

    # Federate moderation trigger event if bridge is enabled
    if settings.bridge_enabled:
        bridge_client = get_bridge_client()
        idempotency_key = (
            f"moderation-trigger-{post_id}-{current_user.user_id.hex()}-{trigger_day_seq}"
        )
        try:
            serialized_envelope = await bridge_client.create_moderation_trigger_envelope(
                post_id=post_id,
                trigger_user_id_bytes=current_user.user_id,
                creation_day=trigger_day_seq,
                idempotency_key=idempotency_key,
            )
            await bridge_client.send_federation_envelope(db, serialized_envelope, idempotency_key)
        except BridgeDisabledError:
            print("Bridge is disabled, moderation trigger not federated.")
        except Exception as e:
            print(f"Error federating moderation trigger: {e}")

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
        community_id = post.community_id or _ensure_default_community(db)
        case = ModerationCase(
            post_id=post_id,
            community_id=community_id,
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

    await moderation_service.update_moderation_state(post_id, db)
    db.commit()

    # Anchor moderation event to Bridge (if enabled)
    if settings.bridge_enabled:
        bridge_client = get_bridge_client()
        event_data = {
            "post_id": post_id,
            "voter_user_id": current_user.user_id.hex(),
            "choice": choice,
            # Add other relevant hashes/minimal data as per CFP-006/CFP-005
        }
        try:
            await bridge_client.anchor_moderation_event(db, event_data)
        except BridgeDisabledError:
            pass # Bridge moderation anchoring is disabled, do nothing
        except BridgeError as exc:
            print(f"Error anchoring moderation vote to Bridge: {exc}")
            # Log error, but don't block local moderation action

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


def _get_community_by_slug(db: Session, slug: str) -> Community | None:
    return db.query(Community).filter(Community.internal_slug == slug).first()


@router.get("/community/{internal_slug}/stats")
async def get_community_moderation_stats(
    internal_slug: str,
    db: SessionDep,
) -> dict[str, Any]:
    """Aggregated moderation stats for a community (by slug)."""
    community = _get_community_by_slug(db, internal_slug)
    if community is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Community not found")

    total_cases = (
        db.query(functions.count())
        .select_from(ModerationCase)
        .filter(ModerationCase.community_id == community.id)
        .scalar()
        or 0
    )
    counts = (
        db.query(
            func.sum(func.cast(ModerationCase.state == MODERATION_STATE_OPEN, Integer())),
            func.sum(func.cast(ModerationCase.state == MODERATION_STATE_PENDING, Integer())),
            func.sum(func.cast(ModerationCase.state == MODERATION_STATE_CLOSED, Integer())),
        )
        .filter(ModerationCase.community_id == community.id)
        .one()
    )
    open_cases = int(counts[0] or 0)
    cleared_cases = int(counts[1] or 0)
    hidden_cases = int(counts[2] or 0)

    harmful_votes = (
        db.query(functions.count())
        .select_from(ModerationVote)
        .join(ModerationCase, ModerationCase.post_id == ModerationVote.post_id)
        .filter(ModerationCase.community_id == community.id, ModerationVote.choice == 1)
        .scalar()
        or 0
    )
    not_harmful_votes = (
        db.query(functions.count())
        .select_from(ModerationVote)
        .join(ModerationCase, ModerationCase.post_id == ModerationVote.post_id)
        .filter(ModerationCase.community_id == community.id, ModerationVote.choice == 0)
        .scalar()
        or 0
    )

    top_posts = (
        db.query(Post.id, Post.harmful_vote_count, Post.moderation_state)
        .filter(Post.community_id == community.id, Post.deleted.is_(False))
        .order_by(Post.harmful_vote_count.desc())
        .limit(10)
        .all()
    )

    return {
        "community_id": community.id,
        "internal_slug": community.internal_slug,
        "cases": {
            "total": int(total_cases),
            "open": open_cases,
            "cleared": cleared_cases,
            "hidden": hidden_cases,
        },
        "votes": {
            "harmful": int(harmful_votes),
            "not_harmful": int(not_harmful_votes),
        },
        "top_flagged_posts": [
            {
                "post_id": pid,
                "harmful_vote_count": int(hcount or 0),
                "moderation_state": int(state or 0),
            }
            for (pid, hcount, state) in top_posts
        ],
    }


@router.get("/community/{internal_slug}/cases")
async def list_community_cases(
    internal_slug: str,
    db: SessionDep,
    limit: int = Query(50, le=100),
    before: int | None = Query(None),
) -> list[dict[str, int]]:
    """List case summaries within a specific community (by slug)."""
    community = _get_community_by_slug(db, internal_slug)
    if community is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Community not found")

    query = db.query(ModerationCase).filter(ModerationCase.community_id == community.id)
    if before is not None:
        query = query.filter(ModerationCase.opened_order_index < before)
    cases = query.order_by(ModerationCase.opened_order_index.desc()).limit(limit).all()

    results: list[dict[str, int]] = []
    for case in cases:
        harmful = (
            db.query(functions.count())
            .select_from(ModerationVote)
            .filter(ModerationVote.post_id == case.post_id, ModerationVote.choice == 1)
            .scalar()
            or 0
        )
        not_harmful = (
            db.query(functions.count())
            .select_from(ModerationVote)
            .filter(ModerationVote.post_id == case.post_id, ModerationVote.choice == 0)
            .scalar()
            or 0
        )
        post = db.query(Post).filter(Post.id == case.post_id).first()
        results.append(
            {
                "post_id": case.post_id,
                "state": case.state,
                "opened_order_index": int(case.opened_order_index),
                "closed_order_index": (
                    int(case.closed_order_index) if case.closed_order_index else 0
                ),
                "harmful_votes": int(harmful),
                "not_harmful_votes": int(not_harmful),
                "harmful_vote_count": int(post.harmful_vote_count) if post else 0,
            }
        )
    return results


def _collect_ledger_events(db: Session, community_id: int | None = None) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    # Case opened
    query = db.query(ModerationCase)
    if community_id is not None:
        query = query.filter(ModerationCase.community_id == community_id)
    for case in query.all():
        events.append(
            {
                "type": "case_opened",
                "post_id": case.post_id,
                "community_id": case.community_id,
                "order_index": int(case.opened_order_index),
            }
        )

    # Case closed
    query = db.query(ModerationCase).filter(ModerationCase.closed_order_index.isnot(None))
    if community_id is not None:
        query = query.filter(ModerationCase.community_id == community_id)
    for case in query.all():
        events.append(
            {
                "type": "case_closed",
                "post_id": case.post_id,
                "community_id": case.community_id,
                "order_index": (
                    int(case.closed_order_index) if case.closed_order_index is not None else 0
                ),
            }
        )

    # Triggers
    trig_query = db.query(ModerationTrigger)
    if community_id is not None:
        trig_query = (
            db.query(ModerationTrigger)
            .join(Post, Post.id == ModerationTrigger.post_id)
            .filter(Post.community_id == community_id)
        )
    for trig in trig_query.all():
        # Resolve community via Post
        post = db.query(Post).filter(Post.id == trig.post_id).first()
        events.append(
            {
                "type": "trigger",
                "post_id": trig.post_id,
                "community_id": post.community_id if post else 0,
                "order_index": int(trig.day_seq),
            }
        )

    events.sort(key=lambda e: int(e["order_index"]), reverse=True)
    return events


@router.get("/ledger")
async def get_moderation_ledger(
    db: SessionDep,
    limit: int = Query(50, le=200),
    before: int | None = Query(None),
) -> list[dict[str, Any]]:
    """Public anonymized ledger of moderation activity across the network."""
    events = _collect_ledger_events(db)
    if before is not None:
        events = [e for e in events if int(e["order_index"]) < before]
    return events[:limit]


@router.get("/community/{internal_slug}/ledger")
async def get_community_moderation_ledger(
    internal_slug: str,
    db: SessionDep,
    limit: int = Query(50, le=200),
    before: int | None = Query(None),
) -> list[dict[str, Any]]:
    """Public anonymized ledger of moderation activity within a community."""
    community = _get_community_by_slug(db, internal_slug)
    if community is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Community not found")
    events = _collect_ledger_events(db, community_id=community.id)
    if before is not None:
        events = [e for e in events if int(e["order_index"]) < before]
    return events[:limit]


@router.get("/case/{post_id}/summary")
async def get_case_summary(
    post_id: int,
    db: SessionDep,
) -> dict[str, int]:
    """Return a summary of moderation voting for a specific post."""
    case = db.query(ModerationCase).filter(ModerationCase.post_id == post_id).first()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    harmful = (
        db.query(functions.count())
        .select_from(ModerationVote)
        .filter(ModerationVote.post_id == post_id, ModerationVote.choice == 1)
        .scalar()
        or 0
    )
    not_harmful = (
        db.query(functions.count())
        .select_from(ModerationVote)
        .filter(ModerationVote.post_id == post_id, ModerationVote.choice == 0)
        .scalar()
        or 0
    )
    post = db.query(Post).filter(Post.id == post_id).first()
    return {
        "post_id": post_id,
        "community_id": int(post.community_id) if post and post.community_id is not None else 0,
        "state": case.state,
        "opened_order_index": int(case.opened_order_index),
        "closed_order_index": int(case.closed_order_index) if case.closed_order_index else 0,
        "harmful_votes": int(harmful),
        "not_harmful_votes": int(not_harmful),
        "harmful_vote_count": int(post.harmful_vote_count) if post else 0,
    }


@router.get("/cases")
async def list_case_summaries(
    db: SessionDep,
    limit: int = Query(50, le=100),
    before: int | None = Query(None),
) -> list[dict[str, int]]:
    """List recent moderation cases with anonymized summaries."""
    query = db.query(ModerationCase)
    if before is not None:
        query = query.filter(ModerationCase.opened_order_index < before)
    cases = query.order_by(ModerationCase.opened_order_index.desc()).limit(limit).all()

    results: list[dict[str, int]] = []
    for case in cases:
        harmful = (
            db.query(functions.count())
            .select_from(ModerationVote)
            .filter(ModerationVote.post_id == case.post_id, ModerationVote.choice == 1)
            .scalar()
            or 0
        )
        not_harmful = (
            db.query(functions.count())
            .select_from(ModerationVote)
            .filter(ModerationVote.post_id == case.post_id, ModerationVote.choice == 0)
            .scalar()
            or 0
        )
        post = db.query(Post).filter(Post.id == case.post_id).first()
        results.append(
            {
                "post_id": case.post_id,
                "community_id": (
                    int(post.community_id) if post and post.community_id is not None else 0
                ),
                "state": case.state,
                "opened_order_index": int(case.opened_order_index),
                "closed_order_index": (
                    int(case.closed_order_index) if case.closed_order_index else 0
                ),
                "harmful_votes": int(harmful),
                "not_harmful_votes": int(not_harmful),
                "harmful_vote_count": int(post.harmful_vote_count) if post else 0,
            }
        )
    return results
