# src/chorus_stage/api/v1/endpoints/communities.py
"""Community-related endpoints for the Chorus API."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from chorus_stage.db.session import get_db
from chorus_stage.models import Community, CommunityMember, Post, User
from chorus_stage.models.moderation import MODERATION_STATE_HIDDEN
from chorus_stage.schemas.community import CommunityCreate, CommunityResponse
from chorus_stage.schemas.post import PostResponse

from .posts import get_current_user

router = APIRouter(prefix="/communities", tags=["communities"])
SessionDep = Annotated[Session, Depends(get_db)]
CurrentUserDep = Annotated[User, Depends(get_current_user)]


@router.get("/", response_model=list[CommunityResponse])
async def list_communities(db: SessionDep) -> list[Community]:
    """List all communities."""
    communities = db.query(Community).order_by(Community.order_index).all()
    return communities

@router.get("/{community_id}", response_model=CommunityResponse)
async def get_community(
    community_id: int,
    db: SessionDep,
) -> Community:
    """Get a specific community by ID."""
    community = db.query(Community).filter(Community.id == community_id).first()
    if not community:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Community not found"
        )
    return community

@router.post("/",
          response_model=CommunityResponse,
          status_code=status.HTTP_201_CREATED)
async def create_community(
    community_data: CommunityCreate,
    _current_user: CurrentUserDep,
    db: SessionDep,
) -> Community:
    """Create a new community."""
    # Check if slug already exists
    existing = db.query(Community).filter(
        Community.internal_slug == community_data.internal_slug
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Community slug already exists"
        )

    # Get next order_index from system clock
    from .posts import get_system_clock
    clock = get_system_clock(db)

    # Create the community
    new_community = Community(
        internal_slug=community_data.internal_slug,
        display_name=community_data.display_name,
        description_md=community_data.description_md,
        is_profile_like=False,
        order_index=clock.day_seq
    )

    # Increment the clock
    clock.day_seq += 1
    db.add(new_community)
    db.commit()
    db.refresh(new_community)

    return new_community

@router.post("/{community_id}/join", status_code=status.HTTP_201_CREATED)
async def join_community(
    community_id: int,
    current_user: CurrentUserDep,
    db: SessionDep,
) -> dict[str, str]:
    """Join a community."""
    # Check if community exists
    community = db.query(Community).filter(Community.id == community_id).first()
    if not community:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Community not found"
        )

    # Check if already a member
    existing_membership = db.query(CommunityMember).filter(
        CommunityMember.community_id == community_id,
        CommunityMember.user_id == current_user.user_id
    ).first()

    if existing_membership:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Already a member of this community"
        )

    # Create membership
    membership = CommunityMember(
        community_id=community_id,
        user_id=current_user.user_id
    )
    db.add(membership)
    db.commit()

    return {"status": "joined"}

@router.delete(
    "/{community_id}/leave",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def leave_community(
    community_id: int,
    current_user: CurrentUserDep,
    db: SessionDep,
) -> Response:
    """Leave a community."""
    # Check if a member
    membership = db.query(CommunityMember).filter(
        CommunityMember.community_id == community_id,
        CommunityMember.user_id == current_user.user_id
    ).first()

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not a member of this community"
        )

    # Remove membership
    db.delete(membership)
    db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)

@router.get("/{community_id}/posts", response_model=list[PostResponse])
async def get_community_posts(
    community_id: int,
    db: SessionDep,
    limit: int = 50,
    before: int | None = None,
) -> list[Post]:
    """Get posts from a specific community."""
    from sqlalchemy import desc

    from chorus_stage.models import Post

    query = db.query(Post).filter(
        Post.community_id == community_id,
        Post.deleted.is_(False),
        Post.moderation_state != MODERATION_STATE_HIDDEN,
    )

    if before is not None:
        query = query.filter(Post.order_index < before)

    posts = query.order_by(desc(Post.order_index)).limit(limit).all()
    return posts


@router.get("/{community_id}/top-authors")
async def get_top_authors(
    community_id: int,
    db: SessionDep,
    limit: int = 10,
    metric: str = "posts",
) -> list[dict[str, Any]]:
    """Top authors in a community by selected metric.

    Metrics:
      - posts: total posts authored in the community
      - engagement: (upvotes + downvotes) across authored posts
      - harmful_ratio: downvotes / max(1, upvotes + downvotes)
    """
    community = db.query(Community).filter(Community.id == community_id).first()
    if not community:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Community not found")

    # Aggregate by author
    rows = (
        db.query(
            Post.author_user_id,
            func.count(Post.id).label("posts"),
            func.sum(Post.upvotes).label("up"),
            func.sum(Post.downvotes).label("down"),
        )
        .filter(Post.community_id == community_id, Post.deleted.is_(False))
        .group_by(Post.author_user_id)
        .all()
    )

    def score(row: Any) -> float:
        if metric == "posts":
            return float(row.posts or 0)
        total = int((row.up or 0) + (row.down or 0))
        if metric == "engagement":
            return float(total)
        # harmful_ratio
        return float((row.down or 0) / max(1, total))

    # Sort in Python due to computed ratios
    sorted_rows = sorted(rows, key=score, reverse=True)[:limit]

    def _b64(b: bytes | None) -> str | None:
        if b is None:
            return None
        import base64
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    results: list[dict[str, Any]] = []
    for r in sorted_rows:
        total = int((r.up or 0) + (r.down or 0))
        ratio = (r.down or 0) / max(1, total)
        results.append(
            {
                "author_user_id": _b64(r.author_user_id),
                "posts": int(r.posts or 0),
                "upvotes": int(r.up or 0),
                "downvotes": int(r.down or 0),
                "harmful_ratio": float(ratio),
            }
        )
    return results
