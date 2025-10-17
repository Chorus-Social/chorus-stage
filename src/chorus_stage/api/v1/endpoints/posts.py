# src/chorus_stage/api/v1/endpoints/posts.py
"""Post-related endpoints for the Chorus API."""

import hashlib
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import desc
from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.db.session import get_db
from chorus_stage.models import Post, SystemClock, User
from chorus_stage.models.moderation import MODERATION_STATE_HIDDEN, MODERATION_STATE_OPEN
from chorus_stage.schemas.post import PostCreate, PostResponse
from chorus_stage.services.pow import PowService, get_pow_service

router = APIRouter(prefix="/posts", tags=["posts"])
bearer_scheme = HTTPBearer()


def get_pow_service_dep() -> PowService:
    """Return the shared proof-of-work service."""
    return get_pow_service()


SessionDep = Annotated[Session, Depends(get_db)]
PowServiceDep = Annotated[PowService, Depends(get_pow_service_dep)]

def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    db: SessionDep,
) -> User:
    """Get the current authenticated user from JWT token.

    Args:
        credentials: HTTP Bearer token credentials
        db: Database session

    Returns:
        User object for the authenticated user

    Raises:
        HTTPException: If token is invalid or user not found
    """
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        subject = payload.get("sub")
        if subject is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
        try:
            user_id = int(subject)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            ) from exc

        user = db.query(User).filter(User.id == user_id).first()
        if user is None or user.deleted:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or deleted",
            )
        return user
    except JWTError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from err

def get_system_clock(db: Session) -> SystemClock:
    """Get or create the system clock entry.

    Args:
        db: Database session

    Returns:
        SystemClock object
    """
    clock = db.query(SystemClock).first()
    if not clock:
        clock = SystemClock(id=1, day_seq=0, hour_seq=0)
        db.add(clock)
        db.commit()
        db.refresh(clock)
    return clock

@router.get("/", response_model=list[PostResponse])
async def list_posts(
    db: SessionDep,
    limit: int = Query(50, le=100, description="Maximum number of posts to return"),
    before: int | None = Query(None, description="Return posts before this order_index"),
    community_slug: str | None = Query(None, description="Filter by community slug"),
) -> list[Post]:
    """List posts in deterministic order with optional filters."""
    query = db.query(Post).filter(
        Post.deleted.is_(False),
        Post.moderation_state != MODERATION_STATE_HIDDEN,
    )

    # Apply community filter if specified
    if community_slug:
        from chorus_stage.models import Community
        community = db.query(Community).filter(
            Community.internal_slug == community_slug
        ).first()
        if not community:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Community not found"
            )
        query = query.filter(Post.community_id == community.id)

    # Apply order filter if specified
    if before is not None:
        query = query.filter(Post.order_index < before)

    # Order by order_index descending and apply limit
    posts = query.order_by(desc(Post.order_index)).limit(limit).all()

    return posts

@router.get("/{post_id}", response_model=PostResponse)
async def get_post(
    post_id: int,
    db: SessionDep,
) -> Post:
    """Get a specific post by ID."""
    post = db.query(Post).filter(Post.id == post_id, Post.deleted.is_(False)).first()

    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )

    return post

@router.get("/{post_id}/children", response_model=list[PostResponse])
async def get_post_children(
    post_id: int,
    db: SessionDep,
    limit: int = Query(50, le=100),
    before: int | None = Query(None),
) -> list[Post]:
    """Get replies to a post in deterministic order."""
    query = db.query(Post).filter(
        Post.parent_post_id == post_id,
        Post.deleted.is_(False),
        Post.moderation_state != MODERATION_STATE_HIDDEN,
    )

    if before is not None:
        query = query.filter(Post.order_index < before)

    posts = query.order_by(desc(Post.order_index)).limit(limit).all()

    return posts

@router.post("/",
          response_model=PostResponse,
          status_code=status.HTTP_201_CREATED)
async def create_post(
    post_data: PostCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: SessionDep,
    pow_service: PowServiceDep,
) -> Post:
    """Create a new post with proof of work verification."""
    # Verify PoW for posting
    if not pow_service.verify_pow(
        "post",
        current_user.ed25519_pubkey.hex(),
        post_data.pow_nonce
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid proof of work for post creation"
        )

    # Verify content hash
    computed_hash = hashlib.sha256(post_data.content_md.encode()).digest()
    try:
        expected_hash = bytes.fromhex(post_data.content_hash)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content hash does not match content",
        ) from exc

    if computed_hash != expected_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content hash does not match content"
        )

    # Find community if specified
    community_id: int | None = None
    if post_data.community_internal_slug:
        from chorus_stage.models import Community
        community = db.query(Community).filter(
            Community.internal_slug == post_data.community_internal_slug
        ).first()
        if not community:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Community not found"
            )
        community_id = community.id

    # Get next order_index from system clock
    clock = get_system_clock(db)

    # Create the post
    new_post = Post(
        order_index=clock.day_seq,  # Use day_seq for global ordering
        author_user_id=current_user.id,
        author_pubkey=current_user.ed25519_pubkey,
        parent_post_id=post_data.parent_post_id,
        community_id=community_id,
        body_md=post_data.content_md,
        content_hash=computed_hash,
        moderation_state=MODERATION_STATE_OPEN,
        harmful_vote_count=0,
    )

    # Increment the clock
    clock.day_seq += 1
    db.add(new_post)
    db.commit()
    db.refresh(new_post)

    return new_post

@router.delete("/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_post(
    post_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: SessionDep,
) -> None:
    """Soft-delete a post (visible to author only)."""
    post = db.query(Post).filter(Post.id == post_id, Post.deleted.is_(False)).first()

    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )

    # Only the author can delete their own posts
    if post.author_user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only delete your own posts"
        )

    # Soft delete - mark as deleted but keep in database
    post.deleted = True
    db.commit()
