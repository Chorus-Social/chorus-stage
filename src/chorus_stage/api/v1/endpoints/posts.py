# src/chorus_stage/api/v1/endpoints/posts.py
"""Post-related endpoints for the Chorus API."""

import base64
import hashlib
import secrets
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import desc
from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.db.session import get_db
from chorus_stage.models import Community, Post, SystemClock, User
from chorus_stage.models.moderation import (
    MODERATION_STATE_HIDDEN,
    MODERATION_STATE_OPEN,
)

# from chorus_stage.proto import federation_pb2  # Imported conditionally to avoid protobuf issues
from chorus_stage.schemas.post import PostCreate, PostResponse
from chorus_stage.services.bridge import (
    BridgeDisabledError,
    BridgeError,
    BridgePostSubmission,
    get_bridge_client,
)
from chorus_stage.services.pow import PowService, get_pow_service

router = APIRouter(prefix="/posts", tags=["posts"])
bearer_scheme = HTTPBearer()


def get_pow_service_dep() -> PowService:
    """Return the shared proof-of-work service."""
    return get_pow_service()


SessionDep = Annotated[Session, Depends(get_db)]
PowServiceDep = Annotated[PowService, Depends(get_pow_service_dep)]


def _decode_user_id(subject: str) -> bytes:
    padding = "=" * (-len(subject) % 4)
    try:
        return base64.urlsafe_b64decode(subject + padding)
    except Exception as err:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from err

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
        user_id = _decode_user_id(subject)

        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
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
    """List posts in deterministic order with optional filters.

    Args:
        db: Database session
        limit: Maximum number of posts to return (max 100)
        before: Return posts before this order_index for pagination
        community_slug: Filter posts by community internal slug

    Returns:
        List of Post objects in descending order by order_index

    Raises:
        HTTPException: If community not found when filtering by slug
    """
    query = db.query(Post).filter(
        Post.deleted.is_(False),
        Post.moderation_state != MODERATION_STATE_HIDDEN,
    )

    # Apply community filter if specified
    if community_slug:
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
    """Get a specific post by ID.

    Args:
        post_id: ID of the post to retrieve
        db: Database session

    Returns:
        Post object

    Raises:
        HTTPException: If post not found or deleted
    """
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
    """Get replies to a post in deterministic order.

    Args:
        post_id: ID of the parent post
        db: Database session
        limit: Maximum number of replies to return (max 100)
        before: Return replies before this order_index for pagination

    Returns:
        List of Post objects that are replies to the specified post
    """
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
    """Create a new post with proof of work verification.

    Args:
        post_data: Post creation data including content, PoW, and optional parent/community
        current_user: Authenticated user creating the post
        db: Database session
        pow_service: Proof-of-work service for verification

    Returns:
        Created Post object

    Raises:
        HTTPException: If PoW insufficient, replay detected, content hash mismatch,
                      parent post not found, or community not found
    """
    author_pubkey_hex = current_user.pubkey.hex()
    expected_difficulty = pow_service.difficulties.get(
        "post",
        settings.pow_difficulty_post,
    )
    if post_data.pow_difficulty < expected_difficulty:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Insufficient proof-of-work difficulty (expected ≥ {expected_difficulty})",
        )

    if pow_service.is_pow_replay("post", author_pubkey_hex, post_data.pow_nonce):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Proof of work nonce has already been used",
        )

    if not pow_service.verify_pow(
        "post",
        author_pubkey_hex,
        post_data.pow_nonce,
        hash_algorithm=post_data.pow_hash_algorithm,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid proof of work for post creation",
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
            detail="Content hash does not match content",
        )

    parent: Post | None = None
    parent_federation_id: str | None = None
    if post_data.parent_post_id is not None:
        parent = db.query(Post).filter(
            Post.id == post_data.parent_post_id,
            Post.deleted.is_(False),
        ).first()
        if parent is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Parent post not found",
            )
        if parent.federation_post_id:
            parent_federation_id = parent.federation_post_id.hex()

    # Find community if specified
    community_id: int | None = None
    community_slug: str | None = None
    if post_data.community_internal_slug:
        community = db.query(Community).filter(
            Community.internal_slug == post_data.community_internal_slug
        ).first()
        if not community:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Community not found",
            )
        community_id = community.id
        community_slug = community.internal_slug



    clock = get_system_clock(db)

    bridge_registration_result = None
    bridge_client = get_bridge_client()
    if bridge_client.enabled:
        entropy_payload = (
            current_user.pubkey
            + computed_hash
            + post_data.pow_nonce.encode("utf-8")
        )
        idempotency_key = hashlib.blake2b(entropy_payload, digest_size=16).hexdigest()

        submission = BridgePostSubmission(
            author_pubkey_hex=current_user.pubkey.hex(),
            content_hash_hex=computed_hash.hex(),
            body_md=post_data.content_md,
            community_slug=community_slug,
            parent_federation_post_id=parent_federation_id,
            pow_nonce=post_data.pow_nonce,
            pow_difficulty=post_data.pow_difficulty,
        )

        try:
            bridge_registration_result = await bridge_client.register_post(
                submission,
                idempotency_key=idempotency_key,
            )
        except BridgeDisabledError:
            bridge_registration_result = None
        except BridgeError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Bridge registration failed: {exc}",
            ) from exc

    if bridge_registration_result:
        order_index = bridge_registration_result.order_index
        federation_post_id = bridge_registration_result.post_id
        federation_origin = bridge_registration_result.origin_instance
        # Update clock.day_seq if necessary based on bridge_registration_result.day_number
        # For now, we'll just use local clock and generated ID
    else:
        order_index = clock.day_seq
        clock.day_seq += 1 # Increment local clock if not using bridge
        federation_post_id = None
        federation_origin = settings.bridge_instance_id if bridge_client.enabled else None

    new_post = Post(
        order_index=order_index,
        author_user_id=current_user.user_id,
        author_pubkey=current_user.pubkey,
        parent_post_id=post_data.parent_post_id,
        community_id=community_id,
        body_md=post_data.content_md,
        content_hash=computed_hash,
        moderation_state=MODERATION_STATE_OPEN,
        harmful_vote_count=0,
        federation_post_id=federation_post_id,
        federation_origin=federation_origin,
    )

    db.add(new_post)
    db.commit()
    db.refresh(new_post)

    # Create and send federation envelope for post announcement
    if bridge_client.enabled:
        try:
            idempotency_key = secrets.token_hex(8)

            # Create PostAnnouncement envelope
            # Import protobuf module conditionally
            from chorus_stage.proto import federation_pb2

            # Use getattr to safely access protobuf classes
            try:
                # Get the protobuf classes dynamically
                PostAnnouncement = federation_pb2.PostAnnouncement
                FederationEnvelope = federation_pb2.FederationEnvelope

                # Create protobuf messages using the classes
                post_announcement = PostAnnouncement(
                    post_id=federation_post_id or b"",  # Use federation_post_id if available
                    author_pubkey=current_user.pubkey,
                    content_hash=computed_hash,
                    order_index=order_index,
                    creation_day=clock.day_seq,
                )

                federation_envelope = FederationEnvelope(
                    sender_instance=settings.bridge_instance_id,
                    timestamp=int(time.time()),
                    message_type="PostAnnouncement",
                    message_data=post_announcement.SerializeToString(),
                    signature=b"" # Will be signed by bridge client
                )

                envelope_bytes = federation_envelope.SerializeToString()

                # Send to bridge for federation
                await bridge_client.send_federation_envelope(db, envelope_bytes, idempotency_key)
            except AttributeError:
                print("Warning: Protobuf classes not available, skipping federation")

        except BridgeError as exc:
            print(f"Error exporting post to ActivityPub bridge: {exc}")
            # Log error, but don't block post creation
        except (AttributeError, ValueError, TypeError) as e:
            print(f"Warning: Failed to create federation envelope for post: {e}")
            # Continue without federation

    pow_service.register_pow("post", author_pubkey_hex, post_data.pow_nonce)

    return new_post

@router.delete("/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_post(
    post_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: SessionDep,
) -> None:
    """Soft-delete a post (visible to author only).

    Args:
        post_id: ID of the post to delete
        current_user: Authenticated user (must be post author)
        db: Database session

    Raises:
        HTTPException: If post not found or user is not the author
    """
    post = db.query(Post).filter(Post.id == post_id, Post.deleted.is_(False)).first()

    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )

    # Only the author can delete their own posts
    if post.author_user_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only delete your own posts"
        )

    # Soft delete - mark as deleted but keep in database
    db.commit()

    # Federate post deletion event if bridge is enabled
    if settings.bridge_enabled:
        bridge_client = get_bridge_client()
        # Use post.id as target_ref, current_user.user_id as moderator_user_id_bytes
        # and post.order_index as creation_day (or current day_seq if available)
        # For simplicity, using post.order_index as creation_day for the event
        idempotency_key = f"post-delete-{post_id}-{current_user.user_id.hex()}-{post.order_index}"
        try:
            serialized_envelope = await bridge_client.create_post_delete_envelope(
                post_id=post_id,
                moderator_user_id_bytes=current_user.user_id,
                creation_day=post.order_index,
                idempotency_key=idempotency_key,
            )
            await bridge_client.send_federation_envelope(db, serialized_envelope, idempotency_key)
        except BridgeDisabledError:
            print("Bridge is disabled, post deletion not federated.")
        except (BridgeError, ValueError, TypeError) as e:
            print(f"Error federating post deletion: {e}")
