"""Post creation endpoints for Chorus API v1.

This router defines the public HTTP endpoints for creating posts.
PoW, replay protection, and signature verification are handled by the service layer.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from chorus_stage.db.session import get_session
from chorus_stage.repositories.post_repo import PostRepository
from chorus_stage.schemas.post import PostCreate, PostOut
from chorus_stage.services.post_service import create_post, to_post_out

router = APIRouter(tags=["posts"])


@router.post(
    path="",
    response_model=PostOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new post",
    response_description="The created post with assigned order index.",
)
async def create_post_endpoint(
    payload: PostCreate,
    session: AsyncSession = Depends(get_session),
) -> PostOut:
    """Create a post and persist it to the database.

    Args:
        payload: The post body and signature metadata sent by the client.
        session: Database session injected by FastAPI.

    Returns:
        The created post, including its assigned order index.

    Raises:
        HTTPException: If validation in the service layer fails.

    Notes:
        Proof-of-work and replay validation are enforced upstream by other dependencies.
    """
    repo = PostRepository(session)
    try:
        payload_bytes = payload.body_md.encode()
        post = await create_post(
            repo=repo,
            author_pubkey_hex=payload.author_pubkey_hex,
            body_md=payload.body_md,
            signature_hex=payload.signature_hex,
            payload_for_sig=payload_bytes,
        )
        await session.commit()
    except ValueError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return to_post_out(post)
