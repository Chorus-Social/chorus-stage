"""Posting endpoints with explicit contracts."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from chorus.db.session import get_session
from chorus.repositories.post_repo import PostRepository
from chorus.schemas.post import PostCreate, PostOut
from chorus.services.post_service import create_post

router = APIRouter()

@router.post("", response_model=PostOut, status_code=status.HTTP_201_CREATED)
async def create_post_endpoint(payload: PostCreate, session: AsyncSession = Depends(get_session)) -> PostOut:
    """Create a post.

    Note
    ----
    - PoW and replay checks belong to middleware or a higher layer; omitted here for MVP.
    """
    repo = PostRepository(session)
    try:
        result = await create_post(
            repo=repo,
            author_pubkey_hex=payload.author_pubkey_hex,
            body_md=payload.body_md,
            signature_hex=payload.signature_hex,
            payload_for_sig=(payload.body_md.encode("utf-8")),
        )
        await session.commit()
    except ValueError as e:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return PostOut(
        id=result.id,
        order_index=result.order_index,
        body_md=payload.body_md,
        author_pubkey_hex=payload.author_pubkey_hex,
    )
