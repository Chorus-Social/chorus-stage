# src/chorus_stage/api/v1/endpoints/votes.py
"""Vote-related endpoints for the Chorus API."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from chorus_stage.db.session import get_db
from chorus_stage.models import Post, PostVote, User
from chorus_stage.schemas.vote import VoteCreate
from chorus_stage.services.crypto import CryptoService
from chorus_stage.services.pow import PowService, get_pow_service
from chorus_stage.services.replay import ReplayProtectionService, get_replay_service

from .posts import get_current_user

router = APIRouter(prefix="/votes", tags=["votes"])
bearer_scheme = HTTPBearer()
crypto_service = CryptoService()


def get_pow_service_dep() -> PowService:
    """Return the shared proof-of-work service."""
    return get_pow_service()


def get_replay_service_dep() -> ReplayProtectionService:
    """Return the shared replay protection service."""
    return get_replay_service()


SessionDep = Annotated[Session, Depends(get_db)]
CurrentUserDep = Annotated[User, Depends(get_current_user)]
PowServiceDep = Annotated[PowService, Depends(get_pow_service_dep)]
ReplayServiceDep = Annotated[ReplayProtectionService, Depends(get_replay_service_dep)]


def _get_post_or_404(db: Session, post_id: int) -> Post:
    post = db.query(Post).filter(Post.id == post_id, Post.deleted.is_(False)).first()
    if post is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")
    return post


def _validate_pow_and_replay(
    *,
    pow_service: PowService,
    replay_service: ReplayProtectionService,
    current_user: User,
    vote_data: VoteCreate,
) -> None:
    pubkey_hex = current_user.ed25519_pubkey.hex()
    if not pow_service.verify_pow("vote", pubkey_hex, vote_data.pow_nonce):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid proof of work for voting",
        )

    pow_replay = pow_service.is_pow_replay("vote", pubkey_hex, vote_data.pow_nonce)
    client_replay = replay_service.is_replay(pubkey_hex, vote_data.client_nonce)
    if pow_replay or client_replay:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Vote has already been processed",
        )

    pow_service.register_pow("vote", pubkey_hex, vote_data.pow_nonce)
    replay_service.register_replay(pubkey_hex, vote_data.client_nonce)


def _handle_existing_vote(
    *,
    existing_vote: PostVote,
    vote_data: VoteCreate,
    post: Post,
    db: Session,
) -> None:
    if vote_data.direction == existing_vote.direction:
        db.delete(existing_vote)
        if vote_data.direction == 1:
            post.upvotes -= 1
        else:
            post.downvotes -= 1
        return

    if existing_vote.direction == 1 and vote_data.direction == -1:
        post.upvotes -= 1
        post.downvotes += 1
    elif existing_vote.direction == -1 and vote_data.direction == 1:
        post.downvotes -= 1
        post.upvotes += 1

    existing_vote.direction = vote_data.direction


def _create_vote(
    *,
    db: Session,
    post: Post,
    vote_data: VoteCreate,
    voter_id: int,
) -> None:
    db.add(
        PostVote(
            post_id=vote_data.post_id,
            voter_user_id=voter_id,
            direction=vote_data.direction,
            weight=1.0,
        )
    )
    if vote_data.direction == 1:
        post.upvotes += 1
    elif vote_data.direction == -1:
        post.downvotes += 1


def _refresh_harmful_votes(db: Session, post: Post, post_id: int) -> None:
    post.harmful_vote_count = db.query(PostVote).filter(
        PostVote.post_id == post_id,
        PostVote.direction == -1,
    ).count()


@router.post("/", status_code=status.HTTP_201_CREATED)
async def cast_vote(
    vote_data: VoteCreate,
    current_user: CurrentUserDep,
    db: SessionDep,
    pow_service: PowServiceDep,
    replay_service: ReplayServiceDep,
) -> dict[str, str]:
    """Cast a vote on a post with proof of work verification."""
    post = _get_post_or_404(db, vote_data.post_id)
    _validate_pow_and_replay(
        pow_service=pow_service,
        replay_service=replay_service,
        current_user=current_user,
        vote_data=vote_data,
    )

    existing_vote = db.query(PostVote).filter(
        PostVote.post_id == vote_data.post_id,
        PostVote.voter_user_id == current_user.id,
    ).first()

    if existing_vote:
        _handle_existing_vote(existing_vote=existing_vote, vote_data=vote_data, post=post, db=db)
    else:
        _create_vote(db=db, post=post, vote_data=vote_data, voter_id=current_user.id)

    if vote_data.direction == -1:
        _refresh_harmful_votes(db, post, vote_data.post_id)

    db.commit()
    return {"status": "success"}


@router.get("/{post_id}/my-vote")
async def get_my_vote(
    post_id: int,
    current_user: CurrentUserDep,
    db: SessionDep,
) -> dict[str, int]:
    """Get current user's vote on a specific post."""
    vote = db.query(PostVote).filter(
        PostVote.post_id == post_id,
        PostVote.voter_user_id == current_user.id,
    ).first()

    if not vote:
        return {"direction": 0}

    return {"direction": vote.direction}
