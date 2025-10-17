# src/chorus_stage/api/v1/endpoints/votes.py
"""Vote-related endpoints for the Chorus API."""


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

@router.post("/", status_code=status.HTTP_201_CREATED)
async def cast_vote(
    vote_data: VoteCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    pow_service: PowService = Depends(get_pow_service_dep),
    replay_service: ReplayProtectionService = Depends(get_replay_service_dep),
) -> dict[str, str]:
    """Cast a vote on a post with proof of work verification."""
    # Verify the post exists
    post = db.query(Post).filter(
        Post.id == vote_data.post_id,
        Post.deleted == False
    ).first()

    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )

    # Verify PoW for voting
    if not pow_service.verify_pow(
        "vote",
        current_user.ed25519_pubkey.hex(),
        vote_data.pow_nonce
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid proof of work for voting"
        )

    # Check for replay in both PoW and client nonce
    if (pow_service.is_pow_replay("vote", current_user.ed25519_pubkey.hex(), vote_data.pow_nonce) or
        replay_service.is_replay(current_user.ed25519_pubkey.hex(), vote_data.client_nonce)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Vote has already been processed"
        )

    # Register the checks as used
    pow_service.register_pow("vote", current_user.ed25519_pubkey.hex(), vote_data.pow_nonce)
    replay_service.register_replay(current_user.ed25519_pubkey.hex(), vote_data.client_nonce)

    # Check if user has already voted on this post
    existing_vote = db.query(PostVote).filter(
        PostVote.post_id == vote_data.post_id,
        PostVote.voter_user_id == current_user.id
    ).first()

    if existing_vote:
        # Update existing vote
        if vote_data.direction == existing_vote.direction:
            # Same direction, remove vote
            db.delete(existing_vote)

            # Update vote count on post
            if vote_data.direction == 1:
                post.upvotes -= 1
            elif vote_data.direction == -1:
                post.downvotes -= 1
        else:
            # Different direction, update vote
            if existing_vote.direction == 1 and vote_data.direction == -1:
                post.upvotes -= 1
                post.downvotes += 1
            elif existing_vote.direction == -1 and vote_data.direction == 1:
                post.downvotes -= 1
                post.upvotes += 1

            existing_vote.direction = vote_data.direction

    else:
        # Create new vote
        new_vote = PostVote(
            post_id=vote_data.post_id,
            voter_user_id=current_user.id,
            direction=vote_data.direction,
            weight=1.0  # Default weight
        )
        db.add(new_vote)

        # Update vote counts on post
        if vote_data.direction == 1:
            post.upvotes += 1
        elif vote_data.direction == -1:
            post.downvotes += 1

    # Update harmful vote count if this is a downvote
    if vote_data.direction == -1:
        # Get new harmful vote count
        harmful_votes = db.query(PostVote).filter(
            PostVote.post_id == vote_data.post_id,
            PostVote.direction == -1
        ).count()

        post.harmful_vote_count = harmful_votes

    db.commit()
    return {"status": "success"}

@router.get("/{post_id}/my-vote")
async def get_my_vote(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> dict[str, int]:
    """Get current user's vote on a specific post."""
    vote = db.query(PostVote).filter(
        PostVote.post_id == post_id,
        PostVote.voter_user_id == current_user.id
    ).first()

    if not vote:
        return {"direction": 0}

    return {"direction": vote.direction}
