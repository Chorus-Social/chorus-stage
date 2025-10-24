# src/chorus_stage/services/moderation.py
"""Moderation services for Chorus."""

import math

from sqlalchemy import func
from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.models import (
    CommunityMember,
    ModerationCase,
    ModerationVote,
    Post,
    UserState,
)
from chorus_stage.models.moderation import (
    MODERATION_STATE_CLEARED,
    MODERATION_STATE_HIDDEN,
    MODERATION_STATE_OPEN,
)
from chorus_stage.services.bridge import get_bridge_client


class ModerationService:
    """Service handling moderation logic and state transitions."""

    @staticmethod
    async def update_moderation_state(post_id: int, db: Session) -> None:
        """Update the moderation state based on community votes.

        Args:
            post_id: ID of the post to update
            db: Database session
        """
        # Make sure pending work is flushed so queries see latest state
        db.flush()

        # Get the moderation case
        case = db.get(ModerationCase, post_id)

        if not case:
            return

        # Count votes
        harmful_votes = db.query(func.count()).filter(
            ModerationVote.post_id == post_id,
            ModerationVote.choice == 1  # Harmful
        ).scalar() or 0

        not_harmful_votes = db.query(func.count()).filter(
            ModerationVote.post_id == post_id,
            ModerationVote.choice == 0  # Not harmful
        ).scalar() or 0

        # Update harmful vote count on post
        post = db.query(Post).filter(Post.id == post_id).first()
        if post:
            post.harmful_vote_count = harmful_votes

        # Determine moderation state
        min_size = max(settings.moderation_min_community_size, 1)
        community_size = min_size
        if post and post.community_id:
            community_size = db.query(func.count()).filter(
                CommunityMember.community_id == post.community_id
            ).scalar() or 0
            community_size = max(community_size, min_size)

        harmful_threshold = max(
            1,
            math.ceil(community_size * settings.harmful_hide_threshold),
        )
        clear_threshold = max(
            1,
            math.ceil(community_size * settings.clear_threshold),
        )

        if harmful_votes >= harmful_threshold:
            new_state = MODERATION_STATE_HIDDEN
        elif not_harmful_votes >= clear_threshold:
            new_state = MODERATION_STATE_CLEARED
        else:
            new_state = MODERATION_STATE_OPEN

        # Update if state changed
        if case.state != new_state:
            case.state = new_state

            # Update post moderation state as well
            if post:
                post.moderation_state = new_state
                if new_state == MODERATION_STATE_HIDDEN:
                    case.closed_order_index = post.order_index

            db.commit()

            # Anchor moderation event to Bridge
            bridge_client = get_bridge_client()
            if bridge_client.enabled:
                event_data = {
                    "post_id": post_id,
                    "new_state": new_state,
                    "harmful_votes": harmful_votes,
                    "not_harmful_votes": not_harmful_votes,
                    # Add other relevant hashes/metadata as per CFP
                }
                await bridge_client.anchor_moderation_event(event_data)

    @staticmethod
    def can_trigger_moderation(user_id: bytes, post_id: int, db: Session) -> bool:
        """Check if a user can trigger moderation on a post today.

        Args:
            user_id: ID of the user
            post_id: ID of the post
            db: Database session

        Returns:
            True if the user can trigger moderation, False otherwise
        """
        from chorus_stage.models import ModerationTrigger, SystemClock

        # Get current day sequence
        clock = db.query(SystemClock).first()
        if not clock:
            clock = SystemClock(id=1, day_seq=0, hour_seq=0)
            db.add(clock)
            db.commit()

        # Check if the user has already triggered moderation for this post today
        existing_trigger = db.query(ModerationTrigger).filter(
            ModerationTrigger.post_id == post_id,
            ModerationTrigger.trigger_user_id == user_id,
            ModerationTrigger.day_seq >= clock.day_seq - 1  # Today-ish
        ).first()

        return existing_trigger is None

    @staticmethod
    def consume_moderation_token(user_id: bytes, db: Session) -> bool:
        """Consume a moderation token if available.

        Args:
            user_id: ID of the user
            db: Database session

        Returns:
            True if a token was consumed, False if none were available
        """
        state = db.query(UserState).filter(UserState.user_id == user_id).first()
        if not state:
            state = UserState(user_id=user_id)
            db.add(state)
            db.commit()
            state = db.query(UserState).filter(UserState.user_id == user_id).first()
            if not state:  # pragma: no cover - defensive
                return False

        if state.mod_tokens_remaining <= 0:
            return False

        state.mod_tokens_remaining -= 1
        db.commit()
        return True
