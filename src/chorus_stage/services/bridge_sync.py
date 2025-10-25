"""Background synchronization between Chorus Stage and Chorus Bridge.

This module provides the BridgeSyncWorker class that handles bidirectional
synchronization between a Chorus Stage instance and the Chorus Bridge.
It processes outbound federation events and applies inbound events from Bridge.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.db.session import SessionLocal
from chorus_stage.models import (
    Community,
    CommunityMember,
    DirectMessage,
    FederationOutbound,
    Post,
    PostVote,
    SystemClock,
    User,
)
from chorus_stage.models.moderation import MODERATION_STATE_OPEN, ModerationCase, ModerationVote
from chorus_stage.services.bridge import (
    BridgeClient,
    BridgeDisabledError,
    BridgeError,
    BridgeEvent,
    BridgeEventBatch,
    get_bridge_client,
)
from chorus_stage.utils.hash import blake3_digest

# Constants
HEX_STRING_LENGTH = 64

# Configure logger for this module
logger = logging.getLogger(__name__)


@dataclass
class BridgeSyncState:
    """Mutable synchronization state for event polling.

    Tracks the current position in the Bridge event stream to ensure
    no events are missed during synchronization.
    """

    cursor: str | None = None


class BridgeSyncWorker:
    """Periodically pulls federation events from the bridge and applies them locally.

    This worker runs in the background to maintain synchronization between
    the local Stage instance and the Chorus Bridge. It handles:

    - Pulling new events from Bridge
    - Processing outbound federation events
    - Updating the system clock with Bridge day proofs
    - Applying federated events to the local database
    """

    def __init__(
        self, client: BridgeClient | None = None, db_session: Session | None = None
    ) -> None:
        """Initialize the Bridge sync worker.

        Args:
            client: Optional Bridge client instance. If None, uses the global client.
            db_session: Optional database session. If None, creates new sessions as needed.
        """
        self.client = client or get_bridge_client()
        self.state = BridgeSyncState()
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self._db_session = db_session

    async def start(self) -> None:
        """Start the background synchronization loop."""

        if not self.client.enabled:
            return

        if self._task is None or self._task.done():
            self._stopping.clear()
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Stop the background synchronization loop."""

        if self._task is None:
            return

        self._stopping.set()
        await self._task
        self._task = None

    async def _run(self) -> None:
        interval = max(0.1, float(settings.bridge_pull_interval_seconds))

        while not self._stopping.is_set():
            try:
                await self._fetch_and_apply_day_proof()
                await self._process_outbound_events()
                batch = await self._pull_once()
            except BridgeDisabledError:
                return
            except BridgeError as e:
                logger.warning("BridgeSyncWorker encountered BridgeError: %s", e)
                await asyncio.sleep(min(interval * 4, 30.0))
                continue
            except (OSError, ConnectionError, TimeoutError) as e:
                logger.warning("BridgeSyncWorker encountered network error: %s", e)
                await asyncio.sleep(min(interval * 4, 30.0))
                continue
            except (ValueError, TypeError, KeyError, AttributeError) as e:
                logger.error(
                    "BridgeSyncWorker encountered data processing error: %s", e, exc_info=True
                )
                await asyncio.sleep(min(interval * 4, 30.0))
                continue

            if batch.events:
                await asyncio.to_thread(self._apply_events, batch.events)

            if batch.cursor:
                self.state.cursor = batch.cursor

            await asyncio.sleep(interval)

    async def _fetch_and_apply_day_proof(self) -> None:
        """Fetches the canonical day proof from Bridge and updates SystemClock."""
        day_proof = await self.client.fetch_day_proof(self._get_current_local_day())
        if day_proof and day_proof.canonical:
            if self._db_session:
                # Use provided session
                self._update_system_clock(self._db_session, day_proof.day_number)
            else:
                # Create new session
                with SessionLocal() as db:
                    self._update_system_clock(db, day_proof.day_number)

    def _update_system_clock(self, db: Session, day_number: int) -> None:
        """Update SystemClock with the given day number."""
        clock = db.query(SystemClock).first()
        if clock:
            if day_number > clock.day_seq:
                clock.day_seq = day_number
                db.commit()
                logger.info("Updated SystemClock to day %d from Bridge", day_number)
        else:
            # If no clock exists, create one with the Bridge's canonical day
            clock = SystemClock(id=1, day_seq=day_number, hour_seq=0)
            db.add(clock)
            db.commit()
            logger.info("Initialized SystemClock to day %d from Bridge", day_number)

    async def _pull_once(self) -> BridgeEventBatch:
        if not self.client.enabled:
            raise BridgeDisabledError("Bridge integration disabled")

        return await self.client.pull_events(self.state.cursor)

    async def _process_outbound_events(self) -> None:
        """Processes pending outbound federation events, attempting retries."""
        if not self.client.enabled:
            return

        if self._db_session:
            # Use provided session
            await self._process_outbound_events_with_session(self._db_session)
        else:
            # Create new session
            with SessionLocal() as db:
                await self._process_outbound_events_with_session(db)

    async def _process_outbound_events_with_session(self, db: Session) -> None:
        """Process outbound events with a given database session."""
        pending_events = (
            db.query(FederationOutbound)
            .filter(FederationOutbound.status == "pending")
            .order_by(FederationOutbound.id)
            .limit(settings.bridge_outbound_batch_size)
            .all()
        )
        logger.debug("Found %d pending outbound events", len(pending_events))

        for event_record in pending_events:
            logger.debug(
                "Processing outbound event: %s, type: %s",
                event_record.id,
                event_record.event_type
            )
            try:
                success = await self.client.retry_federation_envelope(
                    event_record.payload,
                    event_record.event_hash, # Using event_hash as idempotency_key for retry
                )

                if success:
                    event_record.status = "accepted"
                else:
                    event_record.retry_count += 1
                    if event_record.retry_count >= settings.bridge_outbound_max_retries:
                        event_record.status = "failed"
                db.commit() # Commit changes for this event record

            except BridgeDisabledError:
                db.rollback() # Rollback if bridge becomes disabled
                return
            except (OSError, ConnectionError, TimeoutError) as e:
                logger.warning("Network error processing outbound event %s: %s", event_record.id, e)
                event_record.retry_count += 1
                if event_record.retry_count >= settings.bridge_outbound_max_retries:
                    event_record.status = "failed"
                db.commit()
            except (ValueError, TypeError, KeyError, AttributeError) as e:
                logger.error(
                    "Data processing error processing outbound event %s: %s",
                    event_record.id,
                    e,
                    exc_info=True
                )
                event_record.retry_count += 1
                if event_record.retry_count >= settings.bridge_outbound_max_retries:
                    event_record.status = "failed"
                db.commit()

    def _get_current_local_day(self) -> int:
        """Retrieves the current local day from SystemClock."""
        if self._db_session:
            # Use provided session
            clock = self._db_session.query(SystemClock).first()
            return clock.day_seq if clock else 0
        else:
            # Create new session
            with SessionLocal() as db:
                clock = db.query(SystemClock).first()
                return clock.day_seq if clock else 0

    def _apply_events(self, events: Iterable[BridgeEvent]) -> None:
        if self._db_session:
            # Use provided session
            self._apply_events_with_session(self._db_session, events)
        else:
            # Create new session
            with SessionLocal() as db:
                self._apply_events_with_session(db, events)

    def _apply_events_with_session(self, db: Session, events: Iterable[BridgeEvent]) -> None:
        """Apply events with a given database session."""
        try:
            for event in events:
                # Convert Mapping to dict for type safety
                payload = dict(event.payload) if hasattr(event.payload, 'items') else event.payload

                if event.type == "PostAnnouncement":
                    self._apply_post_event(db, payload)
                elif event.type == "UserRegistration":
                    self._apply_user_registration_event(db, payload)
                elif event.type == "ModerationEvent":
                    self._apply_moderation_event(db, payload)
                elif event.type == "CommunityCreation":
                    self._apply_community_creation_event(db, payload)
                elif event.type == "CommunityJoin":
                    self._apply_community_join_event(db, payload)
                elif event.type == "CommunityLeave":
                    self._apply_community_leave_event(db, payload)
                elif event.type == "DirectMessageSent":
                    self._apply_direct_message_event(db, payload)
                elif event.type == "Vote":
                    self._apply_vote_event(db, payload)

            db.commit()
        except (ValueError, TypeError, KeyError, AttributeError, OSError) as e:
            db.rollback()
            logger.error("Error applying bridge events: %s", e, exc_info=True)
            raise

    def _apply_post_event(self, session: Session, payload: Mapping[str, Any]) -> None:
        clock = session.query(SystemClock).first()
        if not clock:
            clock = SystemClock(id=1, day_seq=0, hour_seq=0)
            session.add(clock)
            session.flush()

        post_id_hex = payload.get("post_id")
        if not post_id_hex:
            return

        try:
            federation_post_id = bytes.fromhex(post_id_hex)
        except ValueError:  # pragma: no cover - defensive
            return

        post = (
            session.query(Post)
            .filter(Post.federation_post_id == federation_post_id)
            .first()
        )

        order_index = payload.get("order_index")
        author_pubkey_hex = payload.get("author_pubkey")
        content_hash_hex = payload.get("content_hash")
        body_md = payload.get("body_md", "")
        community_slug = payload.get("community_slug")
        moderation_state = payload.get("moderation_state", MODERATION_STATE_OPEN)
        harmful_vote_count = payload.get("harmful_vote_count", 0)
        upvotes = payload.get("upvotes", 0)
        downvotes = payload.get("downvotes", 0)
        deleted = bool(payload.get("deleted", False))
        origin_instance = payload.get("origin_instance")

        community_id = None
        if community_slug:
            community = (
                session.query(Community)
                .filter(Community.internal_slug == community_slug)
                .first()
            )
            if community is None:
                community_order_index = payload.get("community_order_index")
                if community_order_index is None:
                    community_order_index = int(clock.day_seq)
                    clock.day_seq = int(clock.day_seq) + 1
                community = Community(
                    internal_slug=community_slug,
                    display_name=community_slug,
                    description_md=None,
                    is_profile_like=False,
                    order_index=community_order_index,
                )
                session.add(community)
                session.flush()
            community_id = community.id

        parent_post_id = None
        parent_federation_hex = payload.get("parent_post_id")
        if parent_federation_hex:
            try:
                parent_federation_id = bytes.fromhex(parent_federation_hex)
            except ValueError:  # pragma: no cover - defensive
                parent_federation_id = None
            if parent_federation_id is not None:
                parent_post = (
                    session.query(Post)
                    .filter(Post.federation_post_id == parent_federation_id)
                    .first()
                )
                if parent_post:
                    parent_post_id = parent_post.id

        if post:
            if order_index is not None:
                post.order_index = order_index
            post.body_md = body_md
            post.content_hash = (
                bytes.fromhex(content_hash_hex) if content_hash_hex else post.content_hash
            )
            post.community_id = community_id
            post.parent_post_id = parent_post_id
            post.moderation_state = moderation_state
            post.harmful_vote_count = harmful_vote_count
            post.upvotes = upvotes
            post.downvotes = downvotes
            post.deleted = deleted
            if origin_instance:
                post.federation_origin = origin_instance
        else:
            post = Post(
                order_index=order_index or 0,
                author_user_id=None,
                author_pubkey=bytes.fromhex(author_pubkey_hex) if author_pubkey_hex else b"",
                parent_post_id=parent_post_id,
                community_id=community_id,
                body_md=body_md,
                content_hash=bytes.fromhex(content_hash_hex) if content_hash_hex else b"",
                moderation_state=moderation_state,
                harmful_vote_count=harmful_vote_count,
                upvotes=upvotes,
                downvotes=downvotes,
                deleted=deleted,
                federation_post_id=federation_post_id,
                federation_origin=origin_instance,
            )
            session.add(post)

        if order_index is not None:
            clock.day_seq = max(int(clock.day_seq), int(order_index) + 1)

    def _apply_user_registration_event(self, session: Session, payload: Mapping[str, Any]) -> None:
        """Apply a UserRegistration event from the bridge.

        Creates a new user account when a user registration event is received
        from the Bridge. This ensures that users registered on other Stage
        instances are available locally.

        Args:
            session: Database session for the operation
            payload: Event payload containing user registration data
        """

        user_pubkey_hex = payload.get("user_pubkey")
        if not user_pubkey_hex:
            return

        try:
            user_pubkey = bytes.fromhex(user_pubkey_hex)
        except ValueError:
            return

        # Check if user already exists
        existing_user = session.query(User).filter(User.pubkey == user_pubkey).first()
        if existing_user:
            return

        # Create new user
        user_id = blake3_digest(user_pubkey)

        user = User(
            user_id=user_id,
            pubkey=user_pubkey,
            creation_day=payload.get("registration_day", 0),
        )
        session.add(user)

    def _apply_moderation_event(self, session: Session, payload: Mapping[str, Any]) -> None:
        """Apply a ModerationEvent from the bridge.

        Processes moderation events (flags, hides, etc.) from other Stage instances.
        Creates or updates moderation cases and records votes from moderators.

        Args:
            session: Database session for the operation
            payload: Event payload containing moderation event data
        """

        target_ref = payload.get("target_ref")
        action = payload.get("action")
        creation_day = payload.get("creation_day")
        moderator_pubkey_hash = payload.get("moderator_pubkey_hash")

        if not all([target_ref, action, creation_day, moderator_pubkey_hash]):
            return

        # Find the post by federation_post_id or local ID
        post = None
        try:
            # Try as federation_post_id first
            if isinstance(target_ref, str) and len(target_ref) == HEX_STRING_LENGTH:  # hex string
                post = (
                    session.query(Post)
                    .filter(Post.federation_post_id == bytes.fromhex(target_ref))
                    .first()
                )
            elif isinstance(target_ref, int | str):
                # Try as local post ID
                post = session.query(Post).filter(Post.id == int(target_ref)).first()
        except (ValueError, TypeError):
            pass

        if not post:
            return

        # Create or update moderation case
        case = session.query(ModerationCase).filter(ModerationCase.post_id == post.id).first()
        if not case:
            case = ModerationCase(
                post_id=post.id,
                state=MODERATION_STATE_OPEN,
                creation_day=creation_day,
            )
            session.add(case)

        # Record the moderation vote
        vote = ModerationVote(
            post_id=post.id,
            voter_pubkey_hash=(
                bytes.fromhex(moderator_pubkey_hash)
                if isinstance(moderator_pubkey_hash, str)
                else moderator_pubkey_hash
            ),
            choice=1 if action in ["flag", "hide"] else 0,  # 1 for harmful, 0 for not harmful
            creation_day=creation_day,
        )
        session.add(vote)

    def _apply_community_creation_event(self, session: Session, payload: Mapping[str, Any]) -> None:
        """Apply a CommunityCreation event from the bridge.

        Creates a new community when a community creation event is received
        from the Bridge. This ensures that communities created on other Stage
        instances are available locally.

        Args:
            session: Database session for the operation
            payload: Event payload containing community creation data
        """

        community_id = payload.get("community_id")
        internal_slug = payload.get("internal_slug")
        display_name = payload.get("display_name")
        creation_day = payload.get("creation_day")

        if not all([community_id, internal_slug, display_name, creation_day]):
            return

        # Check if community already exists
        existing_community = (
            session.query(Community)
            .filter(Community.internal_slug == internal_slug)
            .first()
        )
        if existing_community:
            return

        # Create new community
        community = Community(
            internal_slug=internal_slug,
            display_name=display_name,
            description_md=None,
            is_profile_like=False,
            order_index=creation_day,
        )
        session.add(community)

    def _apply_community_join_event(self, session: Session, payload: Mapping[str, Any]) -> None:
        """Apply a CommunityJoin event from the bridge.

        Records a user joining a community when a community join event is received
        from the Bridge. This ensures that community memberships are synchronized
        across all Stage instances.

        Args:
            session: Database session for the operation
            payload: Event payload containing community join data
        """

        community_id = payload.get("community_id")
        user_id_hex = payload.get("user_id")
        day_seq = payload.get("day_seq")

        if not all([community_id, user_id_hex, day_seq]):
            return

        try:
            user_id = bytes.fromhex(str(user_id_hex))
        except (ValueError, TypeError):
            return

        # Find community and user
        community = session.query(Community).filter(Community.id == community_id).first()
        user = session.query(User).filter(User.user_id == user_id).first()

        if not community or not user:
            return

        # Check if membership already exists
        existing_membership = session.query(CommunityMember).filter(
            CommunityMember.community_id == community_id,
            CommunityMember.user_id == user_id
        ).first()

        if not existing_membership:
            membership = CommunityMember(
                community_id=community_id,
                user_id=user_id,
                day_seq=day_seq,
            )
            session.add(membership)

    def _apply_community_leave_event(self, session: Session, payload: Mapping[str, Any]) -> None:
        """Apply a CommunityLeave event from the bridge.

        Records a user leaving a community when a community leave event is received
        from the Bridge. This ensures that community memberships are synchronized
        across all Stage instances.

        Args:
            session: Database session for the operation
            payload: Event payload containing community leave data
        """

        community_id = payload.get("community_id")
        user_id_hex = payload.get("user_id")
        day_seq = payload.get("day_seq")

        if not all([community_id, user_id_hex, day_seq]):
            return

        try:
            user_id = bytes.fromhex(str(user_id_hex))
        except (ValueError, TypeError):
            return

        # Remove membership
        membership = session.query(CommunityMember).filter(
            CommunityMember.community_id == community_id,
            CommunityMember.user_id == user_id
        ).first()

        if membership:
            session.delete(membership)

    def _apply_direct_message_event(self, session: Session, payload: Mapping[str, Any]) -> None:
        """Apply a DirectMessageSent event from the bridge.

        Records a direct message when a direct message sent event is received
        from the Bridge. Note that message content is not stored for privacy
        reasons - only metadata is recorded.

        Args:
            session: Database session for the operation
            payload: Event payload containing direct message data
        """

        message_id = payload.get("message_id")
        sender_user_id_hex = payload.get("sender_user_id")
        recipient_user_id_hex = payload.get("recipient_user_id")
        day_seq = payload.get("day_seq")

        if not all([message_id, sender_user_id_hex, recipient_user_id_hex, day_seq]):
            return

        try:
            sender_user_id = bytes.fromhex(str(sender_user_id_hex))
            recipient_user_id = bytes.fromhex(str(recipient_user_id_hex))
        except (ValueError, TypeError):
            return

        # Check if message already exists
        existing_message = (
            session.query(DirectMessage)
            .filter(DirectMessage.id == message_id)
            .first()
        )
        if existing_message:
            return

        # Create new direct message record
        message = DirectMessage(
            id=message_id,
            sender_user_id=sender_user_id,
            recipient_user_id=recipient_user_id,
            day_seq=day_seq,
            # Note: encrypted content is not stored in federation events for privacy
        )
        session.add(message)

    def _apply_vote_event(self, session: Session, payload: Mapping[str, Any]) -> None:
        """Apply a Vote event from the bridge.

        Records a vote when a vote event is received from the Bridge.
        This ensures that votes are synchronized across all Stage instances.

        Args:
            session: Database session for the operation
            payload: Event payload containing vote data
        """

        post_id = payload.get("post_id")
        voter_user_id_hex = payload.get("voter_user_id")
        direction = payload.get("direction")
        creation_day = payload.get("creation_day")

        if not all([post_id, voter_user_id_hex, direction is not None, creation_day]):
            return

        try:
            voter_user_id = bytes.fromhex(str(voter_user_id_hex))
        except (ValueError, TypeError):
            return

        # Check if vote already exists
        existing_vote = session.query(PostVote).filter(
            PostVote.post_id == post_id,
            PostVote.voter_user_id == voter_user_id
        ).first()

        if existing_vote:
            # Update existing vote
            existing_vote.direction = int(direction) if direction is not None else 0
        else:
            # Create new vote
            vote = PostVote(
                post_id=post_id,
                voter_user_id=voter_user_id,
                direction=int(direction) if direction is not None else 0,
            )
            session.add(vote)
