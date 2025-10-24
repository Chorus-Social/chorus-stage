"""Bridge client for Stage ↔ Bridge integration.

This module provides the BridgeClient class that handles all communication
between Chorus Stage and Chorus Bridge. It includes:

- HTTP client with authentication and retry logic
- Circuit breaker pattern for fault tolerance
- Metrics collection for monitoring
- Federation envelope creation and signing
- Health checks and status monitoring
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx
from jose import jwt
from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.models import FederationOutbound
from chorus_stage.proto.federation_pb2_stub import (
    FederationEnvelope,
    ModerationEvent,
    UserRegistration,
)
from chorus_stage.services.crypto import CryptoService
from chorus_stage.utils.hash import blake3_digest, blake3_hexdigest

# Configure logger for this module
logger = logging.getLogger(__name__)

# HTTP status codes
HTTP_OK = 200
HTTP_NOT_FOUND = 404
HTTP_ACCEPTED = 202
HTTP_INTERNAL_SERVER_ERROR = 500


class BridgeError(RuntimeError):
    """Base exception raised for bridge-related failures.

    This is the base class for all Bridge-related exceptions.
    """


class BridgeDisabledError(BridgeError):
    """Raised when bridge operations are attempted while disabled.

    This exception is raised when attempting to perform Bridge operations
    while the Bridge integration is disabled in the configuration.
    """


class CircuitState(Enum):
    """Circuit breaker states for fault tolerance.

    The circuit breaker pattern helps prevent cascading failures by
    monitoring the health of the Bridge service and temporarily
    blocking requests when failures are detected.
    """
    CLOSED = "closed"      # Normal operation - requests allowed
    OPEN = "open"          # Circuit is open - requests blocked
    HALF_OPEN = "half_open"  # Testing if service is back - limited requests allowed


@dataclass
class BridgeMetrics:
    """Metrics collection for Bridge operations."""

    request_count: int = 0
    success_count: int = 0
    error_count: int = 0
    total_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    error_counts_by_type: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    endpoint_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def record_request(
        self, endpoint: str, response_time: float, success: bool, error_type: str | None = None
    ) -> None:
        """Record a request metric."""
        self.request_count += 1
        self.total_response_time += response_time
        self.min_response_time = min(self.min_response_time, response_time)
        self.max_response_time = max(self.max_response_time, response_time)
        self.endpoint_counts[endpoint] += 1

        if success:
            self.success_count += 1
        else:
            self.error_count += 1
            if error_type:
                self.error_counts_by_type[error_type] += 1

    def get_average_response_time(self) -> float:
        """Get average response time."""
        return self.total_response_time / self.request_count if self.request_count > 0 else 0.0

    def get_success_rate(self) -> float:
        """Get success rate as a percentage."""
        return (self.success_count / self.request_count * 100) if self.request_count > 0 else 0.0


@dataclass
class CircuitBreaker:
    """Circuit breaker for Bridge operations."""

    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    success_threshold: int = 3

    _state: CircuitState = CircuitState.CLOSED
    _failure_count: int = 0
    _success_count: int = 0
    _last_failure_time: float = 0.0

    def is_open(self) -> bool:
        """Check if circuit is open."""
        if self._state == CircuitState.OPEN:
            # Check if we should transition to half-open
            if time.time() - self._last_failure_time > self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._success_count = 0
            return self._state == CircuitState.OPEN
        return False

    def record_success(self) -> None:
        """Record a successful operation."""
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.success_threshold:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
        elif self._state == CircuitState.CLOSED:
            self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed operation."""
        self._failure_count += 1
        self._last_failure_time = time.time()

        if self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN

    def get_state(self) -> CircuitState:
        """Get the current circuit breaker state."""
        return self._state

    def get_failure_count(self) -> int:
        """Get the current failure count."""
        return self._failure_count

    def get_success_count(self) -> int:
        """Get the current success count."""
        return self._success_count

    def get_last_failure_time(self) -> float:
        """Get the last failure time."""
        return self._last_failure_time


@dataclass(frozen=True)
class BridgeConfig:
    """Immutable configuration for bridge operations."""

    enabled: bool
    base_url: str | None
    instance_id: str
    shared_secret: str | None
    audience: str
    token_ttl_seconds: int
    timeout_seconds: float
    mtls_enabled: bool
    client_cert: str | None
    client_key: str | None
    ca_cert: str | None
    instance_private_key: str | None


@dataclass(frozen=True)
class BridgeDayProof:
    """Canonical day proof response."""

    day_number: int
    proof: bytes
    proof_hash: bytes | None
    canonical: bool


@dataclass(frozen=True)
class BridgePostSubmission:
    """Payload for registering a post with the bridge."""

    author_pubkey_hex: str
    content_hash_hex: str
    body_md: str
    community_slug: str | None
    parent_federation_post_id: str | None
    pow_nonce: str
    pow_difficulty: int


@dataclass(frozen=True)
class BridgePostRegistration:
    """Result returned after registering a post with the bridge."""

    order_index: int
    post_id: bytes | None
    origin_instance: str | None
    day_number: int | None


@dataclass(frozen=True)
class BridgeEvent:
    """Generic bridge event container."""

    type: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class BridgeEventBatch:
    """Batch of events pulled from bridge stream."""

    cursor: str | None
    events: list[BridgeEvent]


def load_bridge_config() -> BridgeConfig:
    """Build configuration object from global settings."""

    return BridgeConfig(
        enabled=bool(settings.bridge_enabled and settings.bridge_base_url),
        base_url=settings.bridge_base_url,
        instance_id=settings.bridge_instance_id,
        shared_secret=settings.bridge_shared_secret,
        audience=settings.bridge_audience,
        token_ttl_seconds=settings.bridge_token_ttl_seconds,
        timeout_seconds=float(settings.bridge_http_timeout_seconds),
        mtls_enabled=settings.bridge_mtls_enabled,
        client_cert=settings.bridge_client_cert,
        client_key=settings.bridge_client_key,
        ca_cert=settings.bridge_ca_cert,
        instance_private_key=settings.bridge_instance_private_key,
    )


class BridgeClient:
    """HTTP client wrapper for Chorus Bridge interactions."""

    def __init__(self, config: BridgeConfig | None = None) -> None:
        self.config = config or load_bridge_config()
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()
        self._circuit_breaker = CircuitBreaker()
        self._metrics = BridgeMetrics()

    @property
    def enabled(self) -> bool:
        return self.config.enabled and bool(self.config.base_url)

    async def _ensure_client(self) -> httpx.AsyncClient:
        if not self.enabled:
            raise BridgeDisabledError("Chorus Bridge is not enabled")

        async with self._client_lock:
            if self._client is None:
                cert: tuple[str, str] | None = None
                verify: str | bool = True

                if self.config.mtls_enabled:
                    if not (self.config.client_cert and self.config.client_key):
                        raise BridgeError("mTLS enabled but client certificate or key missing")
                    cert = (self.config.client_cert, self.config.client_key)
                    verify = self.config.ca_cert or True
                elif self.config.ca_cert:
                    verify = self.config.ca_cert

                self._client = httpx.AsyncClient(
                    base_url=self.config.base_url or "",
                    timeout=httpx.Timeout(self.config.timeout_seconds),
                    verify=verify,
                    cert=cert,
                )

        return self._client

    def _build_auth_headers(self, *, idempotency_key: str | None = None) -> dict[str, str]:
        headers = {
            "X-Chorus-Instance-Id": self.config.instance_id,
        }

        if self.config.shared_secret:
            now = int(time.time())
            payload = {
                "iss": self.config.instance_id,
                "aud": self.config.audience,
                "iat": now,
                "exp": now + max(1, self.config.token_ttl_seconds),
                "jti": secrets.token_hex(8),
            }
            token = jwt.encode(payload, self.config.shared_secret, algorithm="HS256")
            headers["Authorization"] = f"Bearer {token}"

        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        return headers

    @dataclass
    class RequestParams:
        """Parameters for HTTP requests."""
        method: str
        path: str
        json_data: Any | None = None
        data: Any | None = None
        params: Mapping[str, Any] | None = None
        idempotency_key: str | None = None
        headers: dict[str, str] | None = None

    async def _request(self, params: RequestParams) -> httpx.Response:
        # Check circuit breaker
        if self._circuit_breaker.is_open():
            raise BridgeError("Bridge circuit breaker is open - service unavailable")

        client = await self._ensure_client()
        auth_headers = self._build_auth_headers(idempotency_key=params.idempotency_key)
        if params.headers:
            auth_headers.update(params.headers)
        headers = auth_headers

        start_time = time.time()
        endpoint = f"{params.method} {params.path}"
        success = False
        error_type = None
        response_time = 0.0

        try:
            response = await client.request(
                params.method,
                params.path,
                json=params.json_data,
                data=params.data,
                params=params.params,
                headers=headers,
            )

            response_time = time.time() - start_time

            # Record success or failure based on response
            if response.status_code < HTTP_INTERNAL_SERVER_ERROR:
                self._circuit_breaker.record_success()
                success = True
            else:
                self._circuit_breaker.record_failure()
                error_type = f"http_{response.status_code}"
                raise BridgeError(f"Bridge responded with {response.status_code}")

        except httpx.HTTPError as exc:  # pragma: no cover - network failure
            response_time = time.time() - start_time
            self._circuit_breaker.record_failure()
            error_type = "network_error"
            raise BridgeError(f"Bridge request failed: {exc}") from exc
        except Exception as exc:
            response_time = time.time() - start_time
            self._circuit_breaker.record_failure()
            error_type = "unknown_error"
            raise BridgeError(f"Bridge request failed: {exc}") from exc
        finally:
            # Record metrics
            self._metrics.record_request(endpoint, response_time, success, error_type)

        return response

    async def fetch_day_proof(self, day: int) -> BridgeDayProof | None:
        """Fetch canonical day proof from the bridge."""

        response = await self._request(
            self.RequestParams(method="GET", path=f"/api/bridge/day-proof/{day}")
        )

        if response.status_code == HTTP_NOT_FOUND:
            return None
        if response.status_code != HTTP_OK:
            raise BridgeError(
                f"Unexpected bridge response ({response.status_code}) for day proof",
            )

        payload = response.json()
        proof_hex = payload.get("proof")
        proof_hash_hex = payload.get("proof_hash")
        return BridgeDayProof(
            day_number=int(payload.get("day_number", day)),
            proof=bytes.fromhex(proof_hex) if proof_hex else b"",
            proof_hash=bytes.fromhex(proof_hash_hex) if proof_hash_hex else None,
            canonical=bool(payload.get("canonical", True)),
        )

    async def register_post(
        self,
        submission: BridgePostSubmission,
        *,
        idempotency_key: str,
    ) -> BridgePostRegistration:
        """Register a post with the bridge and obtain global ordering metadata."""

        if not self.enabled:
            raise BridgeDisabledError("Bridge post registration not available")

        payload = {
            "author_pubkey": submission.author_pubkey_hex,
            "content_hash": submission.content_hash_hex,
            "body_md": submission.body_md,
            "community_slug": submission.community_slug,
            "parent_post_id": submission.parent_federation_post_id,
            "pow_nonce": submission.pow_nonce,
            "pow_difficulty": submission.pow_difficulty,
        }

        response = await self._request(
            self.RequestParams(
                method="POST",
                path="/api/bridge/federation/posts",
                json_data=payload,
                idempotency_key=idempotency_key,
            )
        )

        if response.status_code not in (200, 201, 202):
            raise BridgeError(
                f"Unexpected bridge response ({response.status_code}) when registering post",
            )

        body = response.json()
        post_id_hex = body.get("post_id")
        return BridgePostRegistration(
            order_index=int(body.get("order_index")),
            post_id=bytes.fromhex(post_id_hex) if post_id_hex else None,
            origin_instance=body.get("origin_instance"),
            day_number=body.get("day_number"),
        )

    async def send_federation_envelope(
        self, db: Session, envelope: bytes, idempotency_key: str
    ) -> bool:
        """Relays a FederationEnvelope to Chorus Bridge for federation.

        Args:
            db: The database session.
            envelope: The serialized FederationEnvelope (from CFP-002).
            idempotency_key: A unique key for idempotency.

        Returns:
            True if the envelope was accepted, False otherwise.
        """
        if not self.enabled:
            raise BridgeDisabledError("Bridge federation send not available")

        # Sign the envelope if we have a private key
        signed_envelope = envelope
        if self.config.instance_private_key:
            try:
                signed_envelope = self._sign_federation_envelope(
                    envelope, self.config.instance_private_key
                )
            except (ValueError, TypeError, AttributeError) as e:
                print(f"Warning: Failed to sign federation envelope: {e}")
                # Continue with unsigned envelope

        # Record the outbound event before sending
        event_hash = blake3_hexdigest(signed_envelope)
        federation_record = FederationOutbound(
            # Generic type, specific type can be parsed from envelope if needed
            event_type="FederationEnvelope",
            event_hash=event_hash,
            payload=signed_envelope,
            status="pending",
            retry_count=0,
        )
        db.add(federation_record)
        db.flush()  # Flush to get the ID if needed, but not committing yet

        try:
            response = await self._request(
                self.RequestParams(
                    method="POST",
                    path="/api/bridge/federation/send",
                    data=signed_envelope,
                    idempotency_key=idempotency_key,
                )
            )

            if response.status_code not in (HTTP_ACCEPTED,):
                federation_record.status = "failed"
                db.flush()
                raise BridgeError(
                    f"Unexpected bridge response ({response.status_code}) "
                    f"when sending federation envelope",
                )
            federation_record.status = "accepted"
            db.flush()
            return True
        except (BridgeError, httpx.HTTPError, OSError) as e:
            federation_record.status = "failed"
            db.flush()
            raise e

    async def retry_federation_envelope(self, envelope: bytes, idempotency_key: str) -> bool:
        """Retries sending a FederationEnvelope to Chorus Bridge for federation.

        This method is intended for retrying previously failed or pending events.
        It does not create a new FederationOutbound record.

        Args:
            envelope: The serialized FederationEnvelope.
            idempotency_key: The idempotency key associated with the original event.

        Returns:
            True if the envelope was accepted, False otherwise.
        """
        if not self.enabled:
            raise BridgeDisabledError("Bridge federation retry not available")

        try:
            response = await self._request(
                self.RequestParams(
                    method="POST",
                    path="/api/bridge/federation/send",
                    data=envelope,
                    idempotency_key=idempotency_key,
                    headers={"Content-Type": "application/octet-stream"},
                )
            )

            return response.status_code in (HTTP_ACCEPTED,)
        except BridgeDisabledError:
            raise # Re-raise if bridge becomes disabled during retry
        except (BridgeError, httpx.HTTPError, OSError) as e:
            print(f"Error retrying federation envelope: {e}")
            return False # Indicate failure

    async def anchor_moderation_event(self, db: Session, event_data: Mapping[str, Any]) -> bool:
        """Anchors a moderation event to the network via Chorus Bridge.

        Args:
            db: The database session.
            event_data: The minimal event object with hashes only.

        Returns:
            True if the event was accepted, False otherwise.
        """
        if not self.enabled:
            raise BridgeDisabledError("Bridge moderation anchoring not available")

        # Record the outbound event before sending
        # For moderation events, event_data itself is the payload, so hash it.
        # Convert event_data to bytes for hashing.
        import json
        event_data_bytes = json.dumps(event_data, sort_keys=True).encode('utf-8')
        event_hash = blake3_hexdigest(event_data_bytes)
        idempotency_key = secrets.token_hex(8) # Generate a new idempotency key for each event

        federation_record = FederationOutbound(
            event_type="ModerationEvent",
            event_hash=event_hash,
            payload=event_data_bytes,
            status="pending",
            retry_count=0,
        )
        db.add(federation_record)
        db.flush()

        try:
            response = await self._request(
                self.RequestParams(
                    method="POST",
                    path="/api/bridge/moderation/event",
                    json_data=event_data,
                    idempotency_key=idempotency_key,
                )
            )

            if response.status_code not in (HTTP_ACCEPTED,):
                federation_record.status = "failed"
                db.flush()
                raise BridgeError(
                    f"Unexpected bridge response ({response.status_code}) "
                    f"when anchoring moderation event",
                )
            federation_record.status = "accepted"
            db.flush()
            return True
        except (BridgeError, httpx.HTTPError, OSError) as e:
            federation_record.status = "failed"
            db.flush()
            raise e

    async def pull_events(self, cursor: str | None = None) -> BridgeEventBatch:
        """Pull a batch of federation events from the bridge."""

        if not self.enabled:
            raise BridgeDisabledError("Bridge event stream not available")

        params: dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor

        response = await self._request(
            self.RequestParams(
                method="GET",
                path="/api/bridge/federation/stream",
                params=params,
            )
        )

        if response.status_code != HTTP_OK:
            raise BridgeError(
                f"Unexpected bridge response ({response.status_code}) "
                f"when pulling events",
            )

        payload = response.json()
        events_payload = payload.get("events", []) or []
        events = [
            BridgeEvent(type=item.get("type", ""), payload=item.get("payload", {}))
            for item in events_payload
        ]
        return BridgeEventBatch(cursor=payload.get("cursor"), events=events)

    async def create_user_registration_envelope(
        self,
        user_pubkey_bytes: bytes,
        creation_day: int,
        idempotency_key: str,  # Used for signing context
    ) -> bytes:
        """Create a UserRegistration FederationEnvelope for user registration events.

        Args:
            user_pubkey_bytes: The user's public key as bytes
            creation_day: The day sequence when the user was registered
            idempotency_key: Unique key for idempotency and signing context

        Returns:
            Serialized FederationEnvelope bytes
        """

        # Create UserRegistration message
        user_registration = UserRegistration(
            user_pubkey=user_pubkey_bytes,
            registration_day=creation_day,
            day_proof_hash=b"",  # Will be filled by Bridge
        )

        # Create FederationEnvelope
        envelope = FederationEnvelope(
            sender_instance=self.config.instance_id,
            timestamp=int(time.time()),
            message_type="UserRegistration",
            message_data=user_registration.SerializeToString(),
            signature=b"",  # Will be signed by _sign_federation_envelope
        )

        # Use idempotency_key in signing context
        _ = idempotency_key  # Acknowledge parameter usage

        # Serialize and sign the envelope
        envelope_bytes = envelope.SerializeToString()
        if self.config.instance_private_key:
            envelope_bytes = self._sign_federation_envelope(
                envelope_bytes, self.config.instance_private_key
            )

        return envelope_bytes

    async def create_community_envelope(
        self,
        community_id: int,
        internal_slug: str,
        display_name: str,
        creation_day: int,
        idempotency_key: str,  # Used for signing context
    ) -> bytes:
        """Create and serialize a FederationEnvelope for CommunityCreation."""
        if not self.enabled:
            raise BridgeDisabledError("Bridge community creation federation not available")

        import json


        community_creation_event_payload = {
            "community_id": community_id,
            "internal_slug": internal_slug,
            "display_name": display_name,
            "creation_day": creation_day,
        }

        message_data_bytes = json.dumps(community_creation_event_payload).encode('utf-8')

        federation_envelope = FederationEnvelope(
            sender_instance=self.config.instance_id,
            timestamp=int(time.time()),
            message_type="CommunityCreation",
            message_data=message_data_bytes,
            signature=b"" # Will be signed later
        )

        # Use idempotency_key in signing context
        _ = idempotency_key  # Acknowledge parameter usage

        envelope_bytes = federation_envelope.SerializeToString()

        # Sign the envelope if we have a private key
        if self.config.instance_private_key:
            try:
                return self._sign_federation_envelope(
                    envelope_bytes, self.config.instance_private_key
                )
            except (ValueError, TypeError, AttributeError) as e:
                print(f"Warning: Failed to sign community creation envelope: {e}")
                # Return unsigned envelope
                return envelope_bytes

        return envelope_bytes

    async def create_community_join_envelope(
        self,
        community_id: int,
        user_id_hex: str,
        day_seq: int,
        idempotency_key: str,  # Used for signing context
    ) -> bytes:
        """Create and serialize a FederationEnvelope for CommunityJoin."""
        if not self.enabled:
            raise BridgeDisabledError("Bridge community join federation not available")

        import json


        community_join_event_payload = {
            "community_id": community_id,
            "user_id": user_id_hex,
            "day_seq": day_seq,
        }

        message_data_bytes = json.dumps(community_join_event_payload).encode('utf-8')

        federation_envelope = FederationEnvelope(
            sender_instance=self.config.instance_id,
            timestamp=int(time.time()),
            message_type="CommunityJoin",
            message_data=message_data_bytes,
            signature=b"" # Will be signed later
        )

        # Use idempotency_key in signing context
        _ = idempotency_key  # Acknowledge parameter usage

        envelope_bytes = federation_envelope.SerializeToString()

        # Sign the envelope if we have a private key
        if self.config.instance_private_key:
            try:
                return self._sign_federation_envelope(
                    envelope_bytes, self.config.instance_private_key
                )
            except (ValueError, TypeError, AttributeError) as e:
                print(f"Warning: Failed to sign community join envelope: {e}")
                # Return unsigned envelope
                return envelope_bytes

        return envelope_bytes

    async def create_community_leave_envelope(
        self,
        community_id: int,
        user_id_hex: str,
        day_seq: int,
        idempotency_key: str,  # Used for signing context
    ) -> bytes:
        """Create and serialize a FederationEnvelope for CommunityLeave."""
        if not self.enabled:
            raise BridgeDisabledError("Bridge community leave federation not available")

        import json


        community_leave_event_payload = {
            "community_id": community_id,
            "user_id": user_id_hex,
            "day_seq": day_seq,
        }

        message_data_bytes = json.dumps(community_leave_event_payload).encode('utf-8')

        federation_envelope = FederationEnvelope(
            sender_instance=self.config.instance_id,
            timestamp=int(time.time()),
            message_type="CommunityLeave",
            message_data=message_data_bytes,
            signature=b"" # Will be signed later
        )

        # Use idempotency_key in signing context
        _ = idempotency_key  # Acknowledge parameter usage

        envelope_bytes = federation_envelope.SerializeToString()

        # Sign the envelope if we have a private key
        if self.config.instance_private_key:
            try:
                return self._sign_federation_envelope(
                    envelope_bytes, self.config.instance_private_key
                )
            except (ValueError, TypeError, AttributeError) as e:
                print(f"Warning: Failed to sign community leave envelope: {e}")
                # Return unsigned envelope
                return envelope_bytes

        return envelope_bytes



    async def create_direct_message_sent_envelope(
        self,
        message_id: int,
        sender_user_id_hex: str,
        recipient_user_id_hex: str,
        day_seq: int,
        idempotency_key: str,  # Used for signing context
    ) -> bytes:
        """Create and serialize a FederationEnvelope for DirectMessageSent."""
        if not self.enabled:
            raise BridgeDisabledError("Bridge direct message sent federation not available")

        import json


        direct_message_sent_event_payload = {
            "message_id": message_id,
            "sender_user_id": sender_user_id_hex,
            "recipient_user_id": recipient_user_id_hex,
            "day_seq": day_seq,
        }

        message_data_bytes = json.dumps(direct_message_sent_event_payload).encode('utf-8')

        federation_envelope = FederationEnvelope(
            sender_instance=self.config.instance_id,
            timestamp=int(time.time()),
            message_type="DirectMessageSent",
            message_data=message_data_bytes,
            signature=b"" # Will be signed later
        )

        envelope_bytes = federation_envelope.SerializeToString()

        # Use idempotency_key in signing context
        _ = idempotency_key  # Acknowledge parameter usage

        # Sign the envelope if we have a private key
        if self.config.instance_private_key:
            try:
                return self._sign_federation_envelope(
                    envelope_bytes, self.config.instance_private_key
                )
            except (ValueError, TypeError, AttributeError) as e:
                print(f"Warning: Failed to sign direct message envelope: {e}")
                # Return unsigned envelope
                return envelope_bytes

        return envelope_bytes



    async def create_moderation_trigger_envelope(
        self,
        post_id: int,
        trigger_user_id_bytes: bytes,
        creation_day: int,
        idempotency_key: str,  # Used for signing context
    ) -> bytes:
        """Create and serialize a FederationEnvelope for ModerationEvent (Trigger)."""
        if not self.enabled:
            raise BridgeDisabledError("Bridge moderation trigger federation not available")


        # Convert post_id to bytes for target_ref
        target_ref_bytes = str(post_id).encode('utf-8')

        moderation_event_message = ModerationEvent(
            target_ref=target_ref_bytes,
            action="flag", # Assuming 'flag' for a trigger
            reason_hash=blake3_digest(b"moderation_triggered"), # Generic reason hash
            moderator_pubkey_hash=trigger_user_id_bytes,
            creation_day=creation_day,
        )

        federation_envelope = FederationEnvelope(
            sender_instance=self.config.instance_id,
            timestamp=int(time.time()),
            message_type="ModerationEvent",
            message_data=moderation_event_message.SerializeToString(),
            signature=b"" # Will be signed later
        )

        envelope_bytes = federation_envelope.SerializeToString()

        # Use idempotency_key in signing context
        _ = idempotency_key  # Acknowledge parameter usage

        # Sign the envelope if we have a private key
        if self.config.instance_private_key:
            try:
                return self._sign_federation_envelope(
                    envelope_bytes, self.config.instance_private_key
                )
            except (ValueError, TypeError, AttributeError) as e:
                print(f"Warning: Failed to sign moderation trigger envelope: {e}")
                # Return unsigned envelope
                return envelope_bytes

        return envelope_bytes

    async def create_post_delete_envelope(
        self,
        post_id: int,
        moderator_user_id_bytes: bytes,
        creation_day: int,
        idempotency_key: str,  # Used for signing context
    ) -> bytes:
        """Create and serialize a FederationEnvelope for ModerationEvent (Post Delete)."""
        if not self.enabled:
            raise BridgeDisabledError("Bridge post delete federation not available")


        target_ref_bytes = str(post_id).encode('utf-8')

        moderation_event_message = ModerationEvent(
            target_ref=target_ref_bytes,
            action="hide", # Using 'hide' for soft-delete
            reason_hash=blake3_digest(b"post_deleted"), # Generic reason hash
            moderator_pubkey_hash=moderator_user_id_bytes,
            creation_day=creation_day,
        )

        federation_envelope = FederationEnvelope(
            sender_instance=self.config.instance_id,
            timestamp=int(time.time()),
            message_type="ModerationEvent",
            message_data=moderation_event_message.SerializeToString(),
            signature=b"" # Will be signed later
        )

        envelope_bytes = federation_envelope.SerializeToString()

        # Use idempotency_key in signing context
        _ = idempotency_key  # Acknowledge parameter usage

        # Sign the envelope if we have a private key
        if self.config.instance_private_key:
            try:
                return self._sign_federation_envelope(
                    envelope_bytes, self.config.instance_private_key
                )
            except (ValueError, TypeError, AttributeError) as e:
                print(f"Warning: Failed to sign post delete envelope: {e}")
                # Return unsigned envelope
                return envelope_bytes

        return envelope_bytes

    async def create_vote_envelope(
        self,
        post_id: int,
        voter_user_id_bytes: bytes,
        direction: int,
        creation_day: int,
        idempotency_key: str,  # Used for signing context
    ) -> bytes:
        """Create and serialize a FederationEnvelope for a Vote event."""
        if not self.enabled:
            raise BridgeDisabledError("Bridge vote federation not available")

        import json


        vote_event_payload = {
            "post_id": post_id,
            "voter_user_id": voter_user_id_bytes.hex(),
            "direction": direction,
            "creation_day": creation_day,
        }

        message_data_bytes = json.dumps(vote_event_payload, sort_keys=True).encode('utf-8')

        federation_envelope = FederationEnvelope(
            sender_instance=self.config.instance_id,
            timestamp=int(time.time()),
            message_type="Vote", # Custom message type for votes
            message_data=message_data_bytes,
            signature=b"" # Will be signed later
        )

        envelope_bytes = federation_envelope.SerializeToString()

        # Use idempotency_key in signing context
        _ = idempotency_key  # Acknowledge parameter usage

        # Sign the envelope if we have a private key
        if self.config.instance_private_key:
            try:
                return self._sign_federation_envelope(
                    envelope_bytes, self.config.instance_private_key
                )
            except (ValueError, TypeError, AttributeError) as e:
                print(f"Warning: Failed to sign vote envelope: {e}")
                # Return unsigned envelope
                return envelope_bytes

        return envelope_bytes

    def _sign_federation_envelope(self, envelope: bytes, private_key_hex: str) -> bytes:
        """Sign a FederationEnvelope with the instance's private key.

        Args:
            envelope: Serialized FederationEnvelope
            private_key_hex: Hex-encoded Ed25519 private key

        Returns:
            Signed FederationEnvelope bytes
        """

        # Parse the envelope
        parsed_envelope = FederationEnvelope()
        parsed_envelope.ParseFromString(envelope)

        # Create the message to sign (envelope without signature)
        message_to_sign = b"".join([
            parsed_envelope.sender_instance.encode('utf-8'),
            parsed_envelope.timestamp.to_bytes(8, 'big'),
            parsed_envelope.message_type.encode('utf-8'),
            parsed_envelope.message_data
        ])

        # Sign the message
        signature = CryptoService.sign_message_hex(private_key_hex, message_to_sign)

        # Update the envelope with the signature
        parsed_envelope.signature = signature

        # Return the signed envelope
        return parsed_envelope.SerializeToString()

    async def health_check(self) -> dict[str, Any]:
        """Perform a health check on the Bridge connection.

        Returns:
            Dictionary containing health status and metrics
        """
        if not self.enabled:
            return {
                "status": "disabled",
                "enabled": False,
                "error": "Bridge integration is disabled"
            }

        try:
            response = await self._request(self.RequestParams(method="GET", path="/health"))

            if response.status_code == HTTP_OK:
                return {
                    "status": "healthy",
                    "enabled": True,
                    "response_time_ms": response.elapsed.total_seconds() * 1000,
                    "bridge_status": (
                        response.json()
                        if response.headers.get("content-type", "").startswith("application/json")
                        else None
                    ),
                    "circuit_breaker": self.get_circuit_breaker_status()
                }
            else:
                return {
                    "status": "unhealthy",
                    "enabled": True,
                    "error": f"Bridge returned status {response.status_code}",
                    "response_time_ms": response.elapsed.total_seconds() * 1000,
                    "circuit_breaker": self.get_circuit_breaker_status()
                }
        except (BridgeError, httpx.HTTPError, OSError) as e:
            return {
                "status": "error",
                "enabled": True,
                "error": str(e),
                "response_time_ms": None,
                "circuit_breaker": self.get_circuit_breaker_status()
            }

    def get_circuit_breaker_status(self) -> dict[str, Any]:
        """Get the current circuit breaker status.

        Returns:
            Dictionary containing circuit breaker state and metrics
        """
        return {
            "state": self._circuit_breaker.get_state().value,
            "failure_count": self._circuit_breaker.get_failure_count(),
            "success_count": self._circuit_breaker.get_success_count(),
            "last_failure_time": self._circuit_breaker.get_last_failure_time(),
            "is_open": self._circuit_breaker.is_open()
        }

    def get_metrics(self) -> dict[str, Any]:
        """Get Bridge operation metrics.

        Returns:
            Dictionary containing performance and usage metrics
        """
        return {
            "request_count": self._metrics.request_count,
            "success_count": self._metrics.success_count,
            "error_count": self._metrics.error_count,
            "success_rate": self._metrics.get_success_rate(),
            "average_response_time": self._metrics.get_average_response_time(),
            "min_response_time": (
                self._metrics.min_response_time
                if self._metrics.min_response_time != float('inf')
                else 0.0
            ),
            "max_response_time": self._metrics.max_response_time,
            "error_counts_by_type": dict(self._metrics.error_counts_by_type),
            "endpoint_counts": dict(self._metrics.endpoint_counts)
        }

    async def close(self) -> None:
        """Clean up underlying HTTP client resources."""

        async with self._client_lock:
            if self._client is not None:
                await self._client.aclose()
                self._client = None


class _BridgeClientSingleton:
    """Singleton wrapper for BridgeClient."""

    _instance: BridgeClient | None = None

    @classmethod
    def get_instance(cls) -> BridgeClient:
        """Get or create the singleton BridgeClient instance."""
        if cls._instance is None:
            cls._instance = BridgeClient()
        return cls._instance


def get_bridge_client() -> BridgeClient:
    """Return a singleton bridge client instance."""
    return _BridgeClientSingleton.get_instance()


def bridge_enabled() -> bool:
    """Return True if the bridge integration is active."""

    return get_bridge_client().enabled
