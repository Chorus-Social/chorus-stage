# src/chorus_stage/api/v1/endpoints/auth.py
"""Authentication endpoints for the Chorus API."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from jose import jwt
from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.db.session import get_db
from chorus_stage.models import User, UserState
from chorus_stage.schemas.user import (
    ChallengeRequest,
    ChallengeResponse,
    LoginRequest,
    LoginResponse,
    PowEnvelope,
    RegisterRequest,
    RegisterResponse,
)
from chorus_stage.services.bridge import BridgeDisabledError, get_bridge_client
from chorus_stage.services.crypto import CryptoService
from chorus_stage.services.pow import PowService, get_pow_service
from chorus_stage.services.replay import ReplayProtectionService, get_replay_service
from chorus_stage.utils.hash import blake3_digest


@dataclass(frozen=True)
class HandshakeArtifacts:
    """Artifacts required to validate a proof-of-work handshake."""

    pow_target: str
    challenge_b64: str
    replay_key: str

router = APIRouter(prefix="/auth", tags=["authentication"])
crypto_service = CryptoService()

SessionDep = Annotated[Session, Depends(get_db)]


def get_pow_service_dep() -> PowService:
    return get_pow_service()


def get_replay_service_dep() -> ReplayProtectionService:
    return get_replay_service()


PowServiceDep = Annotated[PowService, Depends(get_pow_service_dep)]
ReplayServiceDep = Annotated[ReplayProtectionService, Depends(get_replay_service_dep)]


def _encode_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _decode_b64(field: str, data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + padding)
    except Exception as err:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid base64 encoding for {field}",
        ) from err


def _ensure_pow_requirements(
    intent: str,
    pow_envelope: PowEnvelope,
    *,
    pubkey_hex: str,
    pow_service: PowService,
) -> None:
    """Validate difficulty and replay constraints for a submitted PoW envelope."""
    expected_difficulty = pow_service.difficulties.get(
        intent,
        settings.pow_difficulty_post,
    )
    if pow_envelope.difficulty < expected_difficulty:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Insufficient proof-of-work difficulty (expected ≥ {expected_difficulty})",
        )

    if pow_service.is_pow_replay(intent, pubkey_hex, pow_envelope.nonce):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Proof of work nonce has already been used",
        )

    if not pow_service.verify_pow(
        intent, pubkey_hex, pow_envelope.nonce, pow_envelope.target, pow_envelope.hash_algorithm
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid proof of work",
        )


def _validate_handshake_challenge(
    intent: str,
    *,
    pubkey_bytes: bytes,
    artifacts: HandshakeArtifacts,
    replay_service: ReplayProtectionService,
) -> str:
    """Validate signed handshake material and enforce replay protection."""
    try:
        nonce_hex = crypto_service.validate_auth_challenge(
            intent,
            pubkey_bytes,
            artifacts.pow_target,
            artifacts.challenge_b64,
        )
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    if replay_service.is_replay(artifacts.replay_key, nonce_hex):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Challenge has already been used",
        )
    return nonce_hex


async def _get_creation_day_from_bridge() -> int:
    """Get creation day from bridge if enabled, otherwise return 0."""
    creation_day = 0
    if settings.bridge_enabled:
        try:
            bridge_client = get_bridge_client()
            day_proof = await bridge_client.fetch_day_proof(day=0)  # Placeholder for current day
            if day_proof:
                creation_day = day_proof.day_number
        except BridgeDisabledError:
            # Bridge is disabled, use default creation_day
            pass
        except Exception as e:
            # Log the error and proceed with default creation_day
            print(f"Error fetching day proof from bridge: {e}")
            pass
    return creation_day


def _create_or_update_user(
    db: Session, pubkey_bytes: bytes, user_hash: bytes, payload: RegisterRequest, creation_day: int
) -> tuple[User, bool]:
    """Create or update user in database. Returns (user, created)."""
    user = db.query(User).filter(User.pubkey == pubkey_bytes).first()
    created = False
    if user is None:
        user = User(
            user_id=user_hash,
            pubkey=pubkey_bytes,
            display_name=payload.display_name,
            accent_color=payload.accent_color,
            creation_day=creation_day,
        )
        user.state = UserState(user_id=user_hash)
        db.add(user)
        created = True
    else:
        # Update optional persona fields without revealing linkage.
        # NOTE: Profile updates via this endpoint are deprecated.
        # Use PATCH /users/me/profile instead for better performance and UX.
        user.display_name = payload.display_name
        user.accent_color = payload.accent_color
        if user.state is None:
            user.state = UserState(user_id=user.user_id)
    return user, created


async def _federate_user_registration(
    user_hash: bytes, pubkey_bytes: bytes, creation_day: int, db: Session
) -> None:
    """Federate user registration if bridge is enabled."""
    if settings.bridge_enabled:
        try:
            bridge_client = get_bridge_client()
            idempotency_key = f"user-registration-{user_hash.hex()}"
            user_registration_envelope = await bridge_client.create_user_registration_envelope(
                user_pubkey_bytes=pubkey_bytes,
                creation_day=creation_day,
                idempotency_key=idempotency_key,
            )
            await bridge_client.send_federation_envelope(
                db, user_registration_envelope, idempotency_key
            )
        except BridgeDisabledError:
            print("Bridge is disabled, user registration not federated.")
        except Exception as e:
            print(f"Error federating user registration: {e}")


def create_access_token(subject: bytes | str, extra_claims: dict[str, str] | None = None) -> str:
    """Create JWT access token for user authentication."""
    sub = subject if isinstance(subject, str) else _encode_b64(subject)
    to_encode: dict[str, object] = {"sub": sub}
    if extra_claims:
        to_encode.update(extra_claims)
    expire = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode["exp"] = expire
    encoded_jwt: str = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return encoded_jwt


@router.post(
    "/challenge",
    summary="Issue a proof-of-work and signature challenge",
    response_model=ChallengeResponse,
)
async def issue_challenge(
    payload: ChallengeRequest,
    pow_service: PowServiceDep,
) -> ChallengeResponse:
    """Provide clients with challenge material for register/login flows."""
    try:
        pubkey_bytes = crypto_service.validate_and_decode_pubkey(payload.pubkey)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    try:
        pow_target, challenge_b64 = crypto_service.issue_auth_challenge(
            payload.intent,
            pubkey_bytes,
        )
    except ValueError as err:  # pragma: no cover - defensive path
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    difficulty_map = {
        "register": pow_service.difficulties.get("register", settings.pow_difficulty_register),
        "login": pow_service.difficulties.get("login", settings.pow_difficulty_login),
    }

    return ChallengeResponse(
        pow_target=pow_target,
        pow_difficulty=difficulty_map[payload.intent],
        signature_challenge=challenge_b64,
    )


@router.post(
    "/register",
    summary="Register a new anonymous key",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterResponse,
)
async def register_user(
    payload: RegisterRequest,
    db: SessionDep,
    pow_service: PowServiceDep,
    replay_service: ReplayServiceDep,
) -> RegisterResponse:
    """Register or upsert an anonymous Ed25519 identity."""
    try:
        pubkey_bytes = crypto_service.validate_and_decode_pubkey(payload.pubkey)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    pubkey_hex = pubkey_bytes.hex()
    artifacts = HandshakeArtifacts(
        pow_target=payload.pow.target,
        challenge_b64=payload.proof.challenge,
        replay_key=pubkey_hex,
    )
    challenge_nonce_hex = _validate_handshake_challenge(
        "register",
        pubkey_bytes=pubkey_bytes,
        artifacts=artifacts,
        replay_service=replay_service,
    )

    _ensure_pow_requirements(
        "register",
        payload.pow,
        pubkey_hex=pubkey_hex,
        pow_service=pow_service,
    )

    challenge_bytes = _decode_b64("proof.challenge", payload.proof.challenge)
    signature_bytes = _decode_b64("proof.signature", payload.proof.signature)

    if not crypto_service.verify_signature_bytes(pubkey_bytes, challenge_bytes, signature_bytes):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid signature for provided challenge",
        )

    user_hash = blake3_digest(pubkey_bytes)
    creation_day = await _get_creation_day_from_bridge()

    user, created = _create_or_update_user(db, pubkey_bytes, user_hash, payload, creation_day)
    db.commit()

    # Register replay artifacts after the transaction succeeds.
    pow_service.register_pow("register", pubkey_hex, payload.pow.nonce)
    replay_service.register_replay(pubkey_hex, challenge_nonce_hex)

    # Federate user registration if bridge is enabled
    await _federate_user_registration(user_hash, pubkey_bytes, creation_day, db)

    user_id_b64 = _encode_b64(user.user_id)
    return RegisterResponse(user_id=user_id_b64, created=created)


@router.post(
    "/login",
    summary="Authenticate with Ed25519 key",
    status_code=status.HTTP_200_OK,
    response_model=LoginResponse,
)
async def login_user(
    payload: LoginRequest,
    db: SessionDep,
    pow_service: PowServiceDep,
    replay_service: ReplayServiceDep,
) -> LoginResponse:
    """Authenticate by providing a signed challenge response."""
    try:
        pubkey_bytes = crypto_service.validate_and_decode_pubkey(payload.pubkey)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    user = db.query(User).filter(User.pubkey == pubkey_bytes).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    pubkey_hex = pubkey_bytes.hex()

    artifacts = HandshakeArtifacts(
        pow_target=payload.pow.target,
        challenge_b64=payload.proof.challenge,
        replay_key=pubkey_hex,
    )
    challenge_nonce_hex = _validate_handshake_challenge(
        "login",
        pubkey_bytes=pubkey_bytes,
        artifacts=artifacts,
        replay_service=replay_service,
    )

    _ensure_pow_requirements(
        "login",
        payload.pow,
        pubkey_hex=pubkey_hex,
        pow_service=pow_service,
    )

    signature_bytes = _decode_b64("proof.signature", payload.proof.signature)
    challenge_bytes = _decode_b64("proof.challenge", payload.proof.challenge)

    if not crypto_service.verify_signature_bytes(pubkey_bytes, challenge_bytes, signature_bytes):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: invalid signature",
        )

    pow_service.register_pow("login", pubkey_hex, payload.pow.nonce)
    replay_service.register_replay(pubkey_hex, challenge_nonce_hex)

    access_token = create_access_token(user.user_id)
    session_nonce = crypto_service.generate_nonce()

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        session_nonce=session_nonce,
    )
