# src/chorus_stage/api/v1/endpoints/auth.py
"""Authentication endpoints for the Chorus API."""

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from jose import jwt
from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.db.session import get_db
from chorus_stage.models import User
from chorus_stage.schemas.user import UserIdentity, UserResponse
from chorus_stage.services.crypto import CryptoService

router = APIRouter(prefix="/auth", tags=["authentication"])
crypto_service = CryptoService()


def create_access_token(data: dict[str, Any]) -> str:
    """Create JWT access token for user authentication.

    Args:
        data: Data to include in the token payload

    Returns:
        JWT token as string
    """
    to_encode = data.copy()
    expire = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt: str = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return encoded_jwt

@router.post(
    "/register",
    summary="Register a new user with Ed25519 key",
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserIdentity,
    db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Register a new user with an Ed25519 public key.

    This endpoint creates a new user account using only an Ed25519 public key
    as identity. No email or personal information is required.
    """
    # Validate public key format
    try:
        pubkey_bytes = crypto_service.validate_and_decode_pubkey(
            user_data.ed25519_pubkey
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    if user_data.pgp_public_key_asc is not None:
        if not user_data.pgp_public_key_asc.strip().startswith("-----BEGIN PGP PUBLIC KEY BLOCK"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PGP public key must be in ASCII armor format",
            )

    # Check if public key already exists
    existing_user = db.query(User).filter(
        User.ed25519_pubkey == pubkey_bytes
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Public key already registered"
        )

    # Create new user
    new_user = User(
        ed25519_pubkey=pubkey_bytes,
        display_name=user_data.display_name,
        preferred_name=user_data.preferred_name,
        pronouns=user_data.pronouns,
        gender_identity=user_data.gender_identity,
        sexual_orientation=user_data.sexual_orientation,
        bio=user_data.bio,
        pgp_public_key_asc=user_data.pgp_public_key_asc
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Create JWT token
    access_token = create_access_token(data={"sub": str(new_user.id)})

    # Return user info with token
    user_response = UserResponse(
        id=new_user.id,
        ed25519_pubkey=new_user.pubkey_hex,
        display_name=new_user.display_name,
        preferred_name=new_user.preferred_name,
        pronouns=new_user.pronouns,
        gender_identity=new_user.gender_identity,
        sexual_orientation=new_user.sexual_orientation,
        bio=new_user.bio,
        pgp_public_key=new_user.pgp_public_key_asc is not None,
        mod_tokens_remaining=new_user.mod_tokens_remaining,
        deleted=new_user.deleted,
    )

    return {
        "user": user_response.model_dump(),
        "access_token": access_token,
        "token_type": "bearer",
    }

@router.post("/login",
          summary="Authenticate with Ed25519 key",
          status_code=status.HTTP_200_OK)
async def login_user(
    ed25519_pubkey: str,
    signature: str = Header(..., description="Ed25519 signature of server challenge"),
    db: Session = Depends(get_db)
) -> dict[str, str]:
    """Authenticate using Ed25519 signature challenge.

    The server returns a nonce, the client signs it with their private key,
    and then sends the signature back. This proves ownership of the private key
    without transmitting it.
    """
    # Generate a nonce for this session
    # Verify the signature against the stored public key
    try:
        pubkey_bytes = crypto_service.validate_and_decode_pubkey(
            ed25519_pubkey
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    # Find user by public key
    user = db.query(User).filter(
        User.ed25519_pubkey == pubkey_bytes
    ).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Decode signature. Libsodium-style signatures may include the original
    # message appended to the 64-byte signature payload, so strip that off if present.
    try:
        raw_signature = bytes.fromhex(signature)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature format"
        )

    challenge_message = settings.login_challenge
    message_bytes = challenge_message.encode()
    SIGNATURE_LEN = 64

    if len(raw_signature) == SIGNATURE_LEN:
        signature_bytes = raw_signature
    elif len(raw_signature) == SIGNATURE_LEN + len(message_bytes):
        appended = raw_signature[SIGNATURE_LEN:]
        if appended != message_bytes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: invalid signature",
            )
        signature_bytes = raw_signature[:SIGNATURE_LEN]
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: invalid signature"
        )

    # Verify signature of static challenge message
    if not crypto_service.verify(pubkey_bytes, challenge_message, signature_bytes):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: invalid signature"
        )

    # Create JWT token
    access_token = create_access_token(data={"sub": str(user.id)})

    session_nonce = crypto_service.generate_nonce()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "session_nonce": session_nonce,
    }
