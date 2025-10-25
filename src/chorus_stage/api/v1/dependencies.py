"""Shared API dependencies for authentication and common functionality."""

import base64
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.db.session import get_db
from chorus_stage.models import User

# HTTP Bearer scheme for JWT authentication
bearer_scheme = HTTPBearer()

# Type alias for database session dependency
SessionDep = Annotated[Session, Depends(get_db)]


def _decode_user_id(subject: str) -> bytes:
    """Decode a base64-encoded user ID.

    Args:
        subject: Base64-encoded user ID string

    Returns:
        Decoded user ID as bytes

    Raises:
        HTTPException: If the subject cannot be decoded
    """
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


# Type alias for current user dependency
CurrentUserDep = Annotated[User, Depends(get_current_user)]
