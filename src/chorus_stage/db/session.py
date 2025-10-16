"""Database session and engine factory for SQLAlchemy (async)."""
from __future__ import annotations

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from chorus_stage.core.settings import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass

# Import models after Base so they can subclass it without circular imports.
# These imports register tables on Base.metadata via class declaration side-effects.
from chorus_stage.models import (  # noqa: E402,F401
    community,
    message,
    moderation,
    post,
    rate,
    user,
    vote,
)

engine = create_async_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an AsyncSession."""
    async with SessionLocal() as session:
        yield session

__all__ = ["Base", "engine", "SessionLocal", "get_session"]
