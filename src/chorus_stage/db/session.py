"""Database session and engine factory for SQLAlchemy (async)."""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from chorus.core.settings import settings

Base = declarative_base()

engine = create_async_engine(settings.database_url, future=True, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_session() -> AsyncSession:
    """FastAPI dependency that yields an AsyncSession."""
    async with SessionLocal() as session:
        yield session
