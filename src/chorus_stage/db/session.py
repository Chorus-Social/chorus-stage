"""Database session configuration."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from chorus_stage.core.settings import settings


class Base(DeclarativeBase):
    """Declarative base shared by all ORM models."""


# Ensure model modules are imported so that metadata is populated when create_all runs.
import chorus_stage.models  # noqa: E402,F401

engine = create_engine(
    settings.effective_database_url,
    pool_pre_ping=True,
    echo=settings.sql_debug,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Yield a database session for dependency injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables() -> None:
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)


def drop_tables() -> None:
    """Drop all database tables."""
    Base.metadata.drop_all(bind=engine)
