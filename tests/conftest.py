import os
import pytest_asyncio
from typing import AsyncGenerator
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from chorus_stage.db.session import Base, get_session
from chorus_stage.main import app as fastapi_app


@pytest_asyncio.fixture(scope="session")
async def engine() -> AsyncGenerator[AsyncEngine, None]:
    """Create a shared in-memory SQLite engine for all tests."""
    url: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    engine = create_async_engine(url, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture()
async def db(engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Provide an async database session bound to the shared engine."""
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture(scope="session")
def app() -> FastAPI:
    """Return the FastAPI application instance for tests."""
    return fastapi_app


@pytest_asyncio.fixture(autouse=True)
async def override_session_dependency(app: FastAPI, db: AsyncSession) -> AsyncGenerator[None, None]:
    """Override the default get_session dependency to use the test DB."""

    async def _get_session_override() -> AsyncGenerator[AsyncSession, None]:
        yield db

    app.dependency_overrides[get_session] = _get_session_override
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_session, None)


@pytest_asyncio.fixture()
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Create an AsyncClient that uses ASGITransport for in-process HTTP tests."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
