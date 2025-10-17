# tests/conftest.py
from __future__ import annotations

import hashlib
import os
from collections.abc import Generator, Iterator
from itertools import count
from typing import Any, Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from nacl.signing import SigningKey
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("PYTEST_RUNNING", "true")

from chorus_stage.api.v1.endpoints import messages as messages_endpoints
from chorus_stage.api.v1.endpoints import posts as posts_endpoints
from chorus_stage.api.v1.endpoints import votes as votes_endpoints
from chorus_stage.api.v1.endpoints.auth import create_access_token
from chorus_stage.db.session import Base, get_db as app_get_session
from chorus_stage.core.settings import Settings
from chorus_stage.main import app as fastapi_app
from chorus_stage.models import Community, DirectMessage, Post, SystemClock, User

TEST_DB_URL = "sqlite://"

_POST_ORDER_COUNTER = count(1)
_COMMUNITY_ORDER_COUNTER = count(1)
_MESSAGE_ORDER_COUNTER = count(1)
_TEST_SETTINGS_INSTANCE = Settings()


@pytest.fixture(scope="session")
def engine() -> Generator[Engine, None, None]:
    engine = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def db_session(engine: Engine) -> Iterator[Session]:
    connection = engine.connect()
    transaction = connection.begin()
    SessionLocal = sessionmaker(
        bind=connection,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    session = SessionLocal()
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def restart_savepoint(sess: Session, trans) -> None:  # pragma: no cover - SQLAlchemy internals
        if trans.nested and not getattr(trans._parent, "nested", False):
            session.begin_nested()

    try:
        yield session
    finally:
        event.remove(session, "after_transaction_end", restart_savepoint)
        session.close()

        if transaction.is_active:
            transaction.rollback()
        connection.close()

        # Ensure each test sees a clean database even if commits occurred.
        with engine.begin() as cleanup_conn:
            for table in reversed(Base.metadata.sorted_tables):
                cleanup_conn.execute(table.delete())


@pytest.fixture(scope="session")
def app() -> FastAPI:
    return fastapi_app


@pytest.fixture(autouse=True)
def override_session_dependency(app: FastAPI, db_session: Session) -> Iterator[None]:
    def _get_session_override() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[app_get_session] = _get_session_override
    try:
        yield
    finally:
        app.dependency_overrides.pop(app_get_session, None)


@pytest.fixture()
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, base_url="http://test") as test_client:
        yield test_client


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Provide a Settings instance aligned with runtime configuration."""
    return _TEST_SETTINGS_INSTANCE


# Some legacy tests import the fixture function directly; expose attributes on the
# definition so those imports continue to work without invoking pytest's fixture machinery.
test_settings.secret_key = _TEST_SETTINGS_INSTANCE.secret_key  # type: ignore[attr-defined]
test_settings.login_challenge = _TEST_SETTINGS_INSTANCE.login_challenge  # type: ignore[attr-defined]


def _generate_identity(display_name: str) -> dict[str, Any]:
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    pubkey_hex = verify_key.encode().hex()
    return {
        "private_key": signing_key,
        "pubkey_hex": pubkey_hex,
        "user_identity": {
            "ed25519_pubkey": pubkey_hex,
            "display_name": display_name,
        },
    }


@pytest.fixture()
def test_user_data() -> dict[str, Any]:
    """Return identity data for the primary test user."""
    return _generate_identity("Test User")


@pytest.fixture()
def other_user_data() -> dict[str, Any]:
    """Return identity data for the secondary test user."""
    return _generate_identity("Other User")


@pytest.fixture()
def test_user(db_session: Session, test_user_data: dict[str, Any]) -> Iterator[User]:
    """Create and return a persisted test user."""
    user = User(
        ed25519_pubkey=bytes.fromhex(test_user_data["pubkey_hex"]),
        display_name=test_user_data["user_identity"]["display_name"],
    )
    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)
    yield user


@pytest.fixture()
def other_user(db_session: Session, other_user_data: dict[str, Any]) -> Iterator[User]:
    """Create and return a second persisted user."""
    user = User(
        ed25519_pubkey=bytes.fromhex(other_user_data["pubkey_hex"]),
        display_name=other_user_data["user_identity"]["display_name"],
    )
    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)
    yield user


@pytest.fixture()
def auth_token(test_user: User) -> dict[str, str]:
    """Return authorization headers for the primary test user."""
    token = create_access_token({"sub": str(test_user.id)})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def other_auth_token(other_user: User) -> dict[str, str]:
    """Return authorization headers for the secondary test user."""
    token = create_access_token({"sub": str(other_user.id)})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def community(db_session: Session) -> Iterator[Community]:
    """Create a default test community."""
    community = Community(
        internal_slug="test",
        display_name="Test Community",
        description_md="Test community description",
        is_profile_like=False,
        order_index=next(_COMMUNITY_ORDER_COUNTER),
    )
    db_session.add(community)
    db_session.flush()
    db_session.refresh(community)
    yield community


@pytest.fixture()
def setup_system_clock(db_session: Session) -> Iterator[SystemClock]:
    """Ensure a system clock row exists for tests that rely on it."""
    clock = db_session.query(SystemClock).first()
    if clock is None:
        clock = SystemClock(id=1, day_seq=0, hour_seq=0)
        db_session.add(clock)
        db_session.flush()
        db_session.refresh(clock)
    yield clock


@pytest.fixture()
def test_post(db_session: Session, test_user: User) -> Iterator[Post]:
    """Create a baseline post for tests."""
    content = "Test post content"
    post = Post(
        order_index=next(_POST_ORDER_COUNTER),
        author_user_id=test_user.id,
        author_pubkey=test_user.ed25519_pubkey,
        body_md=content,
        content_hash=hashlib.sha256(content.encode()).digest(),
        moderation_state=0,
        harmful_vote_count=0,
    )
    db_session.add(post)
    db_session.flush()
    db_session.refresh(post)
    yield post


@pytest.fixture()
def direct_message(
    db_session: Session,
    test_user: User,
    other_user: User,
) -> Iterator[DirectMessage]:
    """Create a sample direct message."""
    message = DirectMessage(
        order_index=next(_MESSAGE_ORDER_COUNTER),
        sender_user_id=other_user.id,
        recipient_user_id=test_user.id,
        ciphertext=b"encrypted",
        header_blob=None,
        delivered=False,
    )
    db_session.add(message)
    db_session.flush()
    db_session.refresh(message)
    yield message


@pytest.fixture()
def mock_pow_service(app: FastAPI) -> Iterator[Any]:
    """Override proof-of-work dependencies with a permissive stub."""

    class _PowStub:
        def verify_pow(self, action: str, pubkey_hex: str, nonce: str) -> bool:
            return True

        def is_pow_replay(self, action: str, pubkey_hex: str, nonce: str) -> bool:
            return False

        def register_pow(self, action: str, pubkey_hex: str, nonce: str) -> None:
            return None

        def get_challenge(self, action: str, pubkey_hex: str) -> str:
            return "challenge"

    stub = _PowStub()

    overrides: dict[Callable[..., Any], Callable[[], Any]] = {
        posts_endpoints.get_pow_service_dep: lambda: stub,
        votes_endpoints.get_pow_service_dep: lambda: stub,
        messages_endpoints.get_pow_service_dep: lambda: stub,
    }

    for dependency, override in overrides.items():
        app.dependency_overrides[dependency] = override

    try:
        yield stub
    finally:
        for dependency in list(overrides):
            app.dependency_overrides.pop(dependency, None)


@pytest.fixture()
def mock_replay_service(app: FastAPI) -> Iterator[Any]:
    """Override replay protection dependency with a no-op stub."""

    class _ReplayStub:
        def is_replay(self, pubkey_hex: str, client_nonce: str) -> bool:
            return False

        def register_replay(self, pubkey_hex: str, client_nonce: str) -> None:
            return None

    stub = _ReplayStub()
    dependency = votes_endpoints.get_replay_service_dep
    app.dependency_overrides[dependency] = lambda: stub

    try:
        yield stub
    finally:
        app.dependency_overrides.pop(dependency, None)
