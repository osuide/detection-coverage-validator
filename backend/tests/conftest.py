"""Pytest configuration and fixtures."""

import asyncio
import os
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.main import app
from app.core.database import Base, get_db
from app.models.user import (
    User,
    Organization,
    OrganizationMember,
    UserRole,
    MembershipStatus,
)
from app.services.auth_service import AuthService


# Test settings - use DATABASE_URL from environment (set by CI), fallback to Docker hostname
TEST_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@postgres:5432/dcv_test",
    ),
)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """Create a test database engine."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async_session = async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def test_user(db_session: AsyncSession) -> User:
    """Create a test user."""
    user = User(
        id=uuid.uuid4(),
        email="test@example.com",
        full_name="Test User",
        password_hash=AuthService.hash_password("TestPassword123!"),
        email_verified=True,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture(scope="function")
async def test_org(db_session: AsyncSession) -> Organization:
    """Create a test organization."""
    org = Organization(
        id=uuid.uuid4(),
        name="Test Organization",
        slug="test-org",
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture(scope="function")
async def test_membership(
    db_session: AsyncSession,
    test_user: User,
    test_org: Organization,
) -> OrganizationMember:
    """Create a test membership (user as org owner)."""
    membership = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=test_org.id,
        user_id=test_user.id,
        role=UserRole.OWNER,
        status=MembershipStatus.ACTIVE,
        joined_at=datetime.now(timezone.utc),
    )
    db_session.add(membership)
    await db_session.commit()
    return membership


@pytest_asyncio.fixture(scope="function")
async def auth_headers(
    test_user: User,
    test_org: Organization,
    test_membership: OrganizationMember,
) -> dict[str, str]:
    """Generate auth headers with a valid JWT token."""
    token = AuthService.generate_access_token(
        user_id=test_user.id,
        organization_id=test_org.id,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create a test HTTP client (unauthenticated)."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def authenticated_client(
    db_session: AsyncSession,
    auth_headers: dict[str, str],
) -> AsyncGenerator[AsyncClient, None]:
    """Create a test HTTP client with authentication."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        app=app,
        base_url="http://test",
        headers=auth_headers,
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
