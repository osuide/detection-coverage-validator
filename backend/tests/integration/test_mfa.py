"""Integration tests for MFA (Multi-Factor Authentication) flows.

Tests cover:
1. User MFA setup, verification, and disable flows
2. Admin MFA setup and enable flows
3. MFA login flows for both users and admins
4. Error cases and edge conditions

Uses pyotp to generate valid TOTP codes for testing.
"""

import uuid
from datetime import datetime, timezone

import bcrypt
import pyotp
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.admin import AdminUser, AdminRole, AdminIPAllowlist, AdminSession
from app.models.user import (
    User,
    Organization,
    OrganizationMember,
    UserRole,
    MembershipStatus,
)
from app.models.billing import Subscription, AccountTier
from app.services.auth_service import AuthService


# =============================================================================
# Fixtures
# =============================================================================


@pytest_asyncio.fixture(scope="function")
async def test_user_no_mfa(db_session: AsyncSession) -> User:
    """Create a test user without MFA enabled."""
    user = User(
        id=uuid.uuid4(),
        email="mfa_test_user@example.com",
        full_name="MFA Test User",
        password_hash=AuthService.hash_password("TestPassword123!"),
        email_verified=True,
        is_active=True,
        mfa_enabled=False,
        mfa_secret=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture(scope="function")
async def test_user_with_mfa(db_session: AsyncSession) -> User:
    """Create a test user with MFA already enabled."""
    # Generate a valid MFA secret
    mfa_secret = pyotp.random_base32()
    # Generate backup codes (hashed)
    display_codes, hashed_codes = AuthService.generate_backup_codes(count=5)

    user = User(
        id=uuid.uuid4(),
        email="mfa_enabled_user@example.com",
        full_name="MFA Enabled User",
        password_hash=AuthService.hash_password("TestPassword123!"),
        email_verified=True,
        is_active=True,
        mfa_enabled=True,
        mfa_secret=mfa_secret,
        mfa_backup_codes=hashed_codes,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    await db_session.flush()

    # Store the display codes for tests to use
    user._test_backup_codes = display_codes
    return user


@pytest_asyncio.fixture(scope="function")
async def test_org_no_mfa_req(db_session: AsyncSession) -> Organization:
    """Create a test organisation that does not require MFA."""
    org = Organization(
        id=uuid.uuid4(),
        name="Test Org No MFA",
        slug="test-org-no-mfa",
        is_active=True,
        require_mfa=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture(scope="function")
async def test_org_mfa_required(db_session: AsyncSession) -> Organization:
    """Create a test organisation that requires MFA."""
    org = Organization(
        id=uuid.uuid4(),
        name="Test Org MFA Required",
        slug="test-org-mfa-required",
        is_active=True,
        require_mfa=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture(scope="function")
async def test_subscription_for_user(
    db_session: AsyncSession,
    test_org_no_mfa_req: Organization,
) -> Subscription:
    """Create a test subscription for the organisation."""
    subscription = Subscription(
        id=uuid.uuid4(),
        organization_id=test_org_no_mfa_req.id,
        tier=AccountTier.FREE,
        status="active",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(subscription)
    await db_session.flush()
    return subscription


@pytest_asyncio.fixture(scope="function")
async def test_membership_no_mfa(
    db_session: AsyncSession,
    test_user_no_mfa: User,
    test_org_no_mfa_req: Organization,
    test_subscription_for_user: Subscription,
) -> OrganizationMember:
    """Create membership for user without MFA in org that doesn't require MFA."""
    membership = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=test_org_no_mfa_req.id,
        user_id=test_user_no_mfa.id,
        role=UserRole.OWNER,
        status=MembershipStatus.ACTIVE,
        joined_at=datetime.now(timezone.utc),
    )
    db_session.add(membership)
    await db_session.commit()
    return membership


@pytest_asyncio.fixture(scope="function")
async def test_membership_with_mfa(
    db_session: AsyncSession,
    test_user_with_mfa: User,
    test_org_no_mfa_req: Organization,
    test_subscription_for_user: Subscription,
) -> OrganizationMember:
    """Create membership for user with MFA."""
    membership = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=test_org_no_mfa_req.id,
        user_id=test_user_with_mfa.id,
        role=UserRole.OWNER,
        status=MembershipStatus.ACTIVE,
        joined_at=datetime.now(timezone.utc),
    )
    db_session.add(membership)
    await db_session.commit()
    return membership


@pytest_asyncio.fixture(scope="function")
async def auth_headers_no_mfa(
    test_user_no_mfa: User,
    test_org_no_mfa_req: Organization,
    test_membership_no_mfa: OrganizationMember,
) -> dict[str, str]:
    """Generate auth headers for user without MFA."""
    token = AuthService.generate_access_token(
        user_id=test_user_no_mfa.id,
        organization_id=test_org_no_mfa_req.id,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture(scope="function")
async def auth_headers_with_mfa(
    test_user_with_mfa: User,
    test_org_no_mfa_req: Organization,
    test_membership_with_mfa: OrganizationMember,
) -> dict[str, str]:
    """Generate auth headers for user with MFA enabled."""
    token = AuthService.generate_access_token(
        user_id=test_user_with_mfa.id,
        organization_id=test_org_no_mfa_req.id,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture(scope="function")
async def mfa_authenticated_client(
    db_session: AsyncSession,
    auth_headers_no_mfa: dict[str, str],
) -> AsyncClient:
    """Create a test HTTP client authenticated with a user who has no MFA."""
    from redis import asyncio as aioredis
    from fastapi_limiter import FastAPILimiter
    from httpx import ASGITransport
    from app.main import app
    from app.core.database import get_db
    from tests.conftest import TEST_REDIS_URL

    # Initialise rate limiter
    redis = await aioredis.from_url(
        TEST_REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    await FastAPILimiter.init(redis)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers=auth_headers_no_mfa,
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
    await FastAPILimiter.close()
    await redis.aclose()


@pytest_asyncio.fixture(scope="function")
async def mfa_enabled_authenticated_client(
    db_session: AsyncSession,
    auth_headers_with_mfa: dict[str, str],
) -> AsyncClient:
    """Create a test HTTP client authenticated with a user who has MFA enabled."""
    from redis import asyncio as aioredis
    from fastapi_limiter import FastAPILimiter
    from httpx import ASGITransport
    from app.main import app
    from app.core.database import get_db
    from tests.conftest import TEST_REDIS_URL

    # Initialise rate limiter
    redis = await aioredis.from_url(
        TEST_REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    await FastAPILimiter.init(redis)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers=auth_headers_with_mfa,
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
    await FastAPILimiter.close()
    await redis.aclose()


# =============================================================================
# Admin Fixtures
# =============================================================================


@pytest_asyncio.fixture(scope="function")
async def test_admin_no_mfa(db_session: AsyncSession) -> AdminUser:
    """Create a test admin user without MFA enabled."""
    password_hash = bcrypt.hashpw(
        "AdminPassword123!@#".encode(), bcrypt.gensalt(rounds=12)
    ).decode()

    admin = AdminUser(
        id=uuid.uuid4(),
        email="admin_no_mfa@example.com",
        password_hash=password_hash,
        full_name="Admin No MFA",
        role=AdminRole.PLATFORM_ADMIN,
        mfa_enabled=False,
        mfa_secret_encrypted=None,
        is_active=True,
        requires_password_change=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(admin)
    await db_session.flush()
    return admin


@pytest_asyncio.fixture(scope="function")
async def test_admin_with_mfa(db_session: AsyncSession) -> AdminUser:
    """Create a test admin user with MFA enabled."""
    password_hash = bcrypt.hashpw(
        "AdminPassword123!@#".encode(), bcrypt.gensalt(rounds=12)
    ).decode()

    # Generate a valid MFA secret (store unencrypted for testing)
    mfa_secret = pyotp.random_base32()

    admin = AdminUser(
        id=uuid.uuid4(),
        email="admin_with_mfa@example.com",
        password_hash=password_hash,
        full_name="Admin With MFA",
        role=AdminRole.PLATFORM_ADMIN,
        mfa_enabled=True,
        mfa_secret_encrypted=mfa_secret.encode(),  # Unencrypted for dev mode
        is_active=True,
        requires_password_change=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(admin)
    await db_session.flush()

    # Store the secret for tests
    admin._test_mfa_secret = mfa_secret
    return admin


@pytest_asyncio.fixture(scope="function")
async def admin_ip_allowlist(db_session: AsyncSession) -> AdminIPAllowlist:
    """Create an IP allowlist entry for admin access."""
    allowlist = AdminIPAllowlist(
        id=uuid.uuid4(),
        ip_address="0.0.0.0/0",  # Allow all IPs for testing
        description="Test allowlist - all IPs",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(allowlist)
    await db_session.flush()
    return allowlist


@pytest_asyncio.fixture(scope="function")
async def admin_session_no_mfa(
    db_session: AsyncSession,
    test_admin_no_mfa: AdminUser,
    admin_ip_allowlist: AdminIPAllowlist,
) -> AdminSession:
    """Create an AdminSession record for the test admin without MFA.

    The session IP is set to match what the test client reports.
    ASGITransport reports request.client.host as 127.0.0.1, and since
    this isn't in trusted proxies, X-Forwarded-For is ignored by
    get_client_ip in app/core/security.py.
    """
    import hashlib
    import secrets
    from datetime import timedelta

    from app.models.admin import AdminSession

    # Use 127.0.0.1 - this is what ASGITransport reports as request.client.host
    # and since it's not in trusted proxies, X-Forwarded-For is ignored
    test_ip = "127.0.0.1"

    refresh_token = secrets.token_urlsafe(32)
    refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

    session = AdminSession(
        id=uuid.uuid4(),
        admin_id=test_admin_no_mfa.id,
        ip_address=test_ip,
        user_agent="pytest-integration-tests",
        refresh_token_hash=refresh_token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
        last_auth_at=datetime.now(timezone.utc),
        is_active=True,
    )
    db_session.add(session)
    await db_session.commit()

    session._test_ip = test_ip
    return session


@pytest_asyncio.fixture(scope="function")
async def admin_session_with_mfa(
    db_session: AsyncSession,
    test_admin_with_mfa: AdminUser,
    admin_ip_allowlist: AdminIPAllowlist,
) -> AdminSession:
    """Create an AdminSession record for the test admin with MFA.

    The session IP matches what the test client reports (127.0.0.1).
    """
    import hashlib
    import secrets
    from datetime import timedelta

    from app.models.admin import AdminSession

    # Use 127.0.0.1 - same as admin_session_no_mfa
    test_ip = "127.0.0.1"

    refresh_token = secrets.token_urlsafe(32)
    refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

    session = AdminSession(
        id=uuid.uuid4(),
        admin_id=test_admin_with_mfa.id,
        ip_address=test_ip,
        user_agent="pytest-integration-tests",
        refresh_token_hash=refresh_token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
        last_auth_at=datetime.now(timezone.utc),
        is_active=True,
    )
    db_session.add(session)
    await db_session.commit()

    session._test_ip = test_ip
    return session


@pytest_asyncio.fixture(scope="function")
async def admin_auth_headers_no_mfa(
    test_admin_no_mfa: AdminUser,
    admin_session_no_mfa: AdminSession,
) -> dict[str, str]:
    """Generate auth headers for admin without MFA.

    Includes both the Bearer token and X-Forwarded-For header
    to match the session IP.
    """
    from datetime import timedelta

    from app.core.security import create_access_token

    access_token = create_access_token(
        data={
            "sub": str(test_admin_no_mfa.id),
            "type": "admin",
            "role": test_admin_no_mfa.role.value,
            "session_id": str(admin_session_no_mfa.id),
        },
        expires_delta=timedelta(minutes=15),
    )

    return {
        "Authorization": f"Bearer {access_token}",
        "X-Forwarded-For": admin_session_no_mfa._test_ip,
    }


@pytest_asyncio.fixture(scope="function")
async def admin_auth_headers_with_mfa(
    test_admin_with_mfa: AdminUser,
    admin_session_with_mfa: AdminSession,
) -> dict[str, str]:
    """Generate auth headers for admin with MFA.

    Includes both the Bearer token and X-Forwarded-For header.
    """
    from datetime import timedelta

    from app.core.security import create_access_token

    access_token = create_access_token(
        data={
            "sub": str(test_admin_with_mfa.id),
            "type": "admin",
            "role": test_admin_with_mfa.role.value,
            "session_id": str(admin_session_with_mfa.id),
        },
        expires_delta=timedelta(minutes=15),
    )

    return {
        "Authorization": f"Bearer {access_token}",
        "X-Forwarded-For": admin_session_with_mfa._test_ip,
    }


@pytest_asyncio.fixture(scope="function")
async def admin_authenticated_client_no_mfa(
    db_session: AsyncSession,
    admin_auth_headers_no_mfa: dict[str, str],
) -> AsyncClient:
    """Create HTTP client authenticated as admin without MFA."""
    from redis import asyncio as aioredis
    from fastapi_limiter import FastAPILimiter
    from httpx import ASGITransport
    from app.main import app
    from app.core.database import get_db
    from tests.conftest import TEST_REDIS_URL

    redis = await aioredis.from_url(
        TEST_REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    await FastAPILimiter.init(redis)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers=admin_auth_headers_no_mfa,
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
    await FastAPILimiter.close()
    await redis.aclose()


@pytest_asyncio.fixture(scope="function")
async def admin_authenticated_client_with_mfa(
    db_session: AsyncSession,
    admin_auth_headers_with_mfa: dict[str, str],
) -> AsyncClient:
    """Create HTTP client authenticated as admin with MFA."""
    from redis import asyncio as aioredis
    from fastapi_limiter import FastAPILimiter
    from httpx import ASGITransport
    from app.main import app
    from app.core.database import get_db
    from tests.conftest import TEST_REDIS_URL

    redis = await aioredis.from_url(
        TEST_REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    await FastAPILimiter.init(redis)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers=admin_auth_headers_with_mfa,
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
    await FastAPILimiter.close()
    await redis.aclose()


# =============================================================================
# User MFA Tests - Setup Flow
# =============================================================================


class TestUserMFASetup:
    """Tests for user MFA setup flow."""

    @pytest.mark.asyncio
    async def test_setup_mfa_returns_secret_and_uri(
        self,
        mfa_authenticated_client: AsyncClient,
    ):
        """Test that MFA setup returns provisioning URI and secret."""
        response = await mfa_authenticated_client.post("/api/v1/auth/me/mfa/setup")

        assert response.status_code == 200
        data = response.json()

        # Verify response structure
        assert "secret" in data
        assert "provisioning_uri" in data

        # Verify secret is a valid base32 string
        secret = data["secret"]
        assert len(secret) >= 16

        # Verify provisioning URI format
        uri = data["provisioning_uri"]
        assert uri.startswith("otpauth://totp/")
        assert "secret=" in uri
        assert "Detection%20Coverage%20Validator" in uri or "Detection" in uri

    @pytest.mark.asyncio
    async def test_setup_mfa_fails_if_already_enabled(
        self,
        mfa_enabled_authenticated_client: AsyncClient,
    ):
        """Test that MFA setup fails if MFA is already enabled."""
        response = await mfa_enabled_authenticated_client.post(
            "/api/v1/auth/me/mfa/setup"
        )

        assert response.status_code == 400
        data = response.json()
        assert "already enabled" in data["detail"].lower()


class TestUserMFAVerify:
    """Tests for user MFA verification (completing setup)."""

    @pytest.mark.asyncio
    async def test_verify_mfa_with_valid_code_succeeds(
        self,
        mfa_authenticated_client: AsyncClient,
    ):
        """Test that verifying with a valid TOTP code succeeds and returns backup codes."""
        # First, set up MFA to get the secret
        setup_response = await mfa_authenticated_client.post(
            "/api/v1/auth/me/mfa/setup"
        )
        assert setup_response.status_code == 200
        secret = setup_response.json()["secret"]

        # Generate a valid TOTP code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Verify with the valid code
        verify_response = await mfa_authenticated_client.post(
            "/api/v1/auth/me/mfa/verify",
            json={"code": valid_code},
        )

        assert verify_response.status_code == 200
        data = verify_response.json()

        # Should return backup codes
        assert "backup_codes" in data
        assert isinstance(data["backup_codes"], list)
        assert len(data["backup_codes"]) == 10  # Default count

        # Verify backup code format (xxxx-xxxx)
        for code in data["backup_codes"]:
            assert "-" in code
            assert len(code) == 9  # 4-4 with hyphen

    @pytest.mark.asyncio
    async def test_verify_mfa_with_invalid_code_fails(
        self,
        mfa_authenticated_client: AsyncClient,
    ):
        """Test that verifying with an invalid TOTP code fails."""
        # First, set up MFA
        setup_response = await mfa_authenticated_client.post(
            "/api/v1/auth/me/mfa/setup"
        )
        assert setup_response.status_code == 200

        # Try to verify with an invalid code
        verify_response = await mfa_authenticated_client.post(
            "/api/v1/auth/me/mfa/verify",
            json={"code": "000000"},  # Invalid code
        )

        assert verify_response.status_code == 400
        data = verify_response.json()
        assert "invalid" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_verify_mfa_without_setup_fails(
        self,
        mfa_authenticated_client: AsyncClient,
        test_user_no_mfa: User,
        db_session: AsyncSession,
    ):
        """Test that verifying MFA without calling setup first fails."""
        # Ensure user has no mfa_secret set
        test_user_no_mfa.mfa_secret = None
        await db_session.commit()

        verify_response = await mfa_authenticated_client.post(
            "/api/v1/auth/me/mfa/verify",
            json={"code": "123456"},
        )

        assert verify_response.status_code == 400
        data = verify_response.json()
        assert "setup" in data["detail"].lower() or "start" in data["detail"].lower()


class TestUserMFADisable:
    """Tests for user MFA disable flow."""

    @pytest.mark.asyncio
    async def test_disable_mfa_succeeds(
        self,
        mfa_enabled_authenticated_client: AsyncClient,
    ):
        """Test that a user with MFA enabled can disable it."""
        response = await mfa_enabled_authenticated_client.delete("/api/v1/auth/me/mfa")

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_disable_mfa_fails_if_not_enabled(
        self,
        mfa_authenticated_client: AsyncClient,
    ):
        """Test that disabling MFA fails if it's not enabled."""
        response = await mfa_authenticated_client.delete("/api/v1/auth/me/mfa")

        assert response.status_code == 400
        data = response.json()
        assert "not enabled" in data["detail"].lower()


# =============================================================================
# User MFA Login Tests
# =============================================================================


class TestUserMFALogin:
    """Tests for user login with MFA."""

    @pytest.mark.asyncio
    async def test_login_with_mfa_returns_mfa_required(
        self,
        client: AsyncClient,
        test_user_with_mfa: User,
        test_membership_with_mfa: OrganizationMember,
    ):
        """Test that login for MFA-enabled user returns requires_mfa=True."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "mfa_enabled_user@example.com",
                "password": "TestPassword123!",
            },
        )

        assert response.status_code == 200
        data = response.json()

        assert data["requires_mfa"] is True
        assert data["mfa_token"] is not None
        assert data["access_token"] == ""  # No access token until MFA verified
        assert data["user"] is None  # User info not revealed until MFA verified

    @pytest.mark.asyncio
    async def test_mfa_verify_login_with_valid_code_succeeds(
        self,
        client: AsyncClient,
        test_user_with_mfa: User,
        test_membership_with_mfa: OrganizationMember,
    ):
        """Test that MFA verification with valid code completes login."""
        # First, login to get the MFA token
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "mfa_enabled_user@example.com",
                "password": "TestPassword123!",
            },
        )
        assert login_response.status_code == 200
        mfa_token = login_response.json()["mfa_token"]

        # Generate valid TOTP code
        totp = pyotp.TOTP(test_user_with_mfa.mfa_secret)
        valid_code = totp.now()

        # Verify MFA
        verify_response = await client.post(
            "/api/v1/auth/login/mfa",
            json={
                "mfa_token": mfa_token,
                "code": valid_code,
            },
        )

        assert verify_response.status_code == 200
        data = verify_response.json()

        assert data["requires_mfa"] is False
        assert data["access_token"] != ""
        assert data["refresh_token"] != ""
        assert data["user"] is not None
        assert data["user"]["email"] == "mfa_enabled_user@example.com"

    @pytest.mark.asyncio
    async def test_mfa_verify_login_with_invalid_code_fails(
        self,
        client: AsyncClient,
        test_user_with_mfa: User,
        test_membership_with_mfa: OrganizationMember,
    ):
        """Test that MFA verification with invalid code fails."""
        # First, login to get the MFA token
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "mfa_enabled_user@example.com",
                "password": "TestPassword123!",
            },
        )
        assert login_response.status_code == 200
        mfa_token = login_response.json()["mfa_token"]

        # Try with invalid code
        verify_response = await client.post(
            "/api/v1/auth/login/mfa",
            json={
                "mfa_token": mfa_token,
                "code": "000000",  # Invalid
            },
        )

        assert verify_response.status_code == 401
        data = verify_response.json()
        assert "invalid" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_mfa_verify_login_with_invalid_token_fails(
        self,
        client: AsyncClient,
        test_user_with_mfa: User,
        test_membership_with_mfa: OrganizationMember,
    ):
        """Test that MFA verification with invalid/expired token fails."""
        # Generate valid TOTP code (but token is invalid)
        totp = pyotp.TOTP(test_user_with_mfa.mfa_secret)
        valid_code = totp.now()

        # Try with invalid token
        verify_response = await client.post(
            "/api/v1/auth/login/mfa",
            json={
                "mfa_token": "invalid_token_here",
                "code": valid_code,
            },
        )

        assert verify_response.status_code == 401

    @pytest.mark.asyncio
    async def test_mfa_verify_login_with_backup_code_succeeds(
        self,
        client: AsyncClient,
        test_user_with_mfa: User,
        test_membership_with_mfa: OrganizationMember,
    ):
        """Test that MFA verification with a valid backup code succeeds."""
        # First, login to get the MFA token
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "mfa_enabled_user@example.com",
                "password": "TestPassword123!",
            },
        )
        assert login_response.status_code == 200
        mfa_token = login_response.json()["mfa_token"]

        # Use a backup code (stored in fixture)
        backup_code = test_user_with_mfa._test_backup_codes[0]

        # Verify with backup code
        verify_response = await client.post(
            "/api/v1/auth/login/mfa",
            json={
                "mfa_token": mfa_token,
                "code": backup_code,
            },
        )

        assert verify_response.status_code == 200
        data = verify_response.json()
        assert data["access_token"] != ""

    @pytest.mark.asyncio
    async def test_login_without_mfa_succeeds_directly(
        self,
        client: AsyncClient,
        test_user_no_mfa: User,
        test_membership_no_mfa: OrganizationMember,
    ):
        """Test that login for user without MFA returns tokens directly."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "mfa_test_user@example.com",
                "password": "TestPassword123!",
            },
        )

        assert response.status_code == 200
        data = response.json()

        assert data["requires_mfa"] is False
        assert data["access_token"] != ""
        assert data["refresh_token"] != ""
        assert data["user"]["email"] == "mfa_test_user@example.com"


# =============================================================================
# Admin MFA Tests
# =============================================================================


class TestAdminMFASetup:
    """Tests for admin MFA setup flow."""

    @pytest.mark.asyncio
    async def test_admin_setup_mfa_returns_secret_and_uri(
        self,
        admin_authenticated_client_no_mfa: AsyncClient,
    ):
        """Test that admin MFA setup returns provisioning URI and secret."""
        response = await admin_authenticated_client_no_mfa.post(
            "/api/v1/admin/auth/mfa/setup"
        )

        assert response.status_code == 200
        data = response.json()

        assert "provisioning_uri" in data
        assert "secret" in data
        assert data["provisioning_uri"].startswith("otpauth://totp/")
        assert (
            "A13E%20Admin" in data["provisioning_uri"]
            or "A13E" in data["provisioning_uri"]
        )

    @pytest.mark.asyncio
    async def test_admin_setup_mfa_fails_if_already_enabled(
        self,
        admin_authenticated_client_with_mfa: AsyncClient,
    ):
        """Test that admin MFA setup fails if MFA is already enabled."""
        response = await admin_authenticated_client_with_mfa.post(
            "/api/v1/admin/auth/mfa/setup"
        )

        assert response.status_code == 400
        data = response.json()
        assert "already enabled" in data["detail"].lower()


class TestAdminMFAEnable:
    """Tests for admin MFA enable flow."""

    @pytest.mark.asyncio
    async def test_admin_enable_mfa_with_valid_code_succeeds(
        self,
        admin_authenticated_client_no_mfa: AsyncClient,
    ):
        """Test that admin can enable MFA with a valid TOTP code after setup."""
        # First, setup MFA to get the secret
        setup_response = await admin_authenticated_client_no_mfa.post(
            "/api/v1/admin/auth/mfa/setup"
        )
        assert setup_response.status_code == 200
        secret = setup_response.json()["secret"]

        # Generate a valid TOTP code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Enable MFA with the valid code
        enable_response = await admin_authenticated_client_no_mfa.post(
            "/api/v1/admin/auth/mfa/enable",
            json={"totp_code": valid_code},
        )

        assert enable_response.status_code == 200
        data = enable_response.json()
        assert "enabled" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_admin_enable_mfa_with_invalid_code_fails(
        self,
        admin_authenticated_client_no_mfa: AsyncClient,
    ):
        """Test that admin cannot enable MFA with an invalid TOTP code."""
        # First, setup MFA
        setup_response = await admin_authenticated_client_no_mfa.post(
            "/api/v1/admin/auth/mfa/setup"
        )
        assert setup_response.status_code == 200

        # Try to enable with invalid code
        enable_response = await admin_authenticated_client_no_mfa.post(
            "/api/v1/admin/auth/mfa/enable",
            json={"totp_code": "000000"},  # Invalid
        )

        assert enable_response.status_code == 400
        data = enable_response.json()
        assert "invalid" in data["detail"].lower()


class TestAdminMFALogin:
    """Tests for admin login with MFA."""

    @pytest.mark.asyncio
    async def test_admin_login_with_mfa_requires_verification(
        self,
        client: AsyncClient,
        test_admin_with_mfa: AdminUser,
        admin_ip_allowlist: AdminIPAllowlist,
    ):
        """Test that admin login with MFA returns requires_mfa=True."""
        response = await client.post(
            "/api/v1/admin/auth/login",
            json={
                "email": "admin_with_mfa@example.com",
                "password": "AdminPassword123!@#",
            },
        )

        assert response.status_code == 200
        data = response.json()

        assert data["requires_mfa"] is True
        assert data["mfa_token"] is not None
        assert data.get("access_token") is None

    @pytest.mark.asyncio
    async def test_admin_mfa_verify_with_valid_code_succeeds(
        self,
        client: AsyncClient,
        test_admin_with_mfa: AdminUser,
        admin_ip_allowlist: AdminIPAllowlist,
    ):
        """Test that admin MFA verification with valid code completes login."""
        # First, login to get the MFA token
        login_response = await client.post(
            "/api/v1/admin/auth/login",
            json={
                "email": "admin_with_mfa@example.com",
                "password": "AdminPassword123!@#",
            },
        )
        assert login_response.status_code == 200
        mfa_token = login_response.json()["mfa_token"]

        # Generate valid TOTP code using the stored secret
        totp = pyotp.TOTP(test_admin_with_mfa._test_mfa_secret)
        valid_code = totp.now()

        # Verify MFA
        verify_response = await client.post(
            "/api/v1/admin/auth/mfa/verify",
            json={
                "mfa_token": mfa_token,
                "totp_code": valid_code,
            },
        )

        assert verify_response.status_code == 200
        data = verify_response.json()

        assert data["access_token"] is not None
        # refresh_token is now in httpOnly cookie, not in response body (security fix)
        assert "dcv_admin_refresh_token" in verify_response.cookies
        assert data["admin"]["email"] == "admin_with_mfa@example.com"

    @pytest.mark.asyncio
    async def test_admin_mfa_verify_with_invalid_code_fails(
        self,
        client: AsyncClient,
        test_admin_with_mfa: AdminUser,
        admin_ip_allowlist: AdminIPAllowlist,
    ):
        """Test that admin MFA verification with invalid code fails."""
        # First, login to get the MFA token
        login_response = await client.post(
            "/api/v1/admin/auth/login",
            json={
                "email": "admin_with_mfa@example.com",
                "password": "AdminPassword123!@#",
            },
        )
        assert login_response.status_code == 200
        mfa_token = login_response.json()["mfa_token"]

        # Try with invalid code
        verify_response = await client.post(
            "/api/v1/admin/auth/mfa/verify",
            json={
                "mfa_token": mfa_token,
                "totp_code": "000000",  # Invalid
            },
        )

        assert verify_response.status_code == 401


# =============================================================================
# Edge Cases and Security Tests
# =============================================================================


class TestMFASecurityEdgeCases:
    """Tests for MFA security edge cases."""

    @pytest.mark.asyncio
    async def test_mfa_pending_token_cannot_be_used_as_access_token(
        self,
        client: AsyncClient,
        test_user_with_mfa: User,
        test_membership_with_mfa: OrganizationMember,
    ):
        """Test that MFA pending token cannot bypass MFA by using it as access token."""
        # Login to get MFA pending token
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "mfa_enabled_user@example.com",
                "password": "TestPassword123!",
            },
        )
        assert login_response.status_code == 200
        mfa_token = login_response.json()["mfa_token"]

        # Try to use MFA pending token as access token to access protected endpoint
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {mfa_token}"},
        )

        # Should be rejected - MFA pending tokens have type='mfa_pending'
        # which is not 'access' and should be rejected by auth middleware
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_expired_backup_code_removed_after_use(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user_with_mfa: User,
        test_membership_with_mfa: OrganizationMember,
    ):
        """Test that backup code is removed after use."""
        initial_backup_codes_count = len(test_user_with_mfa.mfa_backup_codes)

        # Login to get MFA token
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "mfa_enabled_user@example.com",
                "password": "TestPassword123!",
            },
        )
        assert login_response.status_code == 200
        mfa_token = login_response.json()["mfa_token"]

        # Use a backup code
        backup_code = test_user_with_mfa._test_backup_codes[0]

        verify_response = await client.post(
            "/api/v1/auth/login/mfa",
            json={
                "mfa_token": mfa_token,
                "code": backup_code,
            },
        )
        assert verify_response.status_code == 200

        # Refresh user from database
        await db_session.refresh(test_user_with_mfa)

        # Should have one less backup code
        assert (
            len(test_user_with_mfa.mfa_backup_codes) == initial_backup_codes_count - 1
        )

    @pytest.mark.asyncio
    async def test_reused_backup_code_fails(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user_with_mfa: User,
        test_membership_with_mfa: OrganizationMember,
    ):
        """Test that a backup code cannot be reused after it's been used."""
        import random

        # Use a unique IP to avoid rate limiting from other tests
        # This isolates this test from rate limit counters shared with other tests
        unique_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        rate_limit_headers = {"X-Forwarded-For": unique_ip}

        backup_code = test_user_with_mfa._test_backup_codes[0]

        # First use of backup code
        login_response1 = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "mfa_enabled_user@example.com",
                "password": "TestPassword123!",
            },
            headers=rate_limit_headers,
        )
        mfa_token1 = login_response1.json()["mfa_token"]

        verify_response1 = await client.post(
            "/api/v1/auth/login/mfa",
            json={"mfa_token": mfa_token1, "code": backup_code},
            headers=rate_limit_headers,
        )
        assert verify_response1.status_code == 200

        # Second attempt to use the same backup code
        login_response2 = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "mfa_enabled_user@example.com",
                "password": "TestPassword123!",
            },
            headers=rate_limit_headers,
        )
        mfa_token2 = login_response2.json()["mfa_token"]

        verify_response2 = await client.post(
            "/api/v1/auth/login/mfa",
            json={"mfa_token": mfa_token2, "code": backup_code},
            headers=rate_limit_headers,
        )

        # Should fail - code already used
        assert verify_response2.status_code == 401
