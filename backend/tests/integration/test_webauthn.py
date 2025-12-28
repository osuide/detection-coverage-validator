"""Integration tests for WebAuthn/FIDO2 (Passkeys and Security Keys).

Tests cover:
1. WebAuthn service credential storage and retrieval
2. Registration options generation
3. Credential listing and deletion for users and admins
4. Integration with MFA status

Note: Actual WebAuthn ceremony verification requires browser interaction,
so we test the option generation and credential management flows.
"""

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.admin import AdminUser, AdminRole, AdminIPAllowlist
from app.models.user import (
    User,
    Organization,
    OrganizationMember,
    UserRole,
    MembershipStatus,
)
from app.models.billing import Subscription, AccountTier, SubscriptionStatus
from app.services.auth_service import AuthService
from app.services.webauthn_service import WebAuthnService, WebAuthnCredential


# =============================================================================
# Fixtures
# =============================================================================


@pytest_asyncio.fixture(scope="function")
async def test_user_with_org(db_session: AsyncSession) -> tuple[User, Organization]:
    """Create a test user with organisation for WebAuthn tests."""
    org = Organization(
        id=uuid.uuid4(),
        name="WebAuthn Test Org",
        slug="webauthn-test-org",
        is_active=True,
        require_mfa=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(org)
    await db_session.flush()

    user = User(
        id=uuid.uuid4(),
        email="webauthn_test_user@example.com",
        full_name="WebAuthn Test User",
        password_hash=AuthService.hash_password("TestPassword123!"),
        email_verified=True,
        is_active=True,
        mfa_enabled=False,
        webauthn_credentials=[],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    await db_session.flush()

    # Add subscription for feature access
    subscription = Subscription(
        id=uuid.uuid4(),
        organization_id=org.id,
        tier=AccountTier.FREE,
        status=SubscriptionStatus.ACTIVE,
        current_period_start=datetime.now(timezone.utc),
        current_period_end=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(subscription)

    membership = OrganizationMember(
        id=uuid.uuid4(),
        user_id=user.id,
        organization_id=org.id,
        role=UserRole.OWNER,
        status=MembershipStatus.ACTIVE,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(membership)
    await db_session.flush()

    return user, org


@pytest_asyncio.fixture(scope="function")
async def test_user_with_webauthn(
    db_session: AsyncSession,
) -> tuple[User, Organization]:
    """Create a test user with an existing WebAuthn credential."""
    org = Organization(
        id=uuid.uuid4(),
        name="WebAuthn Existing Org",
        slug="webauthn-existing-org",
        is_active=True,
        require_mfa=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(org)
    await db_session.flush()

    # Create a mock credential
    mock_credential = WebAuthnCredential(
        credential_id=b"test-credential-id-12345",
        public_key=b"test-public-key-data",
        sign_count=0,
        device_name="Test YubiKey",
        transports=["usb"],
    )

    user = User(
        id=uuid.uuid4(),
        email="webauthn_existing_user@example.com",
        full_name="WebAuthn Existing User",
        password_hash=AuthService.hash_password("TestPassword123!"),
        email_verified=True,
        is_active=True,
        mfa_enabled=True,  # Has WebAuthn so MFA is enabled
        webauthn_credentials=[mock_credential.to_dict()],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    await db_session.flush()

    # Add subscription for feature access
    subscription = Subscription(
        id=uuid.uuid4(),
        organization_id=org.id,
        tier=AccountTier.FREE,
        status=SubscriptionStatus.ACTIVE,
        current_period_start=datetime.now(timezone.utc),
        current_period_end=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(subscription)

    membership = OrganizationMember(
        id=uuid.uuid4(),
        user_id=user.id,
        organization_id=org.id,
        role=UserRole.OWNER,
        status=MembershipStatus.ACTIVE,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(membership)
    await db_session.flush()

    return user, org


@pytest_asyncio.fixture(scope="function")
async def test_admin_no_webauthn(db_session: AsyncSession) -> AdminUser:
    """Create a test admin without WebAuthn credentials."""
    # Add IP allowlist for admin
    allowlist = AdminIPAllowlist(
        id=uuid.uuid4(),
        ip_address="0.0.0.0/0",
        description="Test - Allow all",
        is_active=True,
        created_by=None,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(allowlist)
    await db_session.flush()

    admin = AdminUser(
        id=uuid.uuid4(),
        email="webauthn_admin@example.com",
        password_hash=AuthService.hash_password("AdminPassword123!"),
        full_name="WebAuthn Test Admin",
        role=AdminRole.SUPER_ADMIN,
        is_active=True,
        mfa_enabled=False,
        webauthn_credentials=[],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(admin)
    await db_session.flush()
    return admin


@pytest_asyncio.fixture(scope="function")
async def test_admin_with_webauthn(db_session: AsyncSession) -> AdminUser:
    """Create a test admin with an existing WebAuthn credential."""
    # Add IP allowlist for admin
    allowlist = AdminIPAllowlist(
        id=uuid.uuid4(),
        ip_address="0.0.0.0/0",
        description="Test - Allow all",
        is_active=True,
        created_by=None,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(allowlist)
    await db_session.flush()

    # Create a mock credential
    mock_credential = WebAuthnCredential(
        credential_id=b"admin-credential-id-12345",
        public_key=b"admin-public-key-data",
        sign_count=5,
        device_name="Admin YubiKey",
        transports=["usb", "nfc"],
    )

    admin = AdminUser(
        id=uuid.uuid4(),
        email="webauthn_admin_existing@example.com",
        password_hash=AuthService.hash_password("AdminPassword123!"),
        full_name="WebAuthn Existing Admin",
        role=AdminRole.SUPER_ADMIN,
        is_active=True,
        mfa_enabled=True,  # Has WebAuthn so MFA is enabled
        webauthn_credentials=[mock_credential.to_dict()],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(admin)
    await db_session.flush()
    return admin


async def get_user_token(client: AsyncClient, user: User) -> str:
    """Login and get an access token for a user."""
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "TestPassword123!"},
    )
    assert response.status_code == 200, f"Login failed: {response.text}"
    return response.json()["access_token"]


async def get_admin_token(client: AsyncClient, admin: AdminUser) -> str:
    """Login and get an access token for an admin."""
    response = await client.post(
        "/api/v1/admin/auth/login",
        json={"email": admin.email, "password": "AdminPassword123!"},
        headers={"X-Forwarded-For": "127.0.0.1"},
    )
    assert response.status_code == 200, f"Admin login failed: {response.text}"
    return response.json()["access_token"]


# =============================================================================
# WebAuthn Service Unit Tests
# =============================================================================


class TestWebAuthnService:
    """Unit tests for the WebAuthn service layer."""

    def test_credential_serialisation(self):
        """Test WebAuthnCredential can be serialised and deserialised."""
        original = WebAuthnCredential(
            credential_id=b"test-cred-id",
            public_key=b"test-pub-key",
            sign_count=42,
            device_name="My YubiKey 5",
            transports=["usb", "nfc"],
        )

        # Serialise
        data = original.to_dict()
        assert isinstance(data, dict)
        assert "credential_id" in data
        assert "public_key" in data
        assert data["device_name"] == "My YubiKey 5"
        assert data["sign_count"] == 42
        assert data["transports"] == ["usb", "nfc"]

        # Deserialise
        restored = WebAuthnCredential.from_dict(data)
        assert restored.credential_id == original.credential_id
        assert restored.public_key == original.public_key
        assert restored.sign_count == original.sign_count
        assert restored.device_name == original.device_name
        assert restored.transports == original.transports

    def test_registration_options_generation(self):
        """Test registration options are generated with correct structure."""
        service = WebAuthnService(rp_id="localhost", rp_name="Test RP")

        options, challenge = service.generate_registration_options_for_user(
            user_id=uuid.uuid4(),
            user_email="test@example.com",
            user_name="Test User",
            existing_credentials=[],
            authenticator_type=None,
        )

        # Check options structure
        assert isinstance(options, dict)
        assert "challenge" in options
        assert "rp" in options
        assert options["rp"]["id"] == "localhost"
        assert options["rp"]["name"] == "Test RP"
        assert "user" in options
        assert options["user"]["name"] == "test@example.com"
        assert options["user"]["displayName"] == "Test User"

        # Challenge should be bytes
        assert isinstance(challenge, bytes)
        assert len(challenge) > 0

    def test_registration_options_with_platform_authenticator(self):
        """Test options for platform authenticator (Touch ID/Windows Hello)."""
        service = WebAuthnService(rp_id="localhost", rp_name="Test RP")

        options, _ = service.generate_registration_options_for_user(
            user_id=uuid.uuid4(),
            user_email="test@example.com",
            user_name="Test User",
            existing_credentials=[],
            authenticator_type="platform",
        )

        # Check authenticator selection criteria
        assert "authenticatorSelection" in options
        assert (
            options["authenticatorSelection"]["authenticatorAttachment"] == "platform"
        )

    def test_registration_options_with_cross_platform_authenticator(self):
        """Test options for cross-platform authenticator (YubiKey)."""
        service = WebAuthnService(rp_id="localhost", rp_name="Test RP")

        options, _ = service.generate_registration_options_for_user(
            user_id=uuid.uuid4(),
            user_email="test@example.com",
            user_name="Test User",
            existing_credentials=[],
            authenticator_type="cross-platform",
        )

        # Check authenticator selection criteria
        assert "authenticatorSelection" in options
        assert (
            options["authenticatorSelection"]["authenticatorAttachment"]
            == "cross-platform"
        )

    def test_registration_options_excludes_existing_credentials(self):
        """Test that existing credentials are excluded from registration."""
        service = WebAuthnService(rp_id="localhost", rp_name="Test RP")

        existing = WebAuthnCredential(
            credential_id=b"existing-cred",
            public_key=b"existing-key",
            sign_count=0,
            device_name="Existing Key",
        )

        options, _ = service.generate_registration_options_for_user(
            user_id=uuid.uuid4(),
            user_email="test@example.com",
            user_name="Test User",
            existing_credentials=[existing.to_dict()],
            authenticator_type=None,
        )

        # Check exclude credentials is populated
        assert "excludeCredentials" in options
        assert len(options["excludeCredentials"]) == 1

    def test_authentication_options_generation(self):
        """Test authentication options are generated with correct structure."""
        service = WebAuthnService(rp_id="localhost", rp_name="Test RP")

        existing = WebAuthnCredential(
            credential_id=b"test-cred-id",
            public_key=b"test-key",
            sign_count=0,
            device_name="Test Key",
            transports=["usb"],
        )

        options, challenge = service.generate_authentication_options_for_user(
            credentials=[existing.to_dict()],
        )

        # Check options structure
        assert isinstance(options, dict)
        assert "challenge" in options
        assert "rpId" in options
        assert options["rpId"] == "localhost"
        assert "allowCredentials" in options
        assert len(options["allowCredentials"]) == 1

        # Challenge should be bytes
        assert isinstance(challenge, bytes)
        assert len(challenge) > 0


# =============================================================================
# User WebAuthn API Tests
# =============================================================================


@pytest.mark.asyncio
class TestUserWebAuthnAPI:
    """Integration tests for user WebAuthn API endpoints."""

    async def test_get_credentials_empty(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user_with_org: tuple[User, Organization],
    ):
        """Test getting credentials when user has none."""
        user, _ = test_user_with_org
        await db_session.commit()

        token = await get_user_token(client, user)

        response = await client.get(
            "/api/v1/auth/me/webauthn/credentials",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "credentials" in data
        assert isinstance(data["credentials"], list)
        assert len(data["credentials"]) == 0

    async def test_get_credentials_with_existing(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user_with_webauthn: tuple[User, Organization],
    ):
        """Test getting credentials when user has existing ones."""
        user, _ = test_user_with_webauthn
        await db_session.commit()

        token = await get_user_token(client, user)

        response = await client.get(
            "/api/v1/auth/me/webauthn/credentials",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "credentials" in data
        credentials = data["credentials"]
        assert isinstance(credentials, list)
        assert len(credentials) == 1
        assert credentials[0]["device_name"] == "Test YubiKey"
        assert "credential_id" in credentials[0]
        assert "created_at" in credentials[0]

    async def test_get_registration_options(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user_with_org: tuple[User, Organization],
    ):
        """Test getting registration options for a new credential."""
        user, _ = test_user_with_org
        await db_session.commit()

        token = await get_user_token(client, user)

        response = await client.post(
            "/api/v1/auth/me/webauthn/register/options",
            headers={"Authorization": f"Bearer {token}"},
            json={"device_name": "My New YubiKey"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "options" in data
        options = data["options"]
        assert "challenge" in options
        assert "rp" in options
        assert "user" in options

    async def test_get_registration_options_platform_authenticator(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user_with_org: tuple[User, Organization],
    ):
        """Test getting registration options for platform authenticator."""
        user, _ = test_user_with_org
        await db_session.commit()

        token = await get_user_token(client, user)

        response = await client.post(
            "/api/v1/auth/me/webauthn/register/options",
            headers={"Authorization": f"Bearer {token}"},
            json={"device_name": "This Device", "authenticator_type": "platform"},
        )

        assert response.status_code == 200
        data = response.json()
        options = data["options"]
        assert "authenticatorSelection" in options
        assert (
            options["authenticatorSelection"]["authenticatorAttachment"] == "platform"
        )

    async def test_delete_credential_success(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user_with_webauthn: tuple[User, Organization],
    ):
        """Test deleting a credential when user has TOTP as backup."""
        user, _ = test_user_with_webauthn
        # Add TOTP so MFA remains enabled after WebAuthn deletion
        user.mfa_secret = "TESTSECRET123456"
        await db_session.commit()

        token = await get_user_token(client, user)

        # Get the credential ID
        creds_response = await client.get(
            "/api/v1/auth/me/webauthn/credentials",
            headers={"Authorization": f"Bearer {token}"},
        )
        cred_id = creds_response.json()["credentials"][0]["credential_id"]

        # Delete the credential
        response = await client.post(
            "/api/v1/auth/me/webauthn/credentials/delete",
            headers={"Authorization": f"Bearer {token}"},
            json={"credential_id": cred_id},
        )

        assert response.status_code == 200

        # Verify credential was deleted
        creds_response = await client.get(
            "/api/v1/auth/me/webauthn/credentials",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert len(creds_response.json()["credentials"]) == 0

    async def test_delete_credential_not_found(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_user_with_org: tuple[User, Organization],
    ):
        """Test deleting a non-existent credential."""
        user, _ = test_user_with_org
        await db_session.commit()

        token = await get_user_token(client, user)

        response = await client.post(
            "/api/v1/auth/me/webauthn/credentials/delete",
            headers={"Authorization": f"Bearer {token}"},
            json={"credential_id": "nonexistent-credential-id"},
        )

        assert response.status_code == 404


# =============================================================================
# Admin WebAuthn API Tests
# =============================================================================


@pytest.mark.asyncio
class TestAdminWebAuthnAPI:
    """Integration tests for admin WebAuthn API endpoints."""

    async def test_get_credentials_empty(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_admin_no_webauthn: AdminUser,
    ):
        """Test getting credentials when admin has none."""
        await db_session.commit()

        token = await get_admin_token(client, test_admin_no_webauthn)

        response = await client.get(
            "/api/v1/admin/auth/webauthn/credentials",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Forwarded-For": "127.0.0.1",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "credentials" in data
        assert isinstance(data["credentials"], list)
        assert len(data["credentials"]) == 0

    async def test_get_credentials_with_existing(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_admin_with_webauthn: AdminUser,
    ):
        """Test getting credentials when admin has existing ones."""
        await db_session.commit()

        token = await get_admin_token(client, test_admin_with_webauthn)

        response = await client.get(
            "/api/v1/admin/auth/webauthn/credentials",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Forwarded-For": "127.0.0.1",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "credentials" in data
        credentials = data["credentials"]
        assert isinstance(credentials, list)
        assert len(credentials) == 1
        assert credentials[0]["device_name"] == "Admin YubiKey"

    async def test_get_registration_options(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_admin_no_webauthn: AdminUser,
    ):
        """Test getting registration options for a new admin credential."""
        await db_session.commit()

        token = await get_admin_token(client, test_admin_no_webauthn)

        response = await client.post(
            "/api/v1/admin/auth/webauthn/register/options",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Forwarded-For": "127.0.0.1",
            },
            json={"device_name": "Admin YubiKey 5"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "options" in data
        options = data["options"]
        assert "challenge" in options
        assert "rp" in options
        assert "user" in options

    async def test_webauthn_login_options_with_credential(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_admin_with_webauthn: AdminUser,
    ):
        """Test getting WebAuthn login options for admin with credentials."""
        await db_session.commit()

        response = await client.post(
            "/api/v1/admin/auth/webauthn/auth/options",
            headers={"X-Forwarded-For": "127.0.0.1"},
            json={"email": test_admin_with_webauthn.email},
        )

        assert response.status_code == 200
        data = response.json()
        assert "options" in data
        assert "auth_token" in data
        assert "allowCredentials" in data["options"]
        assert len(data["options"]["allowCredentials"]) == 1

    async def test_webauthn_login_options_no_credentials(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_admin_no_webauthn: AdminUser,
    ):
        """Test getting WebAuthn login options for admin without credentials."""
        await db_session.commit()

        response = await client.post(
            "/api/v1/admin/auth/webauthn/auth/options",
            headers={"X-Forwarded-For": "127.0.0.1"},
            json={"email": test_admin_no_webauthn.email},
        )

        # Should fail because admin has no WebAuthn credentials
        assert response.status_code == 400
        assert "No security keys" in response.json()["detail"]

    async def test_webauthn_login_options_invalid_email(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        test_admin_no_webauthn: AdminUser,
    ):
        """Test getting WebAuthn login options for non-existent admin."""
        await db_session.commit()

        response = await client.post(
            "/api/v1/admin/auth/webauthn/auth/options",
            headers={"X-Forwarded-For": "127.0.0.1"},
            json={"email": "nonexistent@example.com"},
        )

        # Should fail with generic error (don't reveal if email exists)
        assert response.status_code == 400
