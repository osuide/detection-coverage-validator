"""Integration tests for credential endpoint ACL security (CWE-639 fix).

These tests verify that account-level access controls are properly enforced
on credential endpoints, preventing IDOR vulnerabilities where users with
restricted allowed_account_ids could access credentials outside their scope.
"""

import hashlib
import os
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from fastapi_limiter import FastAPILimiter
from httpx import ASGITransport, AsyncClient
from redis import asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.main import app
from app.models.billing import AccountTier, Subscription
from app.models.cloud_account import CloudAccount, CloudProvider
from app.models.cloud_credential import (
    CloudCredential,
    CredentialStatus,
    CredentialType,
)
from app.models.user import (
    MembershipStatus,
    Organization,
    OrganizationMember,
    User,
    UserRole,
)
from app.services.auth_service import AuthService

# Test Redis URL from environment or default
TEST_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def generate_global_account_hash(provider: str, account_id: str) -> str:
    """Generate SHA-256 hash for fraud prevention."""
    return hashlib.sha256(f"{provider}:{account_id}".encode()).hexdigest()


@pytest_asyncio.fixture(scope="function")
async def org_with_accounts(db_session: AsyncSession):
    """Create an organization with multiple cloud accounts."""
    # Create org
    org = Organization(
        id=uuid.uuid4(),
        name="ACL Test Organization",
        slug="acl-test-org",
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(org)
    await db_session.flush()

    # Create subscription
    subscription = Subscription(
        id=uuid.uuid4(),
        organization_id=org.id,
        tier=AccountTier.PRO,  # PRO tier for multiple accounts
        status="active",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(subscription)

    # Create two cloud accounts
    account1 = CloudAccount(
        id=uuid.uuid4(),
        organization_id=org.id,
        name="Production Account",
        provider=CloudProvider.AWS,
        account_id="111111111111",
        global_account_hash=generate_global_account_hash("aws", "111111111111"),
        regions=["us-east-1"],
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    account2 = CloudAccount(
        id=uuid.uuid4(),
        organization_id=org.id,
        name="Development Account",
        provider=CloudProvider.AWS,
        account_id="222222222222",
        global_account_hash=generate_global_account_hash("aws", "222222222222"),
        regions=["us-west-2"],
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(account1)
    db_session.add(account2)
    await db_session.flush()

    # Create credentials for both accounts
    cred1 = CloudCredential(
        id=uuid.uuid4(),
        organization_id=org.id,
        cloud_account_id=account1.id,
        credential_type=CredentialType.AWS_IAM_ROLE,
        status=CredentialStatus.VALID,
        aws_role_arn="arn:aws:iam::111111111111:role/A13EScannerRole",
        aws_external_id=CloudCredential.generate_external_id(),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    cred2 = CloudCredential(
        id=uuid.uuid4(),
        organization_id=org.id,
        cloud_account_id=account2.id,
        credential_type=CredentialType.AWS_IAM_ROLE,
        status=CredentialStatus.VALID,
        aws_role_arn="arn:aws:iam::222222222222:role/A13EScannerRole",
        aws_external_id=CloudCredential.generate_external_id(),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(cred1)
    db_session.add(cred2)
    await db_session.commit()

    return {
        "org": org,
        "account1": account1,
        "account2": account2,
        "cred1": cred1,
        "cred2": cred2,
    }


@pytest_asyncio.fixture(scope="function")
async def restricted_member(db_session: AsyncSession, org_with_accounts: dict):
    """Create a MEMBER user with restricted allowed_account_ids (only account1)."""
    user = User(
        id=uuid.uuid4(),
        email="restricted@example.com",
        full_name="Restricted Member",
        password_hash=AuthService.hash_password("TestPassword123!"),
        email_verified=True,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    await db_session.flush()

    # Create membership with restricted account access
    membership = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=org_with_accounts["org"].id,
        user_id=user.id,
        role=UserRole.MEMBER,
        status=MembershipStatus.ACTIVE,
        # Only allowed to access account1, NOT account2
        allowed_account_ids=[str(org_with_accounts["account1"].id)],
        joined_at=datetime.now(timezone.utc),
    )
    db_session.add(membership)
    await db_session.commit()

    return {"user": user, "membership": membership}


@pytest_asyncio.fixture(scope="function")
async def owner_member(db_session: AsyncSession, org_with_accounts: dict):
    """Create an OWNER user (unrestricted access to all accounts)."""
    user = User(
        id=uuid.uuid4(),
        email="owner@example.com",
        full_name="Organization Owner",
        password_hash=AuthService.hash_password("TestPassword123!"),
        email_verified=True,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    await db_session.flush()

    membership = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=org_with_accounts["org"].id,
        user_id=user.id,
        role=UserRole.OWNER,
        status=MembershipStatus.ACTIVE,
        allowed_account_ids=None,  # None = unrestricted access
        joined_at=datetime.now(timezone.utc),
    )
    db_session.add(membership)
    await db_session.commit()

    return {"user": user, "membership": membership}


@pytest_asyncio.fixture(scope="function")
async def restricted_client(
    db_session: AsyncSession,
    org_with_accounts: dict,
    restricted_member: dict,
) -> AsyncClient:
    """Create a test client authenticated as a restricted member."""
    redis = await aioredis.from_url(
        TEST_REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    await FastAPILimiter.init(redis)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    token = AuthService.generate_access_token(
        user_id=restricted_member["user"].id,
        organization_id=org_with_accounts["org"].id,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
    await FastAPILimiter.close()
    await redis.aclose()


@pytest_asyncio.fixture(scope="function")
async def owner_client(
    db_session: AsyncSession,
    org_with_accounts: dict,
    owner_member: dict,
) -> AsyncClient:
    """Create a test client authenticated as an owner."""
    redis = await aioredis.from_url(
        TEST_REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    await FastAPILimiter.init(redis)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    token = AuthService.generate_access_token(
        user_id=owner_member["user"].id,
        organization_id=org_with_accounts["org"].id,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
    await FastAPILimiter.close()
    await redis.aclose()


class TestCredentialIDORFix:
    """Tests for credential endpoint IDOR vulnerability fix (CWE-639)."""

    @pytest.mark.asyncio
    async def test_restricted_member_can_access_allowed_account_credential(
        self,
        restricted_client: AsyncClient,
        org_with_accounts: dict,
    ):
        """Test that restricted member CAN access credentials for their allowed accounts."""
        # account1 is in allowed_account_ids
        account1_id = org_with_accounts["account1"].id
        response = await restricted_client.get(f"/api/v1/credentials/{account1_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["cloud_account_id"] == str(account1_id)
        assert data["status"] == "valid"

    @pytest.mark.asyncio
    async def test_restricted_member_cannot_access_disallowed_account_credential(
        self,
        restricted_client: AsyncClient,
        org_with_accounts: dict,
    ):
        """Test that restricted member CANNOT access credentials outside allowed_account_ids.

        This is the core IDOR fix test - previously this would return 200 with the credential.
        Now it should return 403 Access Denied.
        """
        # account2 is NOT in allowed_account_ids
        account2_id = org_with_accounts["account2"].id
        response = await restricted_client.get(f"/api/v1/credentials/{account2_id}")

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_owner_can_access_all_account_credentials(
        self,
        owner_client: AsyncClient,
        org_with_accounts: dict,
    ):
        """Test that owner (unrestricted) can access all account credentials."""
        # Test account1
        account1_id = org_with_accounts["account1"].id
        response1 = await owner_client.get(f"/api/v1/credentials/{account1_id}")
        assert response1.status_code == 200

        # Test account2
        account2_id = org_with_accounts["account2"].id
        response2 = await owner_client.get(f"/api/v1/credentials/{account2_id}")
        assert response2.status_code == 200

    @pytest.mark.asyncio
    async def test_restricted_admin_cannot_delete_disallowed_account_credential(
        self,
        db_session: AsyncSession,
        org_with_accounts: dict,
    ):
        """Test that restricted ADMIN CANNOT delete credentials outside allowed_account_ids.

        Even with ADMIN role, the account-level ACL should block deletion.
        """
        # Create an ADMIN user with restricted account access
        user = User(
            id=uuid.uuid4(),
            email="restricted-admin-delete@example.com",
            full_name="Restricted Admin",
            password_hash=AuthService.hash_password("TestPassword123!"),
            email_verified=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        await db_session.flush()

        # Admin role but restricted to account1 only
        membership = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org_with_accounts["org"].id,
            user_id=user.id,
            role=UserRole.ADMIN,  # ADMIN role
            status=MembershipStatus.ACTIVE,
            allowed_account_ids=[
                str(org_with_accounts["account1"].id)
            ],  # Only account1
            joined_at=datetime.now(timezone.utc),
        )
        db_session.add(membership)
        await db_session.commit()

        # Create client for this admin
        redis = await aioredis.from_url(
            TEST_REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        await FastAPILimiter.init(redis)

        async def override_get_db():
            yield db_session

        app.dependency_overrides[get_db] = override_get_db

        token = AuthService.generate_access_token(
            user_id=user.id,
            organization_id=org_with_accounts["org"].id,
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": f"Bearer {token}"},
        ) as ac:
            # account2 is NOT in allowed_account_ids
            account2_id = org_with_accounts["account2"].id
            response = await ac.delete(f"/api/v1/credentials/{account2_id}")

            # Should be 403 Forbidden due to ACL check (not 404 which would leak existence)
            assert response.status_code == 403
            assert "Access denied" in response.json()["detail"]

        app.dependency_overrides.clear()
        await FastAPILimiter.close()
        await redis.aclose()

    @pytest.mark.asyncio
    async def test_credential_not_found_returns_404(
        self,
        owner_client: AsyncClient,
    ):
        """Test that non-existent credential returns 404 (not 403)."""
        fake_account_id = uuid.uuid4()
        response = await owner_client.get(f"/api/v1/credentials/{fake_account_id}")

        # Owner has access to all accounts, so if credential doesn't exist, it's 404
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_acl_check_happens_before_db_query(
        self,
        restricted_client: AsyncClient,
    ):
        """Test that ACL check happens BEFORE database query to prevent info disclosure.

        If ACL check happened after fetching from DB, a user could distinguish between
        'credential exists but I can't access it' vs 'credential doesn't exist' based
        on timing or response differences. By checking ACL first, we return 403 for
        any account the user doesn't have access to, regardless of whether a credential
        exists.
        """
        # Non-existent account that restricted user doesn't have access to
        fake_account_id = uuid.uuid4()
        response = await restricted_client.get(f"/api/v1/credentials/{fake_account_id}")

        # Should return 403 (ACL denied) not 404 (not found)
        # This prevents information disclosure about credential existence
        assert response.status_code == 403


class TestCredentialACLEdgeCases:
    """Edge case tests for credential ACL enforcement."""

    @pytest.mark.asyncio
    async def test_empty_allowed_accounts_list_blocks_all_access(
        self,
        db_session: AsyncSession,
        org_with_accounts: dict,
    ):
        """Test that empty allowed_account_ids list (not None) blocks all account access."""
        # Create user with empty allowed_account_ids (different from None)
        user = User(
            id=uuid.uuid4(),
            email="empty-access@example.com",
            full_name="No Access User",
            password_hash=AuthService.hash_password("TestPassword123!"),
            email_verified=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        await db_session.flush()

        membership = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org_with_accounts["org"].id,
            user_id=user.id,
            role=UserRole.MEMBER,
            status=MembershipStatus.ACTIVE,
            allowed_account_ids=[],  # Empty list = no accounts allowed
            joined_at=datetime.now(timezone.utc),
        )
        db_session.add(membership)
        await db_session.commit()

        # Create client for this user
        redis = await aioredis.from_url(
            TEST_REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        await FastAPILimiter.init(redis)

        async def override_get_db():
            yield db_session

        app.dependency_overrides[get_db] = override_get_db

        token = AuthService.generate_access_token(
            user_id=user.id,
            organization_id=org_with_accounts["org"].id,
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": f"Bearer {token}"},
        ) as ac:
            # Should be blocked from all accounts
            response = await ac.get(
                f"/api/v1/credentials/{org_with_accounts['account1'].id}"
            )
            assert response.status_code == 403

        app.dependency_overrides.clear()
        await FastAPILimiter.close()
        await redis.aclose()

    @pytest.mark.asyncio
    async def test_admin_with_restrictions_still_blocked(
        self,
        db_session: AsyncSession,
        org_with_accounts: dict,
    ):
        """Test that ADMIN role with allowed_account_ids restriction is still blocked.

        The allowed_account_ids restriction should apply regardless of role.
        """
        user = User(
            id=uuid.uuid4(),
            email="restricted-admin@example.com",
            full_name="Restricted Admin",
            password_hash=AuthService.hash_password("TestPassword123!"),
            email_verified=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        await db_session.flush()

        # Admin role but with account restrictions
        membership = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org_with_accounts["org"].id,
            user_id=user.id,
            role=UserRole.ADMIN,  # Admin role
            status=MembershipStatus.ACTIVE,
            allowed_account_ids=[
                str(org_with_accounts["account1"].id)
            ],  # But restricted
            joined_at=datetime.now(timezone.utc),
        )
        db_session.add(membership)
        await db_session.commit()

        redis = await aioredis.from_url(
            TEST_REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        await FastAPILimiter.init(redis)

        async def override_get_db():
            yield db_session

        app.dependency_overrides[get_db] = override_get_db

        token = AuthService.generate_access_token(
            user_id=user.id,
            organization_id=org_with_accounts["org"].id,
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": f"Bearer {token}"},
        ) as ac:
            # Admin can access account1 (allowed)
            response1 = await ac.get(
                f"/api/v1/credentials/{org_with_accounts['account1'].id}"
            )
            assert response1.status_code == 200

            # Admin CANNOT access account2 (not in allowed list)
            response2 = await ac.get(
                f"/api/v1/credentials/{org_with_accounts['account2'].id}"
            )
            assert response2.status_code == 403

        app.dependency_overrides.clear()
        await FastAPILimiter.close()
        await redis.aclose()
