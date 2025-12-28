"""Integration tests for security authorization fixes.

These tests verify that authorization controls are properly enforced.
"""

import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import (
    User,
    Organization,
    OrganizationMember,
    UserRole,
    MembershipStatus,
    APIKey,
)
from app.models.cloud_account import CloudAccount
from app.models.gap import CoverageGap, GapStatus, GapPriority
from app.models.billing import AccountTier, Subscription
from app.models.schedule import ScanSchedule, ScheduleFrequency
from app.models.scan import Scan, ScanStatus
from app.services.auth_service import AuthService


# ============================================================================
# FINDING 1: Cross-tenant IDOR Tests
# ============================================================================


class TestCrossTenantIDOR:
    """Tests for cross-tenant IDOR vulnerability fix in gaps endpoints."""

    @pytest_asyncio.fixture
    async def two_orgs_setup(self, db_session: AsyncSession):
        """Create two organisations with cloud accounts and gaps."""
        # Org A
        org_a = Organization(
            id=uuid.uuid4(),
            name="Org A",
            slug="org-a-idor-test",
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        user_a = User(
            id=uuid.uuid4(),
            email="user_a_idor@example.com",
            full_name="User A",
            password_hash=AuthService.hash_password("Password123!"),
            email_verified=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(org_a)
        db_session.add(user_a)
        await db_session.flush()

        account_a = CloudAccount(
            id=uuid.uuid4(),
            organization_id=org_a.id,
            name="Account A",
            provider="aws",
            account_id="111111111111",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(account_a)
        await db_session.flush()

        gap_a = CoverageGap(
            id=uuid.uuid4(),
            cloud_account_id=account_a.id,
            organization_id=org_a.id,
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic_id="TA0001",
            tactic_name="Initial Access",
            status=GapStatus.OPEN,
            priority=GapPriority.HIGH,
        )
        db_session.add(gap_a)

        # Org B
        org_b = Organization(
            id=uuid.uuid4(),
            name="Org B",
            slug="org-b-idor-test",
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        user_b = User(
            id=uuid.uuid4(),
            email="user_b_idor@example.com",
            full_name="User B",
            password_hash=AuthService.hash_password("Password123!"),
            email_verified=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(org_b)
        db_session.add(user_b)
        await db_session.flush()

        account_b = CloudAccount(
            id=uuid.uuid4(),
            organization_id=org_b.id,
            name="Account B",
            provider="aws",
            account_id="222222222222",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(account_b)

        # Add memberships
        member_a = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org_a.id,
            user_id=user_a.id,
            role=UserRole.OWNER,
            status=MembershipStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
        )
        member_b = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org_b.id,
            user_id=user_b.id,
            role=UserRole.OWNER,
            status=MembershipStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(member_a)
        db_session.add(member_b)

        # Add subscriptions
        sub_a = Subscription(
            id=uuid.uuid4(),
            organization_id=org_a.id,
            tier=AccountTier.FREE,
            status="active",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        sub_b = Subscription(
            id=uuid.uuid4(),
            organization_id=org_b.id,
            tier=AccountTier.FREE,
            status="active",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(sub_a)
        db_session.add(sub_b)

        await db_session.commit()

        return {
            "org_a": org_a,
            "user_a": user_a,
            "account_a": account_a,
            "gap_a": gap_a,
            "org_b": org_b,
            "user_b": user_b,
            "account_b": account_b,
        }

    async def _get_token(self, client: AsyncClient, email: str) -> str:
        """Helper to get auth token."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "Password123!"},
        )
        assert response.status_code == 200, f"Login failed: {response.text}"
        return response.json()["access_token"]

    @pytest.mark.asyncio
    async def test_cannot_list_other_org_gaps(
        self, client: AsyncClient, two_orgs_setup, db_session: AsyncSession
    ):
        """User B cannot list gaps for Org A's cloud account."""
        setup = two_orgs_setup

        # Login as User B
        token = await self._get_token(client, setup["user_b"].email)

        # Try to list gaps for Org A's account
        response = await client.get(
            f"/api/v1/gaps?cloud_account_id={setup['account_a'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        # Should return 404 (account not found in user's org)
        assert response.status_code == 404
        assert "Cloud account not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_cannot_acknowledge_other_org_gap(
        self, client: AsyncClient, two_orgs_setup, db_session: AsyncSession
    ):
        """User B cannot acknowledge a gap in Org A's account."""
        setup = two_orgs_setup

        token = await self._get_token(client, setup["user_b"].email)

        response = await client.post(
            f"/api/v1/gaps/T1078/acknowledge?cloud_account_id={setup['account_a'].id}",
            headers={"Authorization": f"Bearer {token}"},
            json={"notes": "Attempted IDOR attack"},
        )

        assert response.status_code == 404
        assert "Cloud account not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_cannot_accept_risk_other_org_gap(
        self, client: AsyncClient, two_orgs_setup, db_session: AsyncSession
    ):
        """User B cannot accept risk for a gap in Org A's account."""
        setup = two_orgs_setup

        token = await self._get_token(client, setup["user_b"].email)

        response = await client.post(
            f"/api/v1/gaps/T1078/accept-risk?cloud_account_id={setup['account_a'].id}",
            headers={"Authorization": f"Bearer {token}"},
            json={"reason": "Attempted IDOR attack"},
        )

        # Should return 404 (account not found in user's org)
        assert response.status_code == 404
        assert "Cloud account not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_own_org_gap_operations_work(
        self, client: AsyncClient, two_orgs_setup, db_session: AsyncSession
    ):
        """User A can manage gaps in their own org."""
        setup = two_orgs_setup

        token = await self._get_token(client, setup["user_a"].email)

        # List gaps - should work
        response = await client.get(
            f"/api/v1/gaps?cloud_account_id={setup['account_a'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        # Should have at least the gap we created
        assert response.json()["total"] >= 1


# ============================================================================
# FINDING 4: Cognito State Validation Tests
# ============================================================================


class TestCognitoStateValidation:
    """Tests for Cognito state parameter validation."""

    @pytest.mark.asyncio
    async def test_token_exchange_requires_state(self, client: AsyncClient):
        """Token exchange without state should fail with 422."""
        response = await client.post(
            "/api/v1/cognito/token",
            json={
                "code": "test-code",
                "redirect_uri": "http://localhost:3000/callback",
                "code_verifier": "test-verifier",
                # state is missing - should fail validation
            },
        )

        # Should get 422 validation error for missing required field
        assert response.status_code == 422
        # The error should mention 'state' field
        error_detail = response.json()
        assert any(
            "state" in str(err).lower() for err in error_detail.get("detail", [])
        )

    @pytest.mark.asyncio
    async def test_token_exchange_rejects_invalid_state(self, client: AsyncClient):
        """Token exchange with invalid state should fail with 401."""
        response = await client.post(
            "/api/v1/cognito/token",
            json={
                "code": "test-code",
                "redirect_uri": "http://localhost:3000/callback",
                "code_verifier": "test-verifier",
                "state": "invalid-state-value-not-from-authorize",
            },
        )

        # Either 401 (invalid state) or 503 (Cognito not configured)
        assert response.status_code in (401, 503)
        if response.status_code == 401:
            assert "Invalid or expired OAuth state" in response.json()["detail"]


# ============================================================================
# FINDING 2: API Key Scope Enforcement Tests
# ============================================================================


class TestAPIKeyScopeEnforcement:
    """Tests for API key scope enforcement on schedules and scans endpoints."""

    @pytest_asyncio.fixture
    async def api_key_setup(self, db_session: AsyncSession):
        """Create organisation, cloud account, schedule, scan, and API keys with various scopes."""
        # Create organisation
        org = Organization(
            id=uuid.uuid4(),
            name="API Key Test Org",
            slug="api-key-test-org",
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(org)
        await db_session.flush()

        # Create subscription (required for scheduled_scans feature)
        subscription = Subscription(
            id=uuid.uuid4(),
            organization_id=org.id,
            tier=AccountTier.INDIVIDUAL,  # Has scheduled_scans feature
            status="active",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(subscription)

        # Create cloud account
        cloud_account = CloudAccount(
            id=uuid.uuid4(),
            organization_id=org.id,
            name="Test Account",
            provider="aws",
            account_id="123456789012",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(cloud_account)
        await db_session.flush()

        # Create a schedule
        schedule = ScanSchedule(
            id=uuid.uuid4(),
            cloud_account_id=cloud_account.id,
            name="Test Schedule",
            frequency=ScheduleFrequency.DAILY,
            hour=12,
            minute=0,
            timezone="UTC",
            is_active=False,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(schedule)

        # Create a scan (for cancel test)
        scan = Scan(
            id=uuid.uuid4(),
            cloud_account_id=cloud_account.id,
            status=ScanStatus.RUNNING,
            scan_type="full",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(scan)

        # Create API key with only read:scans scope
        api_key_read_scans = f"dcv_{uuid.uuid4().hex}"
        api_key_read_scans_model = APIKey(
            id=uuid.uuid4(),
            organization_id=org.id,
            name="Read Scans Only",
            key_prefix=api_key_read_scans[:12],
            key_hash=AuthService.hash_token(api_key_read_scans),
            scopes=["read:scans"],
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(api_key_read_scans_model)

        # Create API key with read:schedules scope (no write)
        api_key_read_schedules = f"dcv_{uuid.uuid4().hex}"
        api_key_read_schedules_model = APIKey(
            id=uuid.uuid4(),
            organization_id=org.id,
            name="Read Schedules Only",
            key_prefix=api_key_read_schedules[:12],
            key_hash=AuthService.hash_token(api_key_read_schedules),
            scopes=["read:schedules"],
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(api_key_read_schedules_model)

        # Create API key with write:schedules scope
        api_key_write_schedules = f"dcv_{uuid.uuid4().hex}"
        api_key_write_schedules_model = APIKey(
            id=uuid.uuid4(),
            organization_id=org.id,
            name="Write Schedules",
            key_prefix=api_key_write_schedules[:12],
            key_hash=AuthService.hash_token(api_key_write_schedules),
            scopes=["read:schedules", "write:schedules"],
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(api_key_write_schedules_model)

        # Create API key with write:scans scope
        api_key_write_scans = f"dcv_{uuid.uuid4().hex}"
        api_key_write_scans_model = APIKey(
            id=uuid.uuid4(),
            organization_id=org.id,
            name="Write Scans",
            key_prefix=api_key_write_scans[:12],
            key_hash=AuthService.hash_token(api_key_write_scans),
            scopes=["read:scans", "write:scans"],
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(api_key_write_scans_model)

        # Create a user with MEMBER role (not admin - for role tests)
        member_user = User(
            id=uuid.uuid4(),
            email="member_user_scope@example.com",
            full_name="Member User",
            password_hash=AuthService.hash_password("Password123!"),
            email_verified=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(member_user)
        await db_session.flush()

        member_membership = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org.id,
            user_id=member_user.id,
            role=UserRole.MEMBER,  # Not ADMIN/OWNER
            status=MembershipStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(member_membership)

        await db_session.commit()

        return {
            "org": org,
            "cloud_account": cloud_account,
            "schedule": schedule,
            "scan": scan,
            "api_key_read_scans": api_key_read_scans,
            "api_key_read_schedules": api_key_read_schedules,
            "api_key_write_schedules": api_key_write_schedules,
            "api_key_write_scans": api_key_write_scans,
            "member_user": member_user,
        }

    # -------------------------------------------------------------------------
    # Schedule endpoint scope tests
    # -------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_list_schedules_requires_read_scope(
        self, client: AsyncClient, api_key_setup
    ):
        """API key with only read:scans cannot list schedules."""
        setup = api_key_setup

        response = await client.get(
            "/api/v1/schedules",
            headers={"Authorization": f"Bearer {setup['api_key_read_scans']}"},
        )

        assert response.status_code == 403
        assert "Missing required scope" in response.json()["detail"]
        assert "read:schedules" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_schedules_works_with_correct_scope(
        self, client: AsyncClient, api_key_setup
    ):
        """API key with read:schedules can list schedules."""
        setup = api_key_setup

        response = await client.get(
            "/api/v1/schedules",
            headers={"Authorization": f"Bearer {setup['api_key_read_schedules']}"},
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_schedule_requires_read_scope(
        self, client: AsyncClient, api_key_setup
    ):
        """API key with only read:scans cannot get a specific schedule."""
        setup = api_key_setup

        response = await client.get(
            f"/api/v1/schedules/{setup['schedule'].id}",
            headers={"Authorization": f"Bearer {setup['api_key_read_scans']}"},
        )

        assert response.status_code == 403
        assert "Missing required scope" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_get_schedule_status_requires_read_scope(
        self, client: AsyncClient, api_key_setup
    ):
        """API key with only read:scans cannot get schedule status."""
        setup = api_key_setup

        response = await client.get(
            f"/api/v1/schedules/{setup['schedule'].id}/status",
            headers={"Authorization": f"Bearer {setup['api_key_read_scans']}"},
        )

        assert response.status_code == 403
        assert "Missing required scope" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_activate_schedule_requires_write_scope(
        self, client: AsyncClient, api_key_setup
    ):
        """API key with only read:schedules cannot activate a schedule."""
        setup = api_key_setup

        response = await client.post(
            f"/api/v1/schedules/{setup['schedule'].id}/activate",
            headers={"Authorization": f"Bearer {setup['api_key_read_schedules']}"},
        )

        assert response.status_code == 403
        assert "Missing required scope" in response.json()["detail"]
        assert "write:schedules" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_deactivate_schedule_requires_write_scope(
        self, client: AsyncClient, api_key_setup
    ):
        """API key with only read:schedules cannot deactivate a schedule."""
        setup = api_key_setup

        response = await client.post(
            f"/api/v1/schedules/{setup['schedule'].id}/deactivate",
            headers={"Authorization": f"Bearer {setup['api_key_read_schedules']}"},
        )

        assert response.status_code == 403
        assert "Missing required scope" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_run_now_requires_write_scope(
        self, client: AsyncClient, api_key_setup
    ):
        """API key with only read:schedules cannot trigger run-now."""
        setup = api_key_setup

        response = await client.post(
            f"/api/v1/schedules/{setup['schedule'].id}/run-now",
            headers={"Authorization": f"Bearer {setup['api_key_read_schedules']}"},
        )

        assert response.status_code == 403
        assert "Missing required scope" in response.json()["detail"]

    # -------------------------------------------------------------------------
    # Scan endpoint scope tests
    # -------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_cancel_scan_requires_write_scope(
        self, client: AsyncClient, api_key_setup
    ):
        """API key with only read:scans cannot cancel a scan."""
        setup = api_key_setup

        response = await client.post(
            f"/api/v1/scans/{setup['scan'].id}/cancel",
            headers={"Authorization": f"Bearer {setup['api_key_read_scans']}"},
        )

        assert response.status_code == 403
        assert "Missing required scope" in response.json()["detail"]
        assert "write:scans" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_cancel_scan_works_with_write_scope(
        self, client: AsyncClient, api_key_setup
    ):
        """API key with write:scans can cancel a scan."""
        setup = api_key_setup

        response = await client.post(
            f"/api/v1/scans/{setup['scan'].id}/cancel",
            headers={"Authorization": f"Bearer {setup['api_key_write_scans']}"},
        )

        # Should succeed or return 400 if scan already not running
        assert response.status_code in (200, 400)

    # -------------------------------------------------------------------------
    # Role enforcement tests (activate/deactivate/run-now require ADMIN/OWNER)
    # -------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_activate_schedule_requires_admin_role(
        self, client: AsyncClient, api_key_setup
    ):
        """MEMBER role cannot activate schedules even with write:schedules scope."""
        setup = api_key_setup

        # Login as member user
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": setup["member_user"].email, "password": "Password123!"},
        )
        assert response.status_code == 200
        token = response.json()["access_token"]

        # Try to activate schedule
        response = await client.post(
            f"/api/v1/schedules/{setup['schedule'].id}/activate",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Requires role" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_deactivate_schedule_requires_admin_role(
        self, client: AsyncClient, api_key_setup
    ):
        """MEMBER role cannot deactivate schedules."""
        setup = api_key_setup

        # Login as member user
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": setup["member_user"].email, "password": "Password123!"},
        )
        assert response.status_code == 200
        token = response.json()["access_token"]

        # Try to deactivate schedule
        response = await client.post(
            f"/api/v1/schedules/{setup['schedule'].id}/deactivate",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Requires role" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_run_now_requires_admin_role(
        self, client: AsyncClient, api_key_setup
    ):
        """MEMBER role cannot trigger run-now."""
        setup = api_key_setup

        # Login as member user
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": setup["member_user"].email, "password": "Password123!"},
        )
        assert response.status_code == 200
        token = response.json()["access_token"]

        # Try to run schedule now
        response = await client.post(
            f"/api/v1/schedules/{setup['schedule'].id}/run-now",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Requires role" in response.json()["detail"]
