"""Integration tests for security authorization fixes.

These tests verify that authorization controls are properly enforced.
"""

import hashlib
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


def _make_global_hash(provider: str, account_id: str) -> str:
    """Create global account hash for fraud prevention."""
    return hashlib.sha256(f"{provider}:{account_id}".encode()).hexdigest()


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
            global_account_hash=_make_global_hash("aws", "111111111111"),
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
            global_account_hash=_make_global_hash("aws", "222222222222"),
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

    def _generate_token(self, user: User, org: Organization) -> str:
        """Generate auth token directly without hitting login endpoint.

        This avoids rate limiting issues when running multiple tests.
        """
        return AuthService.generate_access_token(
            user_id=user.id,
            organization_id=org.id,
        )

    @pytest.mark.asyncio
    async def test_cannot_list_other_org_gaps(
        self, client: AsyncClient, two_orgs_setup, db_session: AsyncSession
    ):
        """User B cannot list gaps for Org A's cloud account."""
        setup = two_orgs_setup

        # Generate token for User B (org B)
        token = self._generate_token(setup["user_b"], setup["org_b"])

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

        token = self._generate_token(setup["user_b"], setup["org_b"])

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

        token = self._generate_token(setup["user_b"], setup["org_b"])

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

        token = self._generate_token(setup["user_a"], setup["org_a"])

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
            "/api/v1/auth/cognito/token",
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
            "/api/v1/auth/cognito/token",
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
            global_account_hash=_make_global_hash("aws", "123456789012"),
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
            regions=["eu-west-2"],
            detection_types=[],
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

    def _generate_member_token(self, setup: dict) -> str:
        """Generate token for member user without hitting login endpoint."""
        return AuthService.generate_access_token(
            user_id=setup["member_user"].id,
            organization_id=setup["org"].id,
        )

    @pytest.mark.asyncio
    async def test_activate_schedule_requires_admin_role(
        self, client: AsyncClient, api_key_setup
    ):
        """MEMBER role cannot activate schedules even with write:schedules scope."""
        setup = api_key_setup

        # Generate token for member user
        token = self._generate_member_token(setup)

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

        # Generate token for member user
        token = self._generate_member_token(setup)

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

        # Generate token for member user
        token = self._generate_member_token(setup)

        # Try to run schedule now
        response = await client.post(
            f"/api/v1/schedules/{setup['schedule'].id}/run-now",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Requires role" in response.json()["detail"]


# ============================================================================
# FINDING: Account-Level ACL (allowed_account_ids) Enforcement Tests
# ============================================================================


class TestAccountLevelACL:
    """Tests for account-level ACL enforcement via allowed_account_ids.

    These tests verify that users with restricted account access
    (allowed_account_ids set on their membership) can only access
    data from their allowed accounts.
    """

    @pytest_asyncio.fixture
    async def acl_setup(self, db_session: AsyncSession):
        """Create org with multiple accounts and users with different ACL restrictions."""
        from app.models.detection import Detection, DetectionType, DetectionStatus

        # Create organisation
        org = Organization(
            id=uuid.uuid4(),
            name="ACL Test Org",
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
            tier=AccountTier.INDIVIDUAL,
            status="active",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(subscription)

        # Create 3 cloud accounts
        account_a = CloudAccount(
            id=uuid.uuid4(),
            organization_id=org.id,
            name="Account A",
            provider="aws",
            account_id="111111111111",
            global_account_hash=_make_global_hash("aws", "111111111111"),
            created_at=datetime.now(timezone.utc),
        )
        account_b = CloudAccount(
            id=uuid.uuid4(),
            organization_id=org.id,
            name="Account B",
            provider="aws",
            account_id="222222222222",
            global_account_hash=_make_global_hash("aws", "222222222222"),
            created_at=datetime.now(timezone.utc),
        )
        account_c = CloudAccount(
            id=uuid.uuid4(),
            organization_id=org.id,
            name="Account C",
            provider="aws",
            account_id="333333333333",
            global_account_hash=_make_global_hash("aws", "333333333333"),
            created_at=datetime.now(timezone.utc),
        )
        db_session.add_all([account_a, account_b, account_c])
        await db_session.flush()

        # Create detections in each account
        detection_a = Detection(
            id=uuid.uuid4(),
            cloud_account_id=account_a.id,
            name="Detection in Account A",
            detection_type=DetectionType.CLOUDWATCH_ALARM,
            status=DetectionStatus.ACTIVE,
            source_arn="arn:aws:cloudwatch:us-east-1:111111111111:alarm:test-a",
            region="us-east-1",
            discovered_at=datetime.now(timezone.utc),
        )
        detection_b = Detection(
            id=uuid.uuid4(),
            cloud_account_id=account_b.id,
            name="Detection in Account B",
            detection_type=DetectionType.CLOUDWATCH_ALARM,
            status=DetectionStatus.ACTIVE,
            source_arn="arn:aws:cloudwatch:us-east-1:222222222222:alarm:test-b",
            region="us-east-1",
            discovered_at=datetime.now(timezone.utc),
        )
        detection_c = Detection(
            id=uuid.uuid4(),
            cloud_account_id=account_c.id,
            name="Detection in Account C",
            detection_type=DetectionType.CLOUDWATCH_ALARM,
            status=DetectionStatus.ACTIVE,
            source_arn="arn:aws:cloudwatch:us-east-1:333333333333:alarm:test-c",
            region="us-east-1",
            discovered_at=datetime.now(timezone.utc),
        )
        db_session.add_all([detection_a, detection_b, detection_c])

        # Create scans in each account
        scan_a = Scan(
            id=uuid.uuid4(),
            cloud_account_id=account_a.id,
            status=ScanStatus.COMPLETED,
            created_at=datetime.now(timezone.utc),
        )
        scan_b = Scan(
            id=uuid.uuid4(),
            cloud_account_id=account_b.id,
            status=ScanStatus.COMPLETED,
            created_at=datetime.now(timezone.utc),
        )
        scan_c = Scan(
            id=uuid.uuid4(),
            cloud_account_id=account_c.id,
            status=ScanStatus.COMPLETED,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add_all([scan_a, scan_b, scan_c])

        # Create owner user (unrestricted access)
        owner_user = User(
            id=uuid.uuid4(),
            email="owner_acl_test@example.com",
            full_name="Owner User",
            password_hash=AuthService.hash_password("Password123!"),
            email_verified=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(owner_user)
        await db_session.flush()

        owner_membership = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org.id,
            user_id=owner_user.id,
            role=UserRole.OWNER,
            status=MembershipStatus.ACTIVE,
            allowed_account_ids=None,  # Unrestricted
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(owner_membership)

        # Create restricted member (only has access to account_a)
        restricted_user = User(
            id=uuid.uuid4(),
            email="restricted_acl_test@example.com",
            full_name="Restricted User",
            password_hash=AuthService.hash_password("Password123!"),
            email_verified=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(restricted_user)
        await db_session.flush()

        restricted_membership = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org.id,
            user_id=restricted_user.id,
            role=UserRole.MEMBER,
            status=MembershipStatus.ACTIVE,
            # Only allowed to access account_a
            allowed_account_ids=[str(account_a.id)],
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(restricted_membership)

        # Create unrestricted member (null allowed_account_ids = full access)
        unrestricted_member = User(
            id=uuid.uuid4(),
            email="unrestricted_member_acl@example.com",
            full_name="Unrestricted Member",
            password_hash=AuthService.hash_password("Password123!"),
            email_verified=True,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(unrestricted_member)
        await db_session.flush()

        unrestricted_membership = OrganizationMember(
            id=uuid.uuid4(),
            organization_id=org.id,
            user_id=unrestricted_member.id,
            role=UserRole.MEMBER,
            status=MembershipStatus.ACTIVE,
            allowed_account_ids=None,  # Full access
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(unrestricted_membership)

        await db_session.commit()

        return {
            "org": org,
            "account_a": account_a,
            "account_b": account_b,
            "account_c": account_c,
            "detection_a": detection_a,
            "detection_b": detection_b,
            "detection_c": detection_c,
            "scan_a": scan_a,
            "scan_b": scan_b,
            "scan_c": scan_c,
            "owner_user": owner_user,
            "restricted_user": restricted_user,
            "unrestricted_member": unrestricted_member,
        }

    def _get_token(self, setup: dict, user_key: str) -> str:
        """Helper to generate auth token directly (bypasses rate limits)."""
        user = setup[user_key]
        org = setup["org"]
        return AuthService.generate_access_token(
            user_id=user.id,
            organization_id=org.id,
        )

    # -------------------------------------------------------------------------
    # List Detections ACL Tests
    # -------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_owner_sees_all_detections(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Owner with unrestricted access sees all detections."""
        setup = acl_setup
        token = self._get_token(setup, "owner_user")

        response = await client.get(
            "/api/v1/detections",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        # Should see all 3 detections
        assert data["total"] == 3

    @pytest.mark.asyncio
    async def test_restricted_user_sees_only_allowed_detections(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user only sees detections from allowed accounts."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            "/api/v1/detections",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        # Should only see detection from account_a
        assert data["total"] == 1
        assert data["items"][0]["name"] == "Detection in Account A"

    @pytest.mark.asyncio
    async def test_restricted_user_cannot_filter_by_non_allowed_account(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user cannot filter by account they don't have access to."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            f"/api/v1/detections?cloud_account_id={setup['account_b'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_unrestricted_member_sees_all_detections(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Member with null allowed_account_ids sees all detections."""
        setup = acl_setup
        token = self._get_token(setup, "unrestricted_member")

        response = await client.get(
            "/api/v1/detections",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        # Should see all 3 detections
        assert data["total"] == 3

    # -------------------------------------------------------------------------
    # List Scans ACL Tests
    # -------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_owner_sees_all_scans(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Owner with unrestricted access sees all scans."""
        setup = acl_setup
        token = self._get_token(setup, "owner_user")

        response = await client.get(
            "/api/v1/scans",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3

    @pytest.mark.asyncio
    async def test_restricted_user_sees_only_allowed_scans(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user only sees scans from allowed accounts."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            "/api/v1/scans",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        # Should only see scan from account_a
        assert data["total"] == 1

    @pytest.mark.asyncio
    async def test_restricted_user_cannot_filter_scans_by_non_allowed_account(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user cannot filter scans by account they don't have access to."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            f"/api/v1/scans?cloud_account_id={setup['account_c'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    # -------------------------------------------------------------------------
    # Bulk Endpoint ACL Tests
    # -------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_restricted_user_bulk_validate_requires_account_id(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user must specify cloud_account_id for bulk validate."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.post(
            "/api/v1/detections/validate-all",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 400
        assert "cloud_account_id is required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_restricted_user_bulk_validate_with_allowed_account_succeeds(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user can bulk validate with allowed account specified."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.post(
            f"/api/v1/detections/validate-all?cloud_account_id={setup['account_a'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        # Should succeed (or 200 with results)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_restricted_user_bulk_validate_with_non_allowed_account_fails(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user cannot bulk validate with non-allowed account."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.post(
            f"/api/v1/detections/validate-all?cloud_account_id={setup['account_b'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_owner_bulk_validate_without_account_id_succeeds(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Owner can bulk validate without specifying account (org-wide)."""
        setup = acl_setup
        token = self._get_token(setup, "owner_user")

        response = await client.post(
            "/api/v1/detections/validate-all",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_restricted_user_health_summary_requires_account_id(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user must specify cloud_account_id for health summary."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            "/api/v1/detections/health/summary",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 400
        assert "cloud_account_id is required" in response.json()["detail"]

    # -------------------------------------------------------------------------
    # Detection Health ACL Tests
    # -------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_restricted_user_can_get_allowed_detection_health(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user can get health of detection in allowed account."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            f"/api/v1/detections/{setup['detection_a'].id}/health",
            headers={"Authorization": f"Bearer {token}"},
        )

        # Should succeed (200 with health data)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_restricted_user_cannot_get_non_allowed_detection_health(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user cannot get health of detection in non-allowed account."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            f"/api/v1/detections/{setup['detection_b'].id}/health",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_restricted_user_can_validate_allowed_detection(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user can validate detection in allowed account."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.post(
            f"/api/v1/detections/{setup['detection_a'].id}/validate",
            headers={"Authorization": f"Bearer {token}"},
        )

        # Should succeed
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_restricted_user_cannot_validate_non_allowed_detection(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user cannot validate detection in non-allowed account."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.post(
            f"/api/v1/detections/{setup['detection_c'].id}/validate",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    # -------------------------------------------------------------------------
    # Get Single Detection ACL Tests
    # -------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_restricted_user_can_get_allowed_detection(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user can get detection in allowed account."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            f"/api/v1/detections/{setup['detection_a'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert response.json()["name"] == "Detection in Account A"

    @pytest.mark.asyncio
    async def test_restricted_user_cannot_get_non_allowed_detection(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user cannot get detection in non-allowed account."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            f"/api/v1/detections/{setup['detection_b'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    # -------------------------------------------------------------------------
    # Get Single Scan ACL Tests
    # -------------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_restricted_user_can_get_allowed_scan(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user can get scan in allowed account."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            f"/api/v1/scans/{setup['scan_a'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_restricted_user_cannot_get_non_allowed_scan(
        self, client: AsyncClient, acl_setup, db_session: AsyncSession
    ):
        """Restricted user cannot get scan in non-allowed account."""
        setup = acl_setup
        token = self._get_token(setup, "restricted_user")

        response = await client.get(
            f"/api/v1/scans/{setup['scan_b'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]
