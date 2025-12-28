# Security Audit Fixes - December 2025

## Executive Summary

This plan addresses 5 security findings from the latest audit. All findings have been validated and require code changes.

---

## Finding 1: CRITICAL — Cross-tenant IDOR in Gaps Endpoints

### Validation
**CONFIRMED VULNERABLE**

The following endpoints query `CoverageGap` by `cloud_account_id` without verifying organisation ownership:

| Endpoint | Function | Line | Issue |
|----------|----------|------|-------|
| `POST /{technique_id}/acknowledge` | `acknowledge_gap` | 107-112 | No org filter |
| `POST /{technique_id}/accept-risk` | `accept_risk` | 188-193 | No org filter |
| `POST /{technique_id}/reopen` | `reopen_gap` | 265-270 | No org filter |
| `GET ""` | `list_gaps` | 323 | No org filter |
| `GET /acknowledged` | `list_acknowledged_gaps` | 376-381 | No org filter |

**Attack vector**: Any authenticated user can read/modify another tenant's gap records by guessing/obtaining a `cloud_account_id` UUID.

### Implementation Plan

#### Step 1: Create helper function to validate cloud account ownership
Add to `backend/app/api/routes/gaps.py`:

```python
async def _validate_cloud_account_access(
    db: AsyncSession,
    cloud_account_id: UUID,
    auth: AuthContext,
) -> None:
    """Validate cloud account belongs to user's organisation and user has access."""
    from app.models.cloud_account import CloudAccount

    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Check allowed_account_ids ACL if set
    if not auth.can_access_account(cloud_account_id):
        raise HTTPException(status_code=403, detail="Access denied to this cloud account")
```

#### Step 2: Update all gap queries to include org filter

For existing gap lookups, change from:
```python
stmt = select(CoverageGap).where(
    and_(
        CoverageGap.cloud_account_id == cloud_account_id,
        CoverageGap.technique_id == technique_id,
    )
)
```

To:
```python
stmt = select(CoverageGap).where(
    and_(
        CoverageGap.cloud_account_id == cloud_account_id,
        CoverageGap.technique_id == technique_id,
        CoverageGap.organization_id == auth.organization_id,  # ADD THIS
    )
)
```

#### Step 3: Add validation call at start of each endpoint

Add at the beginning of `acknowledge_gap`, `accept_risk`, `reopen_gap`, `list_gaps`, and `list_acknowledged_gaps`:
```python
await _validate_cloud_account_access(db, cloud_account_id, auth)
```

### Files to Modify
- `backend/app/api/routes/gaps.py`

---

## Finding 2: HIGH — API Key Scope Bypass on Schedules/Scans

### Validation
**CONFIRMED**

| Endpoint | Function | Line | Required Scope | Current State |
|----------|----------|------|----------------|---------------|
| `GET /schedules` | `list_schedules` | 31 | `read:schedules` | ❌ Missing |
| `GET /schedules/{id}` | `get_schedule` | 137 | `read:schedules` | ❌ Missing |
| `GET /schedules/{id}/status` | `get_schedule_status` | 158 | `read:schedules` | ❌ Missing |
| `POST /schedules/{id}/activate` | `activate_schedule` | 261 | `write:schedules` | ❌ Missing |
| `POST /schedules/{id}/deactivate` | `deactivate_schedule` | 291 | `write:schedules` | ❌ Missing |
| `POST /schedules/{id}/run-now` | `run_schedule_now` | 322 | `write:schedules` | ❌ Missing |
| `POST /scans/{id}/cancel` | `cancel_scan` | 175 | `write:scans` | ❌ Missing |

### Implementation Plan

#### Step 1: Add scope requirements to schedule read endpoints

```python
@router.get(
    "",
    response_model=ScheduleListResponse,
    dependencies=[Depends(require_scope("read:schedules"))],  # ADD
)
async def list_schedules(...):

@router.get(
    "/{schedule_id}",
    response_model=ScheduleResponse,
    dependencies=[Depends(require_scope("read:schedules"))],  # ADD
)
async def get_schedule(...):

@router.get(
    "/{schedule_id}/status",
    response_model=ScheduleStatusResponse,
    dependencies=[Depends(require_scope("read:schedules"))],  # ADD
)
async def get_schedule_status(...):
```

#### Step 2: Add scope + role requirements to schedule write endpoints

For `activate`, `deactivate`, and `run-now`, require both scope AND admin role:

```python
@router.post(
    "/{schedule_id}/activate",
    response_model=ScheduleResponse,
    dependencies=[
        Depends(require_scope("write:schedules")),
        Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),  # Restrict to admins
    ],
)
async def activate_schedule(...):
```

#### Step 3: Add scope to scan cancel endpoint

```python
@router.post(
    "/{scan_id}/cancel",
    response_model=ScanResponse,
    dependencies=[Depends(require_scope("write:scans"))],  # ADD
)
async def cancel_scan(...):
```

### Files to Modify
- `backend/app/api/routes/schedules.py`
- `backend/app/api/routes/scans.py`

---

## Finding 3: HIGH — Account-level ACL Not Enforced

### Validation
**CONFIRMED**

The `allowed_account_ids` field on `OrganizationMember` is designed to restrict member access to specific cloud accounts, but it's not enforced in list queries.

| File | Endpoint | Line | Issue |
|------|----------|------|-------|
| `detections.py` | `list_detections` | 102-108 | No ACL filter on list |
| `scans.py` | `list_scans` | 38-43 | No ACL filter on list |
| `schedules.py` | `list_schedules` | 41-46 | No ACL filter on list |
| `coverage.py` | `get_coverage` | 146-151 | No ACL check |
| `reports.py` | Multiple | 88-91 | No ACL check |
| `gaps.py` | Multiple | Various | No ACL check |

### Implementation Plan

#### Step 1: Create reusable helper function

Add to `backend/app/core/security.py`:

```python
def get_allowed_account_filter(auth: AuthContext) -> Optional[list[UUID]]:
    """Get list of allowed account IDs for filtering, or None if unrestricted.

    Returns:
        - None if user is admin/owner OR allowed_account_ids is not set (full access)
        - List of UUIDs if user has restricted access
    """
    if not auth.membership:
        return []  # No membership = no access

    # Owners and admins have full access
    if auth.is_admin():
        return None

    # If allowed_account_ids is not set, member has access to all
    if auth.membership.allowed_account_ids is None:
        return None

    return auth.membership.allowed_account_ids
```

#### Step 2: Update list queries to filter by allowed accounts

Example for `detections.py`:

```python
# After org filter, add ACL filter
allowed_accounts = get_allowed_account_filter(auth)
if allowed_accounts is not None:
    if not allowed_accounts:
        # User has no access to any accounts
        return DetectionListResponse(items=[], total=0, page=1, page_size=limit)
    query = query.where(Detection.cloud_account_id.in_(allowed_accounts))
```

#### Step 3: Add `require_account_access` to single-resource endpoints

For endpoints that take `cloud_account_id` as a path/query parameter, add the dependency:

```python
from app.core.security import require_account_access

@router.get(
    "/{cloud_account_id}",
    dependencies=[Depends(require_account_access("cloud_account_id"))],
)
async def get_coverage(...):
```

### Files to Modify
- `backend/app/core/security.py` (add helper)
- `backend/app/api/routes/detections.py`
- `backend/app/api/routes/scans.py`
- `backend/app/api/routes/schedules.py`
- `backend/app/api/routes/coverage.py`
- `backend/app/api/routes/reports.py`
- `backend/app/api/routes/gaps.py`

---

## Finding 4: MED — Cognito State is Optional

### Validation
**CONFIRMED**

In `backend/app/api/routes/cognito.py`:
- Line 100: `state: Optional[str] = None` - state is optional
- Line 211: `if body.state and not ...` - only validates if provided

This weakens CSRF protection as attackers can omit the state parameter.

### Implementation Plan

#### Step 1: Make state required in the request model

Change:
```python
class CognitoTokenRequest(BaseModel):
    code: str
    redirect_uri: str
    code_verifier: str
    state: Optional[str] = None  # CURRENT
```

To:
```python
class CognitoTokenRequest(BaseModel):
    code: str
    redirect_uri: str
    code_verifier: str
    state: str  # REQUIRED - for CSRF protection
```

#### Step 2: Always validate state

Change:
```python
if body.state and not _cognito_state_store.validate_and_consume(body.state):
```

To:
```python
if not _cognito_state_store.validate_and_consume(body.state):
```

### Files to Modify
- `backend/app/api/routes/cognito.py`

---

## Finding 5: MED — Secrets in Terraform State

### Validation
**CONFIRMED**

In `infrastructure/terraform/modules/backend/main.tf`:
- Lines 493-496: `secret_string = var.jwt_secret_key`
- Lines 508-511: `secret_string = var.credential_encryption_key`
- Lines 524-527: `secret_string = var.stripe_secret_key`
- etc.

Even with Secrets Manager, plaintext values exist in Terraform state.

### Mitigation Options

#### Option A: Ensure state security (Recommended for now)
1. Verify S3 backend uses encryption at rest (`encrypt = true`)
2. Verify S3 bucket has restricted access (only CI/CD and admins)
3. Verify DynamoDB lock table has restricted access
4. Enable S3 bucket versioning for audit trail

#### Option B: Out-of-band secret management (Future improvement)
1. Remove secret values from Terraform variables
2. Create secrets with placeholder values in Terraform
3. Rotate actual secret values manually in AWS Console or via separate automation
4. Terraform only references secret ARNs, never values

#### Implementation for Option A

Add to `infrastructure/terraform/backend.tf` (or verify existing):

```hcl
terraform {
  backend "s3" {
    bucket         = "a13e-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "eu-west-2"
    encrypt        = true  # REQUIRED
    dynamodb_table = "a13e-terraform-locks"
  }
}
```

Verify S3 bucket policy restricts access to specific IAM roles.

### Files to Verify/Modify
- `infrastructure/terraform/backend.tf`
- S3 bucket policy (out of Terraform scope)

---

## Implementation Order

| Priority | Finding | Severity | Effort | Files |
|----------|---------|----------|--------|-------|
| 1 | Cross-tenant IDOR | CRITICAL | Medium | gaps.py |
| 2 | API key scope bypass | HIGH | Low | schedules.py, scans.py |
| 3 | Account ACL enforcement | HIGH | Medium | 7 files |
| 4 | Cognito state required | MED | Low | cognito.py |
| 5 | Terraform state secrets | MED | Low | Verify config |

---

## Unit Tests

Create new test file: `backend/tests/unit/test_security_acl.py`

```python
"""Unit tests for security ACL and authorization helpers."""

import pytest
from uuid import uuid4
from unittest.mock import MagicMock, AsyncMock

from app.core.security import (
    AuthContext,
    get_allowed_account_filter,
    _check_ip_in_allowlist,
)
from app.models.user import UserRole, OrganizationMember


class TestGetAllowedAccountFilter:
    """Tests for get_allowed_account_filter helper."""

    def test_no_membership_returns_empty_list(self):
        """User with no membership should get empty list (no access)."""
        auth = AuthContext(user=MagicMock(), organization=None, membership=None)
        result = get_allowed_account_filter(auth)
        assert result == []

    def test_owner_returns_none(self):
        """Owner should have unrestricted access (None)."""
        membership = MagicMock(spec=OrganizationMember)
        membership.role = UserRole.OWNER
        membership.allowed_account_ids = [uuid4()]  # Even if set, should be ignored

        auth = AuthContext(
            user=MagicMock(),
            organization=MagicMock(),
            membership=membership,
        )
        result = get_allowed_account_filter(auth)
        assert result is None

    def test_admin_returns_none(self):
        """Admin should have unrestricted access (None)."""
        membership = MagicMock(spec=OrganizationMember)
        membership.role = UserRole.ADMIN
        membership.allowed_account_ids = [uuid4()]

        auth = AuthContext(
            user=MagicMock(),
            organization=MagicMock(),
            membership=membership,
        )
        result = get_allowed_account_filter(auth)
        assert result is None

    def test_member_with_null_allowed_returns_none(self):
        """Member with null allowed_account_ids has full access."""
        membership = MagicMock(spec=OrganizationMember)
        membership.role = UserRole.MEMBER
        membership.allowed_account_ids = None

        auth = AuthContext(
            user=MagicMock(),
            organization=MagicMock(),
            membership=membership,
        )
        result = get_allowed_account_filter(auth)
        assert result is None

    def test_member_with_restricted_access(self):
        """Member with allowed_account_ids should get that list."""
        account_ids = [uuid4(), uuid4()]
        membership = MagicMock(spec=OrganizationMember)
        membership.role = UserRole.MEMBER
        membership.allowed_account_ids = account_ids

        auth = AuthContext(
            user=MagicMock(),
            organization=MagicMock(),
            membership=membership,
        )
        result = get_allowed_account_filter(auth)
        assert result == account_ids

    def test_viewer_with_restricted_access(self):
        """Viewer with allowed_account_ids should get that list."""
        account_ids = [uuid4()]
        membership = MagicMock(spec=OrganizationMember)
        membership.role = UserRole.VIEWER
        membership.allowed_account_ids = account_ids

        auth = AuthContext(
            user=MagicMock(),
            organization=MagicMock(),
            membership=membership,
        )
        result = get_allowed_account_filter(auth)
        assert result == account_ids

    def test_member_with_empty_list_returns_empty(self):
        """Member with empty allowed_account_ids has no access."""
        membership = MagicMock(spec=OrganizationMember)
        membership.role = UserRole.MEMBER
        membership.allowed_account_ids = []

        auth = AuthContext(
            user=MagicMock(),
            organization=MagicMock(),
            membership=membership,
        )
        result = get_allowed_account_filter(auth)
        assert result == []


class TestAuthContextCanAccessAccount:
    """Tests for AuthContext.can_access_account method."""

    def test_owner_can_access_any_account(self):
        """Owner should access any account regardless of ACL."""
        membership = MagicMock(spec=OrganizationMember)
        membership.role = UserRole.OWNER
        membership.allowed_account_ids = [uuid4()]  # Different account

        auth = AuthContext(
            user=MagicMock(),
            organization=MagicMock(),
            membership=membership,
        )

        random_account = uuid4()
        assert auth.can_access_account(random_account) is True

    def test_member_with_null_acl_can_access_any(self):
        """Member with null ACL can access any account."""
        membership = MagicMock(spec=OrganizationMember)
        membership.role = UserRole.MEMBER
        membership.allowed_account_ids = None

        auth = AuthContext(
            user=MagicMock(),
            organization=MagicMock(),
            membership=membership,
        )

        assert auth.can_access_account(uuid4()) is True

    def test_member_can_access_allowed_account(self):
        """Member can access account in allowed list."""
        allowed_id = uuid4()
        membership = MagicMock(spec=OrganizationMember)
        membership.role = UserRole.MEMBER
        membership.allowed_account_ids = [str(allowed_id)]

        auth = AuthContext(
            user=MagicMock(),
            organization=MagicMock(),
            membership=membership,
        )

        assert auth.can_access_account(allowed_id) is True

    def test_member_cannot_access_non_allowed_account(self):
        """Member cannot access account not in allowed list."""
        allowed_id = uuid4()
        other_id = uuid4()

        membership = MagicMock(spec=OrganizationMember)
        membership.role = UserRole.MEMBER
        membership.allowed_account_ids = [str(allowed_id)]

        auth = AuthContext(
            user=MagicMock(),
            organization=MagicMock(),
            membership=membership,
        )

        assert auth.can_access_account(other_id) is False
```

---

## Integration Tests

Create new test file: `backend/tests/integration/test_security_authorization.py`

```python
"""Integration tests for security authorization fixes.

These tests verify that authorization controls are properly enforced.
"""

import pytest
import uuid
from datetime import datetime, timezone
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, Organization, OrganizationMember, UserRole, MembershipStatus
from app.models.cloud_account import CloudAccount
from app.models.gap import CoverageGap, GapStatus, GapPriority
from app.models.billing import AccountTier, Subscription
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
            slug="org-a",
            is_active=True,
        )
        user_a = User(
            id=uuid.uuid4(),
            email="user_a@example.com",
            password_hash=AuthService.hash_password("Password123!"),
            email_verified=True,
            is_active=True,
        )
        account_a = CloudAccount(
            id=uuid.uuid4(),
            organization_id=org_a.id,
            name="Account A",
            provider="aws",
            account_id="111111111111",
        )
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

        # Org B
        org_b = Organization(
            id=uuid.uuid4(),
            name="Org B",
            slug="org-b",
            is_active=True,
        )
        user_b = User(
            id=uuid.uuid4(),
            email="user_b@example.com",
            password_hash=AuthService.hash_password("Password123!"),
            email_verified=True,
            is_active=True,
        )
        account_b = CloudAccount(
            id=uuid.uuid4(),
            organization_id=org_b.id,
            name="Account B",
            provider="aws",
            account_id="222222222222",
        )

        # Add memberships
        member_a = OrganizationMember(
            organization_id=org_a.id,
            user_id=user_a.id,
            role=UserRole.OWNER,
            status=MembershipStatus.ACTIVE,
        )
        member_b = OrganizationMember(
            organization_id=org_b.id,
            user_id=user_b.id,
            role=UserRole.OWNER,
            status=MembershipStatus.ACTIVE,
        )

        # Add subscriptions
        sub_a = Subscription(
            organization_id=org_a.id,
            tier=AccountTier.FREE,
            status="active",
        )
        sub_b = Subscription(
            organization_id=org_b.id,
            tier=AccountTier.FREE,
            status="active",
        )

        db_session.add_all([
            org_a, org_b, user_a, user_b, account_a, account_b,
            gap_a, member_a, member_b, sub_a, sub_b
        ])
        await db_session.commit()

        return {
            "org_a": org_a, "user_a": user_a, "account_a": account_a, "gap_a": gap_a,
            "org_b": org_b, "user_b": user_b, "account_b": account_b,
        }

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
            json={"notes": "Hacked!"},
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
            json={"reason": "Hacked!"},
        )

        assert response.status_code in (403, 404)

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
        assert len(response.json()["gaps"]) >= 1

    async def _get_token(self, client: AsyncClient, email: str) -> str:
        """Helper to get auth token."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "Password123!"},
        )
        return response.json()["access_token"]


# ============================================================================
# FINDING 2: API Key Scope Bypass Tests
# ============================================================================

class TestAPIKeyScopeEnforcement:
    """Tests for API key scope enforcement."""

    @pytest.mark.asyncio
    async def test_schedule_list_requires_read_scope(
        self, client: AsyncClient, api_key_read_scans_only
    ):
        """API key with only read:scans cannot list schedules."""
        response = await client.get(
            "/api/v1/schedules",
            headers={"Authorization": f"Bearer {api_key_read_scans_only}"},
        )

        assert response.status_code == 403
        assert "Missing required scope" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_schedule_activate_requires_write_scope(
        self, client: AsyncClient, api_key_read_schedules_only, test_schedule_id
    ):
        """API key with only read:schedules cannot activate schedules."""
        response = await client.post(
            f"/api/v1/schedules/{test_schedule_id}/activate",
            headers={"Authorization": f"Bearer {api_key_read_schedules_only}"},
        )

        assert response.status_code == 403
        assert "Missing required scope" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_scan_cancel_requires_write_scope(
        self, client: AsyncClient, api_key_read_scans_only, test_scan_id
    ):
        """API key with only read:scans cannot cancel scans."""
        response = await client.post(
            f"/api/v1/scans/{test_scan_id}/cancel",
            headers={"Authorization": f"Bearer {api_key_read_scans_only}"},
        )

        assert response.status_code == 403
        assert "Missing required scope" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_schedule_activate_requires_admin_role(
        self, client: AsyncClient, member_user_token, test_schedule_id
    ):
        """Member role cannot activate schedules (requires admin)."""
        response = await client.post(
            f"/api/v1/schedules/{test_schedule_id}/activate",
            headers={"Authorization": f"Bearer {member_user_token}"},
        )

        assert response.status_code == 403
        assert "Requires role" in response.json()["detail"]


# ============================================================================
# FINDING 3: Account ACL Enforcement Tests
# ============================================================================

class TestAccountACLEnforcement:
    """Tests for allowed_account_ids ACL enforcement."""

    @pytest_asyncio.fixture
    async def restricted_member_setup(self, db_session: AsyncSession, test_org):
        """Create a member with restricted account access."""
        # Create two cloud accounts
        account_1 = CloudAccount(
            id=uuid.uuid4(),
            organization_id=test_org.id,
            name="Account 1",
            provider="aws",
            account_id="111111111111",
        )
        account_2 = CloudAccount(
            id=uuid.uuid4(),
            organization_id=test_org.id,
            name="Account 2",
            provider="aws",
            account_id="222222222222",
        )

        # Create member with access only to account_1
        restricted_user = User(
            id=uuid.uuid4(),
            email="restricted@example.com",
            password_hash=AuthService.hash_password("Password123!"),
            email_verified=True,
            is_active=True,
        )

        restricted_member = OrganizationMember(
            organization_id=test_org.id,
            user_id=restricted_user.id,
            role=UserRole.MEMBER,
            status=MembershipStatus.ACTIVE,
            allowed_account_ids=[str(account_1.id)],  # Only account_1
        )

        db_session.add_all([account_1, account_2, restricted_user, restricted_member])
        await db_session.commit()

        return {
            "account_1": account_1,
            "account_2": account_2,
            "user": restricted_user,
        }

    @pytest.mark.asyncio
    async def test_list_detections_filtered_by_acl(
        self, client: AsyncClient, restricted_member_setup
    ):
        """Restricted member only sees detections from allowed accounts."""
        setup = restricted_member_setup
        token = await self._get_token(client, setup["user"].email)

        response = await client.get(
            "/api/v1/detections",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        # All returned detections should be from account_1 only
        for detection in response.json()["items"]:
            assert detection["cloud_account_id"] == str(setup["account_1"].id)

    @pytest.mark.asyncio
    async def test_cannot_access_restricted_account_directly(
        self, client: AsyncClient, restricted_member_setup
    ):
        """Restricted member cannot access account_2 directly."""
        setup = restricted_member_setup
        token = await self._get_token(client, setup["user"].email)

        response = await client.get(
            f"/api/v1/coverage/{setup['account_2'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_can_access_allowed_account(
        self, client: AsyncClient, restricted_member_setup
    ):
        """Restricted member can access account_1."""
        setup = restricted_member_setup
        token = await self._get_token(client, setup["user"].email)

        response = await client.get(
            f"/api/v1/coverage/{setup['account_1'].id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        # May be 404 if no coverage data, but not 403
        assert response.status_code in (200, 404)
        if response.status_code == 404:
            assert "No coverage data" in response.json()["detail"]

    async def _get_token(self, client: AsyncClient, email: str) -> str:
        """Helper to get auth token."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "Password123!"},
        )
        return response.json()["access_token"]


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
                # state is missing
            },
        )

        assert response.status_code == 422
        assert "state" in response.text.lower()

    @pytest.mark.asyncio
    async def test_token_exchange_rejects_invalid_state(self, client: AsyncClient):
        """Token exchange with invalid state should fail with 401."""
        response = await client.post(
            "/api/v1/cognito/token",
            json={
                "code": "test-code",
                "redirect_uri": "http://localhost:3000/callback",
                "code_verifier": "test-verifier",
                "state": "invalid-state-value",
            },
        )

        # Either 401 (invalid state) or 503 (Cognito not configured)
        assert response.status_code in (401, 503)

    @pytest.mark.asyncio
    async def test_state_is_single_use(self, client: AsyncClient):
        """State token should be consumed after first use."""
        # First, get a valid state from the authorize endpoint
        response = await client.get(
            "/api/v1/cognito/authorize/google?redirect_uri=http://localhost:3000/callback",
        )

        if response.status_code == 503:
            pytest.skip("Cognito not configured")

        state = response.json()["state"]

        # First use should... work or fail on code exchange (not state)
        # Second use should fail on state
        for _ in range(2):
            await client.post(
                "/api/v1/cognito/token",
                json={
                    "code": "test-code",
                    "redirect_uri": "http://localhost:3000/callback",
                    "code_verifier": "test-verifier",
                    "state": state,
                },
            )

        # After consumption, state should be invalid
        response = await client.post(
            "/api/v1/cognito/token",
            json={
                "code": "test-code",
                "redirect_uri": "http://localhost:3000/callback",
                "code_verifier": "test-verifier",
                "state": state,
            },
        )

        assert response.status_code == 401
        assert "Invalid or expired OAuth state" in response.json()["detail"]
```

---

## CI Pipeline Updates

### Update: `.github/workflows/security.yml`

Add a new job for authorization security tests:

```yaml
  # Authorization security tests
  auth-security-tests:
    name: Authorization Security Tests
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: dcv_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'

      - name: Install dependencies
        working-directory: ./backend
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-asyncio httpx

      - name: Run authorization security tests
        working-directory: ./backend
        env:
          DATABASE_URL: postgresql+asyncpg://postgres:postgres@localhost:5432/dcv_test
          REDIS_URL: redis://localhost:6379/0
          SECRET_KEY: test-secret-key-for-ci-at-least-32-chars-long
        run: |
          pytest tests/unit/test_security_acl.py tests/integration/test_security_authorization.py -v --tb=short

      - name: Upload test results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: auth-security-test-results
          path: backend/pytest-results.xml
```

### Update: `.github/workflows/test.yml` (or main CI)

Add authorization tests to the main test suite:

```yaml
      - name: Run security authorization tests
        working-directory: ./backend
        run: |
          pytest tests/unit/test_security_acl.py tests/integration/test_security_authorization.py -v
```

---

## Test Coverage Requirements

| Finding | Test File | Test Class | Min Tests |
|---------|-----------|------------|-----------|
| IDOR | `test_security_authorization.py` | `TestCrossTenantIDOR` | 4 |
| Scope bypass | `test_security_authorization.py` | `TestAPIKeyScopeEnforcement` | 4 |
| ACL enforcement | `test_security_authorization.py` | `TestAccountACLEnforcement` | 3 |
| Cognito state | `test_security_authorization.py` | `TestCognitoStateValidation` | 3 |
| ACL helper | `test_security_acl.py` | `TestGetAllowedAccountFilter` | 7 |
| can_access_account | `test_security_acl.py` | `TestAuthContextCanAccessAccount` | 4 |

**Total: 25 tests minimum**

---

## Test Fixtures Required

Add to `backend/tests/conftest.py`:

```python
@pytest_asyncio.fixture
async def test_cloud_account(
    db_session: AsyncSession,
    test_org: Organization,
) -> CloudAccount:
    """Create a test cloud account."""
    account = CloudAccount(
        id=uuid.uuid4(),
        organization_id=test_org.id,
        name="Test AWS Account",
        provider="aws",
        account_id="123456789012",
        regions=["eu-west-2"],
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(account)
    await db_session.flush()
    return account


@pytest_asyncio.fixture
async def restricted_member(
    db_session: AsyncSession,
    test_org: Organization,
    test_cloud_account: CloudAccount,
) -> tuple[User, OrganizationMember]:
    """Create a member with restricted account access."""
    user = User(
        id=uuid.uuid4(),
        email="restricted@example.com",
        password_hash=AuthService.hash_password("Password123!"),
        email_verified=True,
        is_active=True,
    )
    member = OrganizationMember(
        organization_id=test_org.id,
        user_id=user.id,
        role=UserRole.MEMBER,
        status=MembershipStatus.ACTIVE,
        allowed_account_ids=[str(test_cloud_account.id)],
    )
    db_session.add_all([user, member])
    await db_session.flush()
    return user, member


@pytest_asyncio.fixture
async def api_key_read_scans_only(
    db_session: AsyncSession,
    test_org: Organization,
) -> str:
    """Create an API key with only read:scans scope."""
    from app.models.user import APIKey
    from app.services.auth_service import AuthService

    key = f"dcv_{uuid.uuid4().hex}"
    api_key = APIKey(
        organization_id=test_org.id,
        name="Test Key",
        key_hash=AuthService.hash_token(key),
        scopes=["read:scans"],
        is_active=True,
    )
    db_session.add(api_key)
    await db_session.flush()
    return key
```

---

## Rollback Plan

All changes are code-only and can be reverted via git:
```bash
git revert <commit-hash>
```

No database migrations required.
