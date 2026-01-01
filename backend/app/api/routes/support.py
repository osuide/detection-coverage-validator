"""Support context API for customer support integration.

This module provides a dedicated API endpoint for the Google Workspace
support system to fetch customer context. It is authenticated via a
separate support API key to ensure security isolation.
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.security import verify_support_api_key
from app.models.billing import AccountTier, Subscription
from app.models.cloud_account import CloudAccount
from app.models.coverage import Detection
from app.models.gap import CoverageGap
from app.models.scan import Scan
from app.models.user import Organization, OrganizationMember, User

router = APIRouter(prefix="/support", tags=["support"])


class RecentScanInfo(BaseModel):
    """Summary of a recent scan."""

    id: str
    status: str
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    detections_found: int = 0
    errors_count: int = 0


class CustomerContextResponse(BaseModel):
    """Customer context for support tickets.

    This response provides comprehensive customer information to help
    support staff understand the customer's situation quickly.
    """

    email: EmailStr = Field(..., description="Customer email address")
    user_id: Optional[UUID] = Field(None, description="User ID in the system")
    organisation_id: Optional[UUID] = Field(None, description="Organisation ID")
    organisation_name: Optional[str] = Field(None, description="Organisation name")

    # Subscription information
    tier: str = Field(
        ..., description="Subscription tier (free, individual, pro, enterprise)"
    )
    tier_display: str = Field(..., description="Human-readable tier name")
    is_legacy_tier: bool = Field(False, description="Whether on a deprecated tier")
    subscription_status: str = Field("active", description="Subscription status")

    # Account limits and usage
    cloud_accounts_count: int = Field(
        0, description="Number of connected cloud accounts"
    )
    max_accounts_allowed: int = Field(1, description="Maximum accounts for tier")
    accounts_usage_percent: float = Field(
        0, description="Percentage of account limit used"
    )

    # Coverage metrics
    coverage_score: Optional[float] = Field(
        None, description="Overall coverage score (0-100)"
    )
    open_gaps: int = Field(0, description="Number of unresolved coverage gaps")
    total_detections: int = Field(0, description="Total security detections found")

    # Activity information
    last_scan: Optional[datetime] = Field(
        None, description="Most recent scan timestamp"
    )
    last_scan_status: Optional[str] = Field(None, description="Status of last scan")
    last_login: Optional[datetime] = Field(None, description="Last user login")
    account_created: Optional[datetime] = Field(
        None, description="Account creation date"
    )
    days_since_registration: Optional[int] = Field(
        None, description="Days since signup"
    )

    # Account status
    is_active: bool = Field(True, description="Whether account is active")
    email_verified: bool = Field(False, description="Whether email is verified")
    mfa_enabled: bool = Field(False, description="Whether MFA is enabled")

    # Recent activity
    recent_scans: list[RecentScanInfo] = Field(
        default_factory=list, description="Last 5 scans"
    )

    # Support notes (auto-generated)
    notes: list[str] = Field(
        default_factory=list, description="Contextual notes for support"
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "email": "customer@example.com",
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "organisation_id": "123e4567-e89b-12d3-a456-426614174001",
                "organisation_name": "Acme Security Ltd",
                "tier": "individual",
                "tier_display": "Individual",
                "is_legacy_tier": False,
                "subscription_status": "active",
                "cloud_accounts_count": 4,
                "max_accounts_allowed": 6,
                "accounts_usage_percent": 66.7,
                "coverage_score": 72.5,
                "open_gaps": 15,
                "total_detections": 142,
                "last_scan": "2026-01-01T10:30:00Z",
                "last_scan_status": "completed",
                "last_login": "2026-01-01T09:00:00Z",
                "account_created": "2025-06-15T14:20:00Z",
                "days_since_registration": 200,
                "is_active": True,
                "email_verified": True,
                "mfa_enabled": True,
                "recent_scans": [
                    {
                        "id": "scan-123",
                        "status": "completed",
                        "created_at": "2026-01-01T10:30:00Z",
                        "detections_found": 42,
                        "errors_count": 0,
                    }
                ],
                "notes": ["MFA enabled", "At 67% account limit"],
            }
        }


@router.get(
    "/customer-context",
    response_model=CustomerContextResponse,
    summary="Get customer context for support",
    description="""
    Fetch comprehensive customer context for support ticket handling.

    This endpoint is authenticated via a dedicated support API key
    (X-Support-API-Key header), separate from regular user authentication.

    Returns:
    - Subscription and billing information
    - Cloud account statistics
    - Recent scan activity
    - Coverage metrics
    - Auto-generated support notes
    """,
    responses={
        200: {"description": "Customer context retrieved successfully"},
        401: {"description": "Invalid or missing support API key"},
        404: {"description": "Customer not found"},
        503: {"description": "Support API not configured"},
    },
)
async def get_customer_context(
    email: EmailStr = Query(..., description="Customer email address"),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_support_api_key),
) -> CustomerContextResponse:
    """Get customer context for support ticket handling."""
    # Find user by email
    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="Customer not found")

    # Get organisation membership
    membership_result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == user.id).limit(1)
    )
    membership = membership_result.scalar_one_or_none()

    organisation = None
    subscription = None
    cloud_accounts_count = 0
    total_detections = 0
    open_gaps = 0
    coverage_score = None
    recent_scans: list[RecentScanInfo] = []
    last_scan = None
    last_scan_status = None

    if membership:
        # Get organisation
        org_result = await db.execute(
            select(Organization).where(Organization.id == membership.organization_id)
        )
        organisation = org_result.scalar_one_or_none()

        if organisation:
            # Get subscription
            sub_result = await db.execute(
                select(Subscription).where(
                    Subscription.organization_id == organisation.id
                )
            )
            subscription = sub_result.scalar_one_or_none()

            # Count cloud accounts
            accounts_result = await db.execute(
                select(func.count(CloudAccount.id)).where(
                    CloudAccount.organization_id == organisation.id
                )
            )
            cloud_accounts_count = accounts_result.scalar() or 0

            # Count detections
            detections_result = await db.execute(
                select(func.count(Detection.id))
                .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
                .where(CloudAccount.organization_id == organisation.id)
            )
            total_detections = detections_result.scalar() or 0

            # Count open gaps
            gaps_result = await db.execute(
                select(func.count(CoverageGap.id))
                .join(CloudAccount, CoverageGap.cloud_account_id == CloudAccount.id)
                .where(CloudAccount.organization_id == organisation.id)
                .where(CoverageGap.status == "open")
            )
            open_gaps = gaps_result.scalar() or 0

            # Get recent scans
            scans_result = await db.execute(
                select(Scan)
                .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
                .where(CloudAccount.organization_id == organisation.id)
                .order_by(Scan.created_at.desc())
                .limit(5)
            )
            scans = scans_result.scalars().all()
            recent_scans = [
                RecentScanInfo(
                    id=str(scan.id),
                    status=scan.status.value,
                    created_at=scan.created_at,
                    completed_at=scan.completed_at,
                    detections_found=scan.detections_found or 0,
                    errors_count=len(scan.errors) if scan.errors else 0,
                )
                for scan in scans
            ]

            if recent_scans:
                last_scan = recent_scans[0].created_at
                last_scan_status = recent_scans[0].status

            # Calculate average coverage score (simplified)
            if total_detections > 0:
                coverage_score = round(
                    (total_detections / (total_detections + open_gaps)) * 100, 1
                )

    # Build tier information
    tier = subscription.tier if subscription else AccountTier.FREE
    tier_display = tier.value.title()
    max_accounts = subscription.total_accounts_allowed if subscription else 1
    if max_accounts == -1:
        max_accounts = 999999  # Unlimited

    # Calculate usage percentage
    accounts_usage_percent = 0.0
    if max_accounts > 0 and max_accounts < 999999:
        accounts_usage_percent = round((cloud_accounts_count / max_accounts) * 100, 1)

    # Days since registration
    days_since_registration = None
    if user.created_at:
        delta = datetime.now(timezone.utc) - user.created_at.replace(
            tzinfo=timezone.utc
        )
        days_since_registration = delta.days

    # Build notes for support context
    notes = _build_support_notes(
        user=user,
        subscription=subscription,
        cloud_accounts_count=cloud_accounts_count,
        max_accounts=max_accounts,
        recent_scans=recent_scans,
        open_gaps=open_gaps,
    )

    return CustomerContextResponse(
        email=email,
        user_id=user.id,
        organisation_id=organisation.id if organisation else None,
        organisation_name=organisation.name if organisation else None,
        tier=tier.value,
        tier_display=tier_display,
        is_legacy_tier=subscription.is_legacy_tier if subscription else False,
        subscription_status=subscription.status.value if subscription else "active",
        cloud_accounts_count=cloud_accounts_count,
        max_accounts_allowed=max_accounts,
        accounts_usage_percent=accounts_usage_percent,
        coverage_score=coverage_score,
        open_gaps=open_gaps,
        total_detections=total_detections,
        last_scan=last_scan,
        last_scan_status=last_scan_status,
        last_login=user.last_login_at,
        account_created=user.created_at,
        days_since_registration=days_since_registration,
        is_active=user.is_active,
        email_verified=user.email_verified,
        mfa_enabled=user.mfa_enabled,
        recent_scans=recent_scans,
        notes=notes,
    )


def _build_support_notes(
    user: User,
    subscription: Optional[Subscription],
    cloud_accounts_count: int,
    max_accounts: int,
    recent_scans: list[RecentScanInfo],
    open_gaps: int,
) -> list[str]:
    """Build contextual notes for support staff."""
    notes = []

    # Subscription notes
    if subscription:
        if subscription.is_legacy_tier and subscription.migration_tier:
            notes.append(
                f"Legacy tier - recommend migration to {subscription.migration_tier.value}"
            )
        if subscription.cancel_at_period_end:
            notes.append("Subscription scheduled for cancellation")
        if subscription.status.value == "past_due":
            notes.append("PAYMENT PAST DUE - billing issue")

    # Account status notes
    if not user.email_verified:
        notes.append("Email not verified")
    if user.mfa_enabled:
        notes.append("MFA enabled")
    if not user.is_active:
        notes.append("ACCOUNT DISABLED")

    # Usage notes
    if max_accounts < 999999:
        usage_percent = (cloud_accounts_count / max_accounts) * 100
        if usage_percent >= 100:
            notes.append("AT ACCOUNT LIMIT - upgrade may be needed")
        elif usage_percent >= 80:
            notes.append(f"Near account limit ({usage_percent:.0f}%)")

    # Scan activity notes
    if recent_scans:
        failed_scans = [s for s in recent_scans if s.status == "failed"]
        if len(failed_scans) >= 2:
            notes.append(
                f"Multiple failed scans ({len(failed_scans)}/5) - may need troubleshooting"
            )
        if recent_scans[0].errors_count > 0:
            notes.append(f"Last scan had {recent_scans[0].errors_count} errors")
    else:
        notes.append("No scans yet - new user or setup issue")

    # Coverage notes
    if open_gaps > 50:
        notes.append(f"High gap count ({open_gaps}) - potential concern")

    # Engagement notes
    if user.last_login_at:
        days_since_login = (
            datetime.now(timezone.utc) - user.last_login_at.replace(tzinfo=timezone.utc)
        ).days
        if days_since_login > 30:
            notes.append(f"Inactive - last login {days_since_login} days ago")

    return notes
