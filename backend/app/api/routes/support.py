"""Support API for customer support integration.

This module provides:
1. Internal support API endpoint (support API key auth) for fetching customer context
2. User-facing support endpoints for submitting tickets and getting context

Uses Google Workspace integration for ticket routing and CRM logging.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps.rate_limit import support_ticket_rate_limit
from app.api.routes.auth import get_current_user
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import verify_support_api_key
from app.services.google_workspace_service import sanitise_for_sheets
from app.models.billing import AccountTier, Subscription
from app.models.cloud_account import CloudAccount
from app.models.coverage import CoverageSnapshot
from app.models.detection import Detection

# Note: CoverageGap is for remediation workflow, not coverage calculation
from app.models.scan import Scan
from app.models.user import Organization, OrganizationMember, User

logger = structlog.get_logger()
router = APIRouter(prefix="/support", tags=["support"])
settings = get_settings()

# Rate limiting for support ticket submission
rate_limit_support = support_ticket_rate_limit()


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
    open_gaps: int = Field(0, description="Number of uncovered MITRE ATT&CK techniques")
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

    # Environment info (for correct URL generation)
    environment: str = Field(
        "production", description="Backend environment (staging, production)"
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

            # Get uncovered techniques count from latest coverage snapshots
            # This is the actual number of MITRE techniques without detection coverage
            # (NOT the CoverageGap table, which is for remediation workflow tracking)
            uncovered_result = await db.execute(
                select(func.sum(CoverageSnapshot.uncovered_techniques))
                .join(
                    CloudAccount, CoverageSnapshot.cloud_account_id == CloudAccount.id
                )
                .where(CloudAccount.organization_id == organisation.id)
                .where(
                    CoverageSnapshot.id.in_(
                        select(CoverageSnapshot.id)
                        .where(CoverageSnapshot.cloud_account_id == CloudAccount.id)
                        .order_by(CoverageSnapshot.created_at.desc())
                        .limit(1)
                        .correlate(CloudAccount)
                        .scalar_subquery()
                    )
                )
            )
            open_gaps = uncovered_result.scalar() or 0

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

            # Get actual coverage score from the most recent coverage snapshots
            # This queries the real coverage data, not a simplified formula
            coverage_result = await db.execute(
                select(func.avg(CoverageSnapshot.coverage_percent))
                .join(
                    CloudAccount, CoverageSnapshot.cloud_account_id == CloudAccount.id
                )
                .where(CloudAccount.organization_id == organisation.id)
                .where(
                    CoverageSnapshot.id.in_(
                        select(CoverageSnapshot.id)
                        .where(CoverageSnapshot.cloud_account_id == CloudAccount.id)
                        .order_by(CoverageSnapshot.created_at.desc())
                        .limit(1)
                        .correlate(CloudAccount)
                        .scalar_subquery()
                    )
                )
            )
            avg_coverage = coverage_result.scalar()
            if avg_coverage is not None:
                coverage_score = round(avg_coverage, 1)

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
        # Handle both naive and aware datetimes safely
        created_at_utc = (
            user.created_at.astimezone(timezone.utc)
            if user.created_at.tzinfo
            else user.created_at.replace(tzinfo=timezone.utc)
        )
        delta = datetime.now(timezone.utc) - created_at_utc
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

    # Normalise environment for frontend use
    env = settings.environment.lower()
    if env in ("prod", "production"):
        env = "production"
    elif env in ("staging", "stage"):
        env = "staging"
    # else keep as-is (development, test, etc.)

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
        environment=env,
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
        # Handle both naive and aware datetimes safely
        last_login_utc = (
            user.last_login_at.astimezone(timezone.utc)
            if user.last_login_at.tzinfo
            else user.last_login_at.replace(tzinfo=timezone.utc)
        )
        days_since_login = (datetime.now(timezone.utc) - last_login_utc).days
        if days_since_login > 30:
            notes.append(f"Inactive - last login {days_since_login} days ago")

    return notes


# =========================================================================
# User-Facing Support Endpoints
# =========================================================================


class UserSupportContext(BaseModel):
    """User's support context for form pre-filling."""

    email: str
    full_name: Optional[str] = None
    organisation_name: Optional[str] = None
    tier: str
    tier_display: str
    cloud_accounts_count: int


class SubmitTicketRequest(BaseModel):
    """Request to submit a support ticket."""

    subject: str = Field(..., min_length=5, max_length=200)
    description: str = Field(..., min_length=20, max_length=5000)
    category: str = Field(
        ...,
        pattern="^(billing|technical|feature_request|bug_report|account|integration)$",
    )
    cloud_provider: Optional[str] = Field(None, pattern="^(aws|gcp|multi_cloud)$")


class SubmitTicketResponse(BaseModel):
    """Response after submitting a ticket."""

    ticket_id: str
    message: str
    submitted_at: datetime


@router.get(
    "/context",
    response_model=UserSupportContext,
    summary="Get current user's support context",
    description="Get user context for pre-filling the support form.",
)
async def get_user_support_context(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserSupportContext:
    """Get current user's support context for form pre-fill."""
    # Get organisation membership
    membership_result = await db.execute(
        select(OrganizationMember)
        .where(OrganizationMember.user_id == current_user.id)
        .limit(1)
    )
    membership = membership_result.scalar_one_or_none()

    organisation = None
    subscription = None
    cloud_accounts_count = 0

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

    tier = subscription.tier if subscription else AccountTier.FREE

    return UserSupportContext(
        email=current_user.email,
        full_name=current_user.full_name,
        organisation_name=organisation.name if organisation else None,
        tier=tier.value,
        tier_display=tier.value.title(),
        cloud_accounts_count=cloud_accounts_count,
    )


@router.post(
    "/tickets",
    response_model=SubmitTicketResponse,
    summary="Submit a support ticket",
    description="Submit a support ticket. Logs to CRM and sends email to support.",
    dependencies=[Depends(rate_limit_support)],
)
async def submit_support_ticket(
    request: SubmitTicketRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SubmitTicketResponse:
    """Submit a support ticket.

    This endpoint:
    1. Generates a ticket ID
    2. Logs the ticket to the CRM spreadsheet
    3. Sends an email to support@a13e.com
    """
    # Generate ticket ID
    ticket_id = f"TKT-{uuid.uuid4().hex[:8].upper()}"
    submitted_at = datetime.now(timezone.utc)

    # Get user context for logging
    context = await get_user_support_context(current_user, db)

    # Category display mapping
    category_display = {
        "billing": "Billing",
        "technical": "Technical",
        "feature_request": "Feature Request",
        "bug_report": "Bug Report",
        "account": "Account",
        "integration": "Integration",
    }

    # Track whether critical operations succeeded
    support_email_sent = False
    crm_logged = False

    try:
        from app.services.google_workspace_service import get_workspace_service

        ws = get_workspace_service()
        # Note: Emails are sent FROM the workspace admin (austin@a13e.com) because
        # domain-wide delegation cannot impersonate Google Groups (support@a13e.com).
        # We use reply_to=support@a13e.com so replies go to the support group.

        # Log to CRM spreadsheet if configured (non-critical - continue on failure)
        if settings.support_crm_spreadsheet_id:
            try:
                ws.append_to_sheet(
                    spreadsheet_id=settings.support_crm_spreadsheet_id,
                    sheet_name="Tickets",
                    values=[
                        [
                            ticket_id,
                            submitted_at.isoformat(),
                            sanitise_for_sheets(
                                current_user.email
                            ),  # Prevent formula injection
                            context.tier_display,
                            category_display.get(request.category, request.category),
                            "Normal",  # Default priority
                            "New",  # Initial status
                            sanitise_for_sheets(
                                request.subject
                            ),  # Prevent formula injection
                            sanitise_for_sheets(
                                request.description[:3000]
                            ),  # Truncate + sanitise
                            request.cloud_provider or "N/A",
                            "",  # Assigned To
                            "",  # Resolution Notes
                        ]
                    ],
                )
                crm_logged = True
            except Exception as e:
                logger.error(
                    "support_crm_logging_failed",
                    ticket_id=ticket_id,
                    error=str(e),
                )
                # Continue - CRM logging is not critical

        # Send email to support (CRITICAL - must succeed)
        email_body = f"""
New Support Ticket: {ticket_id}

Customer: {current_user.email}
Name: {context.full_name or 'N/A'}
Organisation: {context.organisation_name or 'N/A'}
Tier: {context.tier_display}
Cloud Accounts: {context.cloud_accounts_count}

Category: {category_display.get(request.category, request.category)}
Cloud Provider: {request.cloud_provider or 'N/A'}

Subject: {request.subject}

Description:
{request.description}

---
Submitted via A13E Support Form at {submitted_at.strftime('%Y-%m-%d %H:%M UTC')}
"""

        ws.send_email(
            to=settings.support_email,
            subject=f"[{ticket_id}] {request.subject}",
            body=email_body,
            from_address=settings.support_email,
            reply_to=settings.support_email,
        )
        support_email_sent = True

        # Send confirmation email to user (non-critical - continue on failure)
        user_confirmation = f"""Hi {context.full_name.split()[0] if context.full_name else 'there'},

Thank you for contacting A13E Support. We've received your request and will get back to you shortly.

Ticket Reference: {ticket_id}
Subject: {request.subject}
Category: {category_display.get(request.category, request.category)}

What happens next:
- Our team will review your request
- You'll receive a response within 24 hours (usually much sooner)
- Reply to this email to add more information to your ticket

If this is urgent, please reply with "URGENT" in the subject line.

Best regards,
The A13E Support Team

---
A13E Detection Coverage Validator
https://app.a13e.com
"""

        try:
            ws.send_email(
                to=current_user.email,
                subject=f"[{ticket_id}] We've received your support request",
                body=user_confirmation,
                from_address=settings.support_email,
                reply_to=settings.support_email,
            )
        except Exception as e:
            # Log error but don't fail if user confirmation fails
            logger.error(
                "support_confirmation_email_failed",
                ticket_id=ticket_id,
                user_email=current_user.email,
                error=str(e),
            )

    except Exception as e:
        logger.error(
            "support_ticket_submission_failed",
            ticket_id=ticket_id,
            support_email_sent=support_email_sent,
            crm_logged=crm_logged,
            error=str(e),
        )
        # If support email wasn't sent, the ticket is lost - return error
        if not support_email_sent:
            raise HTTPException(
                status_code=503,
                detail="Unable to submit support ticket. Please try again or email support@a13e.com directly.",
            )

    return SubmitTicketResponse(
        ticket_id=ticket_id,
        message="Your support ticket has been submitted. We'll respond shortly.",
        submitted_at=submitted_at,
    )


# =========================================================================
# Customer CRM Endpoint
# =========================================================================


class CustomerCRMRecord(BaseModel):
    """Single customer record for CRM."""

    # Identity
    user_id: UUID
    email: EmailStr
    full_name: Optional[str] = None
    organisation_id: Optional[UUID] = None
    organisation_name: Optional[str] = None

    # Registration
    registered_at: datetime
    days_since_registration: int
    registration_source: str  # email, google, github

    # Subscription
    tier: str
    tier_display: str
    subscription_status: str
    is_legacy_tier: bool
    stripe_customer_id: Optional[str] = None

    # Billing Cycle
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    days_until_renewal: Optional[int] = None
    cancel_at_period_end: bool = False
    monthly_value_gbp: float = 0  # £0, £29, £250

    # Usage
    cloud_accounts_count: int = 0
    max_accounts_allowed: int = 1
    accounts_usage_percent: float = 0
    team_members_count: int = 1
    max_team_members: int = 1

    # Engagement
    last_login_at: Optional[datetime] = None
    days_since_login: Optional[int] = None
    total_scans: int = 0
    last_scan_at: Optional[datetime] = None
    scans_last_30_days: int = 0
    coverage_score: Optional[float] = None

    # CRM Signals
    upgrade_opportunity: bool = False
    upgrade_reason: Optional[str] = None
    churn_risk: str = "none"  # none, low, medium, high
    churn_reasons: list[str] = []
    renewal_status: str = (
        "not_applicable"  # not_applicable, ok, upcoming, due_soon, overdue, cancelled
    )

    # Flags
    needs_attention: bool = False
    attention_reasons: list[str] = []


class CRMSummary(BaseModel):
    """Summary statistics for CRM dashboard."""

    total_customers: int
    by_tier: dict[str, int]
    total_mrr_gbp: float
    upgrade_opportunities: int
    churn_risk_high: int
    churn_risk_medium: int
    needs_attention: int
    renewals_this_week: int


class CustomersListResponse(BaseModel):
    """Response for customers list endpoint."""

    customers: list[CustomerCRMRecord]
    total_count: int
    summary: CRMSummary
    environment: str


def _detect_upgrade_opportunity(
    tier: AccountTier,
    accounts_count: int,
    max_accounts: int,
    scans_last_30_days: int,
    team_members: int,
    max_team_members: int,
) -> tuple[bool, Optional[str]]:
    """Detect if customer is an upgrade opportunity.

    Returns (is_opportunity, reason).
    """
    # FREE → INDIVIDUAL triggers
    if tier == AccountTier.FREE:
        if accounts_count >= 1:  # At limit
            return True, "At FREE account limit (1/1)"
        if scans_last_30_days >= 4:  # Weekly user
            return True, "High engagement on FREE tier"

    # INDIVIDUAL → PRO triggers
    elif tier == AccountTier.INDIVIDUAL:
        if accounts_count >= 5:  # 5/6 accounts
            return True, "Near INDIVIDUAL limit (5/6 accounts)"
        if team_members >= 3:  # At team limit
            return True, "At team member limit (3/3)"
        if scans_last_30_days >= 20:  # Daily user
            return True, "Power user - daily scanning"

    # PRO → ENTERPRISE triggers
    elif tier == AccountTier.PRO:
        if accounts_count >= 400:  # 400/500
            return True, "Near PRO limit (400/500 accounts)"
        if team_members >= 8:  # Near limit
            return True, "Near team limit (8/10)"

    return False, None


def _detect_churn_risk(
    tier: AccountTier,
    subscription_status: str,
    days_since_login: Optional[int],
    scans_last_30_days: int,
    cancel_at_period_end: bool,
    days_until_renewal: Optional[int],
) -> tuple[str, list[str]]:
    """Detect churn risk level.

    Returns (risk_level, reasons).
    Risk levels: none, low, medium, high
    """
    reasons = []
    risk_score = 0

    # Payment issues (HIGH risk)
    if subscription_status == "past_due":
        reasons.append("Payment past due")
        risk_score += 50
    elif subscription_status == "unpaid":
        reasons.append("Payment failed")
        risk_score += 70

    # Scheduled cancellation (HIGH risk)
    if cancel_at_period_end:
        reasons.append("Cancellation scheduled")
        risk_score += 60

    # Inactivity (MEDIUM-HIGH risk)
    if days_since_login is not None:
        if days_since_login > 60:
            reasons.append(f"Inactive {days_since_login} days")
            risk_score += 40
        elif days_since_login > 30:
            reasons.append(f"Inactive {days_since_login} days")
            risk_score += 25
        elif days_since_login > 14:
            reasons.append(f"Declining engagement ({days_since_login} days)")
            risk_score += 10

    # No scanning activity (MEDIUM risk for paid tiers)
    if tier != AccountTier.FREE and scans_last_30_days == 0:
        reasons.append("No scans in 30 days")
        risk_score += 20

    # Renewal approaching with risk factors
    if days_until_renewal is not None and days_until_renewal <= 7:
        if risk_score > 0:
            reasons.append(f"Renewal in {days_until_renewal} days with issues")
            risk_score += 15

    # Determine risk level
    if risk_score >= 50:
        return "high", reasons
    elif risk_score >= 25:
        return "medium", reasons
    elif risk_score > 0:
        return "low", reasons
    return "none", []


def _get_renewal_status(
    tier: AccountTier,
    current_period_end: Optional[datetime],
    cancel_at_period_end: bool,
) -> str:
    """Get renewal status."""
    # Free tier doesn't have renewals
    if tier == AccountTier.FREE:
        return "not_applicable"

    if not current_period_end:
        return "not_applicable"

    if cancel_at_period_end:
        return "cancelled"

    now = datetime.now(timezone.utc)
    # Handle timezone-aware comparison
    period_end = (
        current_period_end.astimezone(timezone.utc)
        if current_period_end.tzinfo
        else current_period_end.replace(tzinfo=timezone.utc)
    )
    days_until = (period_end - now).days

    if days_until < 0:
        return "overdue"
    elif days_until <= 3:
        return "due_soon"
    elif days_until <= 7:
        return "upcoming"
    return "ok"


@router.get(
    "/customers",
    response_model=CustomersListResponse,
    summary="Get all customers for CRM",
    description="""
    Fetch all customers with CRM data for support automation.

    This endpoint returns comprehensive customer information including:
    - Subscription and billing status
    - Usage metrics (accounts, team members, scans)
    - Engagement data (last login, scan activity)
    - CRM signals (upgrade opportunities, churn risk)

    Use query parameters to filter results.
    """,
    responses={
        200: {"description": "Customer list retrieved successfully"},
        401: {"description": "Invalid or missing support API key"},
    },
)
async def get_customers_for_crm(
    include_free: bool = Query(True, description="Include free tier users"),
    churn_risk_filter: Optional[str] = Query(
        None, description="Filter by churn risk: none, low, medium, high"
    ),
    upgrade_only: bool = Query(False, description="Only show upgrade opportunities"),
    attention_only: bool = Query(
        False, description="Only show customers needing attention"
    ),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_support_api_key),
) -> CustomersListResponse:
    """Get all customers with CRM data for support automation."""
    from datetime import timedelta

    from app.models.user import MembershipStatus, UserRole

    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)

    # Query all organisation owners (primary account holders)
    query = (
        select(User, Organization, Subscription, OrganizationMember)
        .outerjoin(OrganizationMember, OrganizationMember.user_id == User.id)
        .outerjoin(Organization, Organization.id == OrganizationMember.organization_id)
        .outerjoin(Subscription, Subscription.organization_id == Organization.id)
        .where(OrganizationMember.role == UserRole.OWNER)
        .where(OrganizationMember.status == MembershipStatus.ACTIVE)
    )

    result = await db.execute(query)
    rows = result.all()

    customers: list[CustomerCRMRecord] = []

    for user, org, subscription, membership in rows:
        # Skip if no org (shouldn't happen for owners, but be safe)
        if not org:
            continue

        tier = subscription.tier if subscription else AccountTier.FREE

        # Skip free tier if requested
        if not include_free and tier == AccountTier.FREE:
            continue

        # Get account counts
        accounts_result = await db.execute(
            select(func.count(CloudAccount.id)).where(
                CloudAccount.organization_id == org.id
            )
        )
        accounts_count = accounts_result.scalar() or 0

        # Get team member count
        team_result = await db.execute(
            select(func.count(OrganizationMember.id))
            .where(OrganizationMember.organization_id == org.id)
            .where(OrganizationMember.status == MembershipStatus.ACTIVE)
        )
        team_count = team_result.scalar() or 1

        # Get scan stats
        total_scans_result = await db.execute(
            select(func.count(Scan.id))
            .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
            .where(CloudAccount.organization_id == org.id)
        )
        total_scans = total_scans_result.scalar() or 0

        # Last scan
        last_scan_result = await db.execute(
            select(Scan.created_at)
            .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
            .where(CloudAccount.organization_id == org.id)
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        last_scan_row = last_scan_result.first()
        last_scan_at = last_scan_row[0] if last_scan_row else None

        # Scans last 30 days
        scans_30_result = await db.execute(
            select(func.count(Scan.id))
            .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
            .where(CloudAccount.organization_id == org.id)
            .where(Scan.created_at >= thirty_days_ago)
        )
        scans_last_30 = scans_30_result.scalar() or 0

        # Coverage score (average of latest snapshots)
        coverage_result = await db.execute(
            select(func.avg(CoverageSnapshot.coverage_percent))
            .join(CloudAccount, CoverageSnapshot.cloud_account_id == CloudAccount.id)
            .where(CloudAccount.organization_id == org.id)
        )
        coverage_avg = coverage_result.scalar()
        coverage_score = round(coverage_avg, 1) if coverage_avg else None

        # Calculate derived fields
        max_accounts = subscription.total_accounts_allowed if subscription else 1
        if max_accounts == -1:
            max_accounts = 999999  # Unlimited
        max_team = (
            subscription.max_team_members
            if subscription and subscription.max_team_members
            else 1
        )
        if max_team is None:
            max_team = 999999  # Unlimited

        # Days since login
        days_since_login = None
        if user.last_login_at:
            last_login_utc = (
                user.last_login_at.astimezone(timezone.utc)
                if user.last_login_at.tzinfo
                else user.last_login_at.replace(tzinfo=timezone.utc)
            )
            days_since_login = (now - last_login_utc).days

        # Days until renewal
        days_until_renewal = None
        if subscription and subscription.current_period_end:
            period_end_utc = (
                subscription.current_period_end.astimezone(timezone.utc)
                if subscription.current_period_end.tzinfo
                else subscription.current_period_end.replace(tzinfo=timezone.utc)
            )
            days_until_renewal = (period_end_utc - now).days

        # Days since registration
        created_utc = (
            user.created_at.astimezone(timezone.utc)
            if user.created_at.tzinfo
            else user.created_at.replace(tzinfo=timezone.utc)
        )
        days_since_registration = (now - created_utc).days

        # Detect CRM signals
        upgrade_opp, upgrade_reason = _detect_upgrade_opportunity(
            tier,
            accounts_count,
            max_accounts,
            scans_last_30,
            team_count,
            max_team,
        )

        sub_status = subscription.status.value if subscription else "active"
        churn_risk, churn_reasons = _detect_churn_risk(
            tier,
            sub_status,
            days_since_login,
            scans_last_30,
            subscription.cancel_at_period_end if subscription else False,
            days_until_renewal,
        )

        renewal_status = _get_renewal_status(
            tier,
            subscription.current_period_end if subscription else None,
            subscription.cancel_at_period_end if subscription else False,
        )

        # Calculate monthly value (GBP)
        monthly_value_map = {
            AccountTier.FREE: 0,
            AccountTier.FREE_SCAN: 0,
            AccountTier.INDIVIDUAL: 29,
            AccountTier.SUBSCRIBER: 29,
            AccountTier.PRO: 250,
            AccountTier.ENTERPRISE: 500,  # Placeholder for custom
        }
        monthly_value = monthly_value_map.get(tier, 0)

        # Determine if needs attention
        attention_reasons = []
        if churn_risk in ("medium", "high"):
            attention_reasons.append(f"Churn risk: {churn_risk}")
        if renewal_status in ("due_soon", "overdue"):
            attention_reasons.append(f"Renewal: {renewal_status}")
        if sub_status == "past_due":
            attention_reasons.append("Payment issue")

        # Registration source
        reg_source = user.identity_provider or "email"
        if user.oauth_provider:
            reg_source = user.oauth_provider

        # Build record
        record = CustomerCRMRecord(
            user_id=user.id,
            email=user.email,
            full_name=user.full_name,
            organisation_id=org.id,
            organisation_name=org.name,
            registered_at=user.created_at,
            days_since_registration=days_since_registration,
            registration_source=reg_source,
            tier=tier.value,
            tier_display=tier.value.title(),
            subscription_status=sub_status,
            is_legacy_tier=subscription.is_legacy_tier if subscription else False,
            stripe_customer_id=(
                subscription.stripe_customer_id if subscription else None
            ),
            current_period_start=(
                subscription.current_period_start if subscription else None
            ),
            current_period_end=(
                subscription.current_period_end if subscription else None
            ),
            days_until_renewal=days_until_renewal,
            cancel_at_period_end=(
                subscription.cancel_at_period_end if subscription else False
            ),
            monthly_value_gbp=monthly_value,
            cloud_accounts_count=accounts_count,
            max_accounts_allowed=max_accounts,
            accounts_usage_percent=(
                round((accounts_count / max_accounts) * 100, 1)
                if max_accounts > 0 and max_accounts < 999999
                else 0
            ),
            team_members_count=team_count,
            max_team_members=max_team,
            last_login_at=user.last_login_at,
            days_since_login=days_since_login,
            total_scans=total_scans,
            last_scan_at=last_scan_at,
            scans_last_30_days=scans_last_30,
            coverage_score=coverage_score,
            upgrade_opportunity=upgrade_opp,
            upgrade_reason=upgrade_reason,
            churn_risk=churn_risk,
            churn_reasons=churn_reasons,
            renewal_status=renewal_status,
            needs_attention=len(attention_reasons) > 0,
            attention_reasons=attention_reasons,
        )

        # Apply filters
        if churn_risk_filter and record.churn_risk != churn_risk_filter:
            continue
        if upgrade_only and not record.upgrade_opportunity:
            continue
        if attention_only and not record.needs_attention:
            continue

        customers.append(record)

    # Calculate summary
    all_tiers = [c.tier for c in customers]
    by_tier = {}
    for t in AccountTier:
        by_tier[t.value] = all_tiers.count(t.value)

    summary = CRMSummary(
        total_customers=len(customers),
        by_tier=by_tier,
        total_mrr_gbp=sum(c.monthly_value_gbp for c in customers),
        upgrade_opportunities=len([c for c in customers if c.upgrade_opportunity]),
        churn_risk_high=len([c for c in customers if c.churn_risk == "high"]),
        churn_risk_medium=len([c for c in customers if c.churn_risk == "medium"]),
        needs_attention=len([c for c in customers if c.needs_attention]),
        renewals_this_week=len(
            [
                c
                for c in customers
                if c.days_until_renewal is not None and 0 <= c.days_until_renewal <= 7
            ]
        ),
    )

    # Normalise environment for frontend use
    env = settings.environment.lower()
    if env in ("prod", "production"):
        env = "production"
    elif env in ("staging", "stage"):
        env = "staging"

    return CustomersListResponse(
        customers=customers,
        total_count=len(customers),
        summary=summary,
        environment=env,
    )


# =========================================================================
# Welcome Email Endpoints
# =========================================================================


class NewRegistrationRecord(BaseModel):
    """User record for welcome email sending."""

    user_id: UUID
    email: EmailStr
    full_name: Optional[str] = None
    organisation_name: Optional[str] = None
    registered_at: datetime
    registration_source: str  # email, google, github
    tier: str
    tier_display: str


class NewRegistrationsResponse(BaseModel):
    """Response for new registrations endpoint."""

    registrations: list[NewRegistrationRecord]
    count: int
    environment: str


class WelcomeEmailSentRequest(BaseModel):
    """Request to mark welcome email as sent."""

    user_id: UUID


class WelcomeEmailSentResponse(BaseModel):
    """Response after marking welcome email sent."""

    success: bool
    user_id: UUID
    sent_at: datetime


@router.get(
    "/new-registrations",
    response_model=NewRegistrationsResponse,
    summary="Get users needing welcome emails",
    description="""
    Fetch users who registered but haven't received a welcome email yet.

    Returns users where:
    - welcome_email_sent_at is NULL
    - created_at is within the last 7 days (to avoid spamming old users)

    Called by Apps Script to send AI-personalised welcome emails.
    """,
    responses={
        200: {"description": "New registrations retrieved successfully"},
        401: {"description": "Invalid or missing support API key"},
    },
)
async def get_new_registrations(
    since_days: int = Query(
        7, description="Only include users from last N days", ge=1, le=30
    ),
    limit: int = Query(50, description="Maximum users to return", ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_support_api_key),
) -> NewRegistrationsResponse:
    """Get users who need welcome emails."""
    from datetime import timedelta

    from app.models.user import MembershipStatus, UserRole

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=since_days)

    # Query users who:
    # 1. Have no welcome_email_sent_at
    # 2. Were created after cutoff date
    # 3. Are organisation owners (primary account holders)
    query = (
        select(User, Organization)
        .outerjoin(OrganizationMember, OrganizationMember.user_id == User.id)
        .outerjoin(Organization, Organization.id == OrganizationMember.organization_id)
        .where(User.welcome_email_sent_at.is_(None))
        .where(User.created_at >= cutoff)
        .where(User.is_active == True)  # noqa: E712
        .where(OrganizationMember.role == UserRole.OWNER)
        .where(OrganizationMember.status == MembershipStatus.ACTIVE)
        .order_by(User.created_at.asc())  # Oldest first
        .limit(limit)
    )

    result = await db.execute(query)
    rows = result.all()

    registrations: list[NewRegistrationRecord] = []

    for user, org in rows:
        # Determine registration source
        reg_source = "email"
        if user.identity_provider:
            reg_source = user.identity_provider
        elif user.oauth_provider:
            reg_source = user.oauth_provider

        # Get subscription tier
        tier = "free"
        tier_display = "Free"
        if org:
            sub_result = await db.execute(
                select(Subscription).where(Subscription.organization_id == org.id)
            )
            subscription = sub_result.scalar_one_or_none()
            if subscription:
                tier = subscription.tier.value
                tier_display = subscription.tier.value.title()

        registrations.append(
            NewRegistrationRecord(
                user_id=user.id,
                email=user.email,
                full_name=user.full_name,
                organisation_name=org.name if org else None,
                registered_at=user.created_at,
                registration_source=reg_source,
                tier=tier,
                tier_display=tier_display,
            )
        )

    # Normalise environment
    env = settings.environment.lower()
    if env in ("prod", "production"):
        env = "production"
    elif env in ("staging", "stage"):
        env = "staging"

    return NewRegistrationsResponse(
        registrations=registrations,
        count=len(registrations),
        environment=env,
    )


@router.post(
    "/welcome-email-sent",
    response_model=WelcomeEmailSentResponse,
    summary="Mark welcome email as sent",
    description="""
    Mark a user's welcome email as sent.

    Called by Apps Script after successfully sending the welcome email.
    Sets the welcome_email_sent_at timestamp to prevent duplicate sends.
    """,
    responses={
        200: {"description": "Welcome email marked as sent"},
        401: {"description": "Invalid or missing support API key"},
        404: {"description": "User not found"},
    },
)
async def mark_welcome_email_sent(
    body: WelcomeEmailSentRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_support_api_key),
) -> WelcomeEmailSentResponse:
    """Mark a user's welcome email as sent."""
    # Find the user
    result = await db.execute(select(User).where(User.id == body.user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update the timestamp
    sent_at = datetime.now(timezone.utc)
    user.welcome_email_sent_at = sent_at

    await db.commit()

    logger.info(
        "welcome_email_marked_sent",
        user_id=str(body.user_id),
        email=user.email,
    )

    return WelcomeEmailSentResponse(
        success=True,
        user_id=body.user_id,
        sent_at=sent_at,
    )


# =========================================================================
# Auto-Send Validation Endpoint
# =========================================================================


class AutoSendValidationRequest(BaseModel):
    """Request to validate auto-send eligibility."""

    email: EmailStr = Field(..., description="Customer email address")
    category: str = Field(..., description="Ticket category from AI classification")
    confidence_score: float = Field(
        ..., ge=0.0, le=1.0, description="AI confidence score (0.0-1.0)"
    )
    draft_length: int = Field(
        ..., ge=0, description="Length of draft response in chars"
    )
    ticket_id: str = Field(..., description="Ticket ID for tracking")


class AutoSendValidationResponse(BaseModel):
    """Response for auto-send validation."""

    approved: bool = Field(..., description="Whether auto-send is approved")
    reason: str = Field(..., description="Reason for approval/rejection")


# In-memory rate tracking for anomaly detection
# In production, this should use Redis for persistence across instances
_autosend_validation_cache: dict[str, list[float]] = {}


def _check_anomalous_pattern(email: str) -> tuple[bool, str]:
    """Check for anomalous auto-send validation patterns.

    Returns (is_anomalous, reason).
    """
    import time

    now = time.time()
    hour_ago = now - 3600
    cache_key = email.lower()

    # Get recent requests for this email
    if cache_key not in _autosend_validation_cache:
        _autosend_validation_cache[cache_key] = []

    # Clean old entries
    _autosend_validation_cache[cache_key] = [
        ts for ts in _autosend_validation_cache[cache_key] if ts > hour_ago
    ]

    recent_count = len(_autosend_validation_cache[cache_key])

    # Check for burst (more than 10 requests in an hour from same email)
    if recent_count >= 10:
        return True, f"Anomalous pattern: {recent_count} validation requests in 1 hour"

    # Record this request
    _autosend_validation_cache[cache_key].append(now)

    return False, ""


@router.post(
    "/validate-auto-send",
    response_model=AutoSendValidationResponse,
    summary="Validate auto-send eligibility",
    description="""
    Server-side validation for auto-send eligibility.

    Called by Apps Script before scheduling an auto-send to provide
    an additional layer of validation that cannot be manipulated client-side.

    Validates:
    - Customer exists and is not on free/unknown tier
    - Confidence score is reasonable for the category
    - No anomalous request patterns (rate limiting)

    This is a defence-in-depth measure against potential manipulation
    of the AI classification or confidence scores.
    """,
    responses={
        200: {"description": "Validation result returned"},
        401: {"description": "Invalid or missing support API key"},
    },
)
async def validate_auto_send(
    request: AutoSendValidationRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_support_api_key),
) -> AutoSendValidationResponse:
    """Validate auto-send eligibility from server-side."""
    logger.info(
        "auto_send_validation_request",
        email=request.email,
        category=request.category,
        confidence=request.confidence_score,
        ticket_id=request.ticket_id,
    )

    # Check for anomalous patterns first (rate limiting)
    is_anomalous, anomaly_reason = _check_anomalous_pattern(request.email)
    if is_anomalous:
        logger.warning(
            "auto_send_validation_blocked_anomaly",
            email=request.email,
            reason=anomaly_reason,
            ticket_id=request.ticket_id,
        )
        return AutoSendValidationResponse(approved=False, reason=anomaly_reason)

    # Look up customer
    user_result = await db.execute(select(User).where(User.email == request.email))
    user = user_result.scalar_one_or_none()

    if not user:
        logger.info(
            "auto_send_validation_rejected_unknown",
            email=request.email,
            ticket_id=request.ticket_id,
        )
        return AutoSendValidationResponse(
            approved=False, reason="Unknown customer - requires manual review"
        )

    # Get organisation and subscription
    membership_result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == user.id).limit(1)
    )
    membership = membership_result.scalar_one_or_none()

    tier = AccountTier.FREE
    if membership:
        org_result = await db.execute(
            select(Organization).where(Organization.id == membership.organization_id)
        )
        organisation = org_result.scalar_one_or_none()

        if organisation:
            sub_result = await db.execute(
                select(Subscription).where(
                    Subscription.organization_id == organisation.id
                )
            )
            subscription = sub_result.scalar_one_or_none()
            if subscription:
                tier = subscription.tier

    # Block free tier (should require paid subscription for auto-responses)
    if tier == AccountTier.FREE:
        logger.info(
            "auto_send_validation_rejected_free_tier",
            email=request.email,
            ticket_id=request.ticket_id,
        )
        return AutoSendValidationResponse(
            approved=False, reason="Free tier customers require manual response"
        )

    # Validate confidence score reasonableness
    # Very high confidence (>0.98) on typically complex categories is suspicious
    complex_categories = ["bug_report", "bug-report", "security", "technical"]
    if (
        request.category.lower() in complex_categories
        and request.confidence_score > 0.98
    ):
        logger.warning(
            "auto_send_validation_suspicious_confidence",
            email=request.email,
            category=request.category,
            confidence=request.confidence_score,
            ticket_id=request.ticket_id,
        )
        return AutoSendValidationResponse(
            approved=False,
            reason=f"Unusually high confidence ({request.confidence_score:.2f}) for {request.category}",
        )

    # Validate draft length (too short or too long is suspicious)
    if request.draft_length < 50:
        return AutoSendValidationResponse(
            approved=False, reason="Draft too short for auto-send"
        )
    if request.draft_length > 5000:
        return AutoSendValidationResponse(
            approved=False, reason="Draft too long for auto-send"
        )

    # All checks passed
    logger.info(
        "auto_send_validation_approved",
        email=request.email,
        category=request.category,
        confidence=request.confidence_score,
        tier=tier.value,
        ticket_id=request.ticket_id,
    )

    return AutoSendValidationResponse(
        approved=True,
        reason=f"Approved for {tier.value} tier customer",
    )
