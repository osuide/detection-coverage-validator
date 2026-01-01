"""Billing and subscription API routes."""

from typing import Optional

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import AuthContext, get_client_ip, require_role
from app.core.cache import (
    get_cached_billing_scan_status,
    cache_billing_scan_status,
)
from app.models.user import UserRole, AuditLog, AuditLogAction
from app.services.stripe_service import stripe_service
from app.services.scan_limit_service import ScanLimitService

logger = structlog.get_logger()
router = APIRouter()
settings = get_settings()


# Request/Response Models
class SubscriptionResponse(BaseModel):
    """Subscription info response."""

    id: Optional[str] = None
    tier: str
    tier_display_name: Optional[str] = None
    status: str
    free_scan_used: bool
    free_scan_at: Optional[str] = None
    free_scan_expires_at: Optional[str] = None
    can_scan: bool
    included_accounts: int
    additional_accounts: int
    total_accounts_allowed: int
    # New tier-based limits
    max_accounts: Optional[int] = None
    max_team_members: Optional[int] = None
    org_features_enabled: bool = False
    history_retention_days: Optional[int] = None
    # Billing period
    current_period_start: Optional[str] = None
    current_period_end: Optional[str] = None
    cancel_at_period_end: bool
    has_stripe: bool = False
    # Legacy tier info
    is_legacy_tier: bool = False
    recommended_migration_tier: Optional[str] = None


class CreateCheckoutRequest(BaseModel):
    """Request to create a checkout session."""

    success_url: str
    cancel_url: str
    additional_accounts: int = Field(default=0, ge=0, le=100)


class CheckoutResponse(BaseModel):
    """Checkout session response."""

    checkout_url: str
    session_id: str


class PortalRequest(BaseModel):
    """Request to create a portal session."""

    return_url: str


class PortalResponse(BaseModel):
    """Portal session response."""

    portal_url: str


class InvoiceResponse(BaseModel):
    """Invoice response."""

    id: str
    stripe_invoice_id: str
    amount_cents: int
    amount_pounds: float
    currency: str
    status: Optional[str]
    invoice_pdf_url: Optional[str]
    hosted_invoice_url: Optional[str]
    period_start: Optional[str]
    period_end: Optional[str]
    paid_at: Optional[str]
    created_at: str


class TierPricingInfo(BaseModel):
    """Pricing information for a single tier."""

    tier: str
    display_name: str
    price_monthly_pence: Optional[int]
    price_monthly_pounds: Optional[float]
    max_accounts: Optional[int]  # None = unlimited
    max_team_members: Optional[int]  # None = unlimited
    history_retention_days: Optional[int]  # None = unlimited
    org_features: bool
    is_custom_pricing: bool = False
    key_features: list[str] = []


class PricingResponse(BaseModel):
    """Pricing info response with simplified tiers."""

    # Tier structure
    tiers: list[TierPricingInfo]

    # Legacy pricing (for backward compatibility)
    subscriber_monthly_pence: int
    subscriber_monthly_pounds: float
    enterprise_monthly_pence: Optional[int] = None
    enterprise_monthly_pounds: Optional[float] = None
    additional_account_subscriber_pence: int
    additional_account_subscriber_pounds: float
    free_tier_accounts: int
    subscriber_tier_accounts: int
    enterprise_included_accounts: Optional[int] = None
    free_scan_retention_days: int
    volume_tiers: list[dict] = []


class PricingCalculatorRequest(BaseModel):
    """Request to calculate pricing for a number of accounts."""

    account_count: int = Field(ge=1, le=10000)
    tier: str = Field(pattern="^(free|individual|pro|enterprise|free_scan|subscriber)$")
    wants_org_features: bool = False


class PricingCalculatorResponse(BaseModel):
    """Calculated pricing response."""

    tier: str
    tier_display_name: str
    account_count: int
    included_accounts: Optional[int]
    additional_accounts: int
    base_cost_pence: Optional[int]
    base_cost_pounds: Optional[float]
    additional_cost_pence: int
    additional_cost_pounds: float
    total_cost_pence: Optional[int]
    total_cost_pounds: Optional[float]
    breakdown: list[dict]
    # Upgrade recommendations
    upgrade_required: bool = False
    recommended_tier: Optional[str] = None
    recommended_tier_display_name: Optional[str] = None
    savings_vs_current: Optional[int] = None
    # Legacy tier info
    is_legacy_tier: bool = False
    is_custom_pricing: bool = False


class ScanStatusResponse(BaseModel):
    """Scan usage status response."""

    can_scan: bool  # True if user can start a scan now
    scans_used: int  # Scans used this week
    scans_allowed: Optional[int]  # Weekly limit, None = unlimited
    unlimited: bool  # True if no weekly limits
    next_available_at: Optional[str]  # ISO datetime when next scan available
    week_resets_at: Optional[str]  # ISO datetime when week resets
    total_scans: int  # Lifetime total scans


# Endpoints
@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
    db: AsyncSession = Depends(get_db),
) -> SubscriptionResponse:
    """Get current subscription info."""
    info = await stripe_service.get_subscription_info(db, auth.organization_id)
    return SubscriptionResponse(**info)


@router.get("/scan-status", response_model=ScanStatusResponse)
async def get_scan_status(
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
    db: AsyncSession = Depends(get_db),
) -> ScanStatusResponse:
    """Get scan usage status for the current organisation.

    Returns weekly scan usage and limits for FREE tier users.
    Paid tiers have unlimited scans (is_limited=False).

    Performance: Uses Redis cache with 10s TTL to reduce database load
    during frequent polling. Cache is invalidated when scans are initiated.
    """
    # Try Redis cache first to avoid database queries during polling
    org_id_str = str(auth.organization_id)
    cached = await get_cached_billing_scan_status(org_id_str)
    if cached:
        return ScanStatusResponse(**cached)

    # Cache miss - query database and cache result
    scan_limit_service = ScanLimitService(db)
    status_data = await scan_limit_service.get_scan_status(auth.organization_id)

    # Cache for subsequent polls
    await cache_billing_scan_status(org_id_str, status_data)

    return ScanStatusResponse(**status_data)


@router.get("/pricing", response_model=PricingResponse)
async def get_pricing() -> PricingResponse:
    """Get pricing info with new simplified tier structure."""
    from app.models.billing import (
        STRIPE_PRICES,
        TIER_LIMITS,
        AccountTier,
    )

    # Build tier structure
    tiers = [
        TierPricingInfo(
            tier="free",
            display_name="Free",
            price_monthly_pence=0,
            price_monthly_pounds=0,
            max_accounts=1,
            max_team_members=1,
            history_retention_days=30,
            org_features=False,
            key_features=[
                "1 AWS or GCP account",
                "Coverage heatmap",
                "Gap analysis",
                "PDF reports",
                "Remediation templates",
            ],
        ),
        TierPricingInfo(
            tier="individual",
            display_name="Individual",
            price_monthly_pence=2900,
            price_monthly_pounds=29.00,
            max_accounts=6,
            max_team_members=3,
            history_retention_days=90,
            org_features=False,
            key_features=[
                "Up to 6 accounts",
                "All Free features",
                "Scheduled scans",
                "API access",
                "Historical trends",
                "Alerts & notifications",
            ],
        ),
        TierPricingInfo(
            tier="pro",
            display_name="Pro",
            price_monthly_pence=25000,
            price_monthly_pounds=250.00,
            max_accounts=500,
            max_team_members=10,
            history_retention_days=365,
            org_features=True,
            key_features=[
                "Up to 500 accounts",
                "All Individual features",
                "AWS/GCP Organisation connection",
                "Auto-discovery of accounts",
                "Org-level detection scanning",
                "Unified coverage dashboard",
            ],
        ),
        TierPricingInfo(
            tier="enterprise",
            display_name="Enterprise",
            price_monthly_pence=None,
            price_monthly_pounds=None,
            max_accounts=None,  # Unlimited
            max_team_members=None,  # Unlimited
            history_retention_days=None,  # Unlimited
            org_features=True,
            is_custom_pricing=True,
            key_features=[
                "Unlimited accounts",
                "All Pro features",
                "SSO/SAML integration",
                "Dedicated support",
                "Custom SLAs",
                "Custom integrations",
            ],
        ),
    ]

    return PricingResponse(
        tiers=tiers,
        # Legacy pricing for backward compatibility
        subscriber_monthly_pence=STRIPE_PRICES["subscriber_monthly"],
        subscriber_monthly_pounds=STRIPE_PRICES["subscriber_monthly"] / 100,
        enterprise_monthly_pence=None,  # Custom pricing
        enterprise_monthly_pounds=None,
        additional_account_subscriber_pence=STRIPE_PRICES[
            "additional_account_subscriber"
        ],
        additional_account_subscriber_pounds=STRIPE_PRICES[
            "additional_account_subscriber"
        ]
        / 100,
        free_tier_accounts=TIER_LIMITS[AccountTier.FREE]["max_accounts"],
        subscriber_tier_accounts=TIER_LIMITS[AccountTier.INDIVIDUAL]["max_accounts"],
        enterprise_included_accounts=None,  # Unlimited
        free_scan_retention_days=TIER_LIMITS[AccountTier.FREE][
            "results_retention_days"
        ],
        volume_tiers=[],  # No longer used in simplified model
    )


@router.post("/pricing/calculate", response_model=PricingCalculatorResponse)
async def calculate_pricing(
    body: PricingCalculatorRequest,
) -> PricingCalculatorResponse:
    """Calculate pricing for a given number of accounts and tier."""
    from app.models.billing import AccountTier, calculate_account_cost

    # Map tier strings to enum (supports both new and legacy tiers)
    tier_map = {
        # New tiers
        "free": AccountTier.FREE,
        "individual": AccountTier.INDIVIDUAL,
        "pro": AccountTier.PRO,
        "enterprise": AccountTier.ENTERPRISE,
        # Legacy tiers
        "free_scan": AccountTier.FREE_SCAN,
        "subscriber": AccountTier.SUBSCRIBER,
    }
    tier = tier_map.get(body.tier)
    if not tier:
        raise HTTPException(status_code=400, detail="Invalid tier")

    try:
        result = calculate_account_cost(body.account_count, tier)
    except ValueError as e:
        logger.warning("cost_calculation_failed", error=str(e))
        raise HTTPException(status_code=400, detail="Invalid account count or tier")

    # Format breakdown for response
    breakdown = [
        {
            "description": item[0],
            "quantity": item[1],
            "unit_price_cents": item[2],
            "subtotal_cents": item[3],
        }
        for item in result["breakdown"]
    ]

    # Get tier display names
    tier_display_name = {
        AccountTier.FREE: "Free",
        AccountTier.INDIVIDUAL: "Individual",
        AccountTier.PRO: "Pro",
        AccountTier.ENTERPRISE: "Enterprise",
        AccountTier.FREE_SCAN: "Free (Legacy)",
        AccountTier.SUBSCRIBER: "Subscriber (Legacy)",
    }.get(tier, body.tier.title())

    # Get upgrade recommendation
    recommended_tier = result.get("recommended_tier")
    recommended_tier_display = None
    if recommended_tier:
        recommended_tier_display = {
            "free": "Free",
            "individual": "Individual",
            "pro": "Pro",
            "enterprise": "Enterprise",
        }.get(recommended_tier, recommended_tier.title())

    # Check if org features are requested but tier doesn't support them
    if body.wants_org_features and tier not in [
        AccountTier.PRO,
        AccountTier.ENTERPRISE,
    ]:
        recommended_tier = "pro"
        recommended_tier_display = "Pro"

    # Calculate base and total costs (handle None for Enterprise)
    base_cost_pence = result.get("base_cost_cents")
    total_cost_pence = result.get("total_cost_cents")
    base_cost_pounds = base_cost_pence / 100 if base_cost_pence is not None else None
    total_cost_pounds = total_cost_pence / 100 if total_cost_pence is not None else None

    return PricingCalculatorResponse(
        tier=body.tier,
        tier_display_name=tier_display_name,
        account_count=body.account_count,
        included_accounts=result.get("included_accounts"),
        additional_accounts=result.get("additional_accounts", 0),
        base_cost_pence=base_cost_pence,
        base_cost_pounds=base_cost_pounds,
        additional_cost_pence=result.get("additional_cost_cents", 0),
        additional_cost_pounds=result.get("additional_cost_cents", 0) / 100,
        total_cost_pence=total_cost_pence,
        total_cost_pounds=total_cost_pounds,
        breakdown=breakdown,
        upgrade_required=result.get("upgrade_required", False),
        recommended_tier=recommended_tier,
        recommended_tier_display_name=recommended_tier_display,
        savings_vs_current=None,
        is_legacy_tier=result.get("_legacy_tier", False),
        is_custom_pricing=result.get("is_custom_pricing", False),
    )


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    request: Request,
    body: CreateCheckoutRequest,
    auth: AuthContext = Depends(require_role(UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
) -> CheckoutResponse:
    """Create a Stripe Checkout session for subscription."""
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe billing is not configured",
        )

    try:
        result = await stripe_service.create_checkout_session(
            db=db,
            organization_id=auth.organization_id,
            success_url=body.success_url,
            cancel_url=body.cancel_url,
            customer_email=auth.user.email,
            additional_accounts=body.additional_accounts,
        )

        # Audit log
        audit_log = AuditLog(
            organization_id=auth.organization_id,
            user_id=auth.user.id,
            action=AuditLogAction.ORG_SETTINGS_UPDATED,
            resource_type="billing",
            details={
                "action": "checkout_created",
                "additional_accounts": body.additional_accounts,
            },
            ip_address=get_client_ip(request),
            success=True,
        )
        db.add(audit_log)
        await db.commit()

        return CheckoutResponse(**result)

    except ValueError as e:
        logger.warning("checkout_validation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid checkout request"
        )
    except stripe.error.StripeError as e:
        logger.error("stripe_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to create checkout session",
        )


@router.post("/portal", response_model=PortalResponse)
async def create_portal(
    request: Request,
    body: PortalRequest,
    auth: AuthContext = Depends(require_role(UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
) -> PortalResponse:
    """Create a Stripe Customer Portal session for managing subscription."""
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe billing is not configured",
        )

    try:
        result = await stripe_service.create_portal_session(
            db=db,
            organization_id=auth.organization_id,
            return_url=body.return_url,
        )

        # Audit log
        audit_log = AuditLog(
            organization_id=auth.organization_id,
            user_id=auth.user.id,
            action=AuditLogAction.ORG_SETTINGS_UPDATED,
            resource_type="billing",
            details={"action": "portal_accessed"},
            ip_address=get_client_ip(request),
            success=True,
        )
        db.add(audit_log)
        await db.commit()

        return PortalResponse(**result)

    except ValueError as e:
        logger.warning("portal_validation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid portal request"
        )
    except stripe.error.StripeError as e:
        logger.error("stripe_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to create portal session",
        )


@router.get("/invoices", response_model=list[InvoiceResponse])
async def list_invoices(
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
    limit: int = 10,
) -> list[InvoiceResponse]:
    """List recent invoices."""
    invoices = await stripe_service.get_invoices(db, auth.organization_id, limit)
    return [InvoiceResponse(**inv) for inv in invoices]


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Handle Stripe webhook events."""
    from app.models.billing import ProcessedWebhookEvent

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not settings.stripe_webhook_secret:
        logger.warning("stripe_webhook_secret_not_configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook secret not configured",
        )

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.stripe_webhook_secret
        )
    except ValueError:
        logger.error("stripe_webhook_invalid_payload")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid payload"
        )
    except stripe.error.SignatureVerificationError:
        logger.error("stripe_webhook_invalid_signature")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid signature"
        )

    event_id = event["id"]
    event_type = event["type"]
    data = event["data"]["object"]

    # H11: Check for duplicate event (replay attack prevention)
    existing = await db.execute(
        select(ProcessedWebhookEvent).where(ProcessedWebhookEvent.event_id == event_id)
    )
    if existing.scalar_one_or_none():
        logger.info(
            "stripe_webhook_duplicate",
            event_id=event_id,
            event_type=event_type,
        )
        # Return success - idempotent, event already processed
        return {"status": "already_processed"}

    logger.info("stripe_webhook_received", event_id=event_id, event_type=event_type)

    try:
        if event_type == "checkout.session.completed":
            await stripe_service.handle_checkout_completed(db, data)
        elif event_type == "customer.subscription.updated":
            await stripe_service.handle_subscription_updated(db, data)
        elif event_type == "customer.subscription.deleted":
            await stripe_service.handle_subscription_deleted(db, data)
        elif event_type == "invoice.paid":
            await stripe_service.handle_invoice_paid(db, data)
        elif event_type == "invoice.payment_failed":
            await stripe_service.handle_invoice_payment_failed(db, data)
        else:
            logger.debug("stripe_webhook_unhandled", event_type=event_type)

        # H11: Record event as processed (after successful handling)
        # H12: This happens within the same transaction as the handler's commit
        processed_event = ProcessedWebhookEvent(
            event_id=event_id,
            event_type=event_type,
        )
        db.add(processed_event)
        await db.commit()

    except Exception as e:
        await db.rollback()
        logger.error(
            "stripe_webhook_handler_error",
            event_id=event_id,
            event_type=event_type,
            error=str(e),
            exc_info=True,
        )
        # Return 500 to trigger Stripe retries for failed webhook processing
        # This ensures we don't silently lose billing events
        raise HTTPException(
            status_code=500,
            detail="Webhook processing failed",
        )

    return {"status": "received"}
