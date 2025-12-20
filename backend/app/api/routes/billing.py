"""Billing and subscription API routes."""

from typing import Optional

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import AuthContext, require_role
from app.models.user import UserRole, AuditLog, AuditLogAction
from app.services.stripe_service import stripe_service

logger = structlog.get_logger()
router = APIRouter()
settings = get_settings()


# Request/Response Models
class SubscriptionResponse(BaseModel):
    """Subscription info response."""

    id: Optional[str] = None
    tier: str
    status: str
    free_scan_used: bool
    free_scan_at: Optional[str] = None
    free_scan_expires_at: Optional[str] = None
    can_scan: bool
    included_accounts: int
    additional_accounts: int
    total_accounts_allowed: int
    current_period_start: Optional[str] = None
    current_period_end: Optional[str] = None
    cancel_at_period_end: bool
    has_stripe: bool = False


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
    amount_dollars: float
    currency: str
    status: Optional[str]
    invoice_pdf_url: Optional[str]
    hosted_invoice_url: Optional[str]
    period_start: Optional[str]
    period_end: Optional[str]
    paid_at: Optional[str]
    created_at: str


class PricingResponse(BaseModel):
    """Pricing info response."""

    subscriber_monthly_cents: int
    subscriber_monthly_dollars: float
    enterprise_monthly_cents: int
    enterprise_monthly_dollars: float
    additional_account_subscriber_cents: int
    additional_account_subscriber_dollars: float
    free_tier_accounts: int
    subscriber_tier_accounts: int
    enterprise_included_accounts: int
    free_scan_retention_days: int
    volume_tiers: list[dict]


class PricingCalculatorRequest(BaseModel):
    """Request to calculate pricing for a number of accounts."""

    account_count: int = Field(ge=1, le=10000)
    tier: str = Field(pattern="^(free_scan|subscriber|enterprise)$")


class PricingCalculatorResponse(BaseModel):
    """Calculated pricing response."""

    tier: str
    account_count: int
    included_accounts: int
    additional_accounts: int
    base_cost_cents: int
    base_cost_dollars: float
    additional_cost_cents: int
    additional_cost_dollars: float
    total_cost_cents: int
    total_cost_dollars: float
    breakdown: list[dict]
    recommended_tier: Optional[str] = None
    savings_vs_current: Optional[int] = None


# Endpoints
@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
    db: AsyncSession = Depends(get_db),
):
    """Get current subscription info."""
    info = await stripe_service.get_subscription_info(db, auth.organization_id)
    return SubscriptionResponse(**info)


@router.get("/pricing", response_model=PricingResponse)
async def get_pricing():
    """Get pricing info (public endpoint within authenticated context)."""
    from app.models.billing import (
        STRIPE_PRICES,
        TIER_LIMITS,
        ACCOUNT_VOLUME_TIERS,
        AccountTier,
    )

    # Format volume tiers for response
    volume_tiers = []
    prev_max = 0
    for max_accounts, price_cents in ACCOUNT_VOLUME_TIERS:
        if max_accounts == 0:
            continue
        tier_info = {
            "min_accounts": prev_max + 1,
            "max_accounts": max_accounts if max_accounts else "unlimited",
            "price_per_account_cents": price_cents,
            "price_per_account_dollars": price_cents / 100 if price_cents else 0,
        }
        if max_accounts is None:
            tier_info["label"] = f"{prev_max + 1}+ accounts"
        elif price_cents == 0:
            tier_info["label"] = f"1-{max_accounts} accounts (included)"
        else:
            tier_info["label"] = f"{prev_max + 1}-{max_accounts} accounts"
        volume_tiers.append(tier_info)
        prev_max = max_accounts if max_accounts else prev_max

    return PricingResponse(
        subscriber_monthly_cents=STRIPE_PRICES["subscriber_monthly"],
        subscriber_monthly_dollars=STRIPE_PRICES["subscriber_monthly"] / 100,
        enterprise_monthly_cents=STRIPE_PRICES["enterprise_monthly"],
        enterprise_monthly_dollars=STRIPE_PRICES["enterprise_monthly"] / 100,
        additional_account_subscriber_cents=STRIPE_PRICES[
            "additional_account_subscriber"
        ],
        additional_account_subscriber_dollars=STRIPE_PRICES[
            "additional_account_subscriber"
        ]
        / 100,
        free_tier_accounts=TIER_LIMITS[AccountTier.FREE_SCAN]["included_accounts"],
        subscriber_tier_accounts=TIER_LIMITS[AccountTier.SUBSCRIBER][
            "included_accounts"
        ],
        enterprise_included_accounts=TIER_LIMITS[AccountTier.ENTERPRISE][
            "included_accounts"
        ],
        free_scan_retention_days=TIER_LIMITS[AccountTier.FREE_SCAN][
            "results_retention_days"
        ],
        volume_tiers=volume_tiers,
    )


@router.post("/pricing/calculate", response_model=PricingCalculatorResponse)
async def calculate_pricing(body: PricingCalculatorRequest):
    """Calculate pricing for a given number of accounts and tier."""
    from app.models.billing import AccountTier, calculate_account_cost

    tier_map = {
        "free_scan": AccountTier.FREE_SCAN,
        "subscriber": AccountTier.SUBSCRIBER,
        "enterprise": AccountTier.ENTERPRISE,
    }
    tier = tier_map.get(body.tier)
    if not tier:
        raise HTTPException(status_code=400, detail="Invalid tier")

    try:
        result = calculate_account_cost(body.account_count, tier)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

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

    # Calculate recommended tier if applicable
    recommended_tier = None
    savings = None

    if body.account_count > 1 and tier == AccountTier.FREE_SCAN:
        recommended_tier = "subscriber"
    elif body.account_count > 3 and tier == AccountTier.SUBSCRIBER:
        # Compare subscriber vs enterprise cost
        sub_cost = calculate_account_cost(body.account_count, AccountTier.SUBSCRIBER)
        ent_cost = calculate_account_cost(body.account_count, AccountTier.ENTERPRISE)
        if ent_cost["total_cost_cents"] < sub_cost["total_cost_cents"]:
            recommended_tier = "enterprise"
            savings = sub_cost["total_cost_cents"] - ent_cost["total_cost_cents"]

    return PricingCalculatorResponse(
        tier=body.tier,
        account_count=body.account_count,
        included_accounts=result["included_accounts"],
        additional_accounts=result["additional_accounts"],
        base_cost_cents=result["base_cost_cents"],
        base_cost_dollars=result["base_cost_cents"] / 100,
        additional_cost_cents=result["additional_cost_cents"],
        additional_cost_dollars=result["additional_cost_cents"] / 100,
        total_cost_cents=result["total_cost_cents"],
        total_cost_dollars=result["total_cost_cents"] / 100,
        breakdown=breakdown,
        recommended_tier=recommended_tier,
        savings_vs_current=savings,
    )


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    request: Request,
    body: CreateCheckoutRequest,
    auth: AuthContext = Depends(require_role(UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
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
            ip_address=request.client.host if request.client else None,
            success=True,
        )
        db.add(audit_log)
        await db.commit()

        return CheckoutResponse(**result)

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
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
):
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
            ip_address=request.client.host if request.client else None,
            success=True,
        )
        db.add(audit_log)
        await db.commit()

        return PortalResponse(**result)

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
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
):
    """List recent invoices."""
    invoices = await stripe_service.get_invoices(db, auth.organization_id, limit)
    return [InvoiceResponse(**inv) for inv in invoices]


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Handle Stripe webhook events."""
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

    event_type = event["type"]
    data = event["data"]["object"]

    logger.info("stripe_webhook_received", event_type=event_type)

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

    except Exception as e:
        logger.error(
            "stripe_webhook_handler_error", event_type=event_type, error=str(e)
        )
        # Return 200 to prevent Stripe retries for non-critical errors
        # In production, you might want to handle this differently

    return {"status": "received"}
