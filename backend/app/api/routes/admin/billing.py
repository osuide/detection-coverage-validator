"""Admin billing routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser
from app.models.user import Organization
from app.models.billing import Subscription, AccountTier, SubscriptionStatus
from app.api.deps import get_current_admin

router = APIRouter(prefix="/billing", tags=["Admin Billing"])


class BillingStatsResponse(BaseModel):
    """Billing stats response."""
    total_revenue: float
    mrr: float
    active_subscriptions: int
    trial_subscriptions: int
    churned_this_month: int
    new_this_month: int


class SubscriptionResponse(BaseModel):
    """Subscription response."""
    id: str
    organization_id: str
    organization_name: str
    plan: str
    status: str
    current_period_end: str
    amount: float
    created_at: str


class SubscriptionsListResponse(BaseModel):
    """Subscriptions list response."""
    subscriptions: list[SubscriptionResponse]
    total: int


# Pricing for tiers (monthly in dollars)
TIER_PRICING = {
    AccountTier.FREE_SCAN: 0,
    AccountTier.SUBSCRIBER: 49,
    AccountTier.ENTERPRISE: 499,
}


@router.get("/stats", response_model=BillingStatsResponse)
async def get_billing_stats(
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get billing statistics."""
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    # Count active subscriptions
    active_result = await db.execute(
        select(func.count(Subscription.id)).where(
            Subscription.status == SubscriptionStatus.ACTIVE
        )
    )
    active_subscriptions = active_result.scalar() or 0

    # Trial subscriptions - not applicable with current model
    trial_subscriptions = 0

    # Count churned this month
    churned_result = await db.execute(
        select(func.count(Subscription.id)).where(
            and_(
                Subscription.status == SubscriptionStatus.CANCELED,
                Subscription.updated_at >= month_start,
            )
        )
    )
    churned_this_month = churned_result.scalar() or 0

    # Count new this month
    new_result = await db.execute(
        select(func.count(Subscription.id)).where(
            Subscription.created_at >= month_start
        )
    )
    new_this_month = new_result.scalar() or 0

    # Calculate MRR (sum of active subscriptions)
    mrr = 0.0
    subscriptions_result = await db.execute(
        select(Subscription).where(
            Subscription.status == SubscriptionStatus.ACTIVE
        )
    )
    active_subs = subscriptions_result.scalars().all()
    for sub in active_subs:
        mrr += TIER_PRICING.get(sub.tier, 0)

    return BillingStatsResponse(
        total_revenue=mrr * 12,  # Estimate ARR
        mrr=mrr,
        active_subscriptions=active_subscriptions,
        trial_subscriptions=trial_subscriptions,
        churned_this_month=churned_this_month,
        new_this_month=new_this_month,
    )


@router.get("/subscriptions", response_model=SubscriptionsListResponse)
async def list_subscriptions(
    limit: int = Query(20, ge=1, le=100),
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """List recent subscriptions."""
    query = (
        select(Subscription, Organization)
        .join(Organization, Subscription.organization_id == Organization.id)
        .order_by(Subscription.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(query)
    rows = result.all()

    subscriptions = []
    for sub, org in rows:
        subscriptions.append(
            SubscriptionResponse(
                id=str(sub.id),
                organization_id=str(sub.organization_id),
                organization_name=org.name,
                plan=sub.tier.value if sub.tier else "free",
                status=sub.status.value if sub.status else "unknown",
                current_period_end=sub.current_period_end.isoformat() if sub.current_period_end else "",
                amount=TIER_PRICING.get(sub.tier, 0),
                created_at=sub.created_at.isoformat() if sub.created_at else "",
            )
        )

    return SubscriptionsListResponse(
        subscriptions=subscriptions,
        total=len(subscriptions),
    )
