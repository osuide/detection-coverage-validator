"""Billing and subscription models."""

import enum
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class AccountTier(str, enum.Enum):
    """Account tier levels."""
    FREE_SCAN = "free_scan"
    SUBSCRIBER = "subscriber"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, enum.Enum):
    """Subscription status."""
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    UNPAID = "unpaid"


# Tier limits configuration
TIER_LIMITS = {
    AccountTier.FREE_SCAN: {
        'cloud_accounts': 1,
        'scans_allowed': 1,
        'results_retention_days': 7,
        'features': {
            'coverage_heatmap': True,
            'gap_list': True,
            'pdf_report': True,
            'historical_trends': False,
            'scheduled_scans': False,
            'alerts': False,
            'api_access': False,
        }
    },
    AccountTier.SUBSCRIBER: {
        'cloud_accounts': 3,
        'scans_allowed': -1,  # Unlimited
        'results_retention_days': -1,  # Forever
        'features': {
            'coverage_heatmap': True,
            'gap_list': True,
            'pdf_report': True,
            'historical_trends': True,
            'scheduled_scans': True,
            'alerts': True,
            'api_access': True,
        }
    },
    AccountTier.ENTERPRISE: {
        'cloud_accounts': -1,  # Unlimited
        'scans_allowed': -1,
        'results_retention_days': -1,
        'features': {
            'all': True,
            'sso': True,
            'sla': True,
        }
    }
}

# Stripe pricing (in cents)
STRIPE_PRICES = {
    'subscriber_monthly': 2900,  # $29.00
    'additional_account_monthly': 900,  # $9.00
}


class Subscription(Base):
    """Organization subscription model."""

    __tablename__ = "subscriptions"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    organization_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True)

    # Stripe fields
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Tier and status
    tier: Mapped[AccountTier] = mapped_column(Enum(AccountTier, name='account_tier', create_type=False), nullable=False, default=AccountTier.FREE_SCAN)
    status: Mapped[SubscriptionStatus] = mapped_column(Enum(SubscriptionStatus, name='subscription_status', create_type=False), nullable=False, default=SubscriptionStatus.ACTIVE)

    # Free scan tracking
    free_scan_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    free_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    free_scan_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Account limits
    included_accounts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    additional_accounts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Billing period
    current_period_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    canceled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Extra data (stored as "metadata" in DB)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    organization = relationship("Organization", back_populates="subscription")

    @property
    def total_accounts_allowed(self) -> int:
        """Total cloud accounts allowed for this subscription."""
        limits = TIER_LIMITS.get(self.tier, TIER_LIMITS[AccountTier.FREE_SCAN])
        base = limits['cloud_accounts']
        if base == -1:  # Unlimited
            return -1
        return base + self.additional_accounts

    @property
    def is_free_scan_expired(self) -> bool:
        """Check if free scan results have expired."""
        if self.tier != AccountTier.FREE_SCAN:
            return False
        if not self.free_scan_expires_at:
            return False
        return datetime.now(self.free_scan_expires_at.tzinfo) > self.free_scan_expires_at

    @property
    def can_scan(self) -> bool:
        """Check if organization can perform a scan."""
        if self.tier == AccountTier.FREE_SCAN:
            return not self.free_scan_used
        return self.status == SubscriptionStatus.ACTIVE

    def use_free_scan(self) -> None:
        """Mark free scan as used and set expiry."""
        from datetime import timezone
        now = datetime.now(timezone.utc)
        self.free_scan_used = True
        self.free_scan_at = now
        self.free_scan_expires_at = now + timedelta(days=7)

    def has_feature(self, feature: str) -> bool:
        """Check if subscription has access to a feature."""
        limits = TIER_LIMITS.get(self.tier, TIER_LIMITS[AccountTier.FREE_SCAN])
        features = limits.get('features', {})
        return features.get(feature, False) or features.get('all', False)


class Invoice(Base):
    """Invoice model for tracking Stripe invoices."""

    __tablename__ = "invoices"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    organization_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)

    stripe_invoice_id: Mapped[str] = mapped_column(String(255), nullable=False)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default='usd')
    status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    invoice_pdf_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hosted_invoice_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    period_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Relationships
    organization = relationship("Organization", back_populates="invoices")

    @property
    def amount_dollars(self) -> float:
        """Amount in dollars."""
        return self.amount_cents / 100.0
