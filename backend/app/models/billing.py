"""Billing and subscription models."""

import enum
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class AccountTier(str, enum.Enum):
    """
    Account tier levels.

    New simplified tier structure (2024-12):
    - FREE: 1 account, basic features
    - INDIVIDUAL: Up to 6 accounts, full account-level features
    - PRO: Up to 500 accounts, organisation-level features
    - ENTERPRISE: Unlimited, SSO, dedicated support

    Legacy tiers (deprecated, but supported for migration):
    - FREE_SCAN: Maps to FREE
    - SUBSCRIBER: Maps to INDIVIDUAL
    """

    # New tiers
    FREE = "free"
    INDIVIDUAL = "individual"
    PRO = "pro"
    ENTERPRISE = "enterprise"

    # Legacy tiers (kept for backward compatibility during migration)
    FREE_SCAN = "free_scan"
    SUBSCRIBER = "subscriber"


class SubscriptionStatus(str, enum.Enum):
    """Subscription status."""

    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    UNPAID = "unpaid"


# Tier limits configuration
# Note: For the canonical tier configuration, see app.core.billing_config.TIER_CONFIG
# This TIER_LIMITS dict maintains backward compatibility with existing code
TIER_LIMITS = {
    # New tiers
    AccountTier.FREE: {
        "cloud_accounts": 1,
        "included_accounts": 1,
        "max_accounts": 1,
        "max_team_members": 1,
        "scans_allowed": -1,  # Unlimited scans
        "results_retention_days": 30,
        "org_discovery": False,
        "features": {
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "remediation_templates": True,
            "historical_trends": False,
            "scheduled_scans": False,
            "alerts": False,
            "api_access": False,
            "org_features": False,
            "org_scanning": False,
            "code_analysis": False,
        },
    },
    AccountTier.INDIVIDUAL: {
        "cloud_accounts": 6,
        "included_accounts": 6,
        "max_accounts": 6,
        "max_team_members": 3,
        "scans_allowed": -1,  # Unlimited
        "results_retention_days": 90,
        "org_discovery": False,  # No org features at Individual tier
        "features": {
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "remediation_templates": True,
            "historical_trends": True,
            "scheduled_scans": True,
            "alerts": True,
            "api_access": True,
            "export_reports": True,
            "code_analysis": True,
            "org_features": False,
            "org_scanning": False,
        },
    },
    AccountTier.PRO: {
        "cloud_accounts": 500,
        "included_accounts": 500,
        "max_accounts": 500,
        "max_team_members": 10,
        "scans_allowed": -1,  # Unlimited
        "results_retention_days": 365,  # 1 year
        "org_discovery": True,
        "features": {
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "remediation_templates": True,
            "historical_trends": True,
            "scheduled_scans": True,
            "alerts": True,
            "api_access": True,
            "export_reports": True,
            "code_analysis": True,
            "org_features": True,
            "org_scanning": True,
            "org_dashboard": True,
            "auto_discovery": True,
            "delegated_scanning": True,
        },
    },
    AccountTier.ENTERPRISE: {
        "cloud_accounts": None,  # Unlimited (None = unlimited)
        "included_accounts": None,  # Unlimited
        "max_accounts": None,  # Unlimited (500+)
        "max_team_members": None,  # Unlimited
        "scans_allowed": None,  # Unlimited
        "results_retention_days": None,  # Unlimited
        "org_discovery": True,
        "features": {
            "all": True,
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "remediation_templates": True,
            "historical_trends": True,
            "scheduled_scans": True,
            "alerts": True,
            "api_access": True,
            "export_reports": True,
            "code_analysis": True,
            "org_features": True,
            "org_scanning": True,
            "org_dashboard": True,
            "auto_discovery": True,
            "delegated_scanning": True,
            "sso": True,
            "sla": True,
            "unlimited_accounts": True,
            "dedicated_support": True,
            "custom_integrations": True,
        },
    },
    # Legacy tiers (deprecated, kept for backward compatibility)
    AccountTier.FREE_SCAN: {
        "cloud_accounts": 1,
        "included_accounts": 1,
        "max_accounts": 1,
        "max_team_members": 1,
        "scans_allowed": 1,
        "results_retention_days": 7,
        "org_discovery": False,
        "_deprecated": True,
        "_migrate_to": AccountTier.FREE,
        "features": {
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "historical_trends": False,
            "scheduled_scans": False,
            "alerts": False,
            "api_access": False,
            "org_scanning": False,
        },
    },
    AccountTier.SUBSCRIBER: {
        "cloud_accounts": 3,  # Base included accounts
        "included_accounts": 3,
        "max_accounts": 3,
        "max_team_members": 3,
        "scans_allowed": -1,  # Unlimited
        "results_retention_days": -1,  # Forever
        "org_discovery": True,
        "_deprecated": True,
        "_migrate_to": AccountTier.INDIVIDUAL,
        "features": {
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "historical_trends": True,
            "scheduled_scans": True,
            "alerts": True,
            "api_access": True,
            "code_analysis": True,
            "org_features": True,  # Legacy SUBSCRIBER had org features
            "org_scanning": True,
        },
    },
}

# Stripe pricing (in cents)
# New simplified pricing model
STRIPE_PRICES = {
    # New tiers
    "free_monthly": 0,
    "individual_monthly": 2900,  # $29.00/month (up to 6 accounts)
    "pro_monthly": 25000,  # $250.00/month (up to 500 accounts)
    "enterprise_monthly": None,  # Custom pricing (contact sales)
    # Legacy tiers (for backward compatibility)
    "subscriber_monthly": 2900,  # $29.00/month base (legacy)
    "additional_account_subscriber": 900,  # $9.00/account for legacy Subscriber overage
}


def calculate_account_cost(account_count: int, tier: AccountTier) -> dict:
    """
    Calculate monthly cost for a given number of accounts.

    New simplified pricing (2024-12):
    - FREE: $0 for 1 account
    - INDIVIDUAL: $29/month for up to 6 accounts
    - PRO: $250/month for up to 500 accounts
    - ENTERPRISE: Custom pricing for 500+ accounts

    Returns dict with:
        - base_cost_cents: Base subscription cost
        - additional_accounts: Number of accounts beyond included
        - additional_cost_cents: Cost for additional accounts
        - total_cost_cents: Total monthly cost
        - breakdown: List of (tier_name, count, unit_price, subtotal)
        - upgrade_required: Whether an upgrade is needed for account_count
        - recommended_tier: Recommended tier for account_count
    """
    # New tier pricing
    if tier == AccountTier.FREE:
        if account_count > 1:
            return {
                "base_cost_cents": 0,
                "included_accounts": 1,
                "additional_accounts": 0,
                "additional_cost_cents": 0,
                "total_cost_cents": 0,
                "breakdown": [("Free (1 account)", 1, 0, 0)],
                "upgrade_required": True,
                "recommended_tier": AccountTier.INDIVIDUAL.value,
            }
        return {
            "base_cost_cents": 0,
            "included_accounts": 1,
            "additional_accounts": 0,
            "additional_cost_cents": 0,
            "total_cost_cents": 0,
            "breakdown": [("Free (1 account)", 1, 0, 0)],
            "upgrade_required": False,
            "recommended_tier": None,
        }

    elif tier == AccountTier.INDIVIDUAL:
        included = TIER_LIMITS[AccountTier.INDIVIDUAL]["max_accounts"]  # 6
        base_cost = STRIPE_PRICES["individual_monthly"]

        if account_count > included:
            return {
                "base_cost_cents": base_cost,
                "included_accounts": included,
                "additional_accounts": 0,
                "additional_cost_cents": 0,
                "total_cost_cents": base_cost,
                "breakdown": [
                    (
                        f"Individual (up to {included} accounts)",
                        1,
                        base_cost,
                        base_cost,
                    ),
                ],
                "upgrade_required": True,
                "recommended_tier": AccountTier.PRO.value,
            }
        return {
            "base_cost_cents": base_cost,
            "included_accounts": included,
            "additional_accounts": 0,
            "additional_cost_cents": 0,
            "total_cost_cents": base_cost,
            "breakdown": [
                (f"Individual (up to {included} accounts)", 1, base_cost, base_cost),
            ],
            "upgrade_required": False,
            "recommended_tier": None,
        }

    elif tier == AccountTier.PRO:
        included = TIER_LIMITS[AccountTier.PRO]["max_accounts"]  # 500
        base_cost = STRIPE_PRICES["pro_monthly"]

        if account_count > included:
            return {
                "base_cost_cents": base_cost,
                "included_accounts": included,
                "additional_accounts": 0,
                "additional_cost_cents": 0,
                "total_cost_cents": base_cost,
                "breakdown": [
                    (f"Pro (up to {included} accounts)", 1, base_cost, base_cost),
                ],
                "upgrade_required": True,
                "recommended_tier": AccountTier.ENTERPRISE.value,
            }
        return {
            "base_cost_cents": base_cost,
            "included_accounts": included,
            "additional_accounts": 0,
            "additional_cost_cents": 0,
            "total_cost_cents": base_cost,
            "breakdown": [
                (f"Pro (up to {included} accounts)", 1, base_cost, base_cost),
            ],
            "upgrade_required": False,
            "recommended_tier": None,
        }

    elif tier == AccountTier.ENTERPRISE:
        # Enterprise has custom pricing - contact sales
        return {
            "base_cost_cents": None,
            "included_accounts": None,  # Unlimited
            "additional_accounts": 0,
            "additional_cost_cents": 0,
            "total_cost_cents": None,
            "breakdown": [("Enterprise (custom pricing)", 1, None, None)],
            "upgrade_required": False,
            "recommended_tier": None,
            "is_custom_pricing": True,
        }

    # Legacy tier handling (for backward compatibility)
    elif tier == AccountTier.FREE_SCAN:
        if account_count > 1:
            return {
                "base_cost_cents": 0,
                "included_accounts": 1,
                "additional_accounts": 0,
                "additional_cost_cents": 0,
                "total_cost_cents": 0,
                "breakdown": [("Free Scan (legacy)", 1, 0, 0)],
                "upgrade_required": True,
                "recommended_tier": AccountTier.INDIVIDUAL.value,
                "_legacy_tier": True,
                "_migrate_to": AccountTier.FREE.value,
            }
        return {
            "base_cost_cents": 0,
            "included_accounts": 1,
            "additional_accounts": 0,
            "additional_cost_cents": 0,
            "total_cost_cents": 0,
            "breakdown": [("Free Scan (legacy)", 1, 0, 0)],
            "upgrade_required": False,
            "recommended_tier": None,
            "_legacy_tier": True,
            "_migrate_to": AccountTier.FREE.value,
        }

    elif tier == AccountTier.SUBSCRIBER:
        included = TIER_LIMITS[AccountTier.SUBSCRIBER]["included_accounts"]  # 3
        base_cost = STRIPE_PRICES["subscriber_monthly"]

        if account_count <= included:
            return {
                "base_cost_cents": base_cost,
                "included_accounts": included,
                "additional_accounts": 0,
                "additional_cost_cents": 0,
                "total_cost_cents": base_cost,
                "breakdown": [
                    ("Subscriber Base (legacy, 3 accounts)", 1, base_cost, base_cost),
                ],
                "upgrade_required": False,
                "recommended_tier": None,
                "_legacy_tier": True,
                "_migrate_to": AccountTier.INDIVIDUAL.value,
            }
        else:
            additional = account_count - included
            additional_cost = (
                additional * STRIPE_PRICES["additional_account_subscriber"]
            )
            # Recommend upgrade to PRO if they have 7+ accounts
            recommended = AccountTier.PRO.value if account_count > 6 else None
            return {
                "base_cost_cents": base_cost,
                "included_accounts": included,
                "additional_accounts": additional,
                "additional_cost_cents": additional_cost,
                "total_cost_cents": base_cost + additional_cost,
                "breakdown": [
                    ("Subscriber Base (legacy, 3 accounts)", 1, base_cost, base_cost),
                    (
                        f"Additional Accounts ({additional})",
                        additional,
                        STRIPE_PRICES["additional_account_subscriber"],
                        additional_cost,
                    ),
                ],
                "upgrade_required": account_count > 6,
                "recommended_tier": recommended,
                "_legacy_tier": True,
                "_migrate_to": (
                    AccountTier.PRO.value
                    if account_count > 6
                    else AccountTier.INDIVIDUAL.value
                ),
            }

    raise ValueError(f"Unknown tier: {tier}")


class Subscription(Base):
    """Organization subscription model."""

    __tablename__ = "subscriptions"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # Stripe fields
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )

    # Tier and status
    tier: Mapped[AccountTier] = mapped_column(
        Enum(
            AccountTier,
            name="account_tier",
            create_type=False,
            values_callable=lambda e: [x.value for x in e],
        ),
        nullable=False,
        default=AccountTier.FREE,  # Use new FREE tier, not legacy FREE_SCAN
    )
    status: Mapped[SubscriptionStatus] = mapped_column(
        Enum(
            SubscriptionStatus,
            name="subscription_status",
            create_type=False,
            values_callable=lambda e: [x.value for x in e],
        ),
        nullable=False,
        default=SubscriptionStatus.ACTIVE,
    )

    # Free scan tracking
    free_scan_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    free_scan_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    free_scan_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Account limits
    included_accounts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    additional_accounts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # New tier-based limits (2024-12 billing model)
    # These are populated based on tier configuration
    max_accounts: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # None = unlimited (Enterprise)
    max_team_members: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # None = unlimited (Enterprise)
    org_features_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    history_retention_days: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # None = unlimited (Enterprise), negative = forever (legacy)

    # Store tier-specific configuration overrides
    tier_config: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Billing period
    current_period_start: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    current_period_end: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancel_at_period_end: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    canceled_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Extra data (stored as "metadata" in DB)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    organization = relationship("Organization", back_populates="subscription")

    @property
    def total_accounts_allowed(self) -> int:
        """Total cloud accounts allowed for this subscription.

        Returns -1 for unlimited (Enterprise tier).
        """
        # Use max_accounts if set (new model), otherwise fall back to tier limits
        if self.max_accounts is not None:
            return self.max_accounts

        limits = TIER_LIMITS.get(self.tier, TIER_LIMITS[AccountTier.FREE])
        base = limits.get("max_accounts") or limits.get("cloud_accounts", 1)

        # None means unlimited (standardised for Enterprise tier)
        if base is None:
            return -1  # Return -1 as API convention for unlimited

        return base + self.additional_accounts

    @property
    def is_free_scan_expired(self) -> bool:
        """Check if free scan results have expired (legacy FREE_SCAN tier only)."""
        if self.tier != AccountTier.FREE_SCAN:
            return False
        if not self.free_scan_expires_at:
            return False
        return (
            datetime.now(self.free_scan_expires_at.tzinfo) > self.free_scan_expires_at
        )

    @property
    def can_scan(self) -> bool:
        """Check if organization can perform a scan."""
        # Legacy free scan tier has scan limit
        if self.tier == AccountTier.FREE_SCAN:
            return not self.free_scan_used
        # New FREE tier has unlimited scans
        return self.status == SubscriptionStatus.ACTIVE

    @property
    def is_legacy_tier(self) -> bool:
        """Check if subscription is on a deprecated legacy tier."""
        limits = TIER_LIMITS.get(self.tier, {})
        return limits.get("_deprecated", False)

    @property
    def migration_tier(self) -> Optional[AccountTier]:
        """Get the recommended new tier for a legacy subscription."""
        limits = TIER_LIMITS.get(self.tier, {})
        return limits.get("_migrate_to")

    def use_free_scan(self) -> None:
        """Mark free scan as used and set expiry (legacy FREE_SCAN tier only)."""
        now = datetime.now(timezone.utc)
        self.free_scan_used = True
        self.free_scan_at = now
        self.free_scan_expires_at = now + timedelta(days=7)

    def has_feature(self, feature: str) -> bool:
        """Check if subscription has access to a feature."""
        # Check tier_config overrides first
        if self.tier_config and "features" in self.tier_config:
            features_override = self.tier_config["features"]
            # Check 'all' flag in override
            if features_override.get("all", False):
                return True
            # Check specific feature in override
            if feature in features_override:
                return features_override[feature]

        # Fall back to tier defaults
        limits = TIER_LIMITS.get(self.tier, TIER_LIMITS[AccountTier.FREE])
        features = limits.get("features", {})
        return features.get(feature, False) or features.get("all", False)

    def has_org_features(self) -> bool:
        """Check if subscription has access to organisation features.

        Uses tier configuration as the source of truth. The org_features_enabled
        flag is set by apply_tier_defaults() and kept in sync with tier config.
        """
        # Tier configuration is the source of truth
        return self.has_feature("org_features")

    def get_tier_limit(self, limit_name: str) -> Optional[int]:
        """Get a tier limit value (max_accounts, max_team_members, etc.)."""
        # Check tier_config overrides first
        if self.tier_config and limit_name in self.tier_config:
            return self.tier_config[limit_name]

        limits = TIER_LIMITS.get(self.tier, TIER_LIMITS[AccountTier.FREE])
        return limits.get(limit_name)

    def get_display_tier(self) -> str:
        """Get the display name for the current tier."""
        # Map legacy tiers to their display names
        if self.tier == AccountTier.FREE_SCAN:
            return "Free (Legacy)"
        elif self.tier == AccountTier.SUBSCRIBER:
            return "Subscriber (Legacy)"
        return self.tier.value.title()

    def apply_tier_defaults(self) -> None:
        """Apply default values from tier configuration."""
        limits = TIER_LIMITS.get(self.tier, TIER_LIMITS[AccountTier.FREE])

        self.max_accounts = limits.get("max_accounts")
        self.max_team_members = limits.get("max_team_members")
        self.history_retention_days = limits.get("results_retention_days")
        self.org_features_enabled = limits.get("features", {}).get(
            "org_features", False
        )
        self.included_accounts = limits.get("included_accounts", 1)


class Invoice(Base):
    """Invoice model for tracking Stripe invoices."""

    __tablename__ = "invoices"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    stripe_invoice_id: Mapped[str] = mapped_column(String(255), nullable=False)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="usd")
    status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    invoice_pdf_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hosted_invoice_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    period_start: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    period_end: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    paid_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    organization = relationship("Organization", back_populates="invoices")

    @property
    def amount_dollars(self) -> float:
        """Amount in dollars."""
        return self.amount_cents / 100.0
