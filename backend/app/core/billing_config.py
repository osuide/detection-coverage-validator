"""
Billing tier configuration for Detection Coverage Validator.

This module defines the new simplified billing model:
- FREE: Try it out (1 account, limited features)
- INDIVIDUAL: For individuals/small teams (up to 6 accounts)
- PRO: Organisation features (up to 500 accounts)
- ENTERPRISE: Custom pricing (500+ accounts, SSO, SLAs)

Note: Both AWS and GCP are included in all tiers.

AccountTier enum is defined in app.models.billing to avoid circular imports
with SQLAlchemy models. Use get_account_tier() to safely import it.
"""

from typing import Optional, Any


def get_account_tier():
    """Lazy import of AccountTier to avoid circular imports."""
    from app.models.billing import AccountTier

    return AccountTier


# Stripe Price IDs (to be configured in Stripe Dashboard)
# These should match the products created in Stripe
STRIPE_PRICE_IDS = {
    "individual_monthly": None,  # Set after creating in Stripe
    "pro_monthly": None,  # Set after creating in Stripe
    "enterprise_monthly": None,  # Custom pricing
}

# Prices in cents (USD)
STRIPE_PRICES = {
    "free_monthly": 0,
    "individual_monthly": 2900,  # $29/month
    "pro_monthly": 25000,  # $250/month
    "enterprise_monthly": None,  # Custom pricing
}

# Tier configuration using string keys to avoid circular import at module load
# Use get_tier_config() to access with AccountTier enum
_TIER_CONFIG_BY_VALUE = {
    "free": {
        "display_name": "Free",
        "price_monthly_cents": 0,
        "max_accounts": 1,
        "max_team_members": 1,
        "history_retention_days": 30,
        "scans_allowed": None,  # Unlimited scans
        "features": {
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "remediation_templates": True,
            "scheduled_scans": False,
            "api_access": False,
            "export_reports": False,
            "historical_trends": False,
            "alerts": False,
            "org_features": False,
            "org_dashboard": False,
            "auto_discovery": False,
            "delegated_scanning": False,
            "sso_saml": False,
            "dedicated_support": False,
            "custom_integrations": False,
            "sla": False,
            "code_analysis": False,
        },
    },
    "individual": {
        "display_name": "Individual",
        "price_monthly_cents": 2900,
        "max_accounts": 6,
        "max_team_members": 3,
        "history_retention_days": 90,
        "scans_allowed": None,
        "features": {
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "remediation_templates": True,
            "scheduled_scans": True,
            "api_access": True,
            "export_reports": True,
            "historical_trends": True,
            "alerts": True,
            "org_features": False,
            "org_dashboard": False,
            "auto_discovery": False,
            "delegated_scanning": False,
            "sso_saml": False,
            "dedicated_support": False,
            "custom_integrations": False,
            "sla": False,
            "code_analysis": True,
        },
    },
    "pro": {
        "display_name": "Pro",
        "price_monthly_cents": 25000,
        "max_accounts": 500,
        "max_team_members": 10,
        "history_retention_days": 365,
        "scans_allowed": None,
        "features": {
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "remediation_templates": True,
            "scheduled_scans": True,
            "api_access": True,
            "export_reports": True,
            "historical_trends": True,
            "alerts": True,
            "org_features": True,
            "org_dashboard": True,
            "auto_discovery": True,
            "delegated_scanning": True,
            "sso_saml": False,
            "dedicated_support": False,
            "custom_integrations": False,
            "sla": False,
            "code_analysis": True,
        },
    },
    "enterprise": {
        "display_name": "Enterprise",
        "price_monthly_cents": None,
        "max_accounts": None,
        "max_team_members": None,
        "history_retention_days": None,
        "scans_allowed": None,
        "features": {
            "all": True,
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "remediation_templates": True,
            "scheduled_scans": True,
            "api_access": True,
            "export_reports": True,
            "historical_trends": True,
            "alerts": True,
            "org_features": True,
            "org_dashboard": True,
            "auto_discovery": True,
            "delegated_scanning": True,
            "sso_saml": True,
            "dedicated_support": True,
            "custom_integrations": True,
            "sla": True,
            "code_analysis": True,
            "unlimited_accounts": True,
        },
    },
    # Legacy tiers
    "free_scan": {
        "display_name": "Free (Legacy)",
        "price_monthly_cents": 0,
        "max_accounts": 1,
        "max_team_members": 1,
        "history_retention_days": 7,
        "scans_allowed": 1,
        "features": {
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "remediation_templates": True,
            "scheduled_scans": False,
            "api_access": False,
            "org_features": False,
            "code_analysis": False,
        },
        "_deprecated": True,
        "_migrate_to": "free",
    },
    "subscriber": {
        "display_name": "Subscriber (Legacy)",
        "price_monthly_cents": 2900,
        "max_accounts": 3,
        "max_team_members": 3,
        "history_retention_days": None,
        "scans_allowed": None,
        "features": {
            "coverage_heatmap": True,
            "gap_list": True,
            "pdf_report": True,
            "remediation_templates": True,
            "historical_trends": True,
            "scheduled_scans": True,
            "alerts": True,
            "api_access": True,
            "code_analysis": True,
            "org_features": True,
        },
        "_deprecated": True,
        "_migrate_to": "individual",
    },
}


def get_tier_config(tier: Any) -> dict:
    """Get configuration for a tier, falling back to FREE if unknown.

    Args:
        tier: AccountTier enum or string tier value

    Returns:
        Tier configuration dict
    """
    # Handle both enum and string values
    tier_value = tier.value if hasattr(tier, "value") else str(tier)
    return _TIER_CONFIG_BY_VALUE.get(tier_value, _TIER_CONFIG_BY_VALUE["free"])


def get_required_tier(account_count: int, wants_org_features: bool = False):
    """
    Determine the minimum required tier based on usage.

    Args:
        account_count: Number of cloud accounts needed
        wants_org_features: Whether organisation features are required

    Returns:
        The minimum AccountTier required to support the usage
    """
    AccountTier = get_account_tier()

    if wants_org_features:
        if account_count > 500:
            return AccountTier.ENTERPRISE
        return AccountTier.PRO

    if account_count > 500:
        return AccountTier.ENTERPRISE
    if account_count > 6:
        return AccountTier.PRO
    if account_count > 1:
        return AccountTier.INDIVIDUAL
    return AccountTier.FREE


def get_upgrade_recommendation(
    current_tier: Any, account_count: int, wants_org_features: bool = False
):
    """
    Get upgrade recommendation if current tier is insufficient.

    Returns:
        Recommended AccountTier to upgrade to, or None if current tier is sufficient
    """
    AccountTier = get_account_tier()
    required = get_required_tier(account_count, wants_org_features)

    tier_order = {
        AccountTier.FREE: 0,
        AccountTier.FREE_SCAN: 0,
        AccountTier.INDIVIDUAL: 1,
        AccountTier.SUBSCRIBER: 1,
        AccountTier.PRO: 2,
        AccountTier.ENTERPRISE: 3,
    }

    current_level = tier_order.get(current_tier, 0)
    required_level = tier_order.get(required, 0)

    if required_level > current_level:
        return required
    return None


def has_feature(tier: Any, feature: str) -> bool:
    """Check if a tier has access to a specific feature."""
    config = get_tier_config(tier)
    features = config.get("features", {})

    if features.get("all", False):
        return True

    return features.get(feature, False)


def has_org_features(tier: Any) -> bool:
    """Check if a tier has access to organisation features."""
    return has_feature(tier, "org_features")


def get_account_limit(tier: Any) -> Optional[int]:
    """Get the maximum number of accounts allowed for a tier."""
    config = get_tier_config(tier)
    return config.get("max_accounts")


def get_team_member_limit(tier: Any) -> Optional[int]:
    """Get the maximum number of team members allowed for a tier."""
    config = get_tier_config(tier)
    return config.get("max_team_members")


def is_legacy_tier(tier: Any) -> bool:
    """Check if a tier is a legacy tier that should be migrated."""
    config = get_tier_config(tier)
    return config.get("_deprecated", False)


def get_migration_tier(tier: Any):
    """Get the new tier that a legacy tier should migrate to."""
    AccountTier = get_account_tier()
    config = get_tier_config(tier)
    migrate_to = config.get("_migrate_to")

    if migrate_to:
        # Convert string to enum
        return AccountTier(migrate_to)
    return None


def calculate_pricing(tier: Any) -> dict:
    """Calculate pricing information for a tier."""
    config = get_tier_config(tier)
    tier_value = tier.value if hasattr(tier, "value") else str(tier)

    price_cents = config.get("price_monthly_cents")
    if price_cents is None:
        return {
            "tier": tier_value,
            "display_name": config.get("display_name"),
            "price_monthly_cents": None,
            "price_monthly_dollars": None,
            "price_yearly_cents": None,
            "price_yearly_dollars": None,
            "is_custom_pricing": True,
        }

    return {
        "tier": tier_value,
        "display_name": config.get("display_name"),
        "price_monthly_cents": price_cents,
        "price_monthly_dollars": price_cents / 100,
        "price_yearly_cents": price_cents * 12,
        "price_yearly_dollars": (price_cents * 12) / 100,
        "is_custom_pricing": False,
    }


# Export key items for easy importing
__all__ = [
    "get_account_tier",
    "STRIPE_PRICES",
    "STRIPE_PRICE_IDS",
    "get_tier_config",
    "get_required_tier",
    "get_upgrade_recommendation",
    "has_feature",
    "has_org_features",
    "get_account_limit",
    "get_team_member_limit",
    "is_legacy_tier",
    "get_migration_tier",
    "calculate_pricing",
]
