"""Database models."""

from app.models.cloud_account import CloudAccount, CloudProvider
from app.models.cloud_organization import (
    CloudOrganization,
    CloudOrganizationMember,
    CloudOrganizationStatus,
    CloudOrganizationMemberStatus,
)
from app.models.detection import (
    Detection,
    DetectionType,
    DetectionStatus,
    DetectionScope,
    HealthStatus,
)
from app.models.mitre import Tactic, Technique
from app.models.mapping import DetectionMapping
from app.models.scan import Scan, ScanStatus
from app.models.coverage import CoverageSnapshot
from app.models.schedule import ScanSchedule, ScheduleFrequency
from app.models.alert import (
    AlertConfig,
    AlertHistory,
    AlertType,
    AlertSeverity,
    NotificationChannel,
)

# Import billing and security BEFORE user (for relationship resolution)
from app.models.billing import (
    Subscription,
    Invoice,
    AccountTier,
    SubscriptionStatus,
    TIER_LIMITS,
    STRIPE_PRICES,
)
from app.models.security import OrganizationSecuritySettings, VerifiedDomain

from app.models.user import (
    User,
    Organization,
    OrganizationMember,
    UserSession,
    APIKey,
    AuditLog,
    FederatedIdentity,
    UserRole,
    MembershipStatus,
    AuditLogAction,
)

__all__ = [
    # Cloud accounts
    "CloudAccount",
    "CloudProvider",
    # Cloud organisations
    "CloudOrganization",
    "CloudOrganizationMember",
    "CloudOrganizationStatus",
    "CloudOrganizationMemberStatus",
    # Detections
    "Detection",
    "DetectionType",
    "DetectionStatus",
    "DetectionScope",
    "HealthStatus",
    # MITRE
    "Tactic",
    "Technique",
    # Mappings
    "DetectionMapping",
    # Scans
    "Scan",
    "ScanStatus",
    # Coverage
    "CoverageSnapshot",
    # Schedules
    "ScanSchedule",
    "ScheduleFrequency",
    # Alerts
    "AlertConfig",
    "AlertHistory",
    "AlertType",
    "AlertSeverity",
    "NotificationChannel",
    # Billing
    "Subscription",
    "Invoice",
    "AccountTier",
    "SubscriptionStatus",
    "TIER_LIMITS",
    "STRIPE_PRICES",
    # Security
    "OrganizationSecuritySettings",
    "VerifiedDomain",
    # Auth & Users
    "User",
    "Organization",
    "OrganizationMember",
    "UserSession",
    "APIKey",
    "AuditLog",
    "FederatedIdentity",
    "UserRole",
    "MembershipStatus",
    "AuditLogAction",
]
