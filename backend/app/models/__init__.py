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
from app.models.coverage_history import CoverageHistory, CoverageAlert, DriftSeverity
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
from app.models.compliance import (
    ComplianceFramework,
    ComplianceControl,
    ControlTechniqueMapping,
    ComplianceCoverageSnapshot,
)
from app.models.mitre_threat import (
    MitreThreatGroup,
    MitreCampaign,
    MitreSoftware,
    MitreTechniqueRelationship,
    MitreCampaignAttribution,
    MitreSyncHistory,
    MitreDataVersion,
    SyncStatus,
    SyncTriggerType,
    RelatedType,
    SoftwareType,
)
from app.models.detection_evaluation_history import (
    DetectionEvaluationHistory,
    DetectionEvaluationDailySummary,
    DetectionEvaluationAlert,
    EvaluationType,
    EvaluationAlertSeverity,
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
    "CoverageHistory",
    "CoverageAlert",
    "DriftSeverity",
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
    # Compliance
    "ComplianceFramework",
    "ComplianceControl",
    "ControlTechniqueMapping",
    "ComplianceCoverageSnapshot",
    # MITRE Threat Intelligence
    "MitreThreatGroup",
    "MitreCampaign",
    "MitreSoftware",
    "MitreTechniqueRelationship",
    "MitreCampaignAttribution",
    "MitreSyncHistory",
    "MitreDataVersion",
    "SyncStatus",
    "SyncTriggerType",
    "RelatedType",
    "SoftwareType",
    # Detection Evaluation History
    "DetectionEvaluationHistory",
    "DetectionEvaluationDailySummary",
    "DetectionEvaluationAlert",
    "EvaluationType",
    "EvaluationAlertSeverity",
]
