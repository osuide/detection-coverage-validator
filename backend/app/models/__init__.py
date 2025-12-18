"""Database models."""

from app.models.cloud_account import CloudAccount, CloudProvider
from app.models.detection import Detection, DetectionType, DetectionStatus
from app.models.mitre import Tactic, Technique
from app.models.mapping import DetectionMapping
from app.models.scan import Scan, ScanStatus
from app.models.coverage import CoverageSnapshot
from app.models.schedule import ScanSchedule, ScheduleFrequency
from app.models.alert import AlertConfig, AlertHistory, AlertType, AlertSeverity, NotificationChannel
from app.models.user import (
    User,
    Organization,
    OrganizationMember,
    UserSession,
    APIKey,
    AuditLog,
    UserRole,
    MembershipStatus,
    AuditLogAction,
)

__all__ = [
    # Cloud accounts
    "CloudAccount",
    "CloudProvider",
    # Detections
    "Detection",
    "DetectionType",
    "DetectionStatus",
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
    # Auth & Users
    "User",
    "Organization",
    "OrganizationMember",
    "UserSession",
    "APIKey",
    "AuditLog",
    "UserRole",
    "MembershipStatus",
    "AuditLogAction",
]
