"""Detection model."""

import uuid
from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DetectionType(str, enum.Enum):
    """Types of detections."""

    # AWS Detection Types
    CLOUDWATCH_LOGS_INSIGHTS = "cloudwatch_logs_insights"
    CLOUDWATCH_ALARM = "cloudwatch_alarm"
    EVENTBRIDGE_RULE = "eventbridge_rule"
    GUARDDUTY_FINDING = "guardduty_finding"
    CONFIG_RULE = "config_rule"
    CUSTOM_LAMBDA = "custom_lambda"
    SECURITY_HUB = "security_hub"

    # GCP Detection Types
    GCP_CLOUD_LOGGING = "gcp_cloud_logging"
    GCP_SECURITY_COMMAND_CENTER = "gcp_security_command_center"
    GCP_EVENTARC = "gcp_eventarc"
    GCP_CLOUD_MONITORING = "gcp_cloud_monitoring"
    GCP_CLOUD_FUNCTION = "gcp_cloud_function"
    GCP_CHRONICLE = "gcp_chronicle"


class DetectionStatus(str, enum.Enum):
    """Detection status."""

    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"
    UNKNOWN = "unknown"


class HealthStatus(str, enum.Enum):
    """Detection health status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    BROKEN = "broken"
    UNKNOWN = "unknown"


class DetectionScope(str, enum.Enum):
    """Scope of a detection - account-level or organisation-level."""

    ACCOUNT = "account"  # Detection applies to a specific account
    ORGANIZATION = (
        "organization"  # Detection applies at org level (e.g., org CloudTrail)
    )


class Detection(Base):
    """Represents a discovered security detection."""

    __tablename__ = "detections"
    __table_args__ = (
        # Ensure scope consistency: account-level detections must have cloud_account_id,
        # org-level detections must have cloud_organization_id
        CheckConstraint(
            """
            (detection_scope = 'account' AND cloud_account_id IS NOT NULL) OR
            (detection_scope = 'organization' AND cloud_organization_id IS NOT NULL)
            """,
            name="ck_detection_scope_consistency",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Account-level detection link (nullable for org-level detections)
    cloud_account_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_accounts.id"),
        nullable=True,
        index=True,
    )

    # Organisation-level detection link (for org CloudTrail, Config Aggregator, etc.)
    cloud_organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Detection scope
    detection_scope: Mapped[DetectionScope] = mapped_column(
        SQLEnum(
            DetectionScope,
            values_callable=lambda x: [e.value for e in x],
            name="detection_scope",  # Must match migration enum name
        ),
        default=DetectionScope.ACCOUNT,
        nullable=False,
        index=True,
    )

    # For org-level detections: which accounts does it apply to?
    applies_to_all_accounts: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    applies_to_account_ids: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True
    )  # List of account IDs if not all

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    detection_type: Mapped[DetectionType] = mapped_column(
        SQLEnum(DetectionType, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    status: Mapped[DetectionStatus] = mapped_column(
        SQLEnum(DetectionStatus, values_callable=lambda x: [e.value for e in x]),
        default=DetectionStatus.UNKNOWN,
    )
    source_arn: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    region: Mapped[str] = mapped_column(String(64), nullable=False)

    # Detection configuration stored as JSONB for flexibility
    raw_config: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Parsed/normalized fields for querying
    query_pattern: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    event_pattern: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    log_groups: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Service awareness - which cloud services this detection monitors
    target_services: Mapped[Optional[list]] = mapped_column(
        JSONB, nullable=True, default=list
    )  # e.g., ["S3", "RDS", "DynamoDB"] - normalised service names

    # Health metrics (Phase 3)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    health_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    health_status: Mapped[HealthStatus] = mapped_column(
        SQLEnum(HealthStatus, values_callable=lambda x: [e.value for e in x]),
        default=HealthStatus.UNKNOWN,
    )
    health_issues: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    last_validated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Metadata
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )
    is_managed: Mapped[bool] = mapped_column(default=False)  # GuardDuty, SCC, etc.

    # Relationships
    cloud_account = relationship(
        "CloudAccount",
        back_populates="detections",
        foreign_keys=[cloud_account_id],
    )
    cloud_organization = relationship(
        "CloudOrganization",
        back_populates="org_detections",
        foreign_keys=[cloud_organization_id],
    )
    mappings = relationship(
        "DetectionMapping", back_populates="detection", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Detection {self.name} ({self.detection_type.value})>"
