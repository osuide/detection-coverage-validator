"""Detection model."""

import uuid
from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import String, DateTime, Enum as SQLEnum, Text, ForeignKey, Float
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DetectionType(str, enum.Enum):
    """Types of detections."""

    # AWS Detection Types
    CLOUDWATCH_LOGS_INSIGHTS = "cloudwatch_logs_insights"
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


class Detection(Base):
    """Represents a discovered security detection."""

    __tablename__ = "detections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cloud_accounts.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    detection_type: Mapped[DetectionType] = mapped_column(
        SQLEnum(DetectionType, values_callable=lambda x: [e.value for e in x]),
        nullable=False, index=True
    )
    status: Mapped[DetectionStatus] = mapped_column(
        SQLEnum(DetectionStatus, values_callable=lambda x: [e.value for e in x]),
        default=DetectionStatus.UNKNOWN
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

    # Health metrics (Phase 3)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    health_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    health_status: Mapped[HealthStatus] = mapped_column(
        SQLEnum(HealthStatus, values_callable=lambda x: [e.value for e in x]),
        default=HealthStatus.UNKNOWN
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
    cloud_account = relationship("CloudAccount", back_populates="detections")
    mappings = relationship(
        "DetectionMapping", back_populates="detection", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Detection {self.name} ({self.detection_type.value})>"
