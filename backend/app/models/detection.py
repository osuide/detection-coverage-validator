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

    CLOUDWATCH_LOGS_INSIGHTS = "cloudwatch_logs_insights"
    EVENTBRIDGE_RULE = "eventbridge_rule"
    GUARDDUTY_FINDING = "guardduty_finding"
    CONFIG_RULE = "config_rule"
    CUSTOM_LAMBDA = "custom_lambda"
    SECURITY_HUB = "security_hub"


class DetectionStatus(str, enum.Enum):
    """Detection status."""

    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"
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
        SQLEnum(DetectionType), nullable=False, index=True
    )
    status: Mapped[DetectionStatus] = mapped_column(
        SQLEnum(DetectionStatus), default=DetectionStatus.UNKNOWN
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

    # Health metrics
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    health_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Metadata
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )
    is_managed: Mapped[bool] = mapped_column(default=False)  # GuardDuty, etc.

    # Relationships
    cloud_account = relationship("CloudAccount", back_populates="detections")
    mappings = relationship(
        "DetectionMapping", back_populates="detection", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Detection {self.name} ({self.detection_type.value})>"
