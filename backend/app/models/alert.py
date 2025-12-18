"""Alert configuration model for notifications."""

import uuid
from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import String, DateTime, Enum as SQLEnum, Integer, ForeignKey, Boolean, Float
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AlertType(str, enum.Enum):
    """Types of alerts."""

    COVERAGE_THRESHOLD = "coverage_threshold"  # Coverage drops below threshold
    GAP_DETECTED = "gap_detected"  # New gap in coverage
    SCAN_COMPLETED = "scan_completed"  # Scan finished
    SCAN_FAILED = "scan_failed"  # Scan failed
    STALE_DETECTION = "stale_detection"  # Detection not triggered in X days
    NEW_TECHNIQUE = "new_technique"  # New MITRE technique added


class NotificationChannel(str, enum.Enum):
    """Notification delivery channels."""

    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"


class AlertSeverity(str, enum.Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertConfig(Base):
    """Configuration for alert rules."""

    __tablename__ = "alert_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cloud_account_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cloud_accounts.id"), nullable=True
    )  # NULL means global alert
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Alert type and conditions
    alert_type: Mapped[AlertType] = mapped_column(
        SQLEnum(AlertType, values_callable=lambda x: [e.value for e in x]),
        nullable=False
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        SQLEnum(AlertSeverity, values_callable=lambda x: [e.value for e in x]),
        default=AlertSeverity.WARNING
    )

    # Threshold configuration (for coverage_threshold type)
    threshold_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    threshold_operator: Mapped[Optional[str]] = mapped_column(
        String(10), nullable=True
    )  # 'lt', 'gt', 'eq', 'lte', 'gte'

    # Notification channels
    channels: Mapped[list] = mapped_column(JSONB, default=list)  # List of channel configs

    # Rate limiting
    cooldown_minutes: Mapped[int] = mapped_column(Integer, default=60)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    cloud_account = relationship("CloudAccount", back_populates="alerts")
    history = relationship("AlertHistory", back_populates="alert_config")

    def __repr__(self) -> str:
        return f"<AlertConfig {self.name} ({self.alert_type.value})>"


class AlertHistory(Base):
    """History of triggered alerts."""

    __tablename__ = "alert_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_config_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert_configs.id"), nullable=False
    )
    cloud_account_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cloud_accounts.id"), nullable=True
    )

    # Alert details
    severity: Mapped[AlertSeverity] = mapped_column(
        SQLEnum(AlertSeverity, values_callable=lambda x: [e.value for e in x]),
        nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(String(2000), nullable=False)
    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Notification status
    channels_notified: Mapped[list] = mapped_column(JSONB, default=list)
    notification_errors: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)

    # Status
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Timestamps
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    # Relationships
    alert_config = relationship("AlertConfig", back_populates="history")

    def __repr__(self) -> str:
        return f"<AlertHistory {self.title} ({self.severity.value})>"
