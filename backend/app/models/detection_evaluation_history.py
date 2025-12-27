"""Detection evaluation history model for tracking compliance changes over time."""

import uuid
import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Enum as SQLEnum,
    CheckConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class EvaluationType(str, enum.Enum):
    """Type of evaluation being tracked."""

    CONFIG_COMPLIANCE = "config_compliance"  # AWS Config rule compliance
    ALARM_STATE = "alarm_state"  # CloudWatch alarm state
    EVENTBRIDGE_STATE = "eventbridge_state"  # EventBridge rule state
    GUARDDUTY_STATE = "guardduty_state"  # GuardDuty detector state
    GCP_SCC_STATE = "gcp_scc_state"  # GCP Security Command Centre state
    GCP_LOGGING_STATE = "gcp_logging_state"  # GCP Cloud Logging state


class EvaluationAlertSeverity(str, enum.Enum):
    """Severity level for evaluation alerts."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class DetectionEvaluationHistory(Base):
    """Stores historical evaluation snapshots for drift detection and trend analysis.

    This is a time-series table designed for efficient querying of:
    - Compliance trends over time
    - State change detection (drift)
    - Historical compliance reporting

    Design considerations:
    - Append-only (immutable records)
    - Denormalised for query performance
    - Designed for partitioning by recorded_at
    """

    __tablename__ = "detection_evaluation_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Detection reference
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Denormalised fields for query performance (avoid joins)
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    detection_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # Evaluation state
    evaluation_type: Mapped[EvaluationType] = mapped_column(
        SQLEnum(EvaluationType, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )

    # State tracking for drift detection
    previous_state: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # NULL for first record
    current_state: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # 'COMPLIANT', 'NON_COMPLIANT', 'OK', 'ALARM', etc.

    # Quick flag for filtering state changes (drift)
    state_changed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Full evaluation summary snapshot (flexible JSONB)
    evaluation_summary: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict
    )

    # Optional link to scan that triggered this evaluation
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Timestamp (designed for BRIN index and partitioning)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True
    )

    # Relationships
    detection = relationship("Detection", foreign_keys=[detection_id])
    scan = relationship("Scan", foreign_keys=[scan_id])

    def __repr__(self) -> str:
        return (
            f"<DetectionEvaluationHistory {self.detection_id} "
            f"{self.current_state} at {self.recorded_at}>"
        )


class DetectionEvaluationDailySummary(Base):
    """Pre-computed daily aggregates for dashboard performance.

    This table is populated by a background job that aggregates
    the raw history data into daily summaries per account and detection type.
    """

    __tablename__ = "detection_evaluation_daily_summary"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Keys
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    summary_date: Mapped[datetime] = mapped_column(Date, nullable=False)
    detection_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # Aggregate counts by state category
    total_detections: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Config Rule states
    compliant_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    non_compliant_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # CloudWatch Alarm states
    alarm_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ok_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    insufficient_data_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    # EventBridge states
    enabled_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    disabled_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Generic states
    unknown_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # State changes that day (for drift metrics)
    state_changes_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Derived compliance rate (0.00 to 100.00)
    compliance_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Metadata
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )

    # Relationships
    cloud_account = relationship("CloudAccount", foreign_keys=[cloud_account_id])

    __table_args__ = (
        # Ensure one summary per account/date/type combination
        {"sqlite_autoincrement": True},
    )

    def __repr__(self) -> str:
        return (
            f"<DetectionEvaluationDailySummary {self.cloud_account_id} "
            f"{self.summary_date} {self.detection_type}>"
        )


class DetectionEvaluationAlert(Base):
    """Alerts generated for significant evaluation state changes.

    Tracks state changes that require attention, such as:
    - Detection becoming non-compliant
    - Multiple alarms triggering
    - Detection being disabled
    """

    __tablename__ = "detection_evaluation_alerts"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('info', 'warning', 'critical')",
            name="ck_evaluation_alert_severity",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # References
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cloud_account_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    detection_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detections.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Reference to the history record (no FK due to partitioning)
    evaluation_history_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # Alert details
    alert_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # 'state_change', 'compliance_drop', 'alarm_triggered'
    severity: Mapped[EvaluationAlertSeverity] = mapped_column(
        SQLEnum(
            EvaluationAlertSeverity,
            values_callable=lambda x: [e.value for e in x],
            name="evaluationalertseverity",
        ),
        nullable=False,
    )

    # State change details
    previous_state: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    current_state: Mapped[str] = mapped_column(String(32), nullable=False)

    # Human-readable message
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    # Additional context
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Acknowledgement workflow
    is_acknowledged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    acknowledged_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True
    )

    # Relationships
    organization = relationship("Organization", foreign_keys=[organization_id])
    cloud_account = relationship("CloudAccount", foreign_keys=[cloud_account_id])
    detection = relationship("Detection", foreign_keys=[detection_id])
    acknowledged_user = relationship("User", foreign_keys=[acknowledged_by])

    def __repr__(self) -> str:
        return f"<DetectionEvaluationAlert {self.alert_type} ({self.severity.value})>"
