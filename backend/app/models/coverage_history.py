"""Coverage history model for tracking changes over time."""

import uuid
import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Enum as SQLEnum,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DriftSeverity(str, enum.Enum):
    """Severity of coverage drift."""

    NONE = "none"  # No drift detected
    INFO = "info"  # Minor changes, technique added/removed
    WARNING = "warning"  # 5-10% drop
    CRITICAL = "critical"  # >10% drop


class CoverageHistory(Base):
    """Stores historical coverage data for drift detection."""

    __tablename__ = "coverage_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Link to cloud account
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Link to the scan that generated this record
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Coverage metrics
    total_techniques: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    covered_techniques: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    coverage_percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Drift from previous record
    coverage_delta: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    techniques_added: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )  # List of technique IDs added
    techniques_removed: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )  # List of technique IDs removed

    # Drift severity
    drift_severity: Mapped[DriftSeverity] = mapped_column(
        SQLEnum(DriftSeverity, values_callable=lambda x: [e.value for e in x]),
        default=DriftSeverity.NONE,
        nullable=False,
    )

    # Detailed coverage by tactic (for breakdown)
    coverage_by_tactic: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Timestamp
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True
    )

    # Relationships
    cloud_account = relationship("CloudAccount", back_populates="coverage_history")
    scan = relationship("Scan", back_populates="coverage_history")

    def __repr__(self) -> str:
        return (
            f"<CoverageHistory {self.coverage_percent:.1f}% "
            f"({self.covered_techniques}/{self.total_techniques})>"
        )


class CoverageAlert(Base):
    """Alerts for significant coverage changes."""

    __tablename__ = "coverage_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Link to organization
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Link to cloud account (nullable for org-wide alerts)
    cloud_account_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Link to the coverage history record
    coverage_history_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_history.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Alert details
    alert_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # coverage_drop, technique_removed, etc.
    severity: Mapped[DriftSeverity] = mapped_column(
        SQLEnum(DriftSeverity, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(String(1024), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Status
    is_acknowledged: Mapped[bool] = mapped_column(default=False)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    acknowledged_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True
    )

    # Relationships
    organization = relationship("Organization")
    cloud_account = relationship("CloudAccount")
    coverage_history = relationship("CoverageHistory")

    def __repr__(self) -> str:
        return f"<CoverageAlert {self.alert_type} ({self.severity.value})>"
