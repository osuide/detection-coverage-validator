"""Gap tracking model for remediation workflow."""

import uuid
from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import String, DateTime, Enum as SQLEnum, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class GapStatus(str, enum.Enum):
    """Gap remediation status workflow.

    Workflow:
    OPEN -> ACKNOWLEDGED -> IN_PROGRESS -> REMEDIATED
                                     |-> RISK_ACCEPTED
    """

    OPEN = "open"  # Newly identified gap
    ACKNOWLEDGED = "acknowledged"  # Team is aware
    IN_PROGRESS = "in_progress"  # Actively being remediated
    REMEDIATED = "remediated"  # Detection deployed
    RISK_ACCEPTED = "risk_accepted"  # Accepted without remediation


class GapPriority(str, enum.Enum):
    """Gap priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CoverageGap(Base):
    """Represents a coverage gap identified in an account."""

    __tablename__ = "coverage_gaps"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cloud_accounts.id"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )

    # MITRE technique info
    technique_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    tactic_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Gap status and priority
    status: Mapped[GapStatus] = mapped_column(
        SQLEnum(GapStatus, values_callable=lambda x: [e.value for e in x]),
        default=GapStatus.OPEN,
        index=True,
    )
    priority: Mapped[GapPriority] = mapped_column(
        SQLEnum(GapPriority, values_callable=lambda x: [e.value for e in x]),
        default=GapPriority.MEDIUM,
        index=True,
    )

    # Analysis info
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    data_sources: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    recommended_detections: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)

    # Remediation tracking
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    remediation_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_due_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    remediated_detection_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detections.id"), nullable=True
    )

    # Risk acceptance
    risk_acceptance_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_accepted_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    risk_accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Timestamps
    first_identified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    status_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Scan reference
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True
    )

    # Relationships
    cloud_account = relationship("CloudAccount", back_populates="coverage_gaps")
    organization = relationship("Organization")
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    risk_accepted_by_user = relationship("User", foreign_keys=[risk_accepted_by])
    remediated_detection = relationship("Detection")

    def __repr__(self) -> str:
        return f"<CoverageGap {self.technique_id} ({self.status.value})>"


class GapHistory(Base):
    """History of gap status changes for audit trail."""

    __tablename__ = "gap_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    gap_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("coverage_gaps.id"), nullable=False
    )

    # Change info
    previous_status: Mapped[Optional[GapStatus]] = mapped_column(
        SQLEnum(GapStatus, values_callable=lambda x: [e.value for e in x]),
        nullable=True,
    )
    new_status: Mapped[GapStatus] = mapped_column(
        SQLEnum(GapStatus, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )

    # Who made the change
    changed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    change_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamp
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    # Relationships
    gap = relationship("CoverageGap")
    user = relationship("User")

    def __repr__(self) -> str:
        return (
            f"<GapHistory {self.gap_id}: {self.previous_status} -> {self.new_status}>"
        )
