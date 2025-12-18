"""Scan job model."""

import uuid
from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import String, DateTime, Enum as SQLEnum, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ScanStatus(str, enum.Enum):
    """Scan job status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    """Represents a scan job for a cloud account."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cloud_accounts.id"), nullable=False
    )
    status: Mapped[ScanStatus] = mapped_column(
        SQLEnum(ScanStatus, values_callable=lambda x: [e.value for e in x]),
        default=ScanStatus.PENDING
    )

    # Scan configuration
    regions: Mapped[list] = mapped_column(JSONB, default=list)  # Regions to scan
    detection_types: Mapped[list] = mapped_column(
        JSONB, default=list
    )  # Types to scan for

    # Progress tracking
    progress_percent: Mapped[int] = mapped_column(Integer, default=0)
    current_step: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Results summary
    detections_found: Mapped[int] = mapped_column(Integer, default=0)
    detections_new: Mapped[int] = mapped_column(Integer, default=0)
    detections_updated: Mapped[int] = mapped_column(Integer, default=0)
    detections_removed: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    # Relationships
    cloud_account = relationship("CloudAccount", back_populates="scans")

    def __repr__(self) -> str:
        return f"<Scan {self.id} ({self.status.value})>"
