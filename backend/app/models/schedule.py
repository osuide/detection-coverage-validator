"""Scan schedule model for automated scanning."""

import uuid
from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import String, DateTime, Enum as SQLEnum, Integer, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ScheduleFrequency(str, enum.Enum):
    """Schedule frequency options."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"  # Custom cron expression


class ScanSchedule(Base):
    """Represents a scan schedule for automated scanning."""

    __tablename__ = "scan_schedules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cloud_accounts.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Schedule configuration
    frequency: Mapped[ScheduleFrequency] = mapped_column(
        SQLEnum(ScheduleFrequency, values_callable=lambda x: [e.value for e in x]),
        default=ScheduleFrequency.DAILY,
    )
    cron_expression: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # For custom schedules

    # Day/time configuration for non-custom schedules
    day_of_week: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # 0=Monday, 6=Sunday (for weekly)
    day_of_month: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # 1-31 (for monthly)
    hour: Mapped[int] = mapped_column(Integer, default=0)  # 0-23
    minute: Mapped[int] = mapped_column(Integer, default=0)  # 0-59
    timezone: Mapped[str] = mapped_column(String(50), default="UTC")

    # Scan configuration (what to scan)
    regions: Mapped[list] = mapped_column(JSONB, default=list)
    detection_types: Mapped[list] = mapped_column(JSONB, default=list)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    run_count: Mapped[int] = mapped_column(Integer, default=0)
    last_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    cloud_account = relationship("CloudAccount", back_populates="schedules")

    def __repr__(self) -> str:
        return f"<ScanSchedule {self.name} ({self.frequency.value})>"

    def get_cron_trigger_args(self) -> dict:
        """Get APScheduler cron trigger arguments."""
        if self.frequency == ScheduleFrequency.CUSTOM and self.cron_expression:
            # Parse custom cron (minute hour day_of_month month day_of_week)
            parts = self.cron_expression.split()
            if len(parts) == 5:
                return {
                    "minute": parts[0],
                    "hour": parts[1],
                    "day": parts[2],
                    "month": parts[3],
                    "day_of_week": parts[4],
                    "timezone": self.timezone,
                }
        elif self.frequency == ScheduleFrequency.HOURLY:
            return {
                "minute": self.minute,
                "timezone": self.timezone,
            }
        elif self.frequency == ScheduleFrequency.DAILY:
            return {
                "hour": self.hour,
                "minute": self.minute,
                "timezone": self.timezone,
            }
        elif self.frequency == ScheduleFrequency.WEEKLY:
            return {
                "day_of_week": self.day_of_week or 0,
                "hour": self.hour,
                "minute": self.minute,
                "timezone": self.timezone,
            }
        elif self.frequency == ScheduleFrequency.MONTHLY:
            return {
                "day": self.day_of_month or 1,
                "hour": self.hour,
                "minute": self.minute,
                "timezone": self.timezone,
            }
        return {}
