"""Pydantic schemas for scan schedules."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, ConfigDict

from app.models.schedule import ScheduleFrequency


class ScheduleBase(BaseModel):
    """Base schema for scan schedules."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    frequency: ScheduleFrequency = ScheduleFrequency.DAILY
    cron_expression: Optional[str] = Field(
        None,
        description="Cron expression for custom schedules (minute hour day month day_of_week)",
    )
    day_of_week: Optional[int] = Field(
        None, ge=0, le=6, description="0=Monday, 6=Sunday (for weekly)"
    )
    day_of_month: Optional[int] = Field(
        None, ge=1, le=31, description="1-31 (for monthly)"
    )
    hour: int = Field(0, ge=0, le=23)
    minute: int = Field(0, ge=0, le=59)
    timezone: str = Field("UTC")
    regions: list[str] = Field(default_factory=list)
    detection_types: list[str] = Field(default_factory=list)

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: Optional[str], info) -> Optional[str]:
        """Validate cron expression format."""
        if v is None:
            return v
        parts = v.split()
        if len(parts) != 5:
            raise ValueError(
                "Cron expression must have 5 parts: minute hour day month day_of_week"
            )
        return v


class ScheduleCreate(ScheduleBase):
    """Schema for creating a scan schedule."""

    cloud_account_id: UUID


class ScheduleUpdate(BaseModel):
    """Schema for updating a scan schedule."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    frequency: Optional[ScheduleFrequency] = None
    cron_expression: Optional[str] = None
    day_of_week: Optional[int] = Field(None, ge=0, le=6)
    day_of_month: Optional[int] = Field(None, ge=1, le=31)
    hour: Optional[int] = Field(None, ge=0, le=23)
    minute: Optional[int] = Field(None, ge=0, le=59)
    timezone: Optional[str] = None
    regions: Optional[list[str]] = None
    detection_types: Optional[list[str]] = None
    is_active: Optional[bool] = None


class ScheduleResponse(BaseModel):
    """Schema for schedule response."""

    id: UUID
    cloud_account_id: UUID
    name: str
    description: Optional[str]
    frequency: ScheduleFrequency
    cron_expression: Optional[str]
    day_of_week: Optional[int]
    day_of_month: Optional[int]
    hour: int
    minute: int
    timezone: str
    regions: list[str]
    detection_types: list[str]
    is_active: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    run_count: int
    last_scan_id: Optional[UUID]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScheduleListResponse(BaseModel):
    """Schema for list of schedules."""

    items: list[ScheduleResponse]
    total: int
    page: int
    page_size: int


class ScheduleStatusResponse(BaseModel):
    """Schema for schedule status with job info."""

    schedule: ScheduleResponse
    job_status: Optional[dict] = None
