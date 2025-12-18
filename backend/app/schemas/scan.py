"""Scan schemas."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.detection import DetectionType
from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    """Schema for creating a scan job."""

    cloud_account_id: UUID
    regions: list[str] = Field(default_factory=list)
    detection_types: list[DetectionType] = Field(default_factory=list)


class ScanResponse(BaseModel):
    """Schema for scan response."""

    id: UUID
    cloud_account_id: UUID
    status: ScanStatus
    regions: list[str]
    detection_types: list[str]
    progress_percent: int
    current_step: Optional[str] = None
    detections_found: int
    detections_new: int
    detections_updated: int
    detections_removed: int
    errors: Optional[list[dict]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Schema for paginated scan list."""

    items: list[ScanResponse]
    total: int
    page: int
    page_size: int
