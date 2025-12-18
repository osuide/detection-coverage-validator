"""Detection schemas."""

from datetime import datetime
from typing import Optional, Any
from uuid import UUID

from pydantic import BaseModel

from app.models.detection import DetectionType, DetectionStatus


class DetectionResponse(BaseModel):
    """Schema for detection response."""

    id: UUID
    cloud_account_id: UUID
    name: str
    detection_type: DetectionType
    status: DetectionStatus
    source_arn: Optional[str] = None
    region: str
    query_pattern: Optional[str] = None
    event_pattern: Optional[dict[str, Any]] = None
    log_groups: Optional[list[str]] = None
    description: Optional[str] = None
    last_triggered_at: Optional[datetime] = None
    health_score: Optional[float] = None
    is_managed: bool
    discovered_at: datetime
    updated_at: datetime
    mapping_count: int = 0
    top_techniques: list[str] = []

    class Config:
        from_attributes = True


class DetectionListResponse(BaseModel):
    """Schema for paginated detection list."""

    items: list[DetectionResponse]
    total: int
    page: int
    page_size: int
    pages: int
