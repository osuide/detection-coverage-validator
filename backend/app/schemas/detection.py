"""Detection schemas."""

from datetime import datetime
from typing import Optional, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.detection import DetectionType, DetectionStatus


class EvaluationSummary(BaseModel):
    """Base schema for evaluation summary data.

    Type-specific fields:
    - config_compliance: compliance_type, non_compliant_count, cap_exceeded
    - alarm_state: state, state_reason, state_updated_at
    - eventbridge_state: state
    """

    type: str
    # Config rule compliance fields
    compliance_type: Optional[str] = None  # COMPLIANT, NON_COMPLIANT, etc.
    non_compliant_count: Optional[int] = None
    cap_exceeded: Optional[bool] = None
    # Alarm state fields
    state: Optional[str] = None  # OK, ALARM, INSUFFICIENT_DATA or ENABLED/DISABLED
    state_reason: Optional[str] = None
    state_updated_at: Optional[str] = None

    model_config = ConfigDict(extra="allow")  # Allow additional fields


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

    # Evaluation/compliance data
    evaluation_summary: Optional[dict[str, Any]] = None
    evaluation_updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class DetectionListResponse(BaseModel):
    """Schema for paginated detection list."""

    items: list[DetectionResponse]
    total: int
    page: int
    page_size: int
    pages: int
