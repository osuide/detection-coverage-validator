"""Coverage schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class TacticCoverage(BaseModel):
    """Coverage for a single tactic."""

    tactic_id: str
    tactic_name: str
    covered: int
    partial: int
    uncovered: int
    total: int
    percent: float


class GapItem(BaseModel):
    """A coverage gap item."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    priority: str  # "critical", "high", "medium", "low"
    reason: str
    data_sources: list[str] = []


class CoverageResponse(BaseModel):
    """Schema for coverage response."""

    id: UUID
    cloud_account_id: UUID
    total_techniques: int
    covered_techniques: int
    partial_techniques: int
    uncovered_techniques: int
    coverage_percent: float
    average_confidence: float
    tactic_coverage: list[TacticCoverage]
    total_detections: int
    active_detections: int
    mapped_detections: int
    top_gaps: list[GapItem]
    mitre_version: str
    created_at: datetime

    class Config:
        from_attributes = True


class CoverageHistoryItem(BaseModel):
    """Schema for coverage history item."""

    date: datetime
    coverage_percent: float
    covered_techniques: int
    total_techniques: int


class CoverageHistoryResponse(BaseModel):
    """Schema for coverage history."""

    cloud_account_id: UUID
    history: list[CoverageHistoryItem]
    trend: str  # "improving", "declining", "stable"
    change_percent: float  # Change over time period
