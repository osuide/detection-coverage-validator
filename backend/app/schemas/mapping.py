"""Mapping schemas."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel

from app.models.mapping import MappingSource


class MappingResponse(BaseModel):
    """Schema for detection mapping response."""

    id: UUID
    detection_id: UUID
    detection_name: str
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    confidence: float
    mapping_source: MappingSource
    rationale: Optional[str] = None
    matched_indicators: Optional[list[str]] = None
    is_stale: bool
    last_validated_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class MappingListResponse(BaseModel):
    """Schema for paginated mapping list."""

    items: list[MappingResponse]
    total: int
    page: int
    page_size: int


class TechniqueResponse(BaseModel):
    """Schema for MITRE technique response."""

    id: UUID
    technique_id: str
    name: str
    description: Optional[str] = None
    tactic_id: str
    tactic_name: str
    platforms: list[str] = []
    data_sources: list[str] = []
    is_subtechnique: bool
    parent_technique_id: Optional[str] = None
    detection_count: int = 0
    coverage_status: str = "uncovered"  # "covered", "partial", "uncovered"
    average_confidence: float = 0.0


class TacticResponse(BaseModel):
    """Schema for MITRE tactic response."""

    id: UUID
    tactic_id: str
    name: str
    short_name: str
    description: Optional[str] = None
    display_order: int
    technique_count: int = 0
