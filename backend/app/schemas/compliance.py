"""Compliance framework schemas."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class ComplianceFrameworkResponse(BaseModel):
    """Response schema for a compliance framework."""

    id: UUID
    framework_id: str
    name: str
    version: str
    description: Optional[str] = None
    source_url: Optional[str] = None
    total_controls: int = 0
    is_active: bool

    class Config:
        from_attributes = True


class ControlResponse(BaseModel):
    """Response schema for a compliance control."""

    id: UUID
    control_id: str
    control_family: str
    name: str
    description: Optional[str] = None
    priority: Optional[str] = None
    is_enhancement: bool
    mapped_technique_count: int = 0

    class Config:
        from_attributes = True


class TechniqueMappingResponse(BaseModel):
    """Response schema for a technique mapping."""

    technique_id: str
    technique_name: str
    mapping_type: str
    mapping_source: str

    class Config:
        from_attributes = True


class ComplianceCoverageSummary(BaseModel):
    """Summary of compliance coverage for a framework."""

    framework_id: str
    framework_name: str
    coverage_percent: float
    covered_controls: int
    total_controls: int


class FamilyCoverageItem(BaseModel):
    """Coverage breakdown for a control family."""

    family: str
    total: int
    covered: int
    partial: int
    uncovered: int
    percent: float


class ControlGapItem(BaseModel):
    """A control that needs attention (gap)."""

    control_id: str
    control_name: str
    control_family: str
    priority: Optional[str] = None
    coverage_percent: float
    missing_techniques: list[str] = []


class ComplianceCoverageResponse(BaseModel):
    """Full compliance coverage response."""

    id: UUID
    cloud_account_id: UUID
    framework: ComplianceFrameworkResponse
    total_controls: int
    covered_controls: int
    partial_controls: int
    uncovered_controls: int
    coverage_percent: float
    family_coverage: list[FamilyCoverageItem]
    top_gaps: list[ControlGapItem]
    created_at: datetime

    class Config:
        from_attributes = True
