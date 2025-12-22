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


class CloudContextResponse(BaseModel):
    """Cloud context for a compliance control."""

    aws_services: list[str] = []
    gcp_services: list[str] = []
    shared_responsibility: str = "customer"  # "customer", "shared", "provider"
    detection_guidance: Optional[str] = None


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
    cloud_applicability: Optional[str] = "highly_relevant"
    cloud_context: Optional[CloudContextResponse] = None

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


class CloudCoverageMetricsResponse(BaseModel):
    """Cloud-specific coverage metrics."""

    cloud_detectable_total: int
    cloud_detectable_covered: int
    cloud_coverage_percent: float
    customer_responsibility_total: int
    customer_responsibility_covered: int
    provider_managed_total: int
    not_assessable_total: int = 0  # Controls that cannot be assessed via cloud scanning


class ComplianceCoverageSummary(BaseModel):
    """Summary of compliance coverage for a framework."""

    framework_id: str
    framework_name: str
    coverage_percent: float
    covered_controls: int
    total_controls: int
    cloud_coverage_percent: Optional[float] = None  # Cloud-detectable coverage


class FamilyCoverageItem(BaseModel):
    """Coverage breakdown for a control family."""

    family: str
    total: int
    covered: int
    partial: int
    uncovered: int
    not_assessable: int = 0  # Controls that cannot be assessed via cloud scanning
    percent: float
    cloud_applicability: Optional[str] = None  # "highly_relevant", etc.
    shared_responsibility: Optional[str] = None  # "customer", "shared", "provider"


class MissingTechniqueDetail(BaseModel):
    """Enriched details for a missing technique with remediation info."""

    technique_id: str
    technique_name: str
    has_template: bool = False  # Whether a remediation template is available
    tactic_ids: list[str] = []  # MITRE tactic IDs (e.g., ["TA0001", "TA0003"])


class ControlGapItem(BaseModel):
    """A control that needs attention (gap)."""

    control_id: str
    control_name: str
    control_family: str
    priority: Optional[str] = None
    coverage_percent: float
    missing_techniques: list[str] = []  # Technique IDs for backwards compatibility
    missing_technique_details: list[MissingTechniqueDetail] = (
        []
    )  # Enriched technique info
    cloud_applicability: Optional[str] = None
    cloud_context: Optional[CloudContextResponse] = None


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
    cloud_metrics: Optional[CloudCoverageMetricsResponse] = None
    family_coverage: list[FamilyCoverageItem]
    top_gaps: list[ControlGapItem]
    created_at: datetime

    class Config:
        from_attributes = True
