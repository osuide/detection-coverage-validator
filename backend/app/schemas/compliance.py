"""Compliance framework schemas."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


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

    model_config = ConfigDict(from_attributes=True)


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

    model_config = ConfigDict(from_attributes=True)


class TechniqueMappingResponse(BaseModel):
    """Response schema for a technique mapping."""

    technique_id: str
    technique_name: str
    mapping_type: str
    mapping_source: str

    model_config = ConfigDict(from_attributes=True)


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
    assessable: int = 0  # Controls that CAN be assessed via cloud scanning
    percent: float  # Percent of ASSESSABLE controls that are covered
    cloud_applicability: Optional[str] = None  # Dominant type or "mixed"
    shared_responsibility: Optional[str] = None  # Dominant type or "mixed"
    # Breakdown for mixed families - shows count by type
    applicability_breakdown: Optional[dict] = (
        None  # e.g., {"highly_relevant": 10, "informational": 2}
    )
    responsibility_breakdown: Optional[dict] = (
        None  # e.g., {"customer": 8, "shared": 4}
    )


class MissingTechniqueDetail(BaseModel):
    """Enriched details for a missing technique with remediation info."""

    technique_id: str
    technique_name: str
    has_template: bool = False  # Whether a remediation template is available
    tactic_ids: list[str] = []  # MITRE tactic IDs (e.g., ["TA0001", "TA0003"])


class DetectionSummary(BaseModel):
    """Summary of a detection providing coverage."""

    id: UUID
    name: str
    source: str  # e.g., "aws_cloudwatch", "aws_config"
    confidence: float


class TechniqueCoverageDetail(BaseModel):
    """Detailed coverage information for a single technique within a control."""

    technique_id: str
    technique_name: str
    status: str  # "covered", "partial", "uncovered"
    confidence: Optional[float] = None  # Max confidence if covered
    detections: list[DetectionSummary] = []  # Detections providing coverage
    has_template: bool = False  # Whether a remediation template is available


class ControlCoverageDetailResponse(BaseModel):
    """Detailed coverage breakdown for a single compliance control."""

    control_id: str
    control_name: str
    control_family: str
    description: Optional[str] = None
    priority: Optional[str] = None
    status: str  # "covered", "partial", "uncovered", "not_assessable"
    coverage_percent: float
    coverage_rationale: (
        str  # Human-readable explanation, e.g., "2 of 4 techniques covered"
    )
    mapped_techniques: int
    covered_techniques: int
    cloud_applicability: Optional[str] = None
    cloud_context: Optional[CloudContextResponse] = None
    techniques: list[TechniqueCoverageDetail] = []


class ControlStatusItem(BaseModel):
    """Compact control info for status-based grouping."""

    control_id: str
    control_name: str
    control_family: str
    priority: Optional[str] = None
    coverage_percent: float
    mapped_techniques: int = 0  # Total mapped techniques
    covered_techniques: int = 0  # Techniques with detections
    cloud_applicability: Optional[str] = None
    shared_responsibility: Optional[str] = None  # customer/shared/provider


class ControlsByStatus(BaseModel):
    """Controls grouped by coverage status."""

    covered: list[ControlStatusItem] = []
    partial: list[ControlStatusItem] = []
    uncovered: list[ControlStatusItem] = []
    not_assessable: list[ControlStatusItem] = []


class ControlsByCloudCategory(BaseModel):
    """Controls grouped by cloud responsibility category."""

    cloud_detectable: list[ControlStatusItem] = []  # Can be assessed via cloud scanning
    customer_responsibility: list[ControlStatusItem] = []  # Customer must cover
    provider_managed: list[ControlStatusItem] = []  # AWS/GCP manages
    not_assessable: list[ControlStatusItem] = []  # Outside cloud scope


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
    # Detailed breakdowns for clickable stat cards
    controls_by_status: Optional[ControlsByStatus] = None
    controls_by_cloud_category: Optional[ControlsByCloudCategory] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
