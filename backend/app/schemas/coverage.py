"""Coverage schemas."""

from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class TacticCoverage(BaseModel):
    """Coverage for a single tactic."""

    tactic_id: str
    tactic_name: str
    covered: int
    partial: int
    uncovered: int
    total: int
    percent: float


class CoverageBreakdown(BaseModel):
    """Breakdown of coverage contribution by source."""

    account_only: int = Field(
        0, description="Techniques covered only by account-level detections"
    )
    org_only: int = Field(
        0, description="Techniques covered only by organisation-level detections"
    )
    both: int = Field(
        0, description="Techniques covered by both account and org detections"
    )
    total_covered: int = Field(0, description="Total covered techniques")
    cloud_organization_id: Optional[str] = Field(
        None, description="Cloud organisation ID if account is part of one"
    )


class SecurityFunctionBreakdown(BaseModel):
    """Breakdown of detections by NIST CSF security function.

    This explains what purpose each detection serves:
    - detect: Threat detection - maps to MITRE ATT&CK techniques
    - protect: Preventive controls - access controls, encryption, MFA
    - identify: Visibility controls - logging, monitoring, posture
    - recover: Recovery controls - backup, DR, versioning
    - operational: Non-security controls - tagging, cost, performance
    """

    detect: int = Field(0, description="Threat detection (MITRE ATT&CK mapped)")
    protect: int = Field(0, description="Preventive controls")
    identify: int = Field(0, description="Visibility/logging/posture")
    recover: int = Field(0, description="Recovery/DR/resilience")
    operational: int = Field(0, description="Non-security (tagging, cost)")
    total: int = Field(0, description="Total detections across all functions")


class RecommendedStrategyItem(BaseModel):
    """A recommended detection strategy."""

    strategy_id: str
    name: str
    detection_type: str
    aws_service: str
    implementation_effort: str
    estimated_time: str
    detection_coverage: str
    has_query: bool = False
    has_cloudformation: bool = False
    has_terraform: bool = False
    # GCP support
    gcp_service: Optional[str] = None
    cloud_provider: Optional[str] = None
    has_gcp_query: bool = False
    has_gcp_terraform: bool = False


class EffortEstimatesResponse(BaseModel):
    """Tiered effort estimates for detection implementation.

    Provides realistic implementation scopes:
    - quick_win: First 2 strategies for fast value
    - typical: First 3 strategies for balanced coverage
    - comprehensive: All strategies for complete implementation
    """

    quick_win_hours: float
    typical_hours: float
    comprehensive_hours: float
    strategy_count: int


class GapItem(BaseModel):
    """A coverage gap item with remediation guidance."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    priority: str  # "critical", "high", "medium", "low"
    reason: str
    data_sources: list[str] = []
    recommended_detections: list[str] = []

    # Enhanced remediation data from templates
    has_template: bool = False
    severity_score: Optional[int] = None
    threat_actors: List[str] = []
    business_impact: List[str] = []
    quick_win_strategy: Optional[str] = None
    total_effort_hours: Optional[float] = None  # Kept for backwards compatibility
    effort_estimates: Optional[EffortEstimatesResponse] = (
        None  # Tiered effort estimates
    )
    mitre_url: Optional[str] = None
    recommended_strategies: List[RecommendedStrategyItem] = []


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

    # Organisation contribution fields
    org_detection_count: int = 0
    org_covered_techniques: int = 0
    account_only_techniques: int = 0
    org_only_techniques: int = 0
    overlap_techniques: int = 0
    coverage_breakdown: Optional[CoverageBreakdown] = None

    # Security function breakdown (NIST CSF)
    security_function_breakdown: Optional[SecurityFunctionBreakdown] = None

    model_config = ConfigDict(from_attributes=True)


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


class OrgTacticCoverage(BaseModel):
    """Aggregate tactic coverage for an organisation."""

    tactic_id: str
    tactic_name: str
    total_techniques: int
    union_covered: int
    minimum_covered: int
    union_percent: float
    minimum_percent: float


class AccountCoverageSummary(BaseModel):
    """Summary of coverage for an account within an organisation."""

    cloud_account_id: UUID
    account_name: str
    account_id: str  # External account ID (AWS account ID or GCP project ID)
    coverage_percent: float
    covered_techniques: int
    total_techniques: int


class OrgCoverageResponse(BaseModel):
    """Schema for organisation-wide coverage response."""

    id: UUID
    cloud_organization_id: UUID

    # Account counts
    total_member_accounts: int
    connected_accounts: int

    # Aggregate coverage metrics
    total_techniques: int
    union_covered_techniques: int = Field(
        description="Techniques covered in ANY account"
    )
    minimum_covered_techniques: int = Field(
        description="Techniques covered in ALL accounts"
    )
    average_coverage_percent: float

    # Coverage percentages
    union_coverage_percent: float = Field(
        description="Percentage of techniques covered in at least one account"
    )
    minimum_coverage_percent: float = Field(
        description="Percentage of techniques covered in all accounts"
    )

    # Org-level detection summary
    org_detection_count: int
    org_covered_techniques: int

    # Per-tactic breakdown
    tactic_coverage: List[OrgTacticCoverage]

    # Per-account summary (optional - may be requested separately for large orgs)
    per_account_coverage: Optional[List[AccountCoverageSummary]] = None

    mitre_version: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrgCoverageBreakdownRequest(BaseModel):
    """Request for detailed org coverage breakdown."""

    include_per_account: bool = Field(
        True, description="Include per-account coverage details"
    )
    include_techniques: bool = Field(
        False, description="Include per-technique coverage details"
    )
    filter_by_hierarchy: Optional[str] = Field(
        None, description="Filter accounts by hierarchy path (e.g., 'Production')"
    )
