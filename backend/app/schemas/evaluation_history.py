"""Evaluation history schemas for Phase 3: Detection Evaluation History."""

from datetime import datetime, date
from typing import Optional, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

# ============================================================================
# Enums and Common Types
# ============================================================================

AggregationLevel = Literal["hourly", "daily", "weekly", "monthly"]
EventType = Literal["state_change", "state_degraded", "state_recovered"]
EventSeverity = Literal["info", "warning", "critical"]
TrendDirection = Literal["improving", "stable", "declining"]
SortOrder = Literal["asc", "desc"]


# ============================================================================
# Common Components
# ============================================================================


class DateRangeResponse(BaseModel):
    """Date range for queries."""

    start_date: datetime
    end_date: datetime


class PaginationResponse(BaseModel):
    """Pagination metadata."""

    offset: int
    limit: int
    total: int
    has_more: bool


class DetectionSummaryInfo(BaseModel):
    """Compact detection info for event responses."""

    id: UUID
    name: str
    detection_type: str


# ============================================================================
# Detection Evaluation History (Single Detection Time Series)
# ============================================================================


class EvaluationHistoryItem(BaseModel):
    """Single history record for a detection."""

    id: UUID
    timestamp: datetime
    evaluation_status: str
    previous_status: Optional[str] = None
    status_changed: bool = False
    evaluation_summary: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)


class EvaluationHistorySummary(BaseModel):
    """Summary statistics for evaluation history."""

    total_records: int = 0
    total_status_changes: int = 0
    time_in_healthy_percent: float = 0.0
    time_in_unhealthy_percent: float = 0.0
    most_common_status: str = "UNKNOWN"


class DetectionEvaluationHistoryResponse(BaseModel):
    """Response for detection evaluation history endpoint."""

    detection_id: UUID
    detection_name: str
    detection_type: str
    date_range: DateRangeResponse
    total_records: int
    history: list[EvaluationHistoryItem]
    summary: EvaluationHistorySummary
    pagination: PaginationResponse

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Account Evaluation Summary (Aggregate Stats)
# ============================================================================


class DetectionTypeStats(BaseModel):
    """Statistics by detection type."""

    detection_type: str
    total: int
    healthy_count: int = 0
    unhealthy_count: int = 0
    unknown_count: int = 0
    # CloudWatch Alarm specific
    ok_count: Optional[int] = None
    alarm_count: Optional[int] = None
    insufficient_data_count: Optional[int] = None
    # Config Rule specific
    compliant_count: Optional[int] = None
    non_compliant_count: Optional[int] = None
    not_applicable_count: Optional[int] = None
    # EventBridge specific
    enabled_count: Optional[int] = None
    disabled_count: Optional[int] = None


class HealthStatusBreakdown(BaseModel):
    """Breakdown of health statuses."""

    healthy: int = 0
    unhealthy: int = 0
    unknown: int = 0


class AccountTrends(BaseModel):
    """Trend information for an account."""

    trend: TrendDirection = "stable"
    health_change_percent: float = 0.0
    status_changes_total: int = 0


class AccountSummaryStats(BaseModel):
    """Summary statistics for an account."""

    total_detections: int
    detections_with_history: int
    health_status_breakdown: HealthStatusBreakdown
    health_percentage: float = 0.0


class AccountEvaluationSummaryResponse(BaseModel):
    """Response for account evaluation summary endpoint."""

    cloud_account_id: UUID
    account_name: str
    date_range: DateRangeResponse
    summary: AccountSummaryStats
    trends: AccountTrends
    by_detection_type: list[DetectionTypeStats]
    generated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Compliance Trend Data (Dashboard Charts)
# ============================================================================


class TrendDataPoint(BaseModel):
    """Single data point in a trend series."""

    date: date
    total_detections: int = 0
    healthy_count: int = 0
    unhealthy_count: int = 0
    health_percentage: float = 0.0
    state_changes: int = 0


class TrendAggregates(BaseModel):
    """Aggregate statistics across the trend period."""

    average_health_percentage: float = 0.0
    max_unhealthy_count: int = 0
    min_unhealthy_count: int = 0
    total_state_changes: int = 0


class PeriodComparison(BaseModel):
    """Comparison with previous period."""

    health_change_percent: float = 0.0
    unhealthy_count_change: int = 0
    trend: TrendDirection = "stable"


class EvaluationTrendsResponse(BaseModel):
    """Response for evaluation trends endpoint."""

    cloud_account_id: UUID
    account_name: str
    date_range: DateRangeResponse
    aggregation: str = "daily"
    data_points: list[TrendDataPoint]
    aggregates: TrendAggregates
    comparison: PeriodComparison

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Evaluation Alerts
# ============================================================================


class EvaluationAlertItem(BaseModel):
    """Single evaluation alert."""

    id: UUID
    alert_type: str
    severity: str
    title: str
    message: str
    detection_id: Optional[UUID] = None
    detection_name: Optional[str] = None
    detection_type: Optional[str] = None
    previous_state: Optional[str] = None
    current_state: str
    is_acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    acknowledged_by_name: Optional[str] = None
    created_at: datetime
    details: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)


class AlertsSummary(BaseModel):
    """Summary statistics for alerts."""

    total_alerts: int
    unacknowledged: int
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}


class EvaluationAlertsResponse(BaseModel):
    """Response for evaluation alerts endpoint."""

    cloud_account_id: Optional[UUID] = None
    account_name: Optional[str] = None
    alerts: list[EvaluationAlertItem]
    summary: AlertsSummary
    pagination: PaginationResponse

    model_config = ConfigDict(from_attributes=True)


class AcknowledgeAlertRequest(BaseModel):
    """Request to acknowledge an alert."""

    pass  # No body needed


class AcknowledgeAlertResponse(BaseModel):
    """Response after acknowledging an alert."""

    message: str
    alert_id: UUID
    acknowledged_at: datetime


# ============================================================================
# Organisation-Wide Evaluation Summary
# ============================================================================


class AccountEvaluationInfo(BaseModel):
    """Evaluation info for a single account in org summary."""

    cloud_account_id: UUID
    account_name: str
    provider: str
    total_detections: int
    health_percentage: float
    unhealthy_count: int
    trend: TrendDirection


class AccountNeedingAttention(BaseModel):
    """Account that needs attention."""

    cloud_account_id: UUID
    account_name: str
    reason: str
    health_percentage: Optional[float] = None
    critical_alerts: int = 0


class OrgSummaryStats(BaseModel):
    """Organisation-wide summary statistics."""

    total_accounts: int
    total_detections: int
    overall_health_percentage: float
    total_alerts: int


class OrganisationEvaluationSummaryResponse(BaseModel):
    """Response for organisation evaluation summary endpoint."""

    organisation_id: UUID
    organisation_name: str
    date_range: DateRangeResponse
    summary: OrgSummaryStats
    by_account: list[AccountEvaluationInfo]
    accounts_needing_attention: list[AccountNeedingAttention]
    generated_at: datetime

    model_config = ConfigDict(from_attributes=True)
