"""Evaluation history API endpoints for Phase 3.

Provides endpoints for querying detection evaluation history, compliance trends,
and evaluation alerts.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select, func, and_, case
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.security import AuthContext, require_role
from app.models.user import UserRole
from app.models.cloud_account import CloudAccount
from app.models.detection import Detection
from app.models.detection_evaluation_history import (
    DetectionEvaluationHistory,
    DetectionEvaluationAlert,
)
from app.schemas.evaluation_history import (
    DetectionEvaluationHistoryResponse,
    EvaluationHistoryItem,
    EvaluationHistorySummary,
    DateRangeResponse,
    PaginationResponse,
    AccountEvaluationSummaryResponse,
    AccountSummaryStats,
    HealthStatusBreakdown,
    AccountTrends,
    DetectionTypeStats,
    EvaluationTrendsResponse,
    TrendDataPoint,
    TrendAggregates,
    PeriodComparison,
    EvaluationAlertsResponse,
    EvaluationAlertItem,
    AlertsSummary,
    AcknowledgeAlertResponse,
    OrganisationEvaluationSummaryResponse,
    OrgSummaryStats,
    AccountEvaluationInfo,
    AccountNeedingAttention,
)
from app.services.evaluation_history_service import (
    get_account_compliance_trend,
    acknowledge_alert,
)


# Cache control headers
TREND_CACHE_HEADER = "private, max-age=300"  # 5 minutes
SUMMARY_CACHE_HEADER = "private, max-age=600"  # 10 minutes
ALERTS_CACHE_HEADER = "private, max-age=60"  # 1 minute
ORG_CACHE_HEADER = "private, max-age=900"  # 15 minutes

# Unhealthy states for calculations
UNHEALTHY_STATES = {"NON_COMPLIANT", "ALARM", "DISABLED"}

# Healthy states for positive detection (managed services are "healthy" when enabled)
HEALTHY_STATES = {"COMPLIANT", "OK", "ENABLED", "PASSED"}


def _determine_health_status(
    detection_type: str,
    evaluation_summary: dict | None,
    raw_config: dict | None,
) -> str:
    """Determine health status for a detection based on type-specific logic.

    Different detection types store their status in different places:
    - Config Rules: evaluation_summary.compliance_type (COMPLIANT/NON_COMPLIANT)
    - CloudWatch Alarms: evaluation_summary.state (OK/ALARM/INSUFFICIENT_DATA)
    - EventBridge: evaluation_summary.state (ENABLED/DISABLED)
    - Security Hub: raw_config.enabled_controls_count (managed, always healthy if enabled)
    - GuardDuty: raw_config.detector_status (ENABLED/DISABLED)
    - Inspector: raw_config (managed, healthy if enabled)
    - Macie: raw_config.macie_status (managed, healthy if enabled)

    Returns: "HEALTHY", "UNHEALTHY", or "UNKNOWN"
    """
    eval_summary = evaluation_summary or {}
    config = raw_config or {}

    # First check evaluation_summary (Config, CloudWatch, EventBridge)
    if eval_summary:
        state = eval_summary.get("compliance_type") or eval_summary.get("state")
        if state:
            state_upper = str(state).upper()
            if state_upper in UNHEALTHY_STATES:
                return "UNHEALTHY"
            if state_upper in HEALTHY_STATES:
                return "HEALTHY"

    # Type-specific logic for managed services that don't use evaluation_summary
    dtype = str(detection_type).lower()

    if "security_hub" in dtype:
        # Security Hub: healthy if any controls are enabled
        enabled = config.get("enabled_controls_count", 0)
        if enabled > 0:
            return "HEALTHY"
        # If it exists but has 0 enabled controls, it's still "enabled" as a service
        if "standard_id" in config or "hub_arn" in config:
            return "HEALTHY"
        return "UNKNOWN"

    if "guardduty" in dtype:
        # GuardDuty: healthy if detector is enabled
        detector_status = config.get("detector_status", "")
        if str(detector_status).upper() == "ENABLED":
            return "HEALTHY"
        if str(detector_status).upper() == "DISABLED":
            return "UNHEALTHY"
        # If we have detector_id, it's at least configured
        if config.get("detector_id"):
            return "HEALTHY"
        return "UNKNOWN"

    if "inspector" in dtype:
        # Inspector: healthy if enabled (presence of coverage data indicates enabled)
        if (
            config.get("coverage")
            or config.get("ec2_coverage")
            or config.get("ecr_coverage")
        ):
            return "HEALTHY"
        if config.get("status") and str(config.get("status")).upper() == "ENABLED":
            return "HEALTHY"
        # Inspector findings exist = Inspector is running = healthy
        if "finding_types" in config or "category" in config:
            return "HEALTHY"
        return "UNKNOWN"

    if "macie" in dtype:
        # Macie: healthy if session is enabled
        macie_status = config.get("macie_status", "")
        if str(macie_status).upper() == "ENABLED":
            return "HEALTHY"
        if str(macie_status).upper() == "DISABLED":
            return "UNHEALTHY"
        # If we have Macie config at all, it's enabled
        if config.get("category") or config.get("finding_types"):
            return "HEALTHY"
        return "UNKNOWN"

    if "cloudwatch_logs_insights" in dtype or "logs_insights" in dtype:
        # CloudWatch Logs Insights queries: if they exist, they're healthy
        # (they don't have a state - they're just query definitions)
        # Note: raw_config uses camelCase (queryString, logGroupNames)
        if (
            config.get("queryString")
            or config.get("query_string")
            or config.get("logGroupNames")
            or config.get("log_group_names")
            or config.get("queryDefinitionId")
        ):
            return "HEALTHY"
        return "UNKNOWN"

    if "lambda" in dtype or "custom_lambda" in dtype:
        # Lambda functions: healthy if they exist and are not in failed state
        state = config.get("State", config.get("state", ""))
        if str(state).upper() in ("ACTIVE", "PENDING"):
            return "HEALTHY"
        if str(state).upper() in ("INACTIVE", "FAILED"):
            return "UNHEALTHY"
        # If it has a function ARN, it exists and is probably healthy
        if config.get("FunctionArn") or config.get("function_arn"):
            return "HEALTHY"
        return "UNKNOWN"

    # GCP detection types
    if "gcp_" in dtype:
        # GCP managed services are healthy if they exist
        if config.get("project_id") or config.get("source_id"):
            return "HEALTHY"
        return "UNKNOWN"

    return "UNKNOWN"


router = APIRouter()


def _get_default_date_range(days: int = 30) -> tuple[datetime, datetime]:
    """Get default date range (last N days to now)."""
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    return start_date, end_date


def _calculate_trend(current: float, previous: float) -> str:
    """Calculate trend direction based on change."""
    if previous == 0:
        return "stable"
    change = ((current - previous) / previous) * 100
    if change > 5:
        return "improving"
    elif change < -5:
        return "declining"
    return "stable"


@router.get(
    "/detections/{detection_id}/history",
    response_model=DetectionEvaluationHistoryResponse,
)
async def get_detection_evaluation_history(
    detection_id: UUID,
    response: Response,
    start_date: Optional[datetime] = Query(
        None, description="Start of date range (ISO 8601)"
    ),
    end_date: Optional[datetime] = Query(
        None, description="End of date range (ISO 8601)"
    ),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER, UserRole.VIEWER)
    ),
) -> DetectionEvaluationHistoryResponse:
    """Get compliance/evaluation history for a single detection as a time series.

    Returns historical evaluation data, useful for tracking how a detection's
    status has changed over time.
    """
    response.headers["Cache-Control"] = TREND_CACHE_HEADER

    # Default date range if not provided
    if not start_date or not end_date:
        default_start, default_end = _get_default_date_range(30)
        start_date = start_date or default_start
        end_date = end_date or default_end

    # Verify detection exists and user has access
    detection_query = (
        select(Detection)
        .options(selectinload(Detection.cloud_account))
        .where(Detection.id == detection_id)
    )
    result = await db.execute(detection_query)
    detection = result.scalar_one_or_none()

    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found",
        )

    # Verify organisation access
    if detection.cloud_account.organization_id != auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found",
        )

    # Query history records
    history_query = (
        select(DetectionEvaluationHistory)
        .where(
            and_(
                DetectionEvaluationHistory.detection_id == detection_id,
                DetectionEvaluationHistory.recorded_at >= start_date,
                DetectionEvaluationHistory.recorded_at <= end_date,
            )
        )
        .order_by(DetectionEvaluationHistory.recorded_at.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(history_query)
    history_records = result.scalars().all()

    # Get total count
    count_query = (
        select(func.count())
        .select_from(DetectionEvaluationHistory)
        .where(
            and_(
                DetectionEvaluationHistory.detection_id == detection_id,
                DetectionEvaluationHistory.recorded_at >= start_date,
                DetectionEvaluationHistory.recorded_at <= end_date,
            )
        )
    )
    result = await db.execute(count_query)
    total_count = result.scalar() or 0

    # Calculate summary stats
    changes_query = (
        select(func.count())
        .select_from(DetectionEvaluationHistory)
        .where(
            and_(
                DetectionEvaluationHistory.detection_id == detection_id,
                DetectionEvaluationHistory.recorded_at >= start_date,
                DetectionEvaluationHistory.recorded_at <= end_date,
                DetectionEvaluationHistory.state_changed == True,  # noqa: E712
            )
        )
    )
    result = await db.execute(changes_query)
    status_changes = result.scalar() or 0

    # Get most common status
    most_common_query = (
        select(
            DetectionEvaluationHistory.current_state,
            func.count().label("cnt"),
        )
        .where(
            and_(
                DetectionEvaluationHistory.detection_id == detection_id,
                DetectionEvaluationHistory.recorded_at >= start_date,
                DetectionEvaluationHistory.recorded_at <= end_date,
            )
        )
        .group_by(DetectionEvaluationHistory.current_state)
        .order_by(func.count().desc())
        .limit(1)
    )
    result = await db.execute(most_common_query)
    most_common_row = result.first()
    most_common_status = most_common_row[0] if most_common_row else "UNKNOWN"

    # Calculate healthy/unhealthy percentages
    healthy_count = sum(
        1 for h in history_records if h.current_state not in UNHEALTHY_STATES
    )
    unhealthy_count = len(history_records) - healthy_count
    total_for_pct = len(history_records) or 1

    history_items = [
        EvaluationHistoryItem(
            id=h.id,
            timestamp=h.recorded_at,
            evaluation_status=h.current_state,
            previous_status=h.previous_state,
            status_changed=h.state_changed,
            evaluation_summary=h.evaluation_summary,
        )
        for h in history_records
    ]

    return DetectionEvaluationHistoryResponse(
        detection_id=detection.id,
        detection_name=detection.name,
        detection_type=detection.detection_type.value,
        date_range=DateRangeResponse(start_date=start_date, end_date=end_date),
        total_records=total_count,
        history=history_items,
        summary=EvaluationHistorySummary(
            total_records=total_count,
            total_status_changes=status_changes,
            time_in_healthy_percent=round((healthy_count / total_for_pct) * 100, 2),
            time_in_unhealthy_percent=round((unhealthy_count / total_for_pct) * 100, 2),
            most_common_status=most_common_status,
        ),
        pagination=PaginationResponse(
            offset=offset,
            limit=limit,
            total=total_count,
            has_more=(offset + limit) < total_count,
        ),
    )


@router.get(
    "/accounts/{cloud_account_id}/summary",
    response_model=AccountEvaluationSummaryResponse,
)
async def get_account_evaluation_summary(
    cloud_account_id: UUID,
    response: Response,
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER, UserRole.VIEWER)
    ),
) -> AccountEvaluationSummaryResponse:
    """Get aggregated evaluation/compliance statistics for all detections in an account.

    Provides a high-level overview of detection health and compliance status
    across the account, with breakdowns by detection type.
    """
    response.headers["Cache-Control"] = SUMMARY_CACHE_HEADER

    # Verify access to account
    account = await db.get(CloudAccount, cloud_account_id)
    if not account or account.organization_id != auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found",
        )

    # Default date range
    if not start_date or not end_date:
        default_start, default_end = _get_default_date_range(30)
        start_date = start_date or default_start
        end_date = end_date or default_end

    # Get current detection states - fetch individual detections for proper health checks
    # We need raw_config for managed services (Security Hub, GuardDuty, etc.)
    detection_query = select(
        Detection.detection_type,
        Detection.evaluation_summary,
        Detection.raw_config,
    ).where(Detection.cloud_account_id == cloud_account_id)
    result = await db.execute(detection_query)
    detection_rows = result.all()

    # Count detections with history
    history_count_query = select(
        func.count(func.distinct(DetectionEvaluationHistory.detection_id))
    ).where(
        and_(
            DetectionEvaluationHistory.cloud_account_id == cloud_account_id,
            DetectionEvaluationHistory.recorded_at >= start_date,
        )
    )
    result = await db.execute(history_count_query)
    detections_with_history = result.scalar() or 0

    # Aggregate stats
    total_detections = 0
    healthy_count = 0
    unhealthy_count = 0
    unknown_count = 0
    by_type: dict[str, DetectionTypeStats] = {}

    for row in detection_rows:
        dtype = (
            row.detection_type.value
            if hasattr(row.detection_type, "value")
            else str(row.detection_type)
        )
        total_detections += 1

        # Use the new helper function to determine health status
        health_status = _determine_health_status(
            dtype,
            row.evaluation_summary,
            row.raw_config,
        )

        if health_status == "UNHEALTHY":
            unhealthy_count += 1
        elif health_status == "UNKNOWN":
            unknown_count += 1
        else:
            healthy_count += 1

        # Build by-type stats
        if dtype not in by_type:
            by_type[dtype] = DetectionTypeStats(
                detection_type=dtype,
                total=0,
                healthy_count=0,
                unhealthy_count=0,
                unknown_count=0,
            )

        by_type[dtype].total += 1
        if health_status == "UNHEALTHY":
            by_type[dtype].unhealthy_count += 1
        elif health_status == "UNKNOWN":
            by_type[dtype].unknown_count += 1
        else:
            by_type[dtype].healthy_count += 1

    # Get state changes count for trends
    changes_query = (
        select(func.count())
        .select_from(DetectionEvaluationHistory)
        .where(
            and_(
                DetectionEvaluationHistory.cloud_account_id == cloud_account_id,
                DetectionEvaluationHistory.recorded_at >= start_date,
                DetectionEvaluationHistory.recorded_at <= end_date,
                DetectionEvaluationHistory.state_changed == True,  # noqa: E712
            )
        )
    )
    result = await db.execute(changes_query)
    status_changes = result.scalar() or 0

    health_pct = (healthy_count / total_detections * 100) if total_detections > 0 else 0

    return AccountEvaluationSummaryResponse(
        cloud_account_id=cloud_account_id,
        account_name=account.name,
        date_range=DateRangeResponse(start_date=start_date, end_date=end_date),
        summary=AccountSummaryStats(
            total_detections=total_detections,
            detections_with_history=detections_with_history,
            health_status_breakdown=HealthStatusBreakdown(
                healthy=healthy_count,
                unhealthy=unhealthy_count,
                unknown=unknown_count,
            ),
            health_percentage=round(health_pct, 2),
        ),
        trends=AccountTrends(
            trend="stable",  # Would calculate from historical data
            health_change_percent=0.0,
            status_changes_total=status_changes,
        ),
        by_detection_type=list(by_type.values()),
        generated_at=datetime.now(timezone.utc),
    )


@router.get(
    "/accounts/{cloud_account_id}/trends",
    response_model=EvaluationTrendsResponse,
)
async def get_account_evaluation_trends(
    cloud_account_id: UUID,
    response: Response,
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER, UserRole.VIEWER)
    ),
) -> EvaluationTrendsResponse:
    """Get time series trend data optimised for dashboard chart visualisation.

    Returns data points suitable for rendering compliance and health trends
    in dashboard charts, with period-over-period comparison.
    """
    response.headers["Cache-Control"] = TREND_CACHE_HEADER

    # Verify access to account
    account = await db.get(CloudAccount, cloud_account_id)
    if not account or account.organization_id != auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found",
        )

    # Default date range
    if not start_date or not end_date:
        default_start, default_end = _get_default_date_range(30)
        start_date = start_date or default_start
        end_date = end_date or default_end

    days = (end_date - start_date).days

    # Get trend data from service
    trend_data = await get_account_compliance_trend(db, cloud_account_id, days)

    data_points = [
        TrendDataPoint(
            date=datetime.fromisoformat(dp["date"]).date(),
            total_detections=dp["total"],
            healthy_count=dp["healthy"],
            unhealthy_count=dp["unhealthy"],
            health_percentage=dp["health_percentage"],
            state_changes=dp["state_changes"],
        )
        for dp in trend_data
    ]

    # Calculate aggregates
    if data_points:
        avg_health = sum(dp.health_percentage for dp in data_points) / len(data_points)
        max_unhealthy = max(dp.unhealthy_count for dp in data_points)
        min_unhealthy = min(dp.unhealthy_count for dp in data_points)
        total_changes = sum(dp.state_changes for dp in data_points)
    else:
        avg_health = 0
        max_unhealthy = 0
        min_unhealthy = 0
        total_changes = 0

    # Calculate period comparison (first half vs second half)
    mid_point = len(data_points) // 2
    if mid_point > 0 and len(data_points) > mid_point:
        first_half_avg = (
            sum(dp.health_percentage for dp in data_points[:mid_point]) / mid_point
        )
        second_half_avg = sum(
            dp.health_percentage for dp in data_points[mid_point:]
        ) / (len(data_points) - mid_point)
        health_change = second_half_avg - first_half_avg
        unhealthy_change = sum(
            dp.unhealthy_count for dp in data_points[mid_point:]
        ) - sum(dp.unhealthy_count for dp in data_points[:mid_point])
        trend = _calculate_trend(second_half_avg, first_half_avg)
    else:
        health_change = 0
        unhealthy_change = 0
        trend = "stable"

    return EvaluationTrendsResponse(
        cloud_account_id=cloud_account_id,
        account_name=account.name,
        date_range=DateRangeResponse(start_date=start_date, end_date=end_date),
        aggregation="daily",
        data_points=data_points,
        aggregates=TrendAggregates(
            average_health_percentage=round(avg_health, 2),
            max_unhealthy_count=max_unhealthy,
            min_unhealthy_count=min_unhealthy,
            total_state_changes=total_changes,
        ),
        comparison=PeriodComparison(
            health_change_percent=round(health_change, 2),
            unhealthy_count_change=unhealthy_change,
            trend=trend,
        ),
    )


@router.get(
    "/accounts/{cloud_account_id}/alerts",
    response_model=EvaluationAlertsResponse,
)
async def get_account_evaluation_alerts(
    cloud_account_id: UUID,
    response: Response,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    is_acknowledged: Optional[bool] = Query(
        None, description="Filter by acknowledgement"
    ),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER, UserRole.VIEWER)
    ),
) -> EvaluationAlertsResponse:
    """Get evaluation alerts for an account.

    Returns alerts for status changes that require attention.
    """
    response.headers["Cache-Control"] = ALERTS_CACHE_HEADER

    # Verify access to account
    account = await db.get(CloudAccount, cloud_account_id)
    if not account or account.organization_id != auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found",
        )

    # Build query
    query = (
        select(DetectionEvaluationAlert)
        .options(selectinload(DetectionEvaluationAlert.detection))
        .where(DetectionEvaluationAlert.cloud_account_id == cloud_account_id)
    )

    if severity:
        query = query.where(DetectionEvaluationAlert.severity == severity)

    if is_acknowledged is not None:
        query = query.where(DetectionEvaluationAlert.is_acknowledged == is_acknowledged)

    query = query.order_by(DetectionEvaluationAlert.created_at.desc())

    # Get total count
    count_query = (
        select(func.count())
        .select_from(DetectionEvaluationAlert)
        .where(DetectionEvaluationAlert.cloud_account_id == cloud_account_id)
    )
    if severity:
        count_query = count_query.where(DetectionEvaluationAlert.severity == severity)
    if is_acknowledged is not None:
        count_query = count_query.where(
            DetectionEvaluationAlert.is_acknowledged == is_acknowledged
        )

    result = await db.execute(count_query)
    total_count = result.scalar() or 0

    # Get alerts with pagination
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()

    # Build summary
    unacked_query = (
        select(func.count())
        .select_from(DetectionEvaluationAlert)
        .where(
            and_(
                DetectionEvaluationAlert.cloud_account_id == cloud_account_id,
                DetectionEvaluationAlert.is_acknowledged == False,  # noqa: E712
            )
        )
    )
    result = await db.execute(unacked_query)
    unacknowledged = result.scalar() or 0

    # Group by severity
    severity_query = (
        select(
            DetectionEvaluationAlert.severity,
            func.count().label("cnt"),
        )
        .where(DetectionEvaluationAlert.cloud_account_id == cloud_account_id)
        .group_by(DetectionEvaluationAlert.severity)
    )
    result = await db.execute(severity_query)
    by_severity = {str(row[0].value): row[1] for row in result.all()}

    # Group by type
    type_query = (
        select(
            DetectionEvaluationAlert.alert_type,
            func.count().label("cnt"),
        )
        .where(DetectionEvaluationAlert.cloud_account_id == cloud_account_id)
        .group_by(DetectionEvaluationAlert.alert_type)
    )
    result = await db.execute(type_query)
    by_type = {row[0]: row[1] for row in result.all()}

    alert_items = [
        EvaluationAlertItem(
            id=a.id,
            alert_type=a.alert_type,
            severity=a.severity.value,
            title=a.title,
            message=a.message,
            detection_id=a.detection_id,
            detection_name=a.detection.name if a.detection else None,
            detection_type=a.detection.detection_type.value if a.detection else None,
            previous_state=a.previous_state,
            current_state=a.current_state,
            is_acknowledged=a.is_acknowledged,
            acknowledged_at=a.acknowledged_at,
            created_at=a.created_at,
            details=a.details,
        )
        for a in alerts
    ]

    return EvaluationAlertsResponse(
        cloud_account_id=cloud_account_id,
        account_name=account.name,
        alerts=alert_items,
        summary=AlertsSummary(
            total_alerts=total_count,
            unacknowledged=unacknowledged,
            by_severity=by_severity,
            by_type=by_type,
        ),
        pagination=PaginationResponse(
            offset=offset,
            limit=limit,
            total=total_count,
            has_more=(offset + limit) < total_count,
        ),
    )


@router.post(
    "/alerts/{alert_id}/acknowledge",
    response_model=AcknowledgeAlertResponse,
)
async def acknowledge_evaluation_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER)
    ),
) -> AcknowledgeAlertResponse:
    """Acknowledge an evaluation alert.

    Marks the alert as acknowledged by the current user.
    """
    alert = await acknowledge_alert(db, alert_id, auth.user_id)

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    # Verify organisation access
    if alert.organization_id != auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    await db.commit()

    return AcknowledgeAlertResponse(
        message="Alert acknowledged successfully",
        alert_id=alert.id,
        acknowledged_at=alert.acknowledged_at,
    )


@router.get(
    "/organisation/summary",
    response_model=OrganisationEvaluationSummaryResponse,
)
async def get_organisation_evaluation_summary(
    response: Response,
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER, UserRole.VIEWER)
    ),
) -> OrganisationEvaluationSummaryResponse:
    """Get aggregated evaluation summary across all accounts in the organisation.

    Provides a bird's-eye view of detection health and compliance across
    the entire organisation, highlighting accounts that need attention.
    """
    response.headers["Cache-Control"] = ORG_CACHE_HEADER

    # Default date range
    if not start_date or not end_date:
        default_start, default_end = _get_default_date_range(30)
        start_date = start_date or default_start
        end_date = end_date or default_end

    # Get all accounts for the organisation
    accounts_query = select(CloudAccount).where(
        CloudAccount.organization_id == auth.organization_id
    )
    result = await db.execute(accounts_query)
    accounts = result.scalars().all()

    by_account: list[AccountEvaluationInfo] = []
    accounts_needing_attention: list[AccountNeedingAttention] = []
    total_detections = 0
    total_healthy = 0
    total_alerts = 0

    for account in accounts:
        # Get detection counts
        detection_query = select(
            func.count().label("total"),
            func.sum(
                case(
                    (
                        Detection.evaluation_summary["compliance_type"].astext.in_(
                            ["NON_COMPLIANT"]
                        ),
                        1,
                    ),
                    (
                        Detection.evaluation_summary["state"].astext.in_(
                            ["ALARM", "DISABLED"]
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("unhealthy"),
        ).where(Detection.cloud_account_id == account.id)
        result = await db.execute(detection_query)
        row = result.first()
        account_total = row.total or 0
        account_unhealthy = row.unhealthy or 0
        account_healthy = account_total - account_unhealthy

        total_detections += account_total
        total_healthy += account_healthy

        health_pct = (
            (account_healthy / account_total * 100) if account_total > 0 else 100
        )

        # Get alert count
        alerts_query = (
            select(func.count())
            .select_from(DetectionEvaluationAlert)
            .where(
                and_(
                    DetectionEvaluationAlert.cloud_account_id == account.id,
                    DetectionEvaluationAlert.is_acknowledged == False,  # noqa: E712
                )
            )
        )
        result = await db.execute(alerts_query)
        account_alerts = result.scalar() or 0
        total_alerts += account_alerts

        by_account.append(
            AccountEvaluationInfo(
                cloud_account_id=account.id,
                account_name=account.name,
                provider=account.provider,
                total_detections=account_total,
                health_percentage=round(health_pct, 2),
                unhealthy_count=account_unhealthy,
                trend="stable",
            )
        )

        # Check if account needs attention
        if health_pct < 70 or account_alerts > 5:
            reason = "low_health" if health_pct < 70 else "many_alerts"
            accounts_needing_attention.append(
                AccountNeedingAttention(
                    cloud_account_id=account.id,
                    account_name=account.name,
                    reason=reason,
                    health_percentage=round(health_pct, 2),
                    critical_alerts=account_alerts,
                )
            )

    overall_health = (
        (total_healthy / total_detections * 100) if total_detections > 0 else 100
    )

    return OrganisationEvaluationSummaryResponse(
        organisation_id=auth.organization_id,
        organisation_name=auth.organization_name or "Organisation",
        date_range=DateRangeResponse(start_date=start_date, end_date=end_date),
        summary=OrgSummaryStats(
            total_accounts=len(accounts),
            total_detections=total_detections,
            overall_health_percentage=round(overall_health, 2),
            total_alerts=total_alerts,
        ),
        by_account=by_account,
        accounts_needing_attention=accounts_needing_attention,
        generated_at=datetime.now(timezone.utc),
    )
