"""Service for managing detection evaluation history.

This service handles:
- Recording evaluation snapshots to history
- Calculating daily aggregates
- Generating alerts for significant state changes
- Querying historical data for trends
"""

import uuid
from datetime import datetime, date, timedelta, timezone
from typing import Optional
from sqlalchemy import select, func, and_, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.models.detection import Detection, DetectionType
from app.models.detection_evaluation_history import (
    DetectionEvaluationHistory,
    DetectionEvaluationDailySummary,
    DetectionEvaluationAlert,
    EvaluationType,
    EvaluationAlertSeverity,
)


# Mapping from detection types to evaluation types
DETECTION_TYPE_TO_EVALUATION_TYPE = {
    DetectionType.CONFIG_RULE: EvaluationType.CONFIG_COMPLIANCE,
    DetectionType.CLOUDWATCH_ALARM: EvaluationType.ALARM_STATE,
    DetectionType.EVENTBRIDGE_RULE: EvaluationType.EVENTBRIDGE_STATE,
    DetectionType.GUARDDUTY_FINDING: EvaluationType.GUARDDUTY_STATE,
    DetectionType.GCP_SECURITY_COMMAND_CENTER: EvaluationType.GCP_SCC_STATE,
    DetectionType.GCP_CLOUD_LOGGING: EvaluationType.GCP_LOGGING_STATE,
}


# States that indicate unhealthy/non-compliant detections
UNHEALTHY_STATES = {"NON_COMPLIANT", "ALARM", "DISABLED", "ERROR", "BROKEN"}


def extract_current_state(
    evaluation_summary: dict | None,
    raw_config: dict | None = None,
    detection_type: str | None = None,
) -> str:
    """Extract the current state from a detection's data.

    Different detection types store their status in different places:
    - Config Rules: evaluation_summary.compliance_type
    - CloudWatch Alarms: evaluation_summary.state
    - EventBridge: evaluation_summary.state
    - Security Hub: raw_config.enabled_controls_count (managed)
    - GuardDuty: raw_config.detector_status
    - Inspector: raw_config (managed)
    - Macie: raw_config.macie_status

    Args:
        evaluation_summary: The evaluation summary JSONB
        raw_config: The raw_config JSONB (for managed services)
        detection_type: The detection type string

    Returns:
        The current state string: COMPLIANT, NON_COMPLIANT, OK, ALARM,
        ENABLED, DISABLED, or UNKNOWN
    """
    eval_summary = evaluation_summary or {}
    config = raw_config or {}
    dtype = str(detection_type or "").lower()

    # First check evaluation_summary (Config, CloudWatch, EventBridge)
    if eval_summary:
        if "compliance_type" in eval_summary:
            return eval_summary.get("compliance_type", "UNKNOWN")
        if "state" in eval_summary:
            return eval_summary.get("state", "UNKNOWN")

    # Type-specific logic for managed services
    if "security_hub" in dtype:
        # Security Hub: ENABLED if any controls are enabled
        enabled = config.get("enabled_controls_count", 0)
        if enabled > 0 or "standard_id" in config or "hub_arn" in config:
            return "ENABLED"
        return "UNKNOWN"

    if "guardduty" in dtype:
        detector_status = config.get("detector_status", "")
        if str(detector_status).upper() == "ENABLED":
            return "ENABLED"
        if str(detector_status).upper() == "DISABLED":
            return "DISABLED"
        if config.get("detector_id"):
            return "ENABLED"
        return "UNKNOWN"

    if "inspector" in dtype:
        if (
            config.get("coverage")
            or config.get("ec2_coverage")
            or config.get("ecr_coverage")
            or config.get("finding_types")
            or config.get("category")
        ):
            return "ENABLED"
        if config.get("status"):
            return str(config.get("status")).upper()
        return "UNKNOWN"

    if "macie" in dtype:
        macie_status = config.get("macie_status", "")
        if str(macie_status).upper() == "ENABLED":
            return "ENABLED"
        if str(macie_status).upper() == "DISABLED":
            return "DISABLED"
        if config.get("category") or config.get("finding_types"):
            return "ENABLED"
        return "UNKNOWN"

    if "cloudwatch_logs_insights" in dtype or "logs_insights" in dtype:
        # Logs Insights queries are always "enabled" if they exist
        if config.get("query_string") or config.get("log_group_names"):
            return "ENABLED"
        return "UNKNOWN"

    if "lambda" in dtype or "custom_lambda" in dtype:
        state = config.get("State", config.get("state", ""))
        if str(state).upper() in ("ACTIVE", "PENDING"):
            return "ENABLED"
        if str(state).upper() in ("INACTIVE", "FAILED"):
            return "DISABLED"
        if config.get("FunctionArn") or config.get("function_arn"):
            return "ENABLED"
        return "UNKNOWN"

    if "gcp_" in dtype:
        # GCP managed services are enabled if they exist
        if config.get("project_id") or config.get("source_id"):
            return "ENABLED"
        return "UNKNOWN"

    return "UNKNOWN"


async def record_evaluation_snapshot(
    session: AsyncSession,
    detection: Detection,
    scan_id: Optional[uuid.UUID] = None,
) -> Optional[DetectionEvaluationHistory]:
    """Record an evaluation snapshot for a detection.

    Args:
        session: Database session
        detection: The detection to record
        scan_id: Optional scan ID that triggered this evaluation

    Returns:
        The created history record, or None if account is missing
    """
    if not detection.cloud_account_id:
        return None

    # Get the current state from evaluation_summary or raw_config
    dtype = (
        detection.detection_type.value
        if hasattr(detection.detection_type, "value")
        else str(detection.detection_type)
    )
    current_state = extract_current_state(
        detection.evaluation_summary,
        detection.raw_config,
        dtype,
    )

    # Skip if we can't determine state at all
    if (
        current_state == "UNKNOWN"
        and not detection.evaluation_summary
        and not detection.raw_config
    ):
        return None

    # Determine evaluation type from detection type
    evaluation_type = DETECTION_TYPE_TO_EVALUATION_TYPE.get(
        detection.detection_type, EvaluationType.CONFIG_COMPLIANCE
    )

    # Get the most recent history record for this detection
    prev_record_query = (
        select(DetectionEvaluationHistory)
        .where(DetectionEvaluationHistory.detection_id == detection.id)
        .order_by(DetectionEvaluationHistory.recorded_at.desc())
        .limit(1)
    )
    result = await session.execute(prev_record_query)
    prev_record = result.scalar_one_or_none()

    # Determine if state changed
    previous_state = prev_record.current_state if prev_record else None
    state_changed = previous_state is not None and previous_state != current_state

    # Create the history record
    history_record = DetectionEvaluationHistory(
        detection_id=detection.id,
        cloud_account_id=detection.cloud_account_id,
        detection_type=detection.detection_type.value,
        evaluation_type=evaluation_type,
        previous_state=previous_state,
        current_state=current_state,
        state_changed=state_changed,
        evaluation_summary=detection.evaluation_summary,
        scan_id=scan_id,
        recorded_at=detection.evaluation_updated_at or datetime.now(timezone.utc),
    )

    session.add(history_record)

    return history_record


async def record_batch_evaluation_snapshots(
    session: AsyncSession,
    detections: list[Detection],
    scan_id: Optional[uuid.UUID] = None,
) -> list[DetectionEvaluationHistory]:
    """Record evaluation snapshots for multiple detections.

    Args:
        session: Database session
        detections: List of detections to record
        scan_id: Optional scan ID

    Returns:
        List of created history records
    """
    records = []
    for detection in detections:
        record = await record_evaluation_snapshot(session, detection, scan_id)
        if record:
            records.append(record)
    return records


async def get_evaluation_trend(
    session: AsyncSession,
    detection_id: uuid.UUID,
    days: int = 30,
) -> list[dict]:
    """Get evaluation trend for a detection over time.

    Args:
        session: Database session
        detection_id: The detection ID
        days: Number of days to look back

    Returns:
        List of daily state summaries
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    query = (
        select(
            func.date_trunc("day", DetectionEvaluationHistory.recorded_at).label("day"),
            DetectionEvaluationHistory.current_state,
            func.count().label("sample_count"),
        )
        .where(
            and_(
                DetectionEvaluationHistory.detection_id == detection_id,
                DetectionEvaluationHistory.recorded_at >= cutoff,
            )
        )
        .group_by(
            func.date_trunc("day", DetectionEvaluationHistory.recorded_at),
            DetectionEvaluationHistory.current_state,
        )
        .order_by(text("day"))
    )

    result = await session.execute(query)
    rows = result.all()

    return [
        {
            "day": row.day.isoformat() if row.day else None,
            "state": row.current_state,
            "count": row.sample_count,
        }
        for row in rows
    ]


async def get_account_compliance_trend(
    session: AsyncSession,
    cloud_account_id: uuid.UUID,
    days: int = 30,
) -> list[dict]:
    """Get compliance trend for an account using daily summaries.

    Args:
        session: Database session
        cloud_account_id: The cloud account ID
        days: Number of days to look back

    Returns:
        List of daily compliance summaries
    """
    cutoff = date.today() - timedelta(days=days)

    query = (
        select(
            DetectionEvaluationDailySummary.summary_date,
            func.sum(DetectionEvaluationDailySummary.total_detections).label("total"),
            func.sum(
                DetectionEvaluationDailySummary.compliant_count
                + DetectionEvaluationDailySummary.ok_count
                + DetectionEvaluationDailySummary.enabled_count
            ).label("healthy"),
            func.sum(
                DetectionEvaluationDailySummary.non_compliant_count
                + DetectionEvaluationDailySummary.alarm_count
                + DetectionEvaluationDailySummary.disabled_count
            ).label("unhealthy"),
            func.sum(DetectionEvaluationDailySummary.state_changes_count).label(
                "state_changes"
            ),
        )
        .where(
            and_(
                DetectionEvaluationDailySummary.cloud_account_id == cloud_account_id,
                DetectionEvaluationDailySummary.summary_date >= cutoff,
            )
        )
        .group_by(DetectionEvaluationDailySummary.summary_date)
        .order_by(DetectionEvaluationDailySummary.summary_date)
    )

    result = await session.execute(query)
    rows = result.all()

    return [
        {
            "date": row.summary_date.isoformat(),
            "total": row.total or 0,
            "healthy": row.healthy or 0,
            "unhealthy": row.unhealthy or 0,
            "state_changes": row.state_changes or 0,
            "health_percentage": (
                round((row.healthy / row.total) * 100, 2)
                if row.total and row.total > 0
                else 0
            ),
        }
        for row in rows
    ]


async def get_recent_state_changes(
    session: AsyncSession,
    cloud_account_id: uuid.UUID,
    hours: int = 24,
    limit: int = 50,
) -> list[DetectionEvaluationHistory]:
    """Get recent state changes for an account.

    Args:
        session: Database session
        cloud_account_id: The cloud account ID
        hours: Number of hours to look back
        limit: Maximum number of results

    Returns:
        List of history records with state changes
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    query = (
        select(DetectionEvaluationHistory)
        .where(
            and_(
                DetectionEvaluationHistory.cloud_account_id == cloud_account_id,
                DetectionEvaluationHistory.state_changed == True,  # noqa: E712
                DetectionEvaluationHistory.recorded_at >= cutoff,
            )
        )
        .order_by(DetectionEvaluationHistory.recorded_at.desc())
        .limit(limit)
    )

    result = await session.execute(query)
    return list(result.scalars().all())


async def calculate_daily_summary(
    session: AsyncSession,
    cloud_account_id: uuid.UUID,
    summary_date: date,
) -> None:
    """Calculate and upsert daily summary for an account.

    Args:
        session: Database session
        cloud_account_id: The cloud account ID
        summary_date: The date to summarise
    """
    # Get all history records for the account on that date
    start_time = datetime.combine(summary_date, datetime.min.time()).replace(
        tzinfo=timezone.utc
    )
    end_time = start_time + timedelta(days=1)

    # Get latest state per detection on that date, grouped by detection type
    subquery = (
        select(
            DetectionEvaluationHistory.detection_id,
            DetectionEvaluationHistory.detection_type,
            DetectionEvaluationHistory.current_state,
            DetectionEvaluationHistory.state_changed,
            func.row_number()
            .over(
                partition_by=DetectionEvaluationHistory.detection_id,
                order_by=DetectionEvaluationHistory.recorded_at.desc(),
            )
            .label("rn"),
        )
        .where(
            and_(
                DetectionEvaluationHistory.cloud_account_id == cloud_account_id,
                DetectionEvaluationHistory.recorded_at >= start_time,
                DetectionEvaluationHistory.recorded_at < end_time,
            )
        )
        .subquery()
    )

    # Get aggregate counts by detection type
    query = (
        select(
            subquery.c.detection_type,
            func.count().label("total"),
            func.count()
            .filter(subquery.c.current_state == "COMPLIANT")
            .label("compliant"),
            func.count()
            .filter(subquery.c.current_state == "NON_COMPLIANT")
            .label("non_compliant"),
            func.count().filter(subquery.c.current_state == "ALARM").label("alarm"),
            func.count().filter(subquery.c.current_state == "OK").label("ok"),
            func.count()
            .filter(subquery.c.current_state == "INSUFFICIENT_DATA")
            .label("insufficient"),
            func.count().filter(subquery.c.current_state == "ENABLED").label("enabled"),
            func.count()
            .filter(subquery.c.current_state == "DISABLED")
            .label("disabled"),
            func.count()
            .filter(subquery.c.state_changed == True)  # noqa: E712
            .label("changes"),
        )
        .where(subquery.c.rn == 1)
        .group_by(subquery.c.detection_type)
    )

    result = await session.execute(query)
    rows = result.all()

    for row in rows:
        total = row.total or 0
        healthy = (row.compliant or 0) + (row.ok or 0) + (row.enabled or 0)
        compliance_rate = (healthy / total * 100) if total > 0 else None

        # Upsert the daily summary
        stmt = pg_insert(DetectionEvaluationDailySummary).values(
            id=uuid.uuid4(),
            cloud_account_id=cloud_account_id,
            summary_date=summary_date,
            detection_type=row.detection_type,
            total_detections=total,
            compliant_count=row.compliant or 0,
            non_compliant_count=row.non_compliant or 0,
            alarm_count=row.alarm or 0,
            ok_count=row.ok or 0,
            insufficient_data_count=row.insufficient or 0,
            enabled_count=row.enabled or 0,
            disabled_count=row.disabled or 0,
            unknown_count=0,
            state_changes_count=row.changes or 0,
            compliance_rate=compliance_rate,
            calculated_at=datetime.now(timezone.utc),
        )

        # On conflict, update the values
        stmt = stmt.on_conflict_do_update(
            constraint="uq_eval_daily_summary_account_date_type",
            set_={
                "total_detections": total,
                "compliant_count": row.compliant or 0,
                "non_compliant_count": row.non_compliant or 0,
                "alarm_count": row.alarm or 0,
                "ok_count": row.ok or 0,
                "insufficient_data_count": row.insufficient or 0,
                "enabled_count": row.enabled or 0,
                "disabled_count": row.disabled or 0,
                "state_changes_count": row.changes or 0,
                "compliance_rate": compliance_rate,
                "calculated_at": datetime.now(timezone.utc),
            },
        )

        await session.execute(stmt)


async def create_state_change_alert(
    session: AsyncSession,
    organization_id: uuid.UUID,
    history_record: DetectionEvaluationHistory,
    detection: Detection,
) -> Optional[DetectionEvaluationAlert]:
    """Create an alert for a significant state change.

    Args:
        session: Database session
        organization_id: The organisation ID
        history_record: The history record with the state change
        detection: The detection that changed

    Returns:
        The created alert, or None if no alert needed
    """
    if not history_record.state_changed:
        return None

    # Determine severity based on state transition
    current_is_unhealthy = history_record.current_state in UNHEALTHY_STATES
    previous_is_unhealthy = (
        history_record.previous_state in UNHEALTHY_STATES
        if history_record.previous_state
        else False
    )

    if current_is_unhealthy and not previous_is_unhealthy:
        # Transitioned to unhealthy state - more severe
        severity = EvaluationAlertSeverity.WARNING
        alert_type = "state_degraded"
        title = f"Detection {detection.name} became {history_record.current_state}"
    elif not current_is_unhealthy and previous_is_unhealthy:
        # Recovered to healthy state - informational
        severity = EvaluationAlertSeverity.INFO
        alert_type = "state_recovered"
        title = (
            f"Detection {detection.name} recovered to {history_record.current_state}"
        )
    else:
        # Other state change
        severity = EvaluationAlertSeverity.INFO
        alert_type = "state_change"
        title = (
            f"Detection {detection.name} changed from "
            f"{history_record.previous_state} to {history_record.current_state}"
        )

    message = (
        f"The detection '{detection.name}' ({detection.detection_type.value}) "
        f"changed state from {history_record.previous_state or 'INITIAL'} "
        f"to {history_record.current_state}."
    )

    alert = DetectionEvaluationAlert(
        organization_id=organization_id,
        cloud_account_id=history_record.cloud_account_id,
        detection_id=detection.id,
        evaluation_history_id=history_record.id,
        alert_type=alert_type,
        severity=severity,
        previous_state=history_record.previous_state,
        current_state=history_record.current_state,
        title=title,
        message=message,
        details={
            "detection_type": detection.detection_type.value,
            "evaluation_summary": history_record.evaluation_summary,
        },
    )

    session.add(alert)
    return alert


async def get_unacknowledged_alerts(
    session: AsyncSession,
    organization_id: uuid.UUID,
    limit: int = 100,
) -> list[DetectionEvaluationAlert]:
    """Get unacknowledged alerts for an organisation.

    Args:
        session: Database session
        organization_id: The organisation ID
        limit: Maximum number of results

    Returns:
        List of unacknowledged alerts
    """
    query = (
        select(DetectionEvaluationAlert)
        .where(
            and_(
                DetectionEvaluationAlert.organization_id == organization_id,
                DetectionEvaluationAlert.is_acknowledged == False,  # noqa: E712
            )
        )
        .order_by(DetectionEvaluationAlert.created_at.desc())
        .limit(limit)
    )

    result = await session.execute(query)
    return list(result.scalars().all())


async def acknowledge_alert(
    session: AsyncSession,
    alert_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Optional[DetectionEvaluationAlert]:
    """Acknowledge an alert.

    Args:
        session: Database session
        alert_id: The alert ID
        user_id: The user acknowledging the alert

    Returns:
        The updated alert, or None if not found
    """
    query = select(DetectionEvaluationAlert).where(
        DetectionEvaluationAlert.id == alert_id
    )
    result = await session.execute(query)
    alert = result.scalar_one_or_none()

    if alert:
        alert.is_acknowledged = True
        alert.acknowledged_at = datetime.now(timezone.utc)
        alert.acknowledged_by = user_id

    return alert
