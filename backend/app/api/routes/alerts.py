"""Alert management endpoints."""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.alert import AlertConfig, AlertHistory, AlertSeverity
from app.models.cloud_account import CloudAccount
from app.schemas.alert import (
    AlertConfigCreate,
    AlertConfigUpdate,
    AlertConfigResponse,
    AlertConfigListResponse,
    AlertHistoryResponse,
    AlertHistoryListResponse,
    TestAlertRequest,
)
from app.services.notification_service import NotificationService

router = APIRouter()


@router.get("", response_model=AlertConfigListResponse)
async def list_alerts(
    cloud_account_id: Optional[UUID] = None,
    alert_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List alert configurations."""
    query = select(AlertConfig)
    count_query = select(AlertConfig)

    if cloud_account_id:
        query = query.where(
            (AlertConfig.cloud_account_id == cloud_account_id)
            | (AlertConfig.cloud_account_id.is_(None))
        )
        count_query = count_query.where(
            (AlertConfig.cloud_account_id == cloud_account_id)
            | (AlertConfig.cloud_account_id.is_(None))
        )

    if alert_type:
        query = query.where(AlertConfig.alert_type == alert_type)
        count_query = count_query.where(AlertConfig.alert_type == alert_type)

    if is_active is not None:
        query = query.where(AlertConfig.is_active == is_active)
        count_query = count_query.where(AlertConfig.is_active == is_active)

    # Get total count
    total_result = await db.execute(count_query)
    total = len(total_result.scalars().all())

    # Get paginated results
    query = query.offset(skip).limit(limit).order_by(AlertConfig.created_at.desc())
    result = await db.execute(query)
    alerts = result.scalars().all()

    return AlertConfigListResponse(
        items=alerts,
        total=total,
        page=skip // limit + 1,
        page_size=limit,
    )


@router.post("", response_model=AlertConfigResponse, status_code=201)
async def create_alert(
    alert_in: AlertConfigCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new alert configuration."""
    # Verify cloud account exists if specified
    if alert_in.cloud_account_id:
        result = await db.execute(
            select(CloudAccount).where(CloudAccount.id == alert_in.cloud_account_id)
        )
        account = result.scalar_one_or_none()
        if not account:
            raise HTTPException(status_code=404, detail="Cloud account not found")

    # Create alert config
    alert = AlertConfig(
        cloud_account_id=alert_in.cloud_account_id,
        name=alert_in.name,
        description=alert_in.description,
        alert_type=alert_in.alert_type,
        severity=alert_in.severity,
        threshold_value=alert_in.threshold_value,
        threshold_operator=alert_in.threshold_operator,
        channels=[c.model_dump() for c in alert_in.channels],
        cooldown_minutes=alert_in.cooldown_minutes,
        is_active=True,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    return alert


@router.get("/{alert_id}", response_model=AlertConfigResponse)
async def get_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific alert configuration."""
    result = await db.execute(
        select(AlertConfig).where(AlertConfig.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.put("/{alert_id}", response_model=AlertConfigResponse)
async def update_alert(
    alert_id: UUID,
    alert_in: AlertConfigUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update an alert configuration."""
    result = await db.execute(
        select(AlertConfig).where(AlertConfig.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Update fields
    update_data = alert_in.model_dump(exclude_unset=True)
    if "channels" in update_data:
        update_data["channels"] = [c.model_dump() if hasattr(c, 'model_dump') else c for c in update_data["channels"]]

    for field, value in update_data.items():
        setattr(alert, field, value)

    await db.commit()
    await db.refresh(alert)

    return alert


@router.delete("/{alert_id}", status_code=204)
async def delete_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete an alert configuration."""
    result = await db.execute(
        select(AlertConfig).where(AlertConfig.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    await db.delete(alert)
    await db.commit()


@router.post("/{alert_id}/activate", response_model=AlertConfigResponse)
async def activate_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Activate an alert."""
    result = await db.execute(
        select(AlertConfig).where(AlertConfig.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_active = True
    await db.commit()
    await db.refresh(alert)

    return alert


@router.post("/{alert_id}/deactivate", response_model=AlertConfigResponse)
async def deactivate_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Deactivate an alert."""
    result = await db.execute(
        select(AlertConfig).where(AlertConfig.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_active = False
    await db.commit()
    await db.refresh(alert)

    return alert


@router.post("/{alert_id}/test")
async def test_alert(
    alert_id: UUID,
    request: TestAlertRequest,
    db: AsyncSession = Depends(get_db),
):
    """Test an alert by sending a test notification."""
    result = await db.execute(
        select(AlertConfig).where(AlertConfig.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if not alert.channels:
        raise HTTPException(status_code=400, detail="No channels configured")

    if request.channel_index >= len(alert.channels):
        raise HTTPException(status_code=400, detail="Invalid channel index")

    # Send test notification
    service = NotificationService(db)
    channel_config = alert.channels[request.channel_index]

    try:
        channel_type = channel_config.get("type")
        if channel_type == "webhook":
            await service._send_webhook(
                channel_config,
                alert,
                f"[TEST] {alert.name}",
                "This is a test notification from Detection Coverage Validator.",
                {"test": True},
            )
        elif channel_type == "slack":
            await service._send_slack(
                channel_config,
                alert,
                f"[TEST] {alert.name}",
                "This is a test notification from Detection Coverage Validator.",
                {"test": True},
            )
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Channel type '{channel_type}' does not support testing",
            )

        return {"status": "success", "message": "Test notification sent"}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send test notification: {str(e)}",
        )


# Alert History endpoints

@router.get("/history/", response_model=AlertHistoryListResponse)
async def list_alert_history(
    cloud_account_id: Optional[UUID] = None,
    alert_config_id: Optional[UUID] = None,
    severity: Optional[AlertSeverity] = None,
    is_resolved: Optional[bool] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List alert history."""
    query = select(AlertHistory)
    count_query = select(AlertHistory)

    if cloud_account_id:
        query = query.where(AlertHistory.cloud_account_id == cloud_account_id)
        count_query = count_query.where(AlertHistory.cloud_account_id == cloud_account_id)

    if alert_config_id:
        query = query.where(AlertHistory.alert_config_id == alert_config_id)
        count_query = count_query.where(AlertHistory.alert_config_id == alert_config_id)

    if severity:
        query = query.where(AlertHistory.severity == severity)
        count_query = count_query.where(AlertHistory.severity == severity)

    if is_resolved is not None:
        query = query.where(AlertHistory.is_resolved == is_resolved)
        count_query = count_query.where(AlertHistory.is_resolved == is_resolved)

    # Get total count
    total_result = await db.execute(count_query)
    total = len(total_result.scalars().all())

    # Get paginated results
    query = query.offset(skip).limit(limit).order_by(AlertHistory.triggered_at.desc())
    result = await db.execute(query)
    history = result.scalars().all()

    return AlertHistoryListResponse(
        items=history,
        total=total,
        page=skip // limit + 1,
        page_size=limit,
    )


@router.post("/history/{history_id}/resolve", response_model=AlertHistoryResponse)
async def resolve_alert(
    history_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Mark an alert as resolved."""
    result = await db.execute(
        select(AlertHistory).where(AlertHistory.id == history_id)
    )
    history = result.scalar_one_or_none()
    if not history:
        raise HTTPException(status_code=404, detail="Alert history not found")

    history.is_resolved = True
    history.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(history)

    return history
