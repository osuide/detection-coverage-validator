"""Alert management endpoints."""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context, require_scope, require_role
from app.models.alert import AlertConfig, AlertHistory, AlertSeverity
from app.models.user import UserRole
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

logger = structlog.get_logger()

router = APIRouter()


@router.get(
    "",
    response_model=AlertConfigListResponse,
    dependencies=[Depends(require_scope("read:alerts"))],
)
async def list_alerts(
    cloud_account_id: Optional[UUID] = None,
    alert_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List alert configurations."""
    query = select(AlertConfig).where(
        AlertConfig.organization_id == auth.organization_id
    )
    count_query = select(AlertConfig).where(
        AlertConfig.organization_id == auth.organization_id
    )

    if cloud_account_id:
        # SECURITY: Check allowed_account_ids ACL
        if not auth.can_access_account(cloud_account_id):
            raise HTTPException(
                status_code=403, detail="Access denied to this cloud account"
            )
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


@router.post(
    "",
    response_model=AlertConfigResponse,
    status_code=201,
    dependencies=[Depends(require_role(UserRole.OWNER, UserRole.ADMIN))],
)
async def create_alert(
    alert_in: AlertConfigCreate,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create a new alert configuration.

    Requires OWNER or ADMIN role. Webhook/channel configuration
    is restricted to admins for security (SSRF prevention).
    """
    # Verify cloud account exists and belongs to user's organization if specified
    if alert_in.cloud_account_id:
        result = await db.execute(
            select(CloudAccount).where(
                CloudAccount.id == alert_in.cloud_account_id,
                CloudAccount.organization_id == auth.organization_id,
            )
        )
        account = result.scalar_one_or_none()
        if not account:
            raise HTTPException(status_code=404, detail="Cloud account not found")

        # SECURITY: Check allowed_account_ids ACL
        if not auth.can_access_account(alert_in.cloud_account_id):
            raise HTTPException(
                status_code=403, detail="Access denied to this cloud account"
            )

    # Create alert config
    alert = AlertConfig(
        organization_id=auth.organization_id,
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


@router.get(
    "/{alert_id}",
    response_model=AlertConfigResponse,
    dependencies=[Depends(require_scope("read:alerts"))],
)
async def get_alert(
    alert_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get a specific alert configuration."""
    result = await db.execute(
        select(AlertConfig).where(
            AlertConfig.id == alert_id,
            AlertConfig.organization_id == auth.organization_id,
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.put(
    "/{alert_id}",
    response_model=AlertConfigResponse,
    dependencies=[Depends(require_role(UserRole.OWNER, UserRole.ADMIN))],
)
async def update_alert(
    alert_id: UUID,
    alert_in: AlertConfigUpdate,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update an alert configuration.

    Requires OWNER or ADMIN role. Webhook/channel configuration
    is restricted to admins for security (SSRF prevention).
    """
    result = await db.execute(
        select(AlertConfig).where(
            AlertConfig.id == alert_id,
            AlertConfig.organization_id == auth.organization_id,
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Update fields
    update_data = alert_in.model_dump(exclude_unset=True)
    if "channels" in update_data:
        update_data["channels"] = [
            c.model_dump() if hasattr(c, "model_dump") else c
            for c in update_data["channels"]
        ]

    for field, value in update_data.items():
        setattr(alert, field, value)

    await db.commit()
    await db.refresh(alert)

    return alert


@router.delete(
    "/{alert_id}",
    status_code=204,
    dependencies=[Depends(require_role(UserRole.OWNER, UserRole.ADMIN))],
)
async def delete_alert(
    alert_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete an alert configuration.

    Requires OWNER or ADMIN role.
    """
    result = await db.execute(
        select(AlertConfig).where(
            AlertConfig.id == alert_id,
            AlertConfig.organization_id == auth.organization_id,
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    await db.delete(alert)
    await db.commit()


@router.post(
    "/{alert_id}/activate",
    response_model=AlertConfigResponse,
    dependencies=[Depends(require_role(UserRole.OWNER, UserRole.ADMIN))],
)
async def activate_alert(
    alert_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Activate an alert."""
    result = await db.execute(
        select(AlertConfig).where(
            AlertConfig.id == alert_id,
            AlertConfig.organization_id == auth.organization_id,
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_active = True
    await db.commit()
    await db.refresh(alert)

    return alert


@router.post(
    "/{alert_id}/deactivate",
    response_model=AlertConfigResponse,
    dependencies=[Depends(require_role(UserRole.OWNER, UserRole.ADMIN))],
)
async def deactivate_alert(
    alert_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Deactivate an alert."""
    result = await db.execute(
        select(AlertConfig).where(
            AlertConfig.id == alert_id,
            AlertConfig.organization_id == auth.organization_id,
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_active = False
    await db.commit()
    await db.refresh(alert)

    return alert


@router.post(
    "/{alert_id}/test",
    dependencies=[Depends(require_role(UserRole.OWNER, UserRole.ADMIN))],
)
async def test_alert(
    alert_id: UUID,
    request: TestAlertRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Test an alert by sending a test notification."""
    result = await db.execute(
        select(AlertConfig).where(
            AlertConfig.id == alert_id,
            AlertConfig.organization_id == auth.organization_id,
        )
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
        logger.error("test_notification_failed", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to send test notification",
        )


# Alert History endpoints


@router.get(
    "/history/",
    response_model=AlertHistoryListResponse,
    dependencies=[Depends(require_scope("read:alerts"))],
)
async def list_alert_history(
    cloud_account_id: Optional[UUID] = None,
    alert_config_id: Optional[UUID] = None,
    severity: Optional[AlertSeverity] = None,
    is_resolved: Optional[bool] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List alert history."""
    query = select(AlertHistory).where(
        AlertHistory.organization_id == auth.organization_id
    )
    count_query = select(AlertHistory).where(
        AlertHistory.organization_id == auth.organization_id
    )

    if cloud_account_id:
        # SECURITY: Check allowed_account_ids ACL
        if not auth.can_access_account(cloud_account_id):
            raise HTTPException(
                status_code=403, detail="Access denied to this cloud account"
            )
        query = query.where(AlertHistory.cloud_account_id == cloud_account_id)
        count_query = count_query.where(
            AlertHistory.cloud_account_id == cloud_account_id
        )

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


@router.post(
    "/history/{history_id}/resolve",
    response_model=AlertHistoryResponse,
    dependencies=[
        Depends(require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER))
    ],
)
async def resolve_alert(
    history_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Mark an alert as resolved."""
    result = await db.execute(
        select(AlertHistory).where(
            AlertHistory.id == history_id,
            AlertHistory.organization_id == auth.organization_id,
        )
    )
    history = result.scalar_one_or_none()
    if not history:
        raise HTTPException(status_code=404, detail="Alert history not found")

    history.is_resolved = True
    history.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(history)

    return history
