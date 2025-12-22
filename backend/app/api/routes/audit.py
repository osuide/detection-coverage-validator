"""Audit log API endpoints."""

from datetime import datetime, timedelta, timezone
from typing import Optional, List
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context, require_role
from app.models.user import (
    AuditLog,
    AuditLogAction,
    User,
    UserRole,
)

logger = structlog.get_logger()
settings = get_settings()
router = APIRouter()


# Response schemas
class AuditLogActorResponse(BaseModel):
    """Actor (user) who performed the action."""

    id: Optional[UUID] = None
    email: Optional[str] = None
    full_name: Optional[str] = None


class AuditLogResponse(BaseModel):
    """Audit log entry response."""

    id: UUID
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    details: Optional[dict]
    ip_address: Optional[str]
    success: bool
    error_message: Optional[str]
    created_at: datetime
    actor: Optional[AuditLogActorResponse]

    model_config = ConfigDict(from_attributes=True)


class AuditLogListResponse(BaseModel):
    """Paginated audit log list response."""

    items: List[AuditLogResponse]
    total: int
    page: int
    page_size: int
    pages: int


class AuditStatsResponse(BaseModel):
    """Audit statistics response."""

    total_events: int
    events_today: int
    events_this_week: int
    top_actions: List[dict]
    top_actors: List[dict]


@router.get("", response_model=AuditLogListResponse)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    action: Optional[str] = Query(None, description="Filter by action type"),
    actor_id: Optional[UUID] = Query(None, description="Filter by actor user ID"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID"),
    start_date: Optional[datetime] = Query(
        None, description="Filter events after this date"
    ),
    end_date: Optional[datetime] = Query(
        None, description="Filter events before this date"
    ),
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """
    List audit logs for the organization.

    Admin and owner roles can view all audit logs.
    Supports filtering by action, actor, resource, and date range.
    """
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    # Build query conditions
    conditions = [AuditLog.organization_id == auth.organization_id]

    if action:
        conditions.append(AuditLog.action == action)
    if actor_id:
        conditions.append(AuditLog.user_id == actor_id)
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)
    if resource_id:
        conditions.append(AuditLog.resource_id == resource_id)
    if start_date:
        conditions.append(AuditLog.created_at >= start_date)
    if end_date:
        conditions.append(AuditLog.created_at <= end_date)

    # Get total count
    from sqlalchemy import func

    count_result = await db.execute(
        select(func.count(AuditLog.id)).where(and_(*conditions))
    )
    total = count_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * page_size
    result = await db.execute(
        select(AuditLog)
        .options(selectinload(AuditLog.user))
        .where(and_(*conditions))
        .order_by(desc(AuditLog.created_at))
        .offset(offset)
        .limit(page_size)
    )
    logs = result.scalars().all()

    # Build response
    items = []
    for log in logs:
        actor = None
        if log.user:
            actor = AuditLogActorResponse(
                id=log.user.id,
                email=log.user.email,
                full_name=log.user.full_name,
            )
        items.append(
            AuditLogResponse(
                id=log.id,
                action=(
                    log.action.value
                    if isinstance(log.action, AuditLogAction)
                    else log.action
                ),
                resource_type=log.resource_type,
                resource_id=log.resource_id,
                details=log.details,
                ip_address=log.ip_address,
                success=log.success,
                error_message=log.error_message,
                created_at=log.created_at,
                actor=actor,
            )
        )

    pages = (total + page_size - 1) // page_size

    return AuditLogListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/actions")
async def list_action_types(
    auth: AuthContext = Depends(get_auth_context),
):
    """List all available audit log action types."""
    actions = []
    for action in AuditLogAction:
        category = action.value.split(".")[0]
        actions.append(
            {
                "value": action.value,
                "label": action.value.replace(".", " ").replace("_", " ").title(),
                "category": category,
            }
        )
    return {"actions": actions}


@router.get("/stats", response_model=AuditStatsResponse)
async def get_audit_stats(
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Get audit log statistics for the organization."""
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)

    from sqlalchemy import func

    # Total events
    total_result = await db.execute(
        select(func.count(AuditLog.id)).where(
            AuditLog.organization_id == auth.organization_id
        )
    )
    total_events = total_result.scalar() or 0

    # Events today
    today_result = await db.execute(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.organization_id == auth.organization_id,
                AuditLog.created_at >= today_start,
            )
        )
    )
    events_today = today_result.scalar() or 0

    # Events this week
    week_result = await db.execute(
        select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.organization_id == auth.organization_id,
                AuditLog.created_at >= week_start,
            )
        )
    )
    events_this_week = week_result.scalar() or 0

    # Top actions (last 30 days)
    month_start = today_start - timedelta(days=30)
    top_actions_result = await db.execute(
        select(AuditLog.action, func.count(AuditLog.id).label("count"))
        .where(
            and_(
                AuditLog.organization_id == auth.organization_id,
                AuditLog.created_at >= month_start,
            )
        )
        .group_by(AuditLog.action)
        .order_by(desc("count"))
        .limit(10)
    )
    top_actions = [
        {
            "action": row.action.value if hasattr(row.action, "value") else row.action,
            "count": row.count,
        }
        for row in top_actions_result.fetchall()
    ]

    # Top actors (last 30 days)
    top_actors_result = await db.execute(
        select(AuditLog.user_id, func.count(AuditLog.id).label("count"))
        .where(
            and_(
                AuditLog.organization_id == auth.organization_id,
                AuditLog.created_at >= month_start,
                AuditLog.user_id.isnot(None),
            )
        )
        .group_by(AuditLog.user_id)
        .order_by(desc("count"))
        .limit(10)
    )
    actor_rows = top_actors_result.fetchall()

    # Get user details for top actors
    top_actors = []
    if actor_rows:
        actor_ids = [row.user_id for row in actor_rows]
        users_result = await db.execute(select(User).where(User.id.in_(actor_ids)))
        users_map = {u.id: u for u in users_result.scalars().all()}

        for row in actor_rows:
            user = users_map.get(row.user_id)
            top_actors.append(
                {
                    "user_id": str(row.user_id),
                    "full_name": user.full_name if user else "Unknown",
                    "email": user.email if user else "Unknown",
                    "count": row.count,
                }
            )

    return AuditStatsResponse(
        total_events=total_events,
        events_today=events_today,
        events_this_week=events_this_week,
        top_actions=top_actions,
        top_actors=top_actors,
    )


@router.get("/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    log_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific audit log entry."""
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    result = await db.execute(
        select(AuditLog)
        .options(selectinload(AuditLog.user))
        .where(
            and_(
                AuditLog.id == log_id,
                AuditLog.organization_id == auth.organization_id,
            )
        )
    )
    log = result.scalar_one_or_none()

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log entry not found",
        )

    actor = None
    if log.user:
        actor = AuditLogActorResponse(
            id=log.user.id,
            email=log.user.email,
            full_name=log.user.full_name,
        )

    return AuditLogResponse(
        id=log.id,
        action=(
            log.action.value if isinstance(log.action, AuditLogAction) else log.action
        ),
        resource_type=log.resource_type,
        resource_id=log.resource_id,
        details=log.details,
        ip_address=log.ip_address,
        success=log.success,
        error_message=log.error_message,
        created_at=log.created_at,
        actor=actor,
    )
