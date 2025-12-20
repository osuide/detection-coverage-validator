"""Admin audit logs routes."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser, AdminAuditLog
from app.api.deps import get_current_admin

router = APIRouter(prefix="/audit-logs", tags=["Admin Audit Logs"])


class AuditLogResponse(BaseModel):
    """Audit log response."""

    id: str
    admin_id: str
    admin_email: str
    admin_role: str
    action: str
    ip_address: str
    user_agent: Optional[str]
    success: bool
    error_message: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    timestamp: str


class AuditLogsListResponse(BaseModel):
    """Audit logs list response."""

    logs: list[AuditLogResponse]
    total: int
    page: int
    per_page: int


@router.get("", response_model=AuditLogsListResponse)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    admin_email: Optional[str] = None,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """List admin audit logs with filtering."""
    # Build query
    query = select(AdminAuditLog)
    count_query = select(func.count(AdminAuditLog.id))

    if action:
        query = query.where(AdminAuditLog.action == action)
        count_query = count_query.where(AdminAuditLog.action == action)

    if admin_email:
        query = query.where(AdminAuditLog.admin_email.ilike(f"%{admin_email}%"))
        count_query = count_query.where(
            AdminAuditLog.admin_email.ilike(f"%{admin_email}%")
        )

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated logs
    offset = (page - 1) * per_page
    query = (
        query.order_by(AdminAuditLog.timestamp.desc()).offset(offset).limit(per_page)
    )
    result = await db.execute(query)
    logs = result.scalars().all()

    log_responses = [
        AuditLogResponse(
            id=str(log.id),
            admin_id=str(log.admin_id),
            admin_email=log.admin_email,
            admin_role=log.admin_role.value if log.admin_role else "unknown",
            action=log.action,
            ip_address=log.ip_address or "unknown",
            user_agent=log.user_agent,
            success=log.success,
            error_message=log.error_message,
            resource_type=log.resource_type,
            resource_id=str(log.resource_id) if log.resource_id else None,
            timestamp=log.timestamp.isoformat() if log.timestamp else "",
        )
        for log in logs
    ]

    return AuditLogsListResponse(
        logs=log_responses,
        total=total,
        page=page,
        per_page=per_page,
    )
