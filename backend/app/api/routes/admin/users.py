"""Admin user management routes."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.database import get_db
from app.core.security import get_client_ip
from app.models.admin import AdminUser, AdminRole
from app.models.user import (
    User,
    OrganizationMember,
    Organization,
    AuditLog,
    AuditEventType,
)
from app.api.deps import get_current_admin

logger = structlog.get_logger()

router = APIRouter(prefix="/users", tags=["Admin Users"])


class UserOrganization(BaseModel):
    """Organization info for user."""

    id: str
    name: str
    role: str


class UserResponse(BaseModel):
    """User response."""

    id: str
    email: str
    full_name: str
    is_active: bool
    email_verified: bool
    created_at: str
    last_login_at: Optional[str]
    organizations: list[UserOrganization]


class UsersListResponse(BaseModel):
    """Users list response."""

    users: list[UserResponse]
    total: int
    page: int
    per_page: int


class UserStatusRequest(BaseModel):
    """User status update request."""

    is_active: bool


@router.get("", response_model=UsersListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    suspended_only: bool = Query(
        False, description="Filter to show only suspended users"
    ),
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> UsersListResponse:
    """List all platform users with pagination and search.

    Use suspended_only=true to see users who have been suspended
    (e.g., for bulk template scraping).
    """
    # Build query
    query = select(User)
    count_query = select(func.count(User.id))

    # Filter for suspended users
    if suspended_only:
        query = query.where(User.is_active.is_(False))
        count_query = count_query.where(User.is_active.is_(False))

    if search:
        search_filter = or_(
            User.email.ilike(f"%{search}%"),
            User.full_name.ilike(f"%{search}%"),
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated users
    offset = (page - 1) * per_page
    query = query.order_by(User.created_at.desc()).offset(offset).limit(per_page)
    result = await db.execute(query)
    users = result.scalars().all()

    # Get organization memberships for each user
    user_responses = []
    for user in users:
        # Get memberships
        memberships_query = (
            select(OrganizationMember, Organization)
            .join(Organization, OrganizationMember.organization_id == Organization.id)
            .where(OrganizationMember.user_id == user.id)
        )
        memberships_result = await db.execute(memberships_query)
        memberships = memberships_result.all()

        orgs = [
            UserOrganization(
                id=str(org.id),
                name=org.name,
                role=member.role.value if member.role else "member",
            )
            for member, org in memberships
        ]

        user_responses.append(
            UserResponse(
                id=str(user.id),
                email=user.email,
                full_name=user.full_name or "",
                is_active=user.is_active,
                email_verified=user.email_verified,
                created_at=user.created_at.isoformat() if user.created_at else "",
                last_login_at=(
                    user.last_login_at.isoformat() if user.last_login_at else None
                ),
                organizations=orgs,
            )
        )

    return UsersListResponse(
        users=user_responses,
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Get user details."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Get memberships
    memberships_query = (
        select(OrganizationMember, Organization)
        .join(Organization, OrganizationMember.organization_id == Organization.id)
        .where(OrganizationMember.user_id == user.id)
    )
    memberships_result = await db.execute(memberships_query)
    memberships = memberships_result.all()

    orgs = [
        UserOrganization(
            id=str(org.id),
            name=org.name,
            role=member.role.value if member.role else "member",
        )
        for member, org in memberships
    ]

    return UserResponse(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name or "",
        is_active=user.is_active,
        email_verified=user.email_verified,
        created_at=user.created_at.isoformat() if user.created_at else "",
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        organizations=orgs,
    )


@router.put("/{user_id}/status")
async def update_user_status(
    user_id: UUID,
    body: UserStatusRequest,
    request: Request,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update user status (suspend/activate)."""
    # Check permissions
    if admin.role not in [
        AdminRole.SUPER_ADMIN,
        AdminRole.PLATFORM_ADMIN,
        AdminRole.SUPPORT_ADMIN,
    ]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    previous_status = user.is_active
    user.is_active = body.is_active

    # Get user's primary organisation for audit log
    membership_result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == user_id).limit(1)
    )
    membership = membership_result.scalar_one_or_none()
    org_id = membership.organization_id if membership else None

    # Create audit log
    action = "activated" if body.is_active else "suspended"
    event_type = (
        AuditEventType.USER_SUSPENDED
        if not body.is_active
        else AuditEventType.SETTINGS_CHANGED
    )

    if org_id:
        audit_log = AuditLog(
            organization_id=org_id,
            user_id=user_id,
            event_type=event_type,
            resource_type="user",
            resource_id=str(user_id),
            ip_address=get_client_ip(request),
            details={
                "action": f"admin_{action}",
                "admin_id": str(admin.id),
                "admin_email": admin.email,
                "previous_status": previous_status,
                "new_status": body.is_active,
            },
        )
        db.add(audit_log)

    await db.commit()

    logger.info(
        f"admin_user_{action}",
        admin_id=str(admin.id),
        admin_email=admin.email,
        user_id=str(user_id),
        user_email=user.email,
    )

    return {"message": f"User {action} successfully"}


class SuspendUserRequest(BaseModel):
    """Request to suspend a user."""

    reason: str


@router.post("/{user_id}/suspend")
async def suspend_user(
    user_id: UUID,
    body: SuspendUserRequest,
    request: Request,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Suspend a user account.

    The user will not be able to log in until reactivated by an admin.
    """
    # Check permissions
    if admin.role not in [
        AdminRole.SUPER_ADMIN,
        AdminRole.PLATFORM_ADMIN,
        AdminRole.SUPPORT_ADMIN,
    ]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already suspended",
        )

    user.is_active = False

    # Get user's primary organisation for audit log
    membership_result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == user_id).limit(1)
    )
    membership = membership_result.scalar_one_or_none()
    org_id = membership.organization_id if membership else None

    # Create audit log
    if org_id:
        audit_log = AuditLog(
            organization_id=org_id,
            user_id=user_id,
            event_type=AuditEventType.USER_SUSPENDED,
            resource_type="user",
            resource_id=str(user_id),
            ip_address=get_client_ip(request),
            details={
                "action": "admin_suspended",
                "reason": body.reason,
                "admin_id": str(admin.id),
                "admin_email": admin.email,
            },
        )
        db.add(audit_log)

    await db.commit()

    logger.warning(
        "admin_user_suspended",
        admin_id=str(admin.id),
        admin_email=admin.email,
        user_id=str(user_id),
        user_email=user.email,
        reason=body.reason,
    )

    return {"message": "User suspended successfully"}


@router.post("/{user_id}/unsuspend")
async def unsuspend_user(
    user_id: UUID,
    request: Request,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Reactivate a suspended user account.

    Use this to restore access for users who were suspended
    (e.g., after reviewing a bulk template access alert).
    """
    # Check permissions
    if admin.role not in [
        AdminRole.SUPER_ADMIN,
        AdminRole.PLATFORM_ADMIN,
        AdminRole.SUPPORT_ADMIN,
    ]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is not suspended",
        )

    user.is_active = True
    user.locked_until = None  # Clear any temporary lock as well

    # Get user's primary organisation for audit log
    membership_result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == user_id).limit(1)
    )
    membership = membership_result.scalar_one_or_none()
    org_id = membership.organization_id if membership else None

    # Create audit log
    if org_id:
        audit_log = AuditLog(
            organization_id=org_id,
            user_id=user_id,
            event_type=AuditEventType.SETTINGS_CHANGED,
            resource_type="user",
            resource_id=str(user_id),
            ip_address=get_client_ip(request),
            details={
                "action": "admin_unsuspended",
                "admin_id": str(admin.id),
                "admin_email": admin.email,
            },
        )
        db.add(audit_log)

    await db.commit()

    logger.info(
        "admin_user_unsuspended",
        admin_id=str(admin.id),
        admin_email=admin.email,
        user_id=str(user_id),
        user_email=user.email,
    )

    return {"message": "User reactivated successfully"}
