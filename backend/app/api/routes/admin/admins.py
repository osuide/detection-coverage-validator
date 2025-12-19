"""Admin user management routes (for managing other admins)."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser, AdminRole
from app.services.admin_auth_service import get_admin_auth_service
from app.api.deps import get_current_admin

router = APIRouter(prefix="/admins", tags=["Admin Management"])


class AdminUserResponse(BaseModel):
    """Admin user response."""
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    last_login_at: Optional[str]
    created_at: str
    created_by_email: Optional[str]


class AdminsListResponse(BaseModel):
    """Admins list response."""
    admins: list[AdminUserResponse]
    total: int


class CreateAdminRequest(BaseModel):
    """Create admin request."""
    email: EmailStr
    full_name: str
    password: str
    role: str


class AdminStatusRequest(BaseModel):
    """Admin status update request."""
    is_active: bool


class ChangePasswordRequest(BaseModel):
    """Change password request."""
    password: str


@router.get("", response_model=AdminsListResponse)
async def list_admins(
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all admin users. Only super_admin can view."""
    # Check permissions - only super_admin can view admin list
    if admin.role != AdminRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super_admin can view admin users"
        )

    result = await db.execute(
        select(AdminUser).order_by(AdminUser.created_at.desc())
    )
    admins = result.scalars().all()

    # Get created_by emails
    admin_responses = []
    for a in admins:
        created_by_email = None
        if a.created_by_id:
            creator_result = await db.execute(
                select(AdminUser.email).where(AdminUser.id == a.created_by_id)
            )
            created_by_email = creator_result.scalar_one_or_none()

        admin_responses.append(
            AdminUserResponse(
                id=str(a.id),
                email=a.email,
                full_name=a.full_name or "",
                role=a.role.value,
                is_active=a.is_active,
                mfa_enabled=a.mfa_enabled,
                last_login_at=a.last_login_at.isoformat() if a.last_login_at else None,
                created_at=a.created_at.isoformat() if a.created_at else "",
                created_by_email=created_by_email,
            )
        )

    return AdminsListResponse(
        admins=admin_responses,
        total=len(admin_responses),
    )


@router.post("", response_model=AdminUserResponse)
async def create_admin(
    body: CreateAdminRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a new admin user. Only super_admin can create."""
    # Check permissions
    if admin.role != AdminRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super_admin can create admin users"
        )

    # Validate role
    try:
        role = AdminRole(body.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role: {body.role}"
        )

    auth_service = get_admin_auth_service(db)

    try:
        new_admin = await auth_service.create_admin(
            email=body.email,
            password=body.password,
            full_name=body.full_name,
            role=role,
            created_by=admin,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    return AdminUserResponse(
        id=str(new_admin.id),
        email=new_admin.email,
        full_name=new_admin.full_name or "",
        role=new_admin.role.value,
        is_active=new_admin.is_active,
        mfa_enabled=new_admin.mfa_enabled,
        last_login_at=None,
        created_at=new_admin.created_at.isoformat() if new_admin.created_at else "",
        created_by_email=admin.email,
    )


@router.put("/{admin_id}/status")
async def update_admin_status(
    admin_id: UUID,
    body: AdminStatusRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update admin status (enable/disable). Only super_admin can modify."""
    # Check permissions
    if admin.role != AdminRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super_admin can modify admin users"
        )

    # Cannot disable yourself
    if admin_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify your own status"
        )

    result = await db.execute(select(AdminUser).where(AdminUser.id == admin_id))
    target_admin = result.scalar_one_or_none()

    if not target_admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Admin user not found"
        )

    # Prevent disabling if this would leave no active super_admins
    if not body.is_active and target_admin.role == AdminRole.SUPER_ADMIN:
        # Count active super_admins excluding this one
        active_super_admins_result = await db.execute(
            select(func.count(AdminUser.id)).where(
                and_(
                    AdminUser.role == AdminRole.SUPER_ADMIN,
                    AdminUser.is_active == True,
                    AdminUser.id != admin_id,
                )
            )
        )
        active_super_admin_count = active_super_admins_result.scalar() or 0

        if active_super_admin_count == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot disable the last active super_admin. This would lock you out of the platform."
            )

    target_admin.is_active = body.is_active
    await db.commit()

    action = "enabled" if body.is_active else "disabled"
    return {"message": f"Admin user {action} successfully"}


@router.put("/{admin_id}/password")
async def change_admin_password(
    admin_id: UUID,
    body: ChangePasswordRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Change admin password. Only super_admin can modify."""
    # Check permissions
    if admin.role != AdminRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super_admin can change admin passwords"
        )

    # Validate password
    if len(body.password) < 16:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 16 characters"
        )

    result = await db.execute(select(AdminUser).where(AdminUser.id == admin_id))
    target_admin = result.scalar_one_or_none()

    if not target_admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Admin user not found"
        )

    auth_service = get_admin_auth_service(db)
    target_admin.password_hash = auth_service._hash_password(body.password)
    await db.commit()

    return {"message": "Password changed successfully"}
