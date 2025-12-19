"""Admin user management routes."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser, AdminRole
from app.models.user import User, OrganizationMember, Organization
from app.api.deps import get_current_admin

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
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all platform users with pagination and search."""
    # Build query
    query = select(User)
    count_query = select(func.count(User.id))

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
                last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
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
):
    """Get user details."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
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
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update user status (suspend/activate)."""
    # Check permissions
    if admin.role not in [AdminRole.SUPER_ADMIN, AdminRole.PLATFORM_ADMIN, AdminRole.SUPPORT_ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.is_active = body.is_active
    await db.commit()

    action = "activated" if body.is_active else "suspended"
    return {"message": f"User {action} successfully"}
