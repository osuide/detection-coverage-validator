"""Admin organization management routes."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser
from app.models.user import Organization, OrganizationMember, User
from app.models.billing import Subscription
from app.api.deps import require_permission

router = APIRouter(prefix="/organizations", tags=["Admin Organizations"])


class OrganizationListItem(BaseModel):
    """Organization list item."""

    id: str
    name: str
    slug: str
    is_active: bool
    user_count: int
    tier: str
    created_at: str
    last_activity: Optional[str] = None


class OrganizationListResponse(BaseModel):
    """Organization list response."""

    items: list[OrganizationListItem]
    total: int
    page: int
    page_size: int


class OrganizationDetailResponse(BaseModel):
    """Organization detail response."""

    id: str
    name: str
    slug: str
    is_active: bool
    created_at: str

    # Subscription
    tier: str
    stripe_customer_id: Optional[str] = None

    # Stats
    user_count: int
    cloud_account_count: int
    scan_count: int
    detection_count: int

    # Users
    owner: Optional[dict] = None
    members: list[dict] = []


class SuspendOrgRequest(BaseModel):
    """Suspend organization request."""

    reason: str


@router.get("", response_model=OrganizationListResponse)
async def list_organizations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    tier: Optional[str] = None,
    is_active: Optional[bool] = None,
    admin: AdminUser = Depends(require_permission("org:read")),
    db: AsyncSession = Depends(get_db),
) -> OrganizationListResponse:
    """List all organizations with filtering and pagination."""
    # Build query
    query = select(Organization)

    if search:
        query = query.where(
            Organization.name.ilike(f"%{search}%")
            | Organization.slug.ilike(f"%{search}%")
        )

    if is_active is not None:
        query = query.where(Organization.is_active == is_active)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.offset((page - 1) * page_size).limit(page_size)
    query = query.order_by(Organization.created_at.desc())

    result = await db.execute(query)
    organizations = result.scalars().all()

    # Build response with additional data
    items = []
    for org in organizations:
        # Get user count
        user_count_result = await db.execute(
            select(func.count()).where(OrganizationMember.organization_id == org.id)
        )
        user_count = user_count_result.scalar() or 0

        # Get subscription tier
        sub_result = await db.execute(
            select(Subscription).where(Subscription.organization_id == org.id)
        )
        subscription = sub_result.scalar_one_or_none()
        tier_value = subscription.tier.value if subscription else "free_scan"

        # Filter by tier if specified
        if tier and tier_value != tier:
            continue

        items.append(
            OrganizationListItem(
                id=str(org.id),
                name=org.name,
                slug=org.slug,
                is_active=org.is_active,
                user_count=user_count,
                tier=tier_value,
                created_at=org.created_at.isoformat() if org.created_at else "",
            )
        )

    return OrganizationListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{org_id}", response_model=OrganizationDetailResponse)
async def get_organization(
    org_id: UUID,
    admin: AdminUser = Depends(require_permission("org:read")),
    db: AsyncSession = Depends(get_db),
) -> OrganizationDetailResponse:
    """Get organization details."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )

    # Get subscription
    sub_result = await db.execute(
        select(Subscription).where(Subscription.organization_id == org.id)
    )
    subscription = sub_result.scalar_one_or_none()

    # Get members with user info
    members_result = await db.execute(
        select(OrganizationMember, User)
        .join(User, OrganizationMember.user_id == User.id)
        .where(OrganizationMember.organization_id == org.id)
    )
    members_data = members_result.all()

    members = []
    owner = None
    for member, user in members_data:
        member_dict = {
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "role": member.role.value,
            "status": member.status.value,
            "joined_at": member.joined_at.isoformat() if member.joined_at else None,
        }
        members.append(member_dict)
        if member.role.value == "owner":
            owner = member_dict

    # Get cloud account count
    from app.models.cloud_account import CloudAccount

    account_count_result = await db.execute(
        select(func.count()).where(CloudAccount.organization_id == org.id)
    )
    cloud_account_count = account_count_result.scalar() or 0

    # Get scan count
    from app.models.scan import Scan

    scan_count_result = await db.execute(
        select(func.count())
        .select_from(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.organization_id == org.id)
    )
    scan_count = scan_count_result.scalar() or 0

    # Get detection count
    from app.models.detection import Detection

    detection_count_result = await db.execute(
        select(func.count())
        .select_from(Detection)
        .join(CloudAccount, Detection.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.organization_id == org.id)
    )
    detection_count = detection_count_result.scalar() or 0

    return OrganizationDetailResponse(
        id=str(org.id),
        name=org.name,
        slug=org.slug,
        is_active=org.is_active,
        created_at=org.created_at.isoformat() if org.created_at else "",
        tier=subscription.tier.value if subscription else "free_scan",
        stripe_customer_id=subscription.stripe_customer_id if subscription else None,
        user_count=len(members),
        cloud_account_count=cloud_account_count,
        scan_count=scan_count,
        detection_count=detection_count,
        owner=owner,
        members=members,
    )


@router.post("/{org_id}/suspend")
async def suspend_organization(
    org_id: UUID,
    body: SuspendOrgRequest,
    admin: AdminUser = Depends(require_permission("org:suspend")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Suspend an organization."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )

    if not org.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization is already suspended",
        )

    org.is_active = False
    await db.commit()

    # TODO: Log to admin audit log
    # TODO: Send notification to org owner

    return {
        "message": f"Organization {org.name} has been suspended",
        "reason": body.reason,
    }


@router.post("/{org_id}/unsuspend")
async def unsuspend_organization(
    org_id: UUID,
    admin: AdminUser = Depends(require_permission("org:suspend")),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Unsuspend an organization."""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )

    if org.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization is already active",
        )

    org.is_active = True
    await db.commit()

    return {"message": f"Organization {org.name} has been unsuspended"}
