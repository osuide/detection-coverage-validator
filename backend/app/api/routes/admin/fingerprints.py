"""Admin fingerprint abuse detection routes."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser, AdminRole
from app.models.fingerprint import DeviceFingerprint, DeviceFingerprintAssociation
from app.models.user import User, Organization
from app.api.deps import get_current_admin

router = APIRouter(prefix="/fingerprints", tags=["Admin Fingerprints"])


# Response models
class AssociationResponse(BaseModel):
    """Fingerprint association details."""

    id: str
    user_id: str
    user_email: str
    user_name: str
    organization_id: Optional[str]
    organization_name: Optional[str]
    ip_address: Optional[str]
    first_seen_at: str
    last_seen_at: str
    seen_count: int


class FingerprintResponse(BaseModel):
    """Fingerprint summary response."""

    id: str
    fingerprint_hash: str  # Truncated for display
    abuse_score: int
    is_flagged: bool
    flag_reason: Optional[str]
    associated_user_count: int
    associated_org_count: int
    first_seen_at: str
    last_seen_at: str
    created_at: str


class FingerprintDetailResponse(FingerprintResponse):
    """Fingerprint detail response with associations."""

    admin_notes: Optional[str]
    associations: list[AssociationResponse]


class FingerprintsListResponse(BaseModel):
    """Fingerprints list response."""

    fingerprints: list[FingerprintResponse]
    total: int
    page: int
    per_page: int


class FingerprintStatsResponse(BaseModel):
    """Fingerprint abuse statistics."""

    total_fingerprints: int
    flagged_count: int
    high_risk_count: int  # abuse_score >= 50
    multi_user_count: int  # > 2 users
    multi_org_count: int  # > 2 orgs
    registrations_today: int
    registrations_this_week: int


class FlagFingerprintRequest(BaseModel):
    """Request to flag a fingerprint."""

    reason: str
    admin_notes: Optional[str] = None


class UnflagFingerprintRequest(BaseModel):
    """Request to unflag a fingerprint."""

    admin_notes: Optional[str] = None


def _truncate_hash(hash_str: str, length: int = 16) -> str:
    """Truncate fingerprint hash for display."""
    if len(hash_str) <= length:
        return hash_str
    return hash_str[:length] + "..."


def _fingerprint_to_response(fp: DeviceFingerprint) -> FingerprintResponse:
    """Convert fingerprint model to response."""
    return FingerprintResponse(
        id=str(fp.id),
        fingerprint_hash=_truncate_hash(fp.fingerprint_hash),
        abuse_score=fp.abuse_score,
        is_flagged=fp.is_flagged,
        flag_reason=fp.flag_reason,
        associated_user_count=fp.associated_user_count,
        associated_org_count=fp.associated_org_count,
        first_seen_at=fp.first_seen_at.isoformat() if fp.first_seen_at else "",
        last_seen_at=fp.last_seen_at.isoformat() if fp.last_seen_at else "",
        created_at=fp.created_at.isoformat() if fp.created_at else "",
    )


@router.get("/stats", response_model=FingerprintStatsResponse)
async def get_fingerprint_stats(
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get fingerprint abuse statistics."""
    from datetime import timedelta, timezone

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)

    # Total fingerprints
    total_result = await db.execute(select(func.count(DeviceFingerprint.id)))
    total = total_result.scalar() or 0

    # Flagged count
    flagged_result = await db.execute(
        select(func.count(DeviceFingerprint.id)).where(
            DeviceFingerprint.is_flagged == True  # noqa: E712
        )
    )
    flagged = flagged_result.scalar() or 0

    # High risk (abuse_score >= 50)
    high_risk_result = await db.execute(
        select(func.count(DeviceFingerprint.id)).where(
            DeviceFingerprint.abuse_score >= 50
        )
    )
    high_risk = high_risk_result.scalar() or 0

    # Multi-user (> 2 users)
    multi_user_result = await db.execute(
        select(func.count(DeviceFingerprint.id)).where(
            DeviceFingerprint.associated_user_count > 2
        )
    )
    multi_user = multi_user_result.scalar() or 0

    # Multi-org (> 2 orgs)
    multi_org_result = await db.execute(
        select(func.count(DeviceFingerprint.id)).where(
            DeviceFingerprint.associated_org_count > 2
        )
    )
    multi_org = multi_org_result.scalar() or 0

    # Registrations today
    today_result = await db.execute(
        select(func.count(DeviceFingerprintAssociation.id)).where(
            DeviceFingerprintAssociation.created_at >= today_start
        )
    )
    today_count = today_result.scalar() or 0

    # Registrations this week
    week_result = await db.execute(
        select(func.count(DeviceFingerprintAssociation.id)).where(
            DeviceFingerprintAssociation.created_at >= week_start
        )
    )
    week_count = week_result.scalar() or 0

    return FingerprintStatsResponse(
        total_fingerprints=total,
        flagged_count=flagged,
        high_risk_count=high_risk,
        multi_user_count=multi_user,
        multi_org_count=multi_org,
        registrations_today=today_count,
        registrations_this_week=week_count,
    )


@router.get("", response_model=FingerprintsListResponse)
async def list_fingerprints(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    min_abuse_score: int = Query(0, ge=0, le=100),
    flagged_only: bool = Query(False),
    sort_by: str = Query(
        "abuse_score", regex="^(abuse_score|created_at|last_seen_at)$"
    ),
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """List fingerprints with pagination and filtering."""
    # Build query
    query = select(DeviceFingerprint)
    count_query = select(func.count(DeviceFingerprint.id))

    # Apply filters
    if min_abuse_score > 0:
        query = query.where(DeviceFingerprint.abuse_score >= min_abuse_score)
        count_query = count_query.where(
            DeviceFingerprint.abuse_score >= min_abuse_score
        )

    if flagged_only:
        query = query.where(DeviceFingerprint.is_flagged == True)  # noqa: E712
        count_query = count_query.where(
            DeviceFingerprint.is_flagged == True  # noqa: E712
        )

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Apply sorting
    if sort_by == "abuse_score":
        query = query.order_by(DeviceFingerprint.abuse_score.desc())
    elif sort_by == "created_at":
        query = query.order_by(DeviceFingerprint.created_at.desc())
    else:
        query = query.order_by(DeviceFingerprint.last_seen_at.desc())

    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    fingerprints = result.scalars().all()

    return FingerprintsListResponse(
        fingerprints=[_fingerprint_to_response(fp) for fp in fingerprints],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/suspicious", response_model=FingerprintsListResponse)
async def list_suspicious_fingerprints(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """List suspicious fingerprints (abuse_score >= 50 or flagged)."""
    from sqlalchemy import or_

    # Build query for suspicious fingerprints
    query = select(DeviceFingerprint).where(
        or_(
            DeviceFingerprint.abuse_score >= 50,
            DeviceFingerprint.is_flagged == True,  # noqa: E712
        )
    )
    count_query = select(func.count(DeviceFingerprint.id)).where(
        or_(
            DeviceFingerprint.abuse_score >= 50,
            DeviceFingerprint.is_flagged == True,  # noqa: E712
        )
    )

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(DeviceFingerprint.abuse_score.desc())
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    fingerprints = result.scalars().all()

    return FingerprintsListResponse(
        fingerprints=[_fingerprint_to_response(fp) for fp in fingerprints],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{fingerprint_id}", response_model=FingerprintDetailResponse)
async def get_fingerprint_detail(
    fingerprint_id: UUID,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get fingerprint details with associations."""
    # Get fingerprint
    result = await db.execute(
        select(DeviceFingerprint).where(DeviceFingerprint.id == fingerprint_id)
    )
    fingerprint = result.scalar_one_or_none()

    if not fingerprint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Fingerprint not found"
        )

    # Get associations with user and org details
    assoc_query = (
        select(DeviceFingerprintAssociation, User, Organization)
        .join(User, DeviceFingerprintAssociation.user_id == User.id)
        .outerjoin(
            Organization,
            DeviceFingerprintAssociation.organization_id == Organization.id,
        )
        .where(DeviceFingerprintAssociation.fingerprint_id == fingerprint_id)
        .order_by(DeviceFingerprintAssociation.created_at.desc())
    )
    assoc_result = await db.execute(assoc_query)
    associations = assoc_result.all()

    assoc_responses = [
        AssociationResponse(
            id=str(assoc.id),
            user_id=str(user.id),
            user_email=user.email,
            user_name=user.full_name or "",
            organization_id=str(org.id) if org else None,
            organization_name=org.name if org else None,
            ip_address=assoc.ip_address,
            first_seen_at=(
                assoc.first_seen_at.isoformat() if assoc.first_seen_at else ""
            ),
            last_seen_at=assoc.last_seen_at.isoformat() if assoc.last_seen_at else "",
            seen_count=assoc.seen_count,
        )
        for assoc, user, org in associations
    ]

    return FingerprintDetailResponse(
        id=str(fingerprint.id),
        fingerprint_hash=_truncate_hash(fingerprint.fingerprint_hash),
        abuse_score=fingerprint.abuse_score,
        is_flagged=fingerprint.is_flagged,
        flag_reason=fingerprint.flag_reason,
        admin_notes=fingerprint.admin_notes,
        associated_user_count=fingerprint.associated_user_count,
        associated_org_count=fingerprint.associated_org_count,
        first_seen_at=(
            fingerprint.first_seen_at.isoformat() if fingerprint.first_seen_at else ""
        ),
        last_seen_at=(
            fingerprint.last_seen_at.isoformat() if fingerprint.last_seen_at else ""
        ),
        created_at=fingerprint.created_at.isoformat() if fingerprint.created_at else "",
        associations=assoc_responses,
    )


@router.patch("/{fingerprint_id}/flag")
async def flag_fingerprint(
    fingerprint_id: UUID,
    body: FlagFingerprintRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Flag a fingerprint as suspicious/abusive."""
    # Check permissions
    if admin.role not in [
        AdminRole.SUPER_ADMIN,
        AdminRole.PLATFORM_ADMIN,
        AdminRole.SUPPORT_ADMIN,
    ]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    result = await db.execute(
        select(DeviceFingerprint).where(DeviceFingerprint.id == fingerprint_id)
    )
    fingerprint = result.scalar_one_or_none()

    if not fingerprint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Fingerprint not found"
        )

    fingerprint.is_flagged = True
    fingerprint.flag_reason = body.reason
    fingerprint.abuse_score = 100  # Max score when manually flagged
    if body.admin_notes:
        fingerprint.admin_notes = body.admin_notes

    await db.commit()

    return {
        "message": "Fingerprint flagged successfully",
        "fingerprint_id": str(fingerprint_id),
    }


@router.patch("/{fingerprint_id}/unflag")
async def unflag_fingerprint(
    fingerprint_id: UUID,
    body: UnflagFingerprintRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Remove flag from a fingerprint."""
    # Check permissions
    if admin.role not in [
        AdminRole.SUPER_ADMIN,
        AdminRole.PLATFORM_ADMIN,
        AdminRole.SUPPORT_ADMIN,
    ]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
        )

    result = await db.execute(
        select(DeviceFingerprint).where(DeviceFingerprint.id == fingerprint_id)
    )
    fingerprint = result.scalar_one_or_none()

    if not fingerprint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Fingerprint not found"
        )

    fingerprint.is_flagged = False
    fingerprint.flag_reason = None
    # Recalculate abuse score
    fingerprint.abuse_score = fingerprint.calculate_abuse_score()
    if body.admin_notes:
        fingerprint.admin_notes = body.admin_notes

    await db.commit()

    return {
        "message": "Fingerprint unflagged successfully",
        "fingerprint_id": str(fingerprint_id),
        "new_abuse_score": fingerprint.abuse_score,
    }
