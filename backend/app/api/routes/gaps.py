"""Gap management API routes."""

from typing import Optional, Tuple
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import AuthContext, require_role
from app.models.user import UserRole
from app.models.gap import GapStatus, GapPriority, CoverageGap
from app.models.mitre import Technique
from sqlalchemy import select, and_

router = APIRouter(tags=["gaps"])


async def get_technique_info(
    db: AsyncSession, technique_id: str
) -> Tuple[str, str, str]:
    """Look up technique name and tactic from the database.

    Args:
        db: Database session
        technique_id: MITRE technique ID (e.g., "T1556.007")

    Returns:
        Tuple of (technique_name, tactic_id, tactic_name)
        Returns ("Unknown", "", "Unknown") if technique not found
    """
    from sqlalchemy.orm import selectinload

    result = await db.execute(
        select(Technique)
        .options(selectinload(Technique.tactic))
        .where(Technique.technique_id == technique_id)
    )
    technique = result.scalar_one_or_none()

    if technique:
        tactic_id_str = ""
        tactic_name = "Unknown"
        if technique.tactic:
            tactic_id_str = technique.tactic.tactic_id
            tactic_name = technique.tactic.name

        return technique.name, tactic_id_str, tactic_name

    return "Unknown", "", "Unknown"


class AcknowledgeGapRequest(BaseModel):
    """Request to acknowledge a gap."""

    notes: Optional[str] = None


class AcceptRiskRequest(BaseModel):
    """Request to accept risk for a gap."""

    reason: str


class GapResponse(BaseModel):
    """Response for a coverage gap."""

    id: UUID
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    status: str
    priority: str
    reason: Optional[str] = None
    remediation_notes: Optional[str] = None
    risk_acceptance_reason: Optional[str] = None

    class Config:
        from_attributes = True


class GapListResponse(BaseModel):
    """Response for gap list."""

    gaps: list[GapResponse]
    total: int


@router.post("/{technique_id}/acknowledge")
async def acknowledge_gap(
    technique_id: str,
    cloud_account_id: UUID = Query(..., description="Cloud account ID"),
    request: AcknowledgeGapRequest = None,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER)
    ),
) -> dict:
    """Acknowledge a coverage gap.

    This marks the gap as acknowledged by the team. Acknowledged gaps
    will not appear in future gap analyses.
    """
    # Check if gap already exists in the database
    stmt = select(CoverageGap).where(
        and_(
            CoverageGap.cloud_account_id == cloud_account_id,
            CoverageGap.technique_id == technique_id,
        )
    )
    result = await db.execute(stmt)
    existing_gap = result.scalar_one_or_none()

    if existing_gap:
        # Update existing gap
        if existing_gap.status in [GapStatus.REMEDIATED]:
            raise HTTPException(
                status_code=400,
                detail="Cannot acknowledge a remediated gap",
            )

        existing_gap.status = GapStatus.ACKNOWLEDGED
        if request and request.notes:
            existing_gap.remediation_notes = request.notes

        await db.commit()
        await db.refresh(existing_gap)

        return {
            "message": "Gap acknowledged",
            "gap_id": str(existing_gap.id),
            "technique_id": technique_id,
            "status": "acknowledged",
        }
    else:
        # Create new gap record with acknowledged status
        # Look up technique info from the database
        technique_name, tactic_id, tactic_name = await get_technique_info(
            db, technique_id
        )

        new_gap = CoverageGap(
            cloud_account_id=cloud_account_id,
            organization_id=auth.organization_id,
            technique_id=technique_id,
            technique_name=technique_name,
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            status=GapStatus.ACKNOWLEDGED,
            priority=GapPriority.MEDIUM,
            remediation_notes=request.notes if request else None,
        )

        db.add(new_gap)
        await db.commit()
        await db.refresh(new_gap)

        return {
            "message": "Gap acknowledged",
            "gap_id": str(new_gap.id),
            "technique_id": technique_id,
            "status": "acknowledged",
        }


@router.post("/{technique_id}/accept-risk")
async def accept_risk(
    technique_id: str,
    cloud_account_id: UUID = Query(..., description="Cloud account ID"),
    request: AcceptRiskRequest = None,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_role(UserRole.ADMIN)),
) -> dict:
    """Accept risk for a coverage gap.

    This marks the gap as risk-accepted. Risk-accepted gaps will not
    appear in future gap analyses. Requires admin role.
    """
    if not request or not request.reason:
        raise HTTPException(
            status_code=400,
            detail="A reason is required to accept risk",
        )

    # Check if gap already exists
    stmt = select(CoverageGap).where(
        and_(
            CoverageGap.cloud_account_id == cloud_account_id,
            CoverageGap.technique_id == technique_id,
        )
    )
    result = await db.execute(stmt)
    existing_gap = result.scalar_one_or_none()

    if existing_gap:
        if existing_gap.status == GapStatus.REMEDIATED:
            raise HTTPException(
                status_code=400,
                detail="Cannot accept risk for a remediated gap",
            )

        existing_gap.status = GapStatus.RISK_ACCEPTED
        existing_gap.risk_acceptance_reason = request.reason
        existing_gap.risk_accepted_by = auth.user_id

        await db.commit()
        await db.refresh(existing_gap)

        return {
            "message": "Risk accepted",
            "gap_id": str(existing_gap.id),
            "technique_id": technique_id,
            "status": "risk_accepted",
        }
    else:
        # Create new gap record with risk_accepted status
        from datetime import datetime

        # Look up technique info from the database
        technique_name, tactic_id, tactic_name = await get_technique_info(
            db, technique_id
        )

        new_gap = CoverageGap(
            cloud_account_id=cloud_account_id,
            organization_id=auth.organization_id,
            technique_id=technique_id,
            technique_name=technique_name,
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            status=GapStatus.RISK_ACCEPTED,
            priority=GapPriority.MEDIUM,
            risk_acceptance_reason=request.reason,
            risk_accepted_by=auth.user_id,
            risk_accepted_at=datetime.utcnow(),
        )

        db.add(new_gap)
        await db.commit()
        await db.refresh(new_gap)

        return {
            "message": "Risk accepted",
            "gap_id": str(new_gap.id),
            "technique_id": technique_id,
            "status": "risk_accepted",
        }


@router.post("/{technique_id}/reopen")
async def reopen_gap(
    technique_id: str,
    cloud_account_id: UUID = Query(..., description="Cloud account ID"),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER)
    ),
) -> dict:
    """Reopen an acknowledged or risk-accepted gap.

    This will make the gap appear in future gap analyses again.
    """
    stmt = select(CoverageGap).where(
        and_(
            CoverageGap.cloud_account_id == cloud_account_id,
            CoverageGap.technique_id == technique_id,
        )
    )
    result = await db.execute(stmt)
    existing_gap = result.scalar_one_or_none()

    if not existing_gap:
        raise HTTPException(status_code=404, detail="Gap not found")

    if existing_gap.status == GapStatus.OPEN:
        return {
            "message": "Gap is already open",
            "gap_id": str(existing_gap.id),
            "technique_id": technique_id,
            "status": "open",
        }

    if existing_gap.status == GapStatus.REMEDIATED:
        raise HTTPException(
            status_code=400,
            detail="Cannot reopen a remediated gap",
        )

    existing_gap.status = GapStatus.OPEN
    existing_gap.risk_acceptance_reason = None
    existing_gap.risk_accepted_by = None
    existing_gap.risk_accepted_at = None

    await db.commit()
    await db.refresh(existing_gap)

    return {
        "message": "Gap reopened",
        "gap_id": str(existing_gap.id),
        "technique_id": technique_id,
        "status": "open",
    }


@router.get("")
async def list_gaps(
    cloud_account_id: UUID = Query(..., description="Cloud account ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER, UserRole.VIEWER)
    ),
) -> GapListResponse:
    """List coverage gaps for a cloud account.

    Returns gaps stored in the database with their status information.
    """
    stmt = select(CoverageGap).where(CoverageGap.cloud_account_id == cloud_account_id)

    if status:
        try:
            gap_status = GapStatus(status)
            stmt = stmt.where(CoverageGap.status == gap_status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    if priority:
        try:
            gap_priority = GapPriority(priority)
            stmt = stmt.where(CoverageGap.priority == gap_priority)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid priority: {priority}")

    stmt = stmt.order_by(CoverageGap.priority).limit(limit).offset(offset)

    result = await db.execute(stmt)
    gaps = result.scalars().all()

    return GapListResponse(
        gaps=[
            GapResponse(
                id=g.id,
                technique_id=g.technique_id,
                technique_name=g.technique_name,
                tactic_id=g.tactic_id,
                tactic_name=g.tactic_name,
                status=g.status.value,
                priority=g.priority.value,
                reason=g.reason,
                remediation_notes=g.remediation_notes,
                risk_acceptance_reason=g.risk_acceptance_reason,
            )
            for g in gaps
        ],
        total=len(gaps),
    )


@router.get("/acknowledged")
async def list_acknowledged_gaps(
    cloud_account_id: UUID = Query(..., description="Cloud account ID"),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER, UserRole.VIEWER)
    ),
) -> dict:
    """Get list of technique IDs that are acknowledged or risk-accepted.

    This is used to filter out these gaps from the coverage analysis.
    """
    stmt = select(CoverageGap.technique_id).where(
        and_(
            CoverageGap.cloud_account_id == cloud_account_id,
            CoverageGap.status.in_([GapStatus.ACKNOWLEDGED, GapStatus.RISK_ACCEPTED]),
        )
    )

    result = await db.execute(stmt)
    technique_ids = [row[0] for row in result.all()]

    return {
        "acknowledged_technique_ids": technique_ids,
        "count": len(technique_ids),
    }


class OrgAcknowledgedGapResponse(BaseModel):
    """Response for organisation-level acknowledged gap."""

    id: UUID
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    status: str
    priority: str
    cloud_account_id: UUID
    cloud_account_name: Optional[str] = None
    reason: Optional[str] = None
    remediation_notes: Optional[str] = None
    risk_acceptance_reason: Optional[str] = None
    acknowledged_at: Optional[str] = None
    acknowledged_by_name: Optional[str] = None

    class Config:
        from_attributes = True


class OrgAcknowledgedGapsResponse(BaseModel):
    """Response for organisation-level acknowledged gaps list."""

    gaps: list[OrgAcknowledgedGapResponse]
    total: int
    by_status: dict[str, int]


@router.get("/org/acknowledged")
async def list_org_acknowledged_gaps(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
) -> OrgAcknowledgedGapsResponse:
    """List all acknowledged and risk-accepted gaps across the organisation.

    This endpoint is for org owners/admins to review all acknowledged gaps
    across all cloud accounts. Allows them to manage and revert acknowledgements.
    """
    from app.models.cloud_account import CloudAccount
    from app.models.user import User

    # Get all acknowledged/risk_accepted gaps for this organisation
    stmt = (
        select(
            CoverageGap,
            CloudAccount.name.label("account_name"),
            User.full_name.label("user_name"),
        )
        .join(CloudAccount, CoverageGap.cloud_account_id == CloudAccount.id)
        .outerjoin(User, CoverageGap.risk_accepted_by == User.id)
        .where(
            and_(
                CoverageGap.organization_id == auth.organization_id,
                CoverageGap.status.in_(
                    [GapStatus.ACKNOWLEDGED, GapStatus.RISK_ACCEPTED]
                ),
            )
        )
        .order_by(CoverageGap.status_changed_at.desc())
    )

    result = await db.execute(stmt)
    rows = result.all()

    # Count by status
    by_status = {"acknowledged": 0, "risk_accepted": 0}
    gaps = []

    for row in rows:
        gap = row[0]
        account_name = row[1]
        user_name = row[2]

        by_status[gap.status.value] = by_status.get(gap.status.value, 0) + 1

        gaps.append(
            OrgAcknowledgedGapResponse(
                id=gap.id,
                technique_id=gap.technique_id,
                technique_name=gap.technique_name,
                tactic_id=gap.tactic_id,
                tactic_name=gap.tactic_name,
                status=gap.status.value,
                priority=gap.priority.value,
                cloud_account_id=gap.cloud_account_id,
                cloud_account_name=account_name,
                reason=gap.reason,
                remediation_notes=gap.remediation_notes,
                risk_acceptance_reason=gap.risk_acceptance_reason,
                acknowledged_at=(
                    gap.status_changed_at.isoformat() if gap.status_changed_at else None
                ),
                acknowledged_by_name=user_name,
            )
        )

    return OrgAcknowledgedGapsResponse(
        gaps=gaps,
        total=len(gaps),
        by_status=by_status,
    )


@router.post("/org/{gap_id}/reopen")
async def reopen_org_gap(
    gap_id: UUID,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
) -> dict:
    """Reopen an acknowledged/risk-accepted gap from the org admin view.

    This allows org owners/admins to revert gap acknowledgements.
    """
    # Get the gap and verify it belongs to this organisation
    stmt = select(CoverageGap).where(
        and_(
            CoverageGap.id == gap_id,
            CoverageGap.organization_id == auth.organization_id,
        )
    )
    result = await db.execute(stmt)
    gap = result.scalar_one_or_none()

    if not gap:
        raise HTTPException(status_code=404, detail="Gap not found")

    if gap.status not in [GapStatus.ACKNOWLEDGED, GapStatus.RISK_ACCEPTED]:
        raise HTTPException(
            status_code=400,
            detail="Only acknowledged or risk-accepted gaps can be reopened",
        )

    gap.status = GapStatus.OPEN
    gap.risk_acceptance_reason = None
    gap.risk_accepted_by = None
    gap.risk_accepted_at = None

    await db.commit()
    await db.refresh(gap)

    return {
        "message": "Gap reopened",
        "gap_id": str(gap.id),
        "technique_id": gap.technique_id,
        "status": "open",
    }
