"""Public API coverage endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.cloud_account import CloudAccount
from app.models.coverage import CoverageSnapshot
from app.api.v1.public.auth import APIKeyContext, get_api_key_context

router = APIRouter(prefix="/accounts", tags=["Public API - Coverage"])


class TechniqueCoverageItem(BaseModel):
    """Technique coverage item."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    detection_count: int
    max_confidence: float
    status: str  # covered, partial, uncovered


class CoverageGapItem(BaseModel):
    """Coverage gap item."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    priority: str
    has_template: bool


class PublicCoverageResponse(BaseModel):
    """Public API coverage response."""

    cloud_account_id: str
    cloud_account_name: str
    total_techniques: int
    covered_techniques: int
    coverage_percent: float
    average_confidence: float
    last_scan_at: Optional[str]
    created_at: str


class TechniquesResponse(BaseModel):
    """Techniques list response."""

    cloud_account_id: str
    techniques: list[TechniqueCoverageItem]
    total: int


class GapsResponse(BaseModel):
    """Gaps list response."""

    cloud_account_id: str
    gaps: list[CoverageGapItem]
    total: int


@router.get("/{cloud_account_id}/coverage", response_model=PublicCoverageResponse)
async def get_account_coverage(
    cloud_account_id: UUID,
    response: Response,
    ctx: APIKeyContext = Depends(get_api_key_context),
    db: AsyncSession = Depends(get_db),
):
    """Get coverage summary for a cloud account.

    Returns the latest coverage snapshot including total techniques,
    covered techniques, and coverage percentage.
    """
    # Add rate limit headers
    for key, value in ctx.rate_limit_headers.items():
        response.headers[key] = value

    # Verify account belongs to organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == ctx.organization_id,
        )
    )
    account = account_result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Get latest coverage snapshot
    snapshot_result = await db.execute(
        select(CoverageSnapshot)
        .where(CoverageSnapshot.cloud_account_id == cloud_account_id)
        .order_by(desc(CoverageSnapshot.created_at))
        .limit(1)
    )
    snapshot = snapshot_result.scalar_one_or_none()

    if not snapshot:
        raise HTTPException(
            status_code=404,
            detail="No coverage data available. Run a scan first.",
        )

    return PublicCoverageResponse(
        cloud_account_id=str(cloud_account_id),
        cloud_account_name=account.name,
        total_techniques=snapshot.total_techniques,
        covered_techniques=snapshot.covered_techniques,
        coverage_percent=snapshot.coverage_percent,
        average_confidence=snapshot.average_confidence or 0.0,
        last_scan_at=(
            account.last_scan_at.isoformat() if account.last_scan_at else None
        ),
        created_at=snapshot.created_at.isoformat(),
    )


@router.get(
    "/{cloud_account_id}/coverage/techniques", response_model=TechniquesResponse
)
async def get_technique_coverage(
    cloud_account_id: UUID,
    response: Response,
    tactic: Optional[str] = Query(None, description="Filter by tactic ID"),
    status_filter: Optional[str] = Query(
        None,
        alias="status",
        description="Filter by status: covered, partial, uncovered",
    ),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    ctx: APIKeyContext = Depends(get_api_key_context),
    db: AsyncSession = Depends(get_db),
):
    """Get per-technique coverage details.

    Returns coverage status for each MITRE ATT&CK technique
    with filtering options by tactic or status.
    """
    # Add rate limit headers
    for key, value in ctx.rate_limit_headers.items():
        response.headers[key] = value

    # Verify account belongs to organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == ctx.organization_id,
        )
    )
    if not account_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Get technique coverage from snapshot
    from app.models.mitre import Technique, Tactic
    from app.models.detection import Detection, DetectionStatus
    from app.models.mapping import DetectionMapping

    # Get all techniques with their tactics
    query = (
        select(Technique, Tactic)
        .join(Tactic, Technique.tactic_id == Tactic.id)
        .where(Technique.is_deprecated == False)  # noqa
    )

    if tactic:
        query = query.where(Tactic.tactic_id == tactic)

    result = await db.execute(query)
    techniques_with_tactics = result.all()

    # Get detections for this account
    detections_result = await db.execute(
        select(Detection.id)
        .where(Detection.cloud_account_id == cloud_account_id)
        .where(Detection.status == DetectionStatus.ACTIVE)
    )
    detection_ids = [d[0] for d in detections_result.all()]

    techniques = []
    for technique, tactic_obj in techniques_with_tactics:
        detection_count = 0
        max_confidence = 0.0

        if detection_ids:
            mappings_result = await db.execute(
                select(DetectionMapping)
                .where(DetectionMapping.technique_id == technique.id)
                .where(DetectionMapping.detection_id.in_(detection_ids))
            )
            mappings = mappings_result.scalars().all()
            detection_count = len(mappings)
            if mappings:
                max_confidence = max(m.confidence for m in mappings)

        # Determine status
        if max_confidence >= 0.6:
            status = "covered"
        elif max_confidence >= 0.4:
            status = "partial"
        else:
            status = "uncovered"

        # Apply status filter
        if status_filter and status != status_filter:
            continue

        techniques.append(
            TechniqueCoverageItem(
                technique_id=technique.technique_id,
                technique_name=technique.name,
                tactic_id=tactic_obj.tactic_id,
                tactic_name=tactic_obj.name,
                detection_count=detection_count,
                max_confidence=round(max_confidence, 2),
                status=status,
            )
        )

    # Apply pagination
    total = len(techniques)
    techniques = techniques[offset : offset + limit]

    return TechniquesResponse(
        cloud_account_id=str(cloud_account_id),
        techniques=techniques,
        total=total,
    )


@router.get("/{cloud_account_id}/coverage/gaps", response_model=GapsResponse)
async def get_coverage_gaps(
    cloud_account_id: UUID,
    response: Response,
    priority: Optional[str] = Query(
        None, description="Filter by priority: critical, high, medium, low"
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ctx: APIKeyContext = Depends(get_api_key_context),
    db: AsyncSession = Depends(get_db),
):
    """Get coverage gaps for a cloud account.

    Returns uncovered techniques prioritised by importance.
    """
    # Add rate limit headers
    for key, value in ctx.rate_limit_headers.items():
        response.headers[key] = value

    # Verify account belongs to organization
    account_result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == ctx.organization_id,
        )
    )
    if not account_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Get latest snapshot for gaps
    snapshot_result = await db.execute(
        select(CoverageSnapshot)
        .where(CoverageSnapshot.cloud_account_id == cloud_account_id)
        .order_by(desc(CoverageSnapshot.created_at))
        .limit(1)
    )
    snapshot = snapshot_result.scalar_one_or_none()

    if not snapshot or not snapshot.top_gaps:
        return GapsResponse(
            cloud_account_id=str(cloud_account_id),
            gaps=[],
            total=0,
        )

    gaps = []
    for gap in snapshot.top_gaps:
        gap_priority = gap.get("priority", "medium")
        if priority and gap_priority != priority:
            continue

        gaps.append(
            CoverageGapItem(
                technique_id=gap.get("technique_id", ""),
                technique_name=gap.get("name", ""),
                tactic_id=gap.get("tactic_id", ""),
                tactic_name=gap.get("tactic_name", ""),
                priority=gap_priority,
                has_template=gap.get("has_template", False),
            )
        )

    total = len(gaps)
    gaps = gaps[offset : offset + limit]

    return GapsResponse(
        cloud_account_id=str(cloud_account_id),
        gaps=gaps,
        total=total,
    )
