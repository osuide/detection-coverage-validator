"""Public API scan endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.models.cloud_account import CloudAccount
from app.models.scan import Scan, ScanStatus
from app.api.v1.public.auth import APIKeyContext, get_api_key_context

router = APIRouter(tags=["Public API - Scans"])


class ScanCreateRequest(BaseModel):
    """Request to create a new scan."""

    regions: Optional[list[str]] = None  # If not provided, scan all configured regions


class ScanItem(BaseModel):
    """Scan item in list response."""

    id: str
    status: str
    progress_percent: int
    detections_found: int
    started_at: Optional[str]
    completed_at: Optional[str]
    created_at: str


class ScanDetailResponse(BaseModel):
    """Full scan detail response."""

    id: str
    cloud_account_id: str
    status: str
    progress_percent: int
    current_step: Optional[str]
    regions: list[str]
    detections_found: int
    detections_new: int
    detections_updated: int
    detections_removed: int
    errors: Optional[list[dict]]
    started_at: Optional[str]
    completed_at: Optional[str]
    created_at: str


class ScanCreateResponse(BaseModel):
    """Response after creating a scan."""

    id: str
    status: str
    message: str


class ScansListResponse(BaseModel):
    """Scans list response."""

    cloud_account_id: str
    scans: list[ScanItem]
    total: int


@router.post("/accounts/{cloud_account_id}/scans", response_model=ScanCreateResponse)
async def create_scan(
    cloud_account_id: UUID,
    request: ScanCreateRequest,
    response: Response,
    ctx: APIKeyContext = Depends(get_api_key_context),
    db: AsyncSession = Depends(get_db),
) -> ScanCreateResponse:
    """Trigger a new scan for a cloud account.

    Creates a new scan job that will discover security detections
    in the specified cloud account. Returns immediately with the
    scan ID - use GET /scans/{id} to check status.
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

    # Check for existing running scan
    running_result = await db.execute(
        select(Scan).where(
            Scan.cloud_account_id == cloud_account_id,
            Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
    )
    if running_result.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="A scan is already in progress for this account.",
        )

    # Check scan limits
    from app.services.scan_limit_service import ScanLimitService

    limit_service = ScanLimitService(db)
    can_perform_scan, reason, next_available = await limit_service.can_scan(
        ctx.organization_id
    )

    if not can_perform_scan:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "scan_limit_reached",
                "message": reason or "Weekly scan limit reached",
                "resets_at": next_available.isoformat() if next_available else None,
            },
        )

    # Create scan
    regions = request.regions or (
        account.regions if isinstance(account.regions, list) else []
    )

    scan = Scan(
        cloud_account_id=cloud_account_id,
        status=ScanStatus.PENDING,
        regions=regions,
    )
    db.add(scan)

    # Record scan for limit tracking
    await limit_service.record_scan(ctx.organization_id)

    await db.commit()
    await db.refresh(scan)

    return ScanCreateResponse(
        id=str(scan.id),
        status=scan.status.value,
        message="Scan created successfully. Check status with GET /scans/{id}",
    )


@router.get("/accounts/{cloud_account_id}/scans", response_model=ScansListResponse)
async def list_account_scans(
    cloud_account_id: UUID,
    response: Response,
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by status"
    ),
    limit: int = Query(20, ge=1, le=100),
    ctx: APIKeyContext = Depends(get_api_key_context),
    db: AsyncSession = Depends(get_db),
) -> ScansListResponse:
    """List scans for a cloud account.

    Returns most recent scans with optional status filtering.
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

    # Build query
    query = select(Scan).where(Scan.cloud_account_id == cloud_account_id)
    count_query = select(func.count(Scan.id)).where(
        Scan.cloud_account_id == cloud_account_id
    )

    if status_filter:
        try:
            ss = ScanStatus(status_filter)
            query = query.where(Scan.status == ss)
            count_query = count_query.where(Scan.status == ss)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status. Valid values: {[s.value for s in ScanStatus]}",
            )

    # Get total
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Get scans
    query = query.order_by(desc(Scan.created_at)).limit(limit)
    result = await db.execute(query)
    scans = result.scalars().all()

    items = [
        ScanItem(
            id=str(scan.id),
            status=scan.status.value,
            progress_percent=scan.progress_percent,
            detections_found=scan.detections_found,
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
            created_at=scan.created_at.isoformat(),
        )
        for scan in scans
    ]

    return ScansListResponse(
        cloud_account_id=str(cloud_account_id),
        scans=items,
        total=total,
    )


@router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: UUID,
    response: Response,
    ctx: APIKeyContext = Depends(get_api_key_context),
    db: AsyncSession = Depends(get_db),
) -> ScanDetailResponse:
    """Get scan details and status.

    Returns full details of a specific scan including
    progress and results.
    """
    # Add rate limit headers
    for key, value in ctx.rate_limit_headers.items():
        response.headers[key] = value

    # Get scan with organization check via account
    result = await db.execute(
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(
            Scan.id == scan_id,
            CloudAccount.organization_id == ctx.organization_id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanDetailResponse(
        id=str(scan.id),
        cloud_account_id=str(scan.cloud_account_id),
        status=scan.status.value,
        progress_percent=scan.progress_percent,
        current_step=scan.current_step,
        regions=scan.regions or [],
        detections_found=scan.detections_found,
        detections_new=scan.detections_new,
        detections_updated=scan.detections_updated,
        detections_removed=scan.detections_removed,
        errors=scan.errors,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        created_at=scan.created_at.isoformat(),
    )


@router.get("/scans/{scan_id}/results")
async def get_scan_results(
    scan_id: UUID,
    response: Response,
    ctx: APIKeyContext = Depends(get_api_key_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get scan results summary.

    Returns a summary of detection changes from this scan.
    """
    # Add rate limit headers
    for key, value in ctx.rate_limit_headers.items():
        response.headers[key] = value

    # Get scan with organization check
    result = await db.execute(
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(
            Scan.id == scan_id,
            CloudAccount.organization_id == ctx.organization_id,
        )
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not completed. Current status: {scan.status.value}",
        )

    return {
        "scan_id": str(scan.id),
        "status": scan.status.value,
        "summary": {
            "total_detections": scan.detections_found,
            "new_detections": scan.detections_new,
            "updated_detections": scan.detections_updated,
            "removed_detections": scan.detections_removed,
        },
        "regions_scanned": scan.regions or [],
        "duration_seconds": (
            int((scan.completed_at - scan.started_at).total_seconds())
            if scan.completed_at and scan.started_at
            else None
        ),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }
