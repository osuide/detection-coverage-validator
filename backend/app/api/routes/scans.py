"""Scan endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context
from app.models.scan import Scan, ScanStatus
from app.models.cloud_account import CloudAccount
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from app.services.scan_service import ScanService
from app.services.scan_limit_service import ScanLimitService

router = APIRouter()


@router.get("", response_model=ScanListResponse)
async def list_scans(
    cloud_account_id: Optional[UUID] = None,
    status: Optional[ScanStatus] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """List scan jobs."""
    # Filter by organization through cloud_account
    query = (
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.organization_id == auth.organization_id)
    )
    if cloud_account_id:
        query = query.where(Scan.cloud_account_id == cloud_account_id)
    if status:
        query = query.where(Scan.status == status)

    # Get total count
    count_query = (
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.organization_id == auth.organization_id)
    )
    if cloud_account_id:
        count_query = count_query.where(Scan.cloud_account_id == cloud_account_id)
    if status:
        count_query = count_query.where(Scan.status == status)

    total_result = await db.execute(count_query)
    total = len(total_result.scalars().all())

    query = query.offset(skip).limit(limit).order_by(Scan.created_at.desc())
    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanListResponse(
        items=scans,
        total=total,
        page=skip // limit + 1,
        page_size=limit,
    )


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Create and start a new scan job."""
    # Verify cloud account exists and belongs to user's organization first
    # (before consuming a scan from the limit)
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == scan_in.cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # H6: Atomically check scan limits and record the scan to prevent race conditions
    # This uses row-level locking to ensure concurrent requests cannot bypass limits
    scan_limit_service = ScanLimitService(db)
    can_scan, reason, next_available = await scan_limit_service.can_scan_and_record(
        auth.organization_id
    )

    if not can_scan:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": reason or "Weekly scan limit reached",
                "next_available_at": (
                    next_available.isoformat() if next_available else None
                ),
                "upgrade_url": "/settings/billing",
            },
        )

    # Only use scan-level regions if explicitly specified in the request
    # Otherwise leave empty so scan service uses account.region_config
    scan_regions = scan_in.regions if scan_in.regions else []

    scan = Scan(
        cloud_account_id=scan_in.cloud_account_id,
        regions=scan_regions,
        detection_types=(
            [dt.value for dt in scan_in.detection_types]
            if scan_in.detection_types
            else []
        ),
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Start scan in background
    scan_service = ScanService(db)
    background_tasks.add_task(scan_service.execute_scan, scan.id)

    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific scan job."""
    result = await db.execute(
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(
            Scan.id == scan_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running scan."""
    result = await db.execute(
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(
            Scan.id == scan_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan with status {scan.status.value}",
        )

    scan.status = ScanStatus.CANCELLED
    await db.flush()
    await db.refresh(scan)
    return scan
