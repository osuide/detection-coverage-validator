"""Scan endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.cloud_account import CloudAccount
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from app.services.scan_service import ScanService

router = APIRouter()


@router.get("", response_model=ScanListResponse)
async def list_scans(
    cloud_account_id: Optional[UUID] = None,
    status: Optional[ScanStatus] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List scan jobs."""
    query = select(Scan)
    if cloud_account_id:
        query = query.where(Scan.cloud_account_id == cloud_account_id)
    if status:
        query = query.where(Scan.status == status)

    # Get total count
    count_query = select(Scan)
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
    db: AsyncSession = Depends(get_db),
):
    """Create and start a new scan job."""
    # Verify cloud account exists
    result = await db.execute(
        select(CloudAccount).where(CloudAccount.id == scan_in.cloud_account_id)
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Use account regions if not specified
    regions = scan_in.regions or account.regions
    if not regions:
        regions = ["us-east-1"]  # Default region

    scan = Scan(
        cloud_account_id=scan_in.cloud_account_id,
        regions=regions,
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
    db: AsyncSession = Depends(get_db),
):
    """Get a specific scan job."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
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
