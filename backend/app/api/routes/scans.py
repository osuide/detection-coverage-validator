"""Scan endpoints."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import (
    AuthContext,
    get_auth_context,
    require_scope,
    require_role,
    get_allowed_account_filter,
)
from app.models.user import UserRole
from app.core.cache import get_cached_scan_status
from app.models.scan import Scan, ScanStatus
from app.models.cloud_account import CloudAccount
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse
from app.services.scan_service import execute_scan_background
from app.services.scan_limit_service import ScanLimitService

router = APIRouter()


@router.get(
    "",
    response_model=ScanListResponse,
    dependencies=[Depends(require_scope("read:scans"))],
)
async def list_scans(
    cloud_account_id: Optional[UUID] = None,
    status: Optional[ScanStatus] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List scan jobs.

    API keys require 'read:scans' scope.
    """
    # Security: Get allowed accounts for ACL filtering
    allowed_accounts = get_allowed_account_filter(auth)

    # If user has restricted access with empty list, return empty result
    if allowed_accounts is not None and len(allowed_accounts) == 0:
        return ScanListResponse(items=[], total=0, page=1, page_size=limit)

    # Security: Check account-level ACL if filtering by specific account
    if cloud_account_id and not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    # Filter by organization through cloud_account
    query = (
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.organization_id == auth.organization_id)
    )

    # Security: Apply ACL filter when no specific account requested
    if cloud_account_id:
        query = query.where(Scan.cloud_account_id == cloud_account_id)
    elif allowed_accounts is not None:
        # Restricted user without specific account - filter to allowed accounts
        query = query.where(Scan.cloud_account_id.in_(allowed_accounts))

    if status:
        query = query.where(Scan.status == status)

    # Get total count
    count_query = (
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.organization_id == auth.organization_id)
    )

    # Security: Apply same ACL filter to count query
    if cloud_account_id:
        count_query = count_query.where(Scan.cloud_account_id == cloud_account_id)
    elif allowed_accounts is not None:
        count_query = count_query.where(Scan.cloud_account_id.in_(allowed_accounts))

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


@router.post(
    "",
    response_model=ScanResponse,
    status_code=201,
    dependencies=[
        Depends(require_scope("write:scans")),
        Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    ],
)
async def create_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create and start a new scan job.

    API keys require 'write:scans' scope.
    """
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

    # Security: Check account-level ACL
    if not auth.can_access_account(scan_in.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

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

    # CRITICAL: Commit the transaction BEFORE starting background task
    # The background task uses a separate database session, so it can only
    # see the scan if it's been committed to the database.
    await db.commit()

    # Start scan in background with its own database session
    # This prevents holding the request's DB connection during the long-running scan
    background_tasks.add_task(execute_scan_background, scan.id, auth.organization_id)

    return scan


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    dependencies=[Depends(require_scope("read:scans"))],
)
async def get_scan(
    scan_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get a specific scan job.

    API keys require 'read:scans' scope.

    Performance: For active scans (pending/running), this endpoint first checks
    Redis cache to avoid database queries during frequent polling. The scan
    service updates Redis after each status change.

    When organization_id is present in the cache (added after account is fetched
    during scan execution), ownership can be verified without a database query.
    """
    # Try Redis cache first for fast polling during active scans
    cached = await get_cached_scan_status(str(scan_id))
    if cached:
        cloud_account_id = cached.get("cloud_account_id")
        cached_org_id = cached.get("organization_id")

        if cloud_account_id:
            # If organization_id is in cache, verify ownership without DB query
            if cached_org_id:
                if UUID(cached_org_id) != auth.organization_id:
                    # Not owned by this organization - fall through to DB query
                    # (don't reveal scan exists via 403)
                    pass
                else:
                    # Ownership verified via cache - check account-level ACL
                    if not auth.can_access_account(UUID(cloud_account_id)):
                        raise HTTPException(
                            status_code=403,
                            detail="Access denied to this cloud account",
                        )
                    # Parse datetime strings back to datetime objects for response
                    if cached.get("started_at"):
                        cached["started_at"] = datetime.fromisoformat(
                            cached["started_at"]
                        )
                    if cached.get("completed_at"):
                        cached["completed_at"] = datetime.fromisoformat(
                            cached["completed_at"]
                        )
                    if cached.get("created_at"):
                        cached["created_at"] = datetime.fromisoformat(
                            cached["created_at"]
                        )
                    # Convert string ID to UUID
                    cached["id"] = UUID(cached["id"])
                    cached["cloud_account_id"] = UUID(cached["cloud_account_id"])
                    # Remove organization_id from response (not in ScanResponse schema)
                    cached.pop("organization_id", None)
                    return ScanResponse(**cached)
            else:
                # Legacy cache entry without organization_id - verify via DB
                result = await db.execute(
                    select(CloudAccount.id).where(
                        CloudAccount.id == UUID(cloud_account_id),
                        CloudAccount.organization_id == auth.organization_id,
                    )
                )
                if result.scalar_one_or_none():
                    # Security: Check account-level ACL
                    if not auth.can_access_account(UUID(cloud_account_id)):
                        raise HTTPException(
                            status_code=403,
                            detail="Access denied to this cloud account",
                        )
                    # Parse datetime strings back to datetime objects for response
                    if cached.get("started_at"):
                        cached["started_at"] = datetime.fromisoformat(
                            cached["started_at"]
                        )
                    if cached.get("completed_at"):
                        cached["completed_at"] = datetime.fromisoformat(
                            cached["completed_at"]
                        )
                    if cached.get("created_at"):
                        cached["created_at"] = datetime.fromisoformat(
                            cached["created_at"]
                        )
                    # Convert string ID to UUID
                    cached["id"] = UUID(cached["id"])
                    cached["cloud_account_id"] = UUID(cached["cloud_account_id"])
                    return ScanResponse(**cached)

    # Fall back to database query
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

    # Security: Check account-level ACL
    if not auth.can_access_account(scan.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    return scan


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanResponse,
    dependencies=[
        Depends(require_scope("write:scans")),
        Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    ],
)
async def cancel_scan(
    scan_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Cancel a running scan.

    API keys require 'write:scans' scope.
    """
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

    # Security: Check account-level ACL
    if not auth.can_access_account(scan.cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan with status {scan.status.value}",
        )

    scan.status = ScanStatus.CANCELLED
    await db.flush()
    await db.refresh(scan)
    return scan
