"""Cloud account endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, delete
import structlog

from app.core.database import get_db
from app.core.security import (
    AuthContext,
    get_auth_context,
    get_auth_context_optional,
    require_role,
)
from app.models.cloud_account import CloudAccount
from app.models.cloud_credential import CloudCredential
from app.models.scan import Scan, ScanStatus
from app.models.detection import Detection
from app.models.schedule import ScanSchedule
from app.models.alert import AlertConfig
from app.models.coverage import CoverageSnapshot
from app.models.gap import CoverageGap
from app.models.compliance import ComplianceCoverageSnapshot
from app.models.custom_detection import CustomDetection
from app.models.user import UserRole
from app.schemas.cloud_account import (
    CloudAccountCreate,
    CloudAccountUpdate,
    CloudAccountResponse,
)

logger = structlog.get_logger()

router = APIRouter()


@router.get("", response_model=list[CloudAccountResponse])
async def list_accounts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    is_active: Optional[bool] = None,
    auth: Optional[AuthContext] = Depends(get_auth_context_optional),
    db: AsyncSession = Depends(get_db),
):
    """
    List all cloud accounts.

    If authenticated with org context, returns accounts for that org.
    """
    query = select(CloudAccount)

    # Filter by organization if authenticated
    if auth and auth.organization:
        query = query.where(CloudAccount.organization_id == auth.organization_id)

        # For members/viewers, filter by allowed accounts if set
        if auth.membership and auth.membership.allowed_account_ids:
            query = query.where(
                CloudAccount.id.in_(
                    [UUID(aid) for aid in auth.membership.allowed_account_ids]
                )
            )

    if is_active is not None:
        query = query.where(CloudAccount.is_active == is_active)

    query = query.offset(skip).limit(limit).order_by(CloudAccount.created_at.desc())

    result = await db.execute(query)
    accounts = result.scalars().all()
    return accounts


@router.post("", response_model=CloudAccountResponse, status_code=201)
async def create_account(
    account_in: CloudAccountCreate,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new cloud account.

    Requires admin or owner role.
    """
    # Check for duplicate account_id within the same organization
    existing = await db.execute(
        select(CloudAccount).where(
            CloudAccount.account_id == account_in.account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail=f"Account with ID {account_in.account_id} already exists in your organization",
        )

    account = CloudAccount(
        **account_in.model_dump(),
        organization_id=auth.organization_id,
    )
    db.add(account)
    await db.flush()
    await db.refresh(account)
    return account


@router.get("/{account_id}", response_model=CloudAccountResponse)
async def get_account(
    account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific cloud account."""
    query = select(CloudAccount).where(CloudAccount.id == account_id)

    # Filter by organization if authenticated
    if auth.organization:
        query = query.where(CloudAccount.organization_id == auth.organization_id)

    result = await db.execute(query)
    account = result.scalar_one_or_none()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    # Check access for members/viewers
    if not auth.can_access_account(account_id):
        raise HTTPException(status_code=403, detail="Access denied to this account")

    return account


@router.patch("/{account_id}", response_model=CloudAccountResponse)
async def update_account(
    account_id: UUID,
    account_in: CloudAccountUpdate,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """
    Update a cloud account.

    Requires admin or owner role.
    """
    query = select(CloudAccount).where(
        and_(
            CloudAccount.id == account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )

    result = await db.execute(query)
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    update_data = account_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(account, field, value)

    await db.flush()
    await db.refresh(account)
    return account


@router.delete("/{account_id}", status_code=204)
async def delete_account(
    account_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a cloud account and all associated data.

    Requires admin or owner role.

    This will delete:
    - All scans for this account
    - All detections for this account
    - All schedules for this account
    - All credentials for this account
    - All coverage data for this account
    """
    query = select(CloudAccount).where(
        and_(
            CloudAccount.id == account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )

    result = await db.execute(query)
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    # H7: Check for active scans before allowing deletion
    active_scans_result = await db.execute(
        select(Scan).where(
            and_(
                Scan.cloud_account_id == account_id,
                Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
            )
        )
    )
    if active_scans_result.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="Cannot delete account with active scans. Please wait for scans to complete or cancel them first.",
        )

    try:
        # Delete related records that don't have CASCADE delete
        # Order matters due to foreign key dependencies
        await db.execute(
            delete(CoverageGap).where(CoverageGap.cloud_account_id == account_id)
        )
        await db.execute(
            delete(ComplianceCoverageSnapshot).where(
                ComplianceCoverageSnapshot.cloud_account_id == account_id
            )
        )
        await db.execute(
            delete(CoverageSnapshot).where(
                CoverageSnapshot.cloud_account_id == account_id
            )
        )
        await db.execute(
            delete(Detection).where(Detection.cloud_account_id == account_id)
        )
        await db.execute(
            delete(CustomDetection).where(
                CustomDetection.cloud_account_id == account_id
            )
        )
        await db.execute(delete(Scan).where(Scan.cloud_account_id == account_id))
        await db.execute(
            delete(ScanSchedule).where(ScanSchedule.cloud_account_id == account_id)
        )
        await db.execute(
            delete(AlertConfig).where(AlertConfig.cloud_account_id == account_id)
        )
        await db.execute(
            delete(CloudCredential).where(
                CloudCredential.cloud_account_id == account_id
            )
        )

        # Now delete the account itself
        await db.delete(account)
        await db.commit()

        logger.info(
            "cloud_account_deleted",
            account_id=str(account_id),
            account_name=account.name,
            organization_id=str(auth.organization_id),
            deleted_by=str(auth.user_id),
        )

    except Exception as e:
        await db.rollback()
        logger.error(
            "cloud_account_delete_failed",
            account_id=str(account_id),
            error=str(e),
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to delete account. Please try again.",
        )
