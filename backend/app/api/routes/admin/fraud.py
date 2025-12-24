"""Admin fraud prevention management routes."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser
from app.models.fraud_prevention import (
    CloudAccountGlobalRegistry,
    FreeEmailCloudAccountBinding,
)
from app.api.deps import get_current_admin

router = APIRouter(prefix="/fraud", tags=["Admin Fraud Prevention"])


# Response models
class CloudAccountRegistryResponse(BaseModel):
    """Cloud account registry entry response."""

    id: str
    account_hash: str  # Truncated for display
    provider: str
    first_registered_org_id: str
    first_registered_at: str
    registration_count: int
    is_free_tier_locked: bool
    created_at: str
    updated_at: str


class EmailBindingResponse(BaseModel):
    """Email-cloud account binding response."""

    id: str
    email_hash: str  # Truncated for privacy
    cloud_account_hash: str  # Truncated for display
    provider: str
    created_at: str


class FraudStatsResponse(BaseModel):
    """Overall fraud prevention statistics."""

    total_registry_entries: int
    free_tier_locked_entries: int
    total_email_bindings: int
    recent_blocks_24h: int  # Placeholder - would need audit log integration


@router.get("/cloud-account-registry")
async def list_cloud_account_registry(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    provider: Optional[str] = Query(None, description="Filter by provider (aws/gcp)"),
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
) -> dict:
    """List all cloud accounts in the global fraud prevention registry."""
    query = select(CloudAccountGlobalRegistry)

    if provider:
        query = query.where(CloudAccountGlobalRegistry.provider == provider)

    # Get total count
    count_query = select(func.count(CloudAccountGlobalRegistry.id))
    if provider:
        count_query = count_query.where(CloudAccountGlobalRegistry.provider == provider)
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Get paginated results
    query = query.order_by(CloudAccountGlobalRegistry.created_at.desc())
    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    entries = result.scalars().all()

    return {
        "items": [
            CloudAccountRegistryResponse(
                id=str(e.id),
                account_hash=e.account_hash[:16] + "...",
                provider=e.provider,
                first_registered_org_id=str(e.first_registered_org_id),
                first_registered_at=e.first_registered_at.isoformat(),
                registration_count=e.registration_count,
                is_free_tier_locked=e.is_free_tier_locked,
                created_at=e.created_at.isoformat(),
                updated_at=e.updated_at.isoformat(),
            ).model_dump()
            for e in entries
        ],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.delete("/cloud-account-registry/{entry_id}")
async def release_cloud_account_lock(
    entry_id: UUID,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
) -> dict:
    """Manually release a cloud account lock (admin override).

    This allows the cloud account to be registered by another free-tier organisation.
    Use with caution - this bypasses fraud prevention.
    """
    result = await db.execute(
        select(CloudAccountGlobalRegistry).where(
            CloudAccountGlobalRegistry.id == entry_id
        )
    )
    entry = result.scalar_one_or_none()

    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Registry entry not found"
        )

    entry.is_free_tier_locked = False
    await db.commit()

    return {"message": "Lock released successfully", "entry_id": str(entry_id)}


@router.get("/email-bindings")
async def list_email_bindings(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
) -> dict:
    """List all email-to-cloud-account bindings.

    These bindings prevent email cycling through different cloud accounts on free tier.
    """
    # Get total count
    count_result = await db.execute(select(func.count(FreeEmailCloudAccountBinding.id)))
    total = count_result.scalar() or 0

    # Get paginated results
    query = (
        select(FreeEmailCloudAccountBinding)
        .order_by(FreeEmailCloudAccountBinding.created_at.desc())
        .offset(skip)
        .limit(limit)
    )

    result = await db.execute(query)
    bindings = result.scalars().all()

    return {
        "items": [
            EmailBindingResponse(
                id=str(b.id),
                email_hash=b.email_hash[:16] + "...",
                cloud_account_hash=b.cloud_account_hash[:16] + "...",
                provider=b.provider,
                created_at=b.created_at.isoformat(),
            ).model_dump()
            for b in bindings
        ],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.delete("/email-bindings/{binding_id}")
async def delete_email_binding(
    binding_id: UUID,
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
) -> dict:
    """Delete an email-cloud account binding (admin override).

    This allows the email to be used with a different cloud account on free tier.
    Use with caution - this bypasses fraud prevention.
    """
    result = await db.execute(
        select(FreeEmailCloudAccountBinding).where(
            FreeEmailCloudAccountBinding.id == binding_id
        )
    )
    binding = result.scalar_one_or_none()

    if not binding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Binding not found"
        )

    await db.delete(binding)
    await db.commit()

    return {"message": "Binding deleted successfully", "binding_id": str(binding_id)}


@router.get("/stats")
async def get_fraud_stats(
    db: AsyncSession = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
) -> FraudStatsResponse:
    """Get overall fraud prevention statistics."""
    # Total registry entries
    registry_count = await db.execute(select(func.count(CloudAccountGlobalRegistry.id)))
    total_registry = registry_count.scalar() or 0

    # Free tier locked entries
    locked_count = await db.execute(
        select(func.count(CloudAccountGlobalRegistry.id)).where(
            CloudAccountGlobalRegistry.is_free_tier_locked == True  # noqa: E712
        )
    )
    locked_entries = locked_count.scalar() or 0

    # Total email bindings
    binding_count = await db.execute(
        select(func.count(FreeEmailCloudAccountBinding.id))
    )
    total_bindings = binding_count.scalar() or 0

    return FraudStatsResponse(
        total_registry_entries=total_registry,
        free_tier_locked_entries=locked_entries,
        total_email_bindings=total_bindings,
        recent_blocks_24h=0,  # Would need audit log integration
    )
