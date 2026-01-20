"""Reusable authorization dependency for account verification."""

from uuid import UUID

from fastapi import Depends, HTTPException, Path, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context
from app.models.cloud_account import CloudAccount


async def verified_account(
    cloud_account_id: UUID = Path(..., description="Cloud account ID"),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> CloudAccount:
    """Get cloud account with ownership verification and ACL check.

    Combines:
    1. Account exists in database
    2. Account belongs to user's organisation
    3. User has access via allowed_account_ids ACL

    Raises:
        HTTPException 404: Account not found or not in organisation
        HTTPException 403: User doesn't have access to this account
    """
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()

    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud account not found",
        )

    if not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this cloud account",
        )

    return account
