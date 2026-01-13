"""Cloud account endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, delete
import structlog

from app.core.database import get_db
from app.core.security import (
    AuthContext,
    get_auth_context,
    require_role,
    require_scope,
)
from app.models.billing import Subscription
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
from app.models.cloud_account import CloudProvider
from app.schemas.cloud_account import (
    CloudAccountCreate,
    CloudAccountUpdate,
    CloudAccountResponse,
    AvailableRegionsResponse,
    DiscoverRegionsResponse,
)
from app.core.service_registry import get_all_regions, get_default_regions
from app.services.region_discovery_service import region_discovery_service
from app.services.aws_credential_service import aws_credential_service
from app.services.cloud_account_fraud_service import CloudAccountFraudService
from app.models.cloud_credential import CredentialStatus, CredentialType
from app.models.billing import AccountTier
from datetime import datetime, timezone

logger = structlog.get_logger()

router = APIRouter()


@router.get(
    "",
    response_model=list[CloudAccountResponse],
    dependencies=[Depends(require_scope("read:accounts"))],
)
async def list_accounts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    is_active: Optional[bool] = None,
    auth: AuthContext = Depends(get_auth_context),  # Security: Require authentication
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    List cloud accounts for the authenticated user's organisation.

    Requires authentication. API keys require 'read:accounts' scope.
    """
    # Security: Always require organisation context to prevent cross-org data leaks
    if not auth.organization:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organisation context required",
        )

    query = select(CloudAccount).where(
        CloudAccount.organization_id == auth.organization_id
    )

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


@router.post(
    "",
    response_model=CloudAccountResponse,
    status_code=201,
    dependencies=[Depends(require_scope("write:accounts"))],
)
async def create_account(
    account_in: CloudAccountCreate,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Create a new cloud account.

    Requires admin or owner role. API keys require 'write:accounts' scope.
    """
    # Check for duplicate account_id within the same organization FIRST
    # This takes precedence over quota limits (can't create what already exists)
    existing = await db.execute(
        select(CloudAccount).where(
            CloudAccount.account_id == account_in.account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail=f"Account with ID {account_in.account_id} already exists in your organisation",
        )

    # H4: Check subscription account limits before creating
    subscription_result = await db.execute(
        select(Subscription).where(Subscription.organization_id == auth.organization_id)
    )
    subscription = subscription_result.scalar_one_or_none()

    if subscription:
        max_accounts = subscription.total_accounts_allowed
        # -1 means unlimited (Enterprise tier)
        if max_accounts != -1:
            # Count current accounts
            count_result = await db.execute(
                select(CloudAccount).where(
                    CloudAccount.organization_id == auth.organization_id
                )
            )
            current_count = len(count_result.scalars().all())

            if current_count >= max_accounts:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Cloud account limit reached ({max_accounts}). "
                    "Please upgrade your subscription to add more accounts.",
                )

    # Fraud prevention: Check cloud account uniqueness and email binding
    fraud_service = CloudAccountFraudService(db)
    allowed, block_reason = await fraud_service.check_cloud_account_allowed(
        provider=account_in.provider,
        account_id=account_in.account_id,
        organization_id=auth.organization_id,
        user_email=auth.user.email,
    )
    if not allowed:
        logger.warning(
            "cloud_account_creation_blocked_fraud",
            account_id=account_in.account_id,
            provider=account_in.provider.value,
            organization_id=str(auth.organization_id),
            reason=block_reason,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=block_reason,
        )

    # Compute the global account hash for fraud prevention tracking
    global_account_hash = CloudAccount.compute_account_hash(
        account_in.provider, account_in.account_id
    )

    # Use mode="json" to serialize region_config properly for JSONB storage
    account_data = account_in.model_dump(mode="json")
    account = CloudAccount(
        **account_data,
        organization_id=auth.organization_id,
        global_account_hash=global_account_hash,
    )
    db.add(account)
    await db.flush()

    # Register in global fraud prevention registry
    is_free_tier = subscription.tier == AccountTier.FREE
    await fraud_service.register_cloud_account(
        provider=account_in.provider,
        account_id=account_in.account_id,
        organization_id=auth.organization_id,
        user_email=auth.user.email,
        is_free_tier=is_free_tier,
    )

    await db.refresh(account)
    return account


@router.get(
    "/{account_id}",
    response_model=CloudAccountResponse,
    dependencies=[Depends(require_scope("read:accounts"))],
)
async def get_account(
    account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get a specific cloud account.

    API keys require 'read:accounts' scope.
    """
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


@router.patch(
    "/{account_id}",
    response_model=CloudAccountResponse,
    dependencies=[Depends(require_scope("write:accounts"))],
)
async def update_account(
    account_id: UUID,
    account_in: CloudAccountUpdate,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Update a cloud account.

    Requires admin or owner role. API keys require 'write:accounts' scope.
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
        # Serialize region_config to JSON-compatible dict for JSONB storage
        if field == "region_config" and value is not None:
            value = account_in.region_config.model_dump(mode="json")
        setattr(account, field, value)

    await db.flush()
    await db.refresh(account)
    return account


@router.delete(
    "/{account_id}",
    status_code=204,
    dependencies=[Depends(require_scope("write:accounts"))],
)
async def delete_account(
    account_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Delete a cloud account and all associated data.

    Requires admin or owner role. API keys require 'write:accounts' scope.

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

    # H3: Validate account access if user has restricted allowed_account_ids
    if auth.membership and auth.membership.allowed_account_ids is not None:
        if not auth.can_access_account(account_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this cloud account",
            )

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
        # Release cloud account from fraud prevention registry
        fraud_service = CloudAccountFraudService(db)
        await fraud_service.release_cloud_account(
            provider=account.provider,
            account_id=account.account_id,
            organization_id=auth.organization_id,
        )

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


@router.get("/regions/{provider}", response_model=AvailableRegionsResponse)
async def list_available_regions(
    provider: CloudProvider,
    auth: AuthContext = Depends(get_auth_context),
) -> AvailableRegionsResponse:
    """
    Get list of available regions for a cloud provider.

    Returns all available regions and commonly enabled defaults.
    """
    provider_str = provider.value
    return AvailableRegionsResponse(
        provider=provider,
        regions=get_all_regions(provider_str),
        default_regions=get_default_regions(provider_str),
    )


@router.post("/{account_id}/discover-regions", response_model=DiscoverRegionsResponse)
async def discover_regions(
    account_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> DiscoverRegionsResponse:
    """
    Discover active regions for a cloud account.

    Uses various signals (EC2, GuardDuty, CloudWatch) to determine
    which regions have active resources or security services enabled.

    Requires admin or owner role.
    """
    # Get the account
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

    # Get credentials for this account
    cred_result = await db.execute(
        select(CloudCredential).where(CloudCredential.cloud_account_id == account_id)
    )
    credential = cred_result.scalar_one_or_none()

    if not credential:
        raise HTTPException(
            status_code=400,
            detail="No credentials configured for this account. Please add credentials first.",
        )

    if credential.status != CredentialStatus.VALID:
        raise HTTPException(
            status_code=400,
            detail=f"Credentials are not valid (status: {credential.status.value}). Please re-validate.",
        )

    discovery_method = ""
    discovered_regions = []

    if account.provider == CloudProvider.AWS:
        if credential.credential_type != CredentialType.AWS_IAM_ROLE:
            raise HTTPException(
                status_code=400,
                detail="AWS region discovery requires IAM Role credentials.",
            )

        try:
            # Assume the role to get temporary credentials (async to avoid blocking event loop)
            creds = await aws_credential_service.assume_role_async(
                role_arn=credential.aws_role_arn,
                external_id=credential.aws_external_id,
                session_name=f"A13E-Discovery-{str(account.id)[:8]}",
            )

            import boto3

            session = boto3.Session(
                aws_access_key_id=creds["access_key_id"],
                aws_secret_access_key=creds["secret_access_key"],
                aws_session_token=creds["session_token"],
            )

            discovered_regions = (
                await region_discovery_service.discover_aws_active_regions(
                    session,
                    check_ec2=True,
                    check_guardduty=True,
                    check_cloudwatch=True,
                )
            )
            discovery_method = "AWS (EC2 + GuardDuty + CloudWatch)"

        except Exception as e:
            logger.error(
                "region_discovery_failed",
                account_id=str(account_id),
                error=str(e),
            )
            raise HTTPException(
                status_code=500,
                detail=f"Failed to discover regions: {str(e)}",
            )

    elif account.provider == CloudProvider.GCP:
        # GCP discovery not yet implemented
        raise HTTPException(
            status_code=501,
            detail="GCP region discovery not yet implemented. Please configure regions manually.",
        )

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider: {account.provider.value}",
        )

    # Update the account with discovered regions
    now = datetime.now(timezone.utc)
    account.set_auto_discovered_regions(discovered_regions)
    await db.commit()

    logger.info(
        "regions_discovered",
        account_id=str(account_id),
        regions=discovered_regions,
        method=discovery_method,
    )

    return DiscoverRegionsResponse(
        discovered_regions=discovered_regions,
        discovery_method=discovery_method,
        discovered_at=now,
    )
