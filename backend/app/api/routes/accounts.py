"""Cloud account endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, delete, func
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
    AccountHierarchyResponse,
)
from app.core.service_registry import get_all_regions, get_default_regions
from app.services.region_discovery_service import region_discovery_service
from app.services.aws_credential_service import aws_credential_service
from app.services.gcp_wif_service import gcp_wif_service, GCPWIFError
from app.services.azure_wif_service import AzureWIFConfiguration
from app.services.cloud_account_fraud_service import CloudAccountFraudService
from app.services.aws_org_discovery import AWSOrganizationDiscoveryService
from app.models.cloud_credential import CredentialStatus, CredentialType
from app.models.billing import AccountTier
from app.core.cache import get_cached_hierarchy, cache_hierarchy
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
    # Security: Check explicitly for None vs empty list
    # - None = unrestricted access (all accounts)
    # - [] = no access (return empty result immediately)
    # - [...] = restricted access (filter to specified accounts)
    if auth.membership and auth.membership.allowed_account_ids is not None:
        if not auth.membership.allowed_account_ids:
            # Empty list means no access to any accounts
            return []
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
            # Count current accounts using SQL COUNT (not in-memory)
            count_result = await db.execute(
                select(func.count(CloudAccount.id)).where(
                    CloudAccount.organization_id == auth.organization_id
                )
            )
            current_count = count_result.scalar() or 0

            if current_count >= max_accounts:
                # Get tier name for better error message
                tier_name = subscription.tier.value.replace("_", " ").title()
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=f"Cloud account limit reached ({current_count}/{max_accounts}) "
                    f"on your {tier_name} plan. "
                    "Upgrade to add more cloud accounts.",
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
        # Serialize azure_workload_identity_config to JSON-compatible dict for JSONB storage
        elif field == "azure_workload_identity_config" and value is not None:
            value = account_in.azure_workload_identity_config.model_dump(mode="json")
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

    # Azure stores WIF config on the CloudAccount itself, not in CloudCredential
    # So we only require a CloudCredential for AWS/GCP
    if not credential and account.provider != CloudProvider.AZURE:
        raise HTTPException(
            status_code=400,
            detail="No credentials configured for this account. Please add credentials first.",
        )

    if credential and credential.status != CredentialStatus.VALID:
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
        # Validate credential type
        if credential.credential_type != CredentialType.GCP_WORKLOAD_IDENTITY:
            raise HTTPException(
                status_code=400,
                detail="GCP region discovery requires Workload Identity Federation credentials.",
            )

        # Get WIF configuration from credential
        wif_config = credential.get_wif_configuration()
        if not wif_config:
            raise HTTPException(
                status_code=400,
                detail="Incomplete GCP credential configuration. Missing project_id or service_account_email.",
            )

        try:
            # Get GCP credentials via WIF
            cred_result = await gcp_wif_service.get_credentials(wif_config)

            # Discover active regions
            discovered_regions = (
                await region_discovery_service.discover_gcp_active_regions(
                    credentials=cred_result.credentials,
                    project_id=wif_config.project_id,
                )
            )
            discovery_method = "GCP (Cloud Asset Inventory + Compute Engine)"

        except GCPWIFError as e:
            logger.error(
                "gcp_wif_credential_error",
                account_id=str(account_id),
                error=str(e),
            )
            raise HTTPException(
                status_code=500,
                detail=f"Failed to obtain GCP credentials: {str(e)}",
            )
        except ImportError as e:
            logger.error(
                "gcp_libraries_missing",
                account_id=str(account_id),
                error=str(e),
            )
            raise HTTPException(
                status_code=500,
                detail="GCP discovery libraries not installed. Please contact support.",
            )
        except Exception as e:
            logger.error(
                "gcp_region_discovery_failed",
                account_id=str(account_id),
                error=str(e),
            )
            raise HTTPException(
                status_code=500,
                detail=f"Failed to discover GCP regions: {str(e)}",
            )

    elif account.provider == CloudProvider.AZURE:
        # Azure stores WIF config on the CloudAccount itself, not in CloudCredential
        # Check Azure is enabled (equivalent to credential validation)
        if not account.azure_enabled:
            raise HTTPException(
                status_code=400,
                detail="Azure credentials are not validated. Please validate your Azure connection first.",
            )

        # Validate Azure WIF configuration exists on the account
        config_data = account.azure_workload_identity_config
        if not config_data:
            raise HTTPException(
                status_code=400,
                detail="Incomplete Azure credential configuration. Missing tenant_id, client_id, or subscription_id.",
            )

        try:
            azure_config = AzureWIFConfiguration.from_dict(config_data)
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid Azure WIF configuration: {str(e)}",
            )

        # Azure scans are subscription-level, not regional
        # Return "global" to match how scans actually work
        discovered_regions = ["global"]
        discovery_method = "Azure (Subscription-level)"

        logger.info(
            "azure_region_discovery",
            account_id=str(account_id),
            subscription_id=azure_config.subscription_id,
            regions=discovered_regions,
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


@router.get(
    "/{account_id}/hierarchy",
    response_model=AccountHierarchyResponse,
    dependencies=[Depends(require_scope("read:accounts"))],
)
async def get_account_hierarchy(
    account_id: UUID,
    auth: AuthContext = Depends(
        require_role(UserRole.OWNER, UserRole.ADMIN, UserRole.MEMBER)
    ),
    db: AsyncSession = Depends(get_db),
) -> AccountHierarchyResponse:
    """
    Get the organisational hierarchy path for an AWS account.

    Returns the path from root to account (e.g., "Root/Production/WebServices").
    Results are cached for 24 hours. Only applicable to AWS accounts in an
    AWS Organisation.

    GCP and Azure accounts will return a null hierarchy path.

    Requires member, admin, or owner role. API keys require 'read:accounts' scope.
    """
    # Get the account and validate access
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

    # Check access for members with restricted accounts
    if not auth.can_access_account(account_id):
        raise HTTPException(status_code=403, detail="Access denied to this account")

    # Non-AWS accounts don't have AWS Organisation hierarchy
    if account.provider != CloudProvider.AWS:
        return AccountHierarchyResponse(
            hierarchy_path=None,
            is_in_organization=False,
            cached=False,
            cached_at=None,
        )

    # Check Redis cache first - skip stale null entries from before the
    # "Permissions Required" fix so they get re-evaluated
    cached_data = await get_cached_hierarchy(account.account_id)
    if cached_data and cached_data.get("hierarchy_path") is not None:
        return AccountHierarchyResponse(
            hierarchy_path=cached_data.get("hierarchy_path"),
            is_in_organization=cached_data.get("is_in_organization", False),
            cached=True,
            cached_at=(
                datetime.fromisoformat(cached_data["cached_at"])
                if cached_data.get("cached_at")
                else None
            ),
        )

    # Get credentials for this account
    cred_result = await db.execute(
        select(CloudCredential).where(CloudCredential.cloud_account_id == account_id)
    )
    credential = cred_result.scalar_one_or_none()

    if not credential:
        # No credentials - can't determine hierarchy
        return AccountHierarchyResponse(
            hierarchy_path=None,
            is_in_organization=False,
            cached=False,
            cached_at=None,
        )

    if credential.status != CredentialStatus.VALID:
        # Invalid credentials - can't determine hierarchy
        return AccountHierarchyResponse(
            hierarchy_path=None,
            is_in_organization=False,
            cached=False,
            cached_at=None,
        )

    if credential.credential_type != CredentialType.AWS_IAM_ROLE:
        # Not an IAM role credential - can't use for hierarchy discovery
        return AccountHierarchyResponse(
            hierarchy_path=None,
            is_in_organization=False,
            cached=False,
            cached_at=None,
        )

    try:
        # Assume the role to get temporary credentials
        creds = await aws_credential_service.assume_role_async(
            role_arn=credential.aws_role_arn,
            external_id=credential.aws_external_id,
            session_name=f"A13E-Hierarchy-{str(account.id)[:8]}",
        )

        import boto3

        session = boto3.Session(
            aws_access_key_id=creds["access_key_id"],
            aws_secret_access_key=creds["secret_access_key"],
            aws_session_token=creds["session_token"],
        )

        # Use the organisation discovery service
        org_service = AWSOrganizationDiscoveryService(session)

        # First, check if the account is in an organisation and get the root
        try:
            org_info = await org_service._get_organisation_info()
            if not org_info:
                # Account is not in an organisation
                await cache_hierarchy(
                    account.account_id,
                    hierarchy_path="Standalone",
                    is_in_organization=False,
                )
                return AccountHierarchyResponse(
                    hierarchy_path="Standalone",
                    is_in_organization=False,
                    cached=False,
                    cached_at=None,
                )

            # Get the root ID
            roots = await org_service._list_roots()
            if not roots:
                # No roots found (unexpected)
                await cache_hierarchy(
                    account.account_id,
                    hierarchy_path=None,
                    is_in_organization=True,
                )
                return AccountHierarchyResponse(
                    hierarchy_path=None,
                    is_in_organization=True,
                    cached=False,
                    cached_at=None,
                )

            root_id = roots[0]["Id"]

            # Get the hierarchy path
            hierarchy_path = await org_service.get_account_hierarchy_path(
                account_id=account.account_id,
                root_id=root_id,
            )

            # Cache the result
            await cache_hierarchy(
                account.account_id,
                hierarchy_path=hierarchy_path,
                is_in_organization=True,
            )

            return AccountHierarchyResponse(
                hierarchy_path=hierarchy_path,
                is_in_organization=True,
                cached=False,
                cached_at=None,
            )

        except PermissionError:
            # Access denied to AWS Organizations - role lacks organisations:* permissions
            await cache_hierarchy(
                account.account_id,
                hierarchy_path="Permissions Required",
                is_in_organization=False,
            )
            return AccountHierarchyResponse(
                hierarchy_path="Permissions Required",
                is_in_organization=False,
                cached=False,
                cached_at=None,
            )

    except Exception as e:
        logger.error(
            "hierarchy_discovery_failed",
            account_id=str(account_id),
            error=str(e),
        )
        # Return empty result on error rather than failing
        return AccountHierarchyResponse(
            hierarchy_path=None,
            is_in_organization=False,
            cached=False,
            cached_at=None,
        )
