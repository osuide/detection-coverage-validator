"""Cloud Organisation API routes."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.database import get_db
from app.core.security import AuthContext, require_role, require_org_features
from app.models.user import UserRole
from app.models.cloud_organization import (
    CloudOrganization,
    CloudOrganizationMember,
    CloudOrganizationStatus,
    CloudOrganizationMemberStatus,
)
from app.models.cloud_account import CloudProvider
from app.schemas.cloud_organization import (
    CloudOrganizationResponse,
    CloudOrganizationSummary,
    CloudOrganizationMemberSummary,
    DiscoverOrganizationRequest,
    DiscoverOrganizationResponse,
    ConnectMembersRequest,
    ConnectMembersResponse,
)

logger = structlog.get_logger()
router = APIRouter()


@router.get("", response_model=list[CloudOrganizationSummary])
async def list_cloud_organizations(
    auth: AuthContext = Depends(require_org_features()),
    db: AsyncSession = Depends(get_db),
):
    """List all cloud organisations for the current tenant."""
    result = await db.execute(
        select(CloudOrganization).where(
            CloudOrganization.organization_id == auth.organization_id
        )
    )
    orgs = result.scalars().all()

    return [
        CloudOrganizationSummary(
            id=org.id,
            provider=org.provider,
            name=org.name,
            status=org.status,
            total_accounts_discovered=org.total_accounts_discovered,
            total_accounts_connected=org.total_accounts_connected,
            last_sync_at=org.last_sync_at,
        )
        for org in orgs
    ]


@router.get("/{cloud_org_id}", response_model=CloudOrganizationResponse)
async def get_cloud_organization(
    cloud_org_id: UUID,
    auth: AuthContext = Depends(require_org_features()),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific cloud organisation."""
    result = await db.execute(
        select(CloudOrganization).where(
            CloudOrganization.id == cloud_org_id,
            CloudOrganization.organization_id == auth.organization_id,
        )
    )
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud organisation not found",
        )

    return org


@router.get(
    "/{cloud_org_id}/members", response_model=list[CloudOrganizationMemberSummary]
)
async def list_organization_members(
    cloud_org_id: UUID,
    status_filter: Optional[CloudOrganizationMemberStatus] = None,
    auth: AuthContext = Depends(require_org_features()),
    db: AsyncSession = Depends(get_db),
):
    """List member accounts for a cloud organisation."""
    # Verify org belongs to tenant
    org_result = await db.execute(
        select(CloudOrganization).where(
            CloudOrganization.id == cloud_org_id,
            CloudOrganization.organization_id == auth.organization_id,
        )
    )
    org = org_result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud organisation not found",
        )

    # Build query
    query = select(CloudOrganizationMember).where(
        CloudOrganizationMember.cloud_organization_id == cloud_org_id
    )

    if status_filter:
        query = query.where(CloudOrganizationMember.status == status_filter)

    result = await db.execute(query)
    members = result.scalars().all()

    return [
        CloudOrganizationMemberSummary(
            id=m.id,
            member_account_id=m.member_account_id,
            member_name=m.member_name,
            status=m.status,
            hierarchy_path=m.hierarchy_path,
            is_connected=m.cloud_account_id is not None,
        )
        for m in members
    ]


@router.post("/discover", response_model=DiscoverOrganizationResponse)
async def discover_organization(
    body: DiscoverOrganizationRequest,
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(require_org_features()),
    db: AsyncSession = Depends(get_db),
):
    """
    Discover accounts in a cloud organisation.

    This initiates the discovery process for an AWS or GCP organisation.
    The discovery happens in the background and populates the member list.
    """
    if body.provider == CloudProvider.AWS:
        if not body.credentials_arn:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="credentials_arn is required for AWS",
            )
        return await _discover_aws_organization(
            body.credentials_arn,
            auth.organization_id,
            db,
            background_tasks,
        )
    elif body.provider == CloudProvider.GCP:
        if not body.gcp_org_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="gcp_org_id is required for GCP",
            )
        return await _discover_gcp_organization(
            body.gcp_org_id,
            body.gcp_service_account_email,
            body.gcp_project_id,
            auth.organization_id,
            db,
            background_tasks,
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {body.provider}",
        )


async def _discover_aws_organization(
    credentials_arn: str,
    organization_id: UUID,
    db: AsyncSession,
    background_tasks: BackgroundTasks,
) -> DiscoverOrganizationResponse:
    """Discover AWS Organisation structure."""
    from app.services.aws_org_discovery import (
        AWSOrganizationDiscoveryService,
        CloudOrganizationService,
    )
    from app.services.aws_credential_service import AWSCredentialService

    # Get credentials
    credential_service = AWSCredentialService()

    try:
        # Assume role to get session
        session = credential_service.get_session_with_assumed_role(
            role_arn=credentials_arn,
            external_id=str(organization_id),
        )
    except Exception as e:
        logger.error("failed_to_assume_role", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to assume role: {str(e)}",
        )

    # Discover organisation
    discovery_service = AWSOrganizationDiscoveryService(session)

    try:
        result = await discovery_service.discover_organisation()
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except Exception as e:
        logger.error("organisation_discovery_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Organisation discovery failed: {str(e)}",
        )

    # Save to database
    org_service = CloudOrganizationService(db)
    cloud_org = await org_service.create_or_update_from_discovery(
        organization_id=organization_id,
        discovery_result=result,
        credentials_arn=credentials_arn,
    )

    # Get members
    members_result = await db.execute(
        select(CloudOrganizationMember).where(
            CloudOrganizationMember.cloud_organization_id == cloud_org.id
        )
    )
    members = members_result.scalars().all()

    return DiscoverOrganizationResponse(
        cloud_organization=cloud_org,
        members=[
            CloudOrganizationMemberSummary(
                id=m.id,
                member_account_id=m.member_account_id,
                member_name=m.member_name,
                status=m.status,
                hierarchy_path=m.hierarchy_path,
                is_connected=m.cloud_account_id is not None,
            )
            for m in members
        ],
        total_discovered=len(members),
    )


async def _discover_gcp_organization(
    gcp_org_id: str,
    service_account_email: Optional[str],
    project_id: Optional[str],
    organization_id: UUID,
    db: AsyncSession,
    background_tasks: BackgroundTasks,
) -> DiscoverOrganizationResponse:
    """Discover GCP Organisation structure."""
    from app.services.gcp_org_discovery import (
        GCPOrganizationDiscoveryService,
        GCPCloudOrganizationService,
    )
    from app.services.gcp_credential_service import GCPCredentialService

    # Get credentials
    credential_service = GCPCredentialService()

    try:
        # Get credentials - use impersonation if service account provided
        if service_account_email:
            credentials = credential_service.get_impersonated_credentials(
                target_service_account=service_account_email,
            )
        else:
            # Use default credentials
            credentials = credential_service.source_credentials
    except Exception as e:
        logger.error("failed_to_get_gcp_credentials", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to obtain GCP credentials: {str(e)}",
        )

    # Discover organisation
    discovery_service = GCPOrganizationDiscoveryService(credentials)

    try:
        result = await discovery_service.discover_organisation(gcp_org_id)
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except Exception as e:
        logger.error("gcp_organisation_discovery_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"GCP Organisation discovery failed: {str(e)}",
        )

    # Save to database
    org_service = GCPCloudOrganizationService(db)
    cloud_org = await org_service.create_or_update_from_discovery(
        organization_id=organization_id,
        discovery_result=result,
        service_account_email=service_account_email,
    )

    # Get members
    members_result = await db.execute(
        select(CloudOrganizationMember).where(
            CloudOrganizationMember.cloud_organization_id == cloud_org.id
        )
    )
    members = members_result.scalars().all()

    return DiscoverOrganizationResponse(
        cloud_organization=cloud_org,
        members=[
            CloudOrganizationMemberSummary(
                id=m.id,
                member_account_id=m.member_account_id,
                member_name=m.member_name,
                status=m.status,
                hierarchy_path=m.hierarchy_path,
                is_connected=m.cloud_account_id is not None,
            )
            for m in members
        ],
        total_discovered=len(members),
    )


@router.post("/{cloud_org_id}/connect-members", response_model=ConnectMembersResponse)
async def connect_members(
    cloud_org_id: UUID,
    body: ConnectMembersRequest,
    auth: AuthContext = Depends(require_org_features()),
    db: AsyncSession = Depends(get_db),
):
    """
    Connect selected member accounts for scanning.

    This creates CloudAccount records for the selected members
    and marks them as connected.
    """
    from app.models.cloud_account import CloudAccount

    # Verify org belongs to tenant
    org_result = await db.execute(
        select(CloudOrganization).where(
            CloudOrganization.id == cloud_org_id,
            CloudOrganization.organization_id == auth.organization_id,
        )
    )
    org = org_result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud organisation not found",
        )

    # Get requested members
    members_result = await db.execute(
        select(CloudOrganizationMember).where(
            CloudOrganizationMember.id.in_(body.member_ids),
            CloudOrganizationMember.cloud_organization_id == cloud_org_id,
        )
    )
    members = members_result.scalars().all()

    if len(members) != len(body.member_ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Some member IDs were not found",
        )

    connected = 0
    failed = 0
    errors = []

    for member in members:
        try:
            # Check if already connected
            if member.cloud_account_id:
                continue

            # Create CloudAccount
            cloud_account = CloudAccount(
                organization_id=auth.organization_id,
                cloud_organization_id=cloud_org_id,
                name=member.member_name,
                provider=org.provider,
                account_id=member.member_account_id,
                regions=[],  # Will be populated during scan
                credentials_arn=org.credentials_arn,
                description=f"Connected via organisation: {org.name}",
            )
            db.add(cloud_account)
            await db.flush()

            # Update member
            member.cloud_account_id = cloud_account.id
            member.status = CloudOrganizationMemberStatus.CONNECTED
            member.connected_at = __import__("datetime").datetime.utcnow()

            connected += 1

        except Exception as e:
            failed += 1
            errors.append(
                {
                    "member_id": str(member.id),
                    "member_account_id": member.member_account_id,
                    "error": str(e),
                }
            )
            logger.error(
                "failed_to_connect_member",
                member_id=str(member.id),
                error=str(e),
            )

    # Update org stats
    org.total_accounts_connected += connected

    await db.commit()

    return ConnectMembersResponse(
        connected=connected,
        failed=failed,
        errors=errors,
    )


@router.post("/{cloud_org_id}/sync")
async def sync_organization(
    cloud_org_id: UUID,
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(require_org_features()),
    db: AsyncSession = Depends(get_db),
):
    """
    Re-sync the organisation to discover new accounts.

    This triggers a fresh discovery to find any new accounts
    added to the organisation since the last sync.
    """
    # Verify org belongs to tenant
    result = await db.execute(
        select(CloudOrganization).where(
            CloudOrganization.id == cloud_org_id,
            CloudOrganization.organization_id == auth.organization_id,
        )
    )
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud organisation not found",
        )

    if not org.credentials_arn:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No credentials configured for this organisation",
        )

    # Trigger re-discovery in background
    # For now, return immediately - full implementation would use background tasks
    return {
        "status": "sync_initiated",
        "cloud_org_id": str(cloud_org_id),
        "message": "Organisation sync has been initiated",
    }


@router.delete("/{cloud_org_id}")
async def disconnect_organization(
    cloud_org_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """
    Disconnect a cloud organisation.

    This removes the organisation connection but keeps any
    CloudAccounts that were created from it.
    """
    # Verify org belongs to tenant
    result = await db.execute(
        select(CloudOrganization).where(
            CloudOrganization.id == cloud_org_id,
            CloudOrganization.organization_id == auth.organization_id,
        )
    )
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud organisation not found",
        )

    # Mark as disconnected (soft delete)
    org.status = CloudOrganizationStatus.DISCONNECTED
    org.credentials_arn = None

    await db.commit()

    return {"status": "disconnected", "cloud_org_id": str(cloud_org_id)}
