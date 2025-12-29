"""AWS Organisation Discovery Service.

This service handles:
- Discovering AWS Organisation structure
- Listing all member accounts
- Building OU hierarchy
- Finding delegated administrators for security services
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

import structlog
from botocore.exceptions import ClientError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_account import CloudProvider
from app.models.cloud_organization import (
    CloudOrganization,
    CloudOrganizationMember,
    CloudOrganizationStatus,
    CloudOrganizationMemberStatus,
)

logger = structlog.get_logger()


@dataclass
class DiscoveredAccount:
    """Represents a discovered AWS account."""

    account_id: str
    name: str
    email: str
    status: str  # ACTIVE, SUSPENDED, PENDING_CLOSURE
    joined_method: str  # INVITED, CREATED
    joined_timestamp: Optional[datetime] = None
    arn: Optional[str] = None


@dataclass
class OrganizationalUnit:
    """Represents an AWS Organizational Unit."""

    ou_id: str
    name: str
    arn: str
    parent_id: str


@dataclass
class DelegatedAdmin:
    """Represents a delegated administrator for a service."""

    account_id: str
    service_principal: str
    delegation_enabled_date: Optional[datetime] = None


@dataclass
class OrgDiscoveryResult:
    """Result of an organisation discovery operation."""

    org_id: str
    org_arn: str
    master_account_id: str
    master_account_email: str
    accounts: list[DiscoveredAccount] = field(default_factory=list)
    organizational_units: list[OrganizationalUnit] = field(default_factory=list)
    delegated_admins: dict[str, list[DelegatedAdmin]] = field(default_factory=dict)
    root_id: Optional[str] = None


class AWSOrganizationDiscoveryService:
    """Service for discovering AWS Organisation structure."""

    def __init__(self, session: Any) -> None:
        """
        Initialise with a boto3 session.

        Args:
            session: boto3.Session with credentials for the management account
                     or a delegated admin account
        """
        self.session = session
        self.logger = logger.bind(service="aws_org_discovery")
        self._org_client = None

    @property
    def org_client(self) -> None:
        """Lazy-initialise the Organizations client."""
        if self._org_client is None:
            self._org_client = self.session.client("organizations")
        return self._org_client

    async def discover_organisation(self) -> OrgDiscoveryResult:
        """
        Discover the full AWS Organisation structure.

        Returns:
            OrgDiscoveryResult with all accounts, OUs, and delegated admins
        """
        self.logger.info("starting_organisation_discovery")

        # Get organisation details
        org_info = await self._get_organisation_info()
        if not org_info:
            raise ValueError("Failed to get organisation information")

        result = OrgDiscoveryResult(
            org_id=org_info["Id"],
            org_arn=org_info["Arn"],
            master_account_id=org_info["MasterAccountId"],
            master_account_email=org_info["MasterAccountEmail"],
        )

        # Get the root
        roots = await self._list_roots()
        if roots:
            result.root_id = roots[0]["Id"]

        # Discover all accounts
        result.accounts = await self._list_all_accounts()
        self.logger.info(
            "discovered_accounts",
            count=len(result.accounts),
        )

        # Build OU hierarchy
        if result.root_id:
            result.organizational_units = await self._build_ou_hierarchy(result.root_id)
            self.logger.info(
                "discovered_ous",
                count=len(result.organizational_units),
            )

        # Find delegated administrators
        result.delegated_admins = await self._discover_delegated_admins()
        self.logger.info(
            "discovered_delegated_admins",
            services=list(result.delegated_admins.keys()),
        )

        return result

    async def _get_organisation_info(self) -> Optional[dict]:
        """Get organisation details."""
        try:
            response = self.org_client.describe_organization()
            return response.get("Organization")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "AWSOrganizationsNotInUseException":
                self.logger.warning("account_not_in_organisation")
                return None
            elif error_code == "AccessDeniedException":
                self.logger.error(
                    "access_denied_to_organisation",
                    error=str(e),
                )
                raise PermissionError(
                    "Access denied to AWS Organizations. Ensure the role has "
                    "organizations:DescribeOrganization permission."
                )
            raise

    async def _list_roots(self) -> list[dict]:
        """List organisation roots."""
        try:
            paginator = self.org_client.get_paginator("list_roots")
            roots = []
            for page in paginator.paginate():
                roots.extend(page.get("Roots", []))
            return roots
        except ClientError as e:
            self.logger.error("failed_to_list_roots", error=str(e))
            return []

    async def _list_all_accounts(self) -> list[DiscoveredAccount]:
        """List all accounts in the organisation."""
        accounts = []
        try:
            paginator = self.org_client.get_paginator("list_accounts")
            for page in paginator.paginate():
                for account in page.get("Accounts", []):
                    accounts.append(
                        DiscoveredAccount(
                            account_id=account["Id"],
                            name=account["Name"],
                            email=account["Email"],
                            status=account["Status"],
                            joined_method=account["JoinedMethod"],
                            joined_timestamp=account.get("JoinedTimestamp"),
                            arn=account.get("Arn"),
                        )
                    )
        except ClientError as e:
            self.logger.error("failed_to_list_accounts", error=str(e))
            raise

        return accounts

    async def _build_ou_hierarchy(
        self, parent_id: str, hierarchy_path: str = "Root"
    ) -> list[OrganizationalUnit]:
        """
        Recursively build the OU hierarchy.

        Args:
            parent_id: ID of the parent (root or OU)
            hierarchy_path: Current path in the hierarchy

        Returns:
            List of all OUs with their hierarchy paths
        """
        all_ous = []

        try:
            paginator = self.org_client.get_paginator(
                "list_organizational_units_for_parent"
            )
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page.get("OrganizationalUnits", []):
                    ou_obj = OrganizationalUnit(
                        ou_id=ou["Id"],
                        name=ou["Name"],
                        arn=ou["Arn"],
                        parent_id=parent_id,
                    )
                    all_ous.append(ou_obj)

                    # Recursively get child OUs
                    child_path = f"{hierarchy_path}/{ou['Name']}"
                    child_ous = await self._build_ou_hierarchy(ou["Id"], child_path)
                    all_ous.extend(child_ous)

        except ClientError as e:
            self.logger.warning(
                "failed_to_list_ous",
                parent_id=parent_id,
                error=str(e),
            )

        return all_ous

    async def get_account_hierarchy_path(
        self, account_id: str, root_id: str
    ) -> Optional[str]:
        """
        Get the hierarchy path for a specific account.

        Args:
            account_id: AWS account ID
            root_id: Organisation root ID

        Returns:
            Hierarchy path like "Root/Production/WebServices" or None
        """
        try:
            parents = []
            current_id = account_id

            # Walk up the tree
            while True:
                paginator = self.org_client.get_paginator("list_parents")
                parent_found = False

                for page in paginator.paginate(ChildId=current_id):
                    for parent in page.get("Parents", []):
                        parent_id = parent["Id"]
                        parent_type = parent["Type"]

                        if parent_type == "ROOT":
                            parents.append("Root")
                            parent_found = True
                            break
                        elif parent_type == "ORGANIZATIONAL_UNIT":
                            # Get OU name
                            ou_response = self.org_client.describe_organizational_unit(
                                OrganizationalUnitId=parent_id
                            )
                            ou_name = ou_response["OrganizationalUnit"]["Name"]
                            parents.append(ou_name)
                            current_id = parent_id
                            parent_found = True
                            break

                    if parent_found:
                        break

                if not parent_found or parents[-1] == "Root":
                    break

            # Reverse to get root-to-account order
            parents.reverse()
            return "/".join(parents) if parents else None

        except ClientError as e:
            self.logger.warning(
                "failed_to_get_hierarchy_path",
                account_id=account_id,
                error=str(e),
            )
            return None

    async def _discover_delegated_admins(self) -> dict[str, list[DelegatedAdmin]]:
        """
        Discover delegated administrators for security services.

        Returns:
            Dict mapping service principal to list of delegated admin accounts
        """
        # Security services that support delegated admin
        security_services = [
            "guardduty.amazonaws.com",
            "securityhub.amazonaws.com",
            "config.amazonaws.com",
            "detective.amazonaws.com",
            "macie.amazonaws.com",
            "inspector2.amazonaws.com",
            "access-analyzer.amazonaws.com",
        ]

        delegated_admins: dict[str, list[DelegatedAdmin]] = {}

        for service in security_services:
            try:
                admins = await self._list_delegated_admins_for_service(service)
                if admins:
                    delegated_admins[service] = admins
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code not in [
                    "AccessDeniedException",
                    "ServiceException",
                    "UnsupportedAPIEndpointException",
                ]:
                    self.logger.warning(
                        "failed_to_list_delegated_admins",
                        service=service,
                        error=str(e),
                    )

        return delegated_admins

    async def _list_delegated_admins_for_service(
        self, service_principal: str
    ) -> list[DelegatedAdmin]:
        """List delegated administrators for a specific service."""
        admins = []

        try:
            paginator = self.org_client.get_paginator("list_delegated_administrators")
            for page in paginator.paginate(ServicePrincipal=service_principal):
                for admin in page.get("DelegatedAdministrators", []):
                    admins.append(
                        DelegatedAdmin(
                            account_id=admin["Id"],
                            service_principal=service_principal,
                            delegation_enabled_date=admin.get("DelegationEnabledDate"),
                        )
                    )
        except ClientError:
            # Some services may not support this API
            pass

        return admins


class CloudOrganizationService:
    """Service for managing CloudOrganization entities in the database."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(service="cloud_organization")

    async def create_or_update_from_discovery(
        self,
        organization_id: UUID,
        discovery_result: OrgDiscoveryResult,
        credentials_arn: Optional[str] = None,
    ) -> CloudOrganization:
        """
        Create or update a CloudOrganization from discovery results.

        Args:
            organization_id: Our tenant organisation ID
            discovery_result: Results from AWS org discovery
            credentials_arn: ARN of the role used for discovery

        Returns:
            Created or updated CloudOrganization
        """
        # Check if org already exists
        result = await self.db.execute(
            select(CloudOrganization).where(
                CloudOrganization.organization_id == organization_id,
                CloudOrganization.cloud_org_id == discovery_result.org_id,
            )
        )
        cloud_org = result.scalar_one_or_none()

        if cloud_org:
            # Update existing
            cloud_org.name = f"AWS Organization ({discovery_result.org_id})"
            cloud_org.master_account_id = discovery_result.master_account_id
            cloud_org.root_email = discovery_result.master_account_email
            cloud_org.status = CloudOrganizationStatus.CONNECTED
            cloud_org.credentials_arn = credentials_arn
            cloud_org.delegated_admins = {
                svc: [
                    {
                        "account_id": admin.account_id,
                        "enabled_date": (
                            admin.delegation_enabled_date.isoformat()
                            if admin.delegation_enabled_date
                            else None
                        ),
                    }
                    for admin in admins
                ]
                for svc, admins in discovery_result.delegated_admins.items()
            }
            cloud_org.total_accounts_discovered = len(discovery_result.accounts)
            cloud_org.last_sync_at = datetime.utcnow()
        else:
            # Create new
            cloud_org = CloudOrganization(
                organization_id=organization_id,
                provider=CloudProvider.AWS,
                cloud_org_id=discovery_result.org_id,
                name=f"AWS Organization ({discovery_result.org_id})",
                master_account_id=discovery_result.master_account_id,
                root_email=discovery_result.master_account_email,
                status=CloudOrganizationStatus.CONNECTED,
                credentials_arn=credentials_arn,
                delegated_admins={
                    svc: [
                        {
                            "account_id": admin.account_id,
                            "enabled_date": (
                                admin.delegation_enabled_date.isoformat()
                                if admin.delegation_enabled_date
                                else None
                            ),
                        }
                        for admin in admins
                    ]
                    for svc, admins in discovery_result.delegated_admins.items()
                },
                org_metadata={
                    "arn": discovery_result.org_arn,
                    "root_id": discovery_result.root_id,
                },
                total_accounts_discovered=len(discovery_result.accounts),
            )
            self.db.add(cloud_org)

        await self.db.flush()

        # Sync member accounts
        await self._sync_members(cloud_org, discovery_result)

        await self.db.commit()
        await self.db.refresh(cloud_org)

        return cloud_org

    async def _sync_members(
        self,
        cloud_org: CloudOrganization,
        discovery_result: OrgDiscoveryResult,
    ) -> None:
        """Sync discovered accounts as CloudOrganizationMembers."""
        # Get existing members
        result = await self.db.execute(
            select(CloudOrganizationMember).where(
                CloudOrganizationMember.cloud_organization_id == cloud_org.id
            )
        )
        existing_members = {m.member_account_id: m for m in result.scalars().all()}

        for account in discovery_result.accounts:
            if account.account_id in existing_members:
                # Update existing member
                member = existing_members[account.account_id]
                member.member_name = account.name
                member.member_email = account.email
                member.join_method = account.joined_method
                member.joined_at = account.joined_timestamp

                # Map AWS status to our status
                if account.status == "ACTIVE":
                    if member.status == CloudOrganizationMemberStatus.CONNECTED:
                        pass  # Keep connected status
                    elif member.status == CloudOrganizationMemberStatus.SKIPPED:
                        pass  # Keep skipped status
                    else:
                        member.status = CloudOrganizationMemberStatus.DISCOVERED
                elif account.status == "SUSPENDED":
                    member.status = CloudOrganizationMemberStatus.SUSPENDED
            else:
                # Create new member
                member = CloudOrganizationMember(
                    cloud_organization_id=cloud_org.id,
                    member_account_id=account.account_id,
                    member_name=account.name,
                    member_email=account.email,
                    join_method=account.joined_method,
                    joined_at=account.joined_timestamp,
                    status=(
                        CloudOrganizationMemberStatus.DISCOVERED
                        if account.status == "ACTIVE"
                        else CloudOrganizationMemberStatus.SUSPENDED
                    ),
                    member_metadata={
                        "arn": account.arn,
                        "aws_status": account.status,
                    },
                )
                self.db.add(member)

        # Update counts
        connected_count = sum(
            1
            for m in existing_members.values()
            if m.status == CloudOrganizationMemberStatus.CONNECTED
        )
        cloud_org.total_accounts_connected = connected_count
