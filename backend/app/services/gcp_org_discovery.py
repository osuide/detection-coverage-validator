"""GCP Organisation Discovery Service.

Discovers GCP organisation structure including folders, projects,
and organisation-level configurations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.cloud_organization import (
    CloudOrganization,
    CloudOrganizationMember,
    CloudOrganizationStatus,
    CloudOrganizationMemberStatus,
)
from app.models.cloud_account import CloudProvider

logger = structlog.get_logger()


@dataclass
class GCPProject:
    """Represents a discovered GCP project."""

    project_id: str
    project_number: str
    name: str
    parent_type: str  # 'organization' or 'folder'
    parent_id: str
    state: str  # 'ACTIVE', 'DELETE_REQUESTED', etc.
    create_time: Optional[datetime] = None
    labels: dict = field(default_factory=dict)


@dataclass
class GCPFolder:
    """Represents a discovered GCP folder."""

    folder_id: str
    name: str
    display_name: str
    parent_type: str  # 'organization' or 'folder'
    parent_id: str
    state: str
    create_time: Optional[datetime] = None


@dataclass
class GCPOrgDiscoveryResult:
    """Result of GCP organisation discovery."""

    org_id: str
    org_display_name: str
    org_directory_customer_id: Optional[str] = None
    projects: list[GCPProject] = field(default_factory=list)
    folders: list[GCPFolder] = field(default_factory=list)
    org_policies: dict[str, Any] = field(default_factory=dict)


class GCPOrganizationDiscoveryService:
    """Service for discovering GCP organisation structure.

    Uses the Cloud Resource Manager API to discover:
    - Organisation metadata
    - Folder hierarchy
    - Projects within the organisation
    - Organisation policies
    """

    def __init__(self, credentials: Any) -> None:
        """Initialise with GCP credentials.

        Args:
            credentials: Google credentials object (service account or impersonated)
        """
        self.credentials = credentials
        self.logger = structlog.get_logger()

    async def discover_organisation(self, org_id: str) -> GCPOrgDiscoveryResult:
        """Discover the complete GCP organisation structure.

        Args:
            org_id: GCP organisation ID (numeric)

        Returns:
            GCPOrgDiscoveryResult with all discovered resources
        """
        self.logger.info("starting_gcp_org_discovery", org_id=org_id)

        result = GCPOrgDiscoveryResult(
            org_id=org_id,
            org_display_name="",
        )

        try:
            # Get organisation details
            org_info = await self._get_organization_info(org_id)
            result.org_display_name = org_info.get("display_name", "")
            result.org_directory_customer_id = org_info.get("directory_customer_id")

            self.logger.info(
                "discovered_org_info",
                org_id=org_id,
                display_name=result.org_display_name,
            )

            # Discover folders
            result.folders = await self._discover_folders(org_id)
            self.logger.info(
                "discovered_folders",
                count=len(result.folders),
            )

            # Discover projects
            result.projects = await self._discover_projects(org_id)
            self.logger.info(
                "discovered_projects",
                count=len(result.projects),
            )

            # Get organisation policies (optional)
            try:
                result.org_policies = await self._get_org_policies(org_id)
            except Exception as e:
                self.logger.warning("org_policies_discovery_failed", error=str(e))

        except Exception as e:
            self.logger.error("gcp_org_discovery_failed", org_id=org_id, error=str(e))
            raise

        return result

    async def _get_organization_info(self, org_id: str) -> dict:
        """Get organisation details."""
        try:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.OrganizationsClient(
                credentials=self.credentials
            )

            org_name = f"organizations/{org_id}"
            org = client.get_organization(request={"name": org_name})

            return {
                "name": org.name,
                "display_name": org.display_name,
                "directory_customer_id": org.directory_customer_id,
                "state": str(org.state),
                "create_time": org.create_time,
            }

        except Exception as e:
            self.logger.error("get_organization_info_failed", error=str(e))
            raise PermissionError(
                f"Failed to get organisation info. "
                f"Ensure the service account has resourcemanager.organizations.get permission: {e}"
            )

    async def _discover_folders(self, org_id: str) -> list[GCPFolder]:
        """Discover all folders in the organisation."""
        folders = []

        try:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.FoldersClient(credentials=self.credentials)

            # Start with folders directly under the organisation
            parent = f"organizations/{org_id}"
            folders.extend(await self._list_folders_recursive(client, parent))

        except Exception as e:
            self.logger.error("discover_folders_failed", error=str(e))

        return folders

    async def _list_folders_recursive(
        self, client: Any, parent: str
    ) -> list[GCPFolder]:
        """Recursively list folders under a parent."""
        folders = []

        try:
            request = {"parent": parent}

            for folder in client.list_folders(request=request):
                # Parse parent info
                parent_parts = folder.parent.split("/")
                parent_type = parent_parts[0].rstrip(
                    "s"
                )  # 'organizations' -> 'organization'
                parent_id = parent_parts[1]

                gcp_folder = GCPFolder(
                    folder_id=folder.name.split("/")[1],
                    name=folder.name,
                    display_name=folder.display_name,
                    parent_type=parent_type,
                    parent_id=parent_id,
                    state=str(folder.state),
                    create_time=folder.create_time,
                )
                folders.append(gcp_folder)

                # Recursively get child folders
                child_folders = await self._list_folders_recursive(client, folder.name)
                folders.extend(child_folders)

        except Exception as e:
            self.logger.warning(
                "list_folders_failed",
                parent=parent,
                error=str(e),
            )

        return folders

    async def _discover_projects(self, org_id: str) -> list[GCPProject]:
        """Discover all projects in the organisation."""
        projects = []

        try:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)

            # Search for all projects in the organisation
            # This uses the searchProjects API which is more efficient
            request = {
                "query": f"parent.type:organization parent.id:{org_id}",
            }

            for project in client.search_projects(request=request):
                if project.state.name != "ACTIVE":
                    continue  # Skip non-active projects

                # Parse parent info
                parent_parts = project.parent.split("/")
                parent_type = parent_parts[0].rstrip("s")
                parent_id = parent_parts[1]

                gcp_project = GCPProject(
                    project_id=project.project_id,
                    project_number=project.name.split("/")[1],
                    name=project.display_name or project.project_id,
                    parent_type=parent_type,
                    parent_id=parent_id,
                    state=str(project.state),
                    create_time=project.create_time,
                    labels=dict(project.labels) if project.labels else {},
                )
                projects.append(gcp_project)

            # Also search for projects in folders
            # The above query only finds direct children
            # We need to also find projects nested in folders
            folder_projects = await self._discover_projects_in_folders(client, org_id)
            # Merge without duplicates
            existing_ids = {p.project_id for p in projects}
            for fp in folder_projects:
                if fp.project_id not in existing_ids:
                    projects.append(fp)

        except Exception as e:
            self.logger.error("discover_projects_failed", error=str(e))

        return projects

    async def _discover_projects_in_folders(
        self, client: Any, org_id: str
    ) -> list[GCPProject]:
        """Discover projects nested within folders."""
        projects = []

        try:
            # Search for all projects with this organisation as ancestor
            request = {
                "query": "parent.type:folder",
            }

            for project in client.search_projects(request=request):
                if project.state.name != "ACTIVE":
                    continue

                # Verify this project belongs to our organisation
                # by checking if the folder is in our org
                parent_parts = project.parent.split("/")
                parent_type = parent_parts[0].rstrip("s")
                parent_id = parent_parts[1]

                gcp_project = GCPProject(
                    project_id=project.project_id,
                    project_number=project.name.split("/")[1],
                    name=project.display_name or project.project_id,
                    parent_type=parent_type,
                    parent_id=parent_id,
                    state=str(project.state),
                    create_time=project.create_time,
                    labels=dict(project.labels) if project.labels else {},
                )
                projects.append(gcp_project)

        except Exception as e:
            self.logger.warning("discover_folder_projects_failed", error=str(e))

        return projects

    async def _get_org_policies(self, org_id: str) -> dict[str, Any]:
        """Get organisation policies."""
        policies = {}

        try:
            from google.cloud import orgpolicy_v2

            client = orgpolicy_v2.OrgPolicyClient(credentials=self.credentials)

            parent = f"organizations/{org_id}"
            request = {"parent": parent}

            for policy in client.list_policies(request=request):
                policy_name = policy.name.split("/")[-1]
                policies[policy_name] = {
                    "name": policy.name,
                    "spec": (
                        {
                            "etag": policy.spec.etag if policy.spec else None,
                            "rules": [
                                {
                                    "allow_all": r.allow_all,
                                    "deny_all": r.deny_all,
                                    "enforce": r.enforce,
                                }
                                for r in (policy.spec.rules if policy.spec else [])
                            ],
                        }
                        if policy.spec
                        else None
                    ),
                    "alternate": policy.alternate.launch if policy.alternate else None,
                    "dry_run_spec": policy.dry_run_spec is not None,
                }

        except Exception as e:
            self.logger.warning("get_org_policies_failed", error=str(e))

        return policies

    def build_hierarchy_path(
        self,
        project: GCPProject,
        folders: list[GCPFolder],
        org_display_name: str,
    ) -> str:
        """Build a human-readable hierarchy path for a project.

        Example: "MyOrg/Production/WebServices" for a project
        in the WebServices folder under Production folder.
        """
        path_parts = []

        # Build folder chain
        current_parent_type = project.parent_type
        current_parent_id = project.parent_id

        # Create folder lookup
        folder_lookup = {f.folder_id: f for f in folders}

        while current_parent_type == "folder":
            folder = folder_lookup.get(current_parent_id)
            if folder:
                path_parts.insert(0, folder.display_name)
                current_parent_type = folder.parent_type
                current_parent_id = folder.parent_id
            else:
                break

        # Add org name at the root
        path_parts.insert(0, org_display_name or "Organization")

        return "/".join(path_parts)


class GCPCloudOrganizationService:
    """Service for managing GCP cloud organisations in the database."""

    def __init__(self, db: AsyncSession):
        """Initialise with database session."""
        self.db = db
        self.logger = structlog.get_logger()

    async def create_or_update_from_discovery(
        self,
        organization_id: UUID,
        discovery_result: GCPOrgDiscoveryResult,
        credentials_json: Optional[str] = None,
        service_account_email: Optional[str] = None,
    ) -> CloudOrganization:
        """Create or update a CloudOrganization from discovery results.

        Args:
            organization_id: Our tenant's organisation ID
            discovery_result: Result from GCPOrganizationDiscoveryService
            credentials_json: Encrypted service account JSON (optional)
            service_account_email: Service account email for impersonation

        Returns:
            Created or updated CloudOrganization
        """
        # Check if org already exists
        result = await self.db.execute(
            select(CloudOrganization).where(
                CloudOrganization.organization_id == organization_id,
                CloudOrganization.cloud_org_id == discovery_result.org_id,
                CloudOrganization.provider == CloudProvider.GCP,
            )
        )
        cloud_org = result.scalar_one_or_none()

        if cloud_org:
            # Update existing
            cloud_org.name = discovery_result.org_display_name
            cloud_org.status = CloudOrganizationStatus.ACTIVE
            cloud_org.total_accounts_discovered = len(discovery_result.projects)
            cloud_org.hierarchy_data = {
                "folders": [
                    {
                        "folder_id": f.folder_id,
                        "display_name": f.display_name,
                        "parent_type": f.parent_type,
                        "parent_id": f.parent_id,
                    }
                    for f in discovery_result.folders
                ],
                "org_policies": discovery_result.org_policies,
            }
            cloud_org.last_sync_at = datetime.utcnow()
        else:
            # Create new
            cloud_org = CloudOrganization(
                organization_id=organization_id,
                provider=CloudProvider.GCP,
                cloud_org_id=discovery_result.org_id,
                name=discovery_result.org_display_name,
                status=CloudOrganizationStatus.ACTIVE,
                total_accounts_discovered=len(discovery_result.projects),
                total_accounts_connected=0,
                hierarchy_data={
                    "folders": [
                        {
                            "folder_id": f.folder_id,
                            "display_name": f.display_name,
                            "parent_type": f.parent_type,
                            "parent_id": f.parent_id,
                        }
                        for f in discovery_result.folders
                    ],
                    "org_policies": discovery_result.org_policies,
                },
                credentials_arn=service_account_email,  # Using this field for SA email
                last_sync_at=datetime.utcnow(),
            )
            self.db.add(cloud_org)

        await self.db.flush()

        # Sync member projects
        await self._sync_members(cloud_org, discovery_result)

        await self.db.commit()
        await self.db.refresh(cloud_org)

        return cloud_org

    async def _sync_members(
        self,
        cloud_org: CloudOrganization,
        discovery_result: GCPOrgDiscoveryResult,
    ) -> None:
        """Sync discovered projects as CloudOrganizationMembers."""
        # Get existing members
        result = await self.db.execute(
            select(CloudOrganizationMember).where(
                CloudOrganizationMember.cloud_organization_id == cloud_org.id
            )
        )
        existing_members = {m.member_account_id: m for m in result.scalars().all()}

        # Build hierarchy paths
        discovery_service = GCPOrganizationDiscoveryService(None)

        for project in discovery_result.projects:
            hierarchy_path = discovery_service.build_hierarchy_path(
                project,
                discovery_result.folders,
                discovery_result.org_display_name,
            )

            if project.project_id in existing_members:
                # Update existing member
                member = existing_members[project.project_id]
                member.member_name = project.name
                member.hierarchy_path = hierarchy_path

                # Update status based on project state
                if project.state == "State.ACTIVE":
                    if member.status not in [
                        CloudOrganizationMemberStatus.CONNECTED,
                        CloudOrganizationMemberStatus.SKIPPED,
                    ]:
                        member.status = CloudOrganizationMemberStatus.DISCOVERED
                else:
                    member.status = CloudOrganizationMemberStatus.SUSPENDED
            else:
                # Create new member
                member = CloudOrganizationMember(
                    cloud_organization_id=cloud_org.id,
                    member_account_id=project.project_id,
                    member_name=project.name,
                    hierarchy_path=hierarchy_path,
                    status=(
                        CloudOrganizationMemberStatus.DISCOVERED
                        if project.state == "State.ACTIVE"
                        else CloudOrganizationMemberStatus.SUSPENDED
                    ),
                    metadata={
                        "project_number": project.project_number,
                        "parent_type": project.parent_type,
                        "parent_id": project.parent_id,
                        "labels": project.labels,
                        "create_time": (
                            project.create_time.isoformat()
                            if project.create_time
                            else None
                        ),
                    },
                )
                self.db.add(member)

        await self.db.flush()
