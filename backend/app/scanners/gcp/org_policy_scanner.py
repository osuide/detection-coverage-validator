"""GCP Organisation Policy Scanner.

Scans for organisation policies that enforce security constraints
across the entire GCP organisation.
"""

from typing import TYPE_CHECKING, Any, Optional

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection

if TYPE_CHECKING:
    from google.cloud.orgpolicy_v2 import OrgPolicyClient
    from google.cloud.orgpolicy_v2.types import Policy
    from google.cloud.resourcemanager_v3 import FoldersClient
    from google.cloud.resourcemanager_v3.types import Folder


# Security-relevant organisation policy constraints
SECURITY_POLICY_CONSTRAINTS = {
    # Compute Engine constraints
    "compute.disableSerialPortAccess": {
        "description": "Disables serial port access to VMs",
        "mitre_techniques": ["T1021"],
    },
    "compute.disableSerialPortLogging": {
        "description": "Disables serial port logging",
        "mitre_techniques": ["T1562"],
    },
    "compute.requireOsLogin": {
        "description": "Requires OS Login for SSH access",
        "mitre_techniques": ["T1078"],
    },
    "compute.requireShieldedVm": {
        "description": "Requires Shielded VM features",
        "mitre_techniques": ["T1542"],
    },
    "compute.vmExternalIpAccess": {
        "description": "Controls external IP assignment to VMs",
        "mitre_techniques": ["T1190"],
    },
    "compute.restrictVpcPeering": {
        "description": "Restricts VPC peering connections",
        "mitre_techniques": ["T1599"],
    },
    # IAM constraints
    "iam.disableServiceAccountKeyCreation": {
        "description": "Prevents service account key creation",
        "mitre_techniques": ["T1528", "T1098"],
    },
    "iam.disableServiceAccountKeyUpload": {
        "description": "Prevents service account key uploads",
        "mitre_techniques": ["T1528"],
    },
    "iam.allowedPolicyMemberDomains": {
        "description": "Restricts IAM policy members to specific domains",
        "mitre_techniques": ["T1078"],
    },
    # Storage constraints
    "storage.uniformBucketLevelAccess": {
        "description": "Enforces uniform bucket-level access",
        "mitre_techniques": ["T1530"],
    },
    "storage.publicAccessPrevention": {
        "description": "Prevents public access to Cloud Storage",
        "mitre_techniques": ["T1530"],
    },
    # SQL constraints
    "sql.restrictPublicIp": {
        "description": "Restricts public IP for Cloud SQL",
        "mitre_techniques": ["T1190"],
    },
    "sql.restrictAuthorizedNetworks": {
        "description": "Restricts authorized networks for Cloud SQL",
        "mitre_techniques": ["T1190"],
    },
    # GKE constraints
    "gke.enableBinaryAuthorization": {
        "description": "Enables Binary Authorization for GKE",
        "mitre_techniques": ["T1610"],
    },
    # General security constraints
    "iam.automaticIamGrantsForDefaultServiceAccounts": {
        "description": "Controls automatic IAM grants for default SAs",
        "mitre_techniques": ["T1078.004"],
    },
    "essentialcontacts.allowedContactDomains": {
        "description": "Restricts essential contact domains",
        "mitre_techniques": ["T1566"],
    },
}


class OrgPolicyScanner(BaseScanner):
    """Scanner for GCP organisation policies.

    Organisation policies are a type of preventive control that can
    restrict what resources can be created or configured.

    While not detections per se, they form part of the security posture
    and affect what misconfigurations are possible.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_SECURITY_COMMAND_CENTER  # Grouped with SCC

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for organisation policies.

        Args:
            regions: Not used (policies are global)
            options: Must include 'organization_id'
                - organization_id: GCP organisation ID
                - include_folders: Include folder-level policies (default False)
                - folder_ids: Specific folders to scan

        Returns:
            List of RawDetection for security-relevant policies
        """
        detections = []
        options = options or {}
        org_id = options.get("organization_id")
        include_folders = options.get("include_folders", False)
        folder_ids = options.get("folder_ids", [])

        if not org_id:
            self.logger.error("organization_id_required")
            return []

        try:
            from google.cloud import orgpolicy_v2
            from google.api_core.exceptions import PermissionDenied

            client = orgpolicy_v2.OrgPolicyClient(credentials=self.session)

            # Scan organisation-level policies
            org_detections = await self._scan_resource_policies(
                client,
                resource_type="organization",
                resource_id=org_id,
                org_id=org_id,
            )
            detections.extend(org_detections)

            self.logger.info(
                "discovered_org_policies",
                org_id=org_id,
                count=len(org_detections),
            )

            # Scan folder-level policies if requested
            if include_folders or folder_ids:
                if folder_ids:
                    for folder_id in folder_ids:
                        folder_detections = await self._scan_resource_policies(
                            client,
                            resource_type="folder",
                            resource_id=folder_id,
                            org_id=org_id,
                        )
                        detections.extend(folder_detections)
                else:
                    # Discover all folders and scan their policies
                    folder_detections = await self._scan_all_folder_policies(
                        client, org_id
                    )
                    detections.extend(folder_detections)

        except PermissionDenied as e:
            self.logger.warning(
                "permission_denied_org_policies",
                org_id=org_id,
                error=str(e),
            )
        except Exception as e:
            self.logger.error(
                "scan_org_policies_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    async def _scan_resource_policies(
        self,
        client: "OrgPolicyClient",
        resource_type: str,
        resource_id: str,
        org_id: str,
    ) -> list[RawDetection]:
        """Scan policies for a specific resource (org or folder)."""
        detections = []

        try:
            parent = f"{resource_type}s/{resource_id}"
            request = {"parent": parent}

            # Use run_sync to avoid blocking the event loop
            # GCP client methods are synchronous
            def fetch_policies() -> list:
                policies = []
                for policy in client.list_policies(request=request):
                    policies.append(policy)
                return policies

            policies = await self.run_sync(fetch_policies)

            for policy in policies:
                detection = self._create_policy_detection(
                    policy=policy,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    org_id=org_id,
                )
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.warning(
                "scan_resource_policies_failed",
                resource_type=resource_type,
                resource_id=resource_id,
                error=str(e),
            )

        return detections

    async def _scan_all_folder_policies(
        self, client: "OrgPolicyClient", org_id: str
    ) -> list[RawDetection]:
        """Discover and scan policies for all folders in the organisation."""
        detections = []

        try:
            from google.cloud import resourcemanager_v3

            rm_client = resourcemanager_v3.FoldersClient(credentials=self.session)

            # List all folders recursively
            folders = await self._list_all_folders(rm_client, org_id)

            for folder in folders:
                folder_id = folder.name.split("/")[1]
                folder_detections = await self._scan_resource_policies(
                    client,
                    resource_type="folder",
                    resource_id=folder_id,
                    org_id=org_id,
                )
                detections.extend(folder_detections)

        except Exception as e:
            self.logger.warning(
                "scan_all_folder_policies_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    async def _list_all_folders(
        self, rm_client: "FoldersClient", org_id: str
    ) -> list["Folder"]:
        """List all folders in the organisation recursively."""
        all_folders: list["Folder"] = []

        async def list_children(parent: str) -> None:
            try:
                request = {"parent": parent}
                for folder in rm_client.list_folders(request=request):
                    all_folders.append(folder)
                    await list_children(folder.name)
            except Exception:
                pass

        await list_children(f"organizations/{org_id}")
        return all_folders

    def _create_policy_detection(
        self,
        policy: "Policy",
        resource_type: str,
        resource_id: str,
        org_id: str,
    ) -> Optional[RawDetection]:
        """Create a RawDetection from an organisation policy."""
        # Extract constraint name from policy name
        # Format: organizations/123/policies/compute.disableSerialPortAccess
        policy_parts = policy.name.split("/")
        constraint_name = policy_parts[-1] if len(policy_parts) > 3 else policy.name

        # Check if this is a security-relevant constraint
        policy_info = SECURITY_POLICY_CONSTRAINTS.get(constraint_name)
        if not policy_info:
            # Still include non-mapped policies but without MITRE mapping
            policy_info = {
                "description": f"Organisation policy: {constraint_name}",
                "mitre_techniques": [],
            }

        # Determine if policy is enforced
        is_enforced = False
        enforcement_type = "not_set"

        if policy.spec and policy.spec.rules:
            for rule in policy.spec.rules:
                if rule.enforce:
                    is_enforced = True
                    enforcement_type = "enforce"
                elif rule.allow_all:
                    enforcement_type = "allow_all"
                elif rule.deny_all:
                    is_enforced = True
                    enforcement_type = "deny_all"
                elif rule.values:
                    if rule.values.allowed_values:
                        enforcement_type = "allowed_values"
                    elif rule.values.denied_values:
                        is_enforced = True
                        enforcement_type = "denied_values"

        scope = "Organisation" if resource_type == "organization" else "Folder"
        description = f"{scope} Policy: {constraint_name} " f"({enforcement_type})"

        return RawDetection(
            name=f"{scope} Policy: {constraint_name}",
            detection_type=self.detection_type,
            source_arn=policy.name,
            region="global",
            raw_config={
                "name": policy.name,
                "constraint": constraint_name,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "enforcement_type": enforcement_type,
                "is_enforced": is_enforced,
                "spec": (
                    {
                        "etag": policy.spec.etag if policy.spec else None,
                        "rules": [
                            {
                                "allow_all": r.allow_all,
                                "deny_all": r.deny_all,
                                "enforce": r.enforce,
                                "condition": (
                                    {
                                        "expression": r.condition.expression,
                                        "title": r.condition.title,
                                    }
                                    if r.condition
                                    else None
                                ),
                                "values": (
                                    {
                                        "allowed_values": list(r.values.allowed_values),
                                        "denied_values": list(r.values.denied_values),
                                    }
                                    if r.values
                                    else None
                                ),
                            }
                            for r in (policy.spec.rules if policy.spec else [])
                        ],
                        "inherit_from_parent": (
                            policy.spec.inherit_from_parent if policy.spec else None
                        ),
                        "reset": policy.spec.reset if policy.spec else None,
                    }
                    if policy.spec
                    else None
                ),
                "dry_run_spec": policy.dry_run_spec is not None,
                "org_id": org_id,
                "mitre_techniques": policy_info.get("mitre_techniques", []),
            },
            description=description,
            is_managed=False,  # User-configured
        )


class EffectiveOrgPolicyScanner(BaseScanner):
    """Scanner for effective organisation policies on projects.

    This scanner determines the effective policy for a project,
    taking into account inheritance from folders and the organisation.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_SECURITY_COMMAND_CENTER

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for effective organisation policies on a project.

        Args:
            regions: Not used
            options: Must include 'project_id'
                - project_id: GCP project ID
                - constraints: Specific constraints to check (optional)

        Returns:
            List of RawDetection for effective policies
        """
        detections = []
        options = options or {}
        project_id = options.get("project_id")
        constraints = options.get(
            "constraints", list(SECURITY_POLICY_CONSTRAINTS.keys())
        )

        if not project_id:
            self.logger.error("project_id_required")
            return []

        try:
            from google.cloud import orgpolicy_v2
            from google.api_core.exceptions import PermissionDenied

            client = orgpolicy_v2.OrgPolicyClient(credentials=self.session)

            for constraint in constraints:
                try:
                    detection = await self._get_effective_policy(
                        client, project_id, constraint
                    )
                    if detection:
                        detections.append(detection)
                except Exception as e:
                    self.logger.warning(
                        "get_effective_policy_failed",
                        project_id=project_id,
                        constraint=constraint,
                        error=str(e),
                    )

            self.logger.info(
                "discovered_effective_policies",
                project_id=project_id,
                count=len(detections),
            )

        except PermissionDenied as e:
            self.logger.warning(
                "permission_denied_effective_policies",
                project_id=project_id,
                error=str(e),
            )
        except Exception as e:
            self.logger.error(
                "scan_effective_policies_failed",
                project_id=project_id,
                error=str(e),
            )

        return detections

    async def _get_effective_policy(
        self, client: "OrgPolicyClient", project_id: str, constraint: str
    ) -> Optional[RawDetection]:
        """Get the effective policy for a specific constraint on a project."""
        try:
            resource = f"projects/{project_id}"
            name = f"{resource}/policies/{constraint}"

            # Get the effective policy (computed from hierarchy)
            policy = client.get_effective_policy(request={"name": name})

            policy_info = SECURITY_POLICY_CONSTRAINTS.get(constraint, {})

            return RawDetection(
                name=f"Effective Policy: {constraint}",
                detection_type=self.detection_type,
                source_arn=name,
                region="global",
                raw_config={
                    "name": name,
                    "constraint": constraint,
                    "project_id": project_id,
                    "spec": (
                        {
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
                    "mitre_techniques": policy_info.get("mitre_techniques", []),
                },
                description=policy_info.get(
                    "description", f"Effective policy: {constraint}"
                ),
                is_managed=False,
            )

        except Exception:
            # Policy not set or inherited
            return None
