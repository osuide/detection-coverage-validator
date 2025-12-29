"""AWS Organisation GuardDuty Scanner.

Scans for GuardDuty configurations from a delegated administrator account,
discovering organisation-wide threat detection coverage.
"""

from typing import Any, Optional

from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


class OrgGuardDutyScanner(BaseScanner):
    """
    Scanner for organisation-level GuardDuty configurations.

    When GuardDuty is managed at the organisation level, a delegated
    administrator account can view and manage detectors across all
    member accounts.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GUARDDUTY_FINDING

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """
        Scan for organisation GuardDuty configurations.

        Args:
            regions: Regions to scan
            options: Optional settings including:
                - org_id: AWS Organisation ID
                - is_delegated_admin: Whether scanning from delegated admin account

        Returns:
            List of RawDetection for org-level GuardDuty configs
        """
        detections = []
        options = options or {}
        org_id = options.get("org_id")
        is_delegated_admin = options.get("is_delegated_admin", False)

        for region in regions:
            region_detections = await self._scan_region(
                region, org_id, is_delegated_admin
            )
            detections.extend(region_detections)

        return detections

    async def _scan_region(
        self,
        region: str,
        org_id: Optional[str],
        is_delegated_admin: bool,
    ) -> list[RawDetection]:
        """Scan GuardDuty in a specific region."""
        detections = []

        try:
            client = self.session.client("guardduty", region_name=region)

            # List detectors in this region
            detector_ids = []
            paginator = client.get_paginator("list_detectors")
            for page in paginator.paginate():
                detector_ids.extend(page.get("DetectorIds", []))

            for detector_id in detector_ids:
                # Get detector details
                try:
                    detector = client.get_detector(DetectorId=detector_id)

                    # Check if this is an organisation configuration
                    org_config = await self._get_org_configuration(
                        client, detector_id, region
                    )

                    if org_config:
                        # Get member accounts
                        members = await self._list_members(client, detector_id)

                        detection = self._create_detection(
                            detector_id=detector_id,
                            detector=detector,
                            region=region,
                            org_config=org_config,
                            members=members,
                            org_id=org_id,
                        )
                        detections.append(detection)

                        self.logger.info(
                            "discovered_org_guardduty",
                            detector_id=detector_id,
                            region=region,
                            member_count=len(members),
                        )

                except ClientError as e:
                    self.logger.warning(
                        "failed_to_get_detector",
                        detector_id=detector_id,
                        region=region,
                        error=str(e),
                    )

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "AccessDeniedException":
                self.logger.warning("access_denied_guardduty", region=region)
            else:
                self.logger.error(
                    "guardduty_scan_error",
                    region=region,
                    error=str(e),
                )

        return detections

    async def _get_org_configuration(
        self, client: Any, detector_id: str, region: str
    ) -> Optional[dict]:
        """Get organisation configuration for a detector."""
        try:
            response = client.describe_organization_configuration(
                DetectorId=detector_id
            )
            return {
                "auto_enable": response.get("AutoEnable", False),
                "auto_enable_organization_members": response.get(
                    "AutoEnableOrganizationMembers", "NONE"
                ),
                "member_account_limit_reached": response.get(
                    "MemberAccountLimitReached", False
                ),
            }
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ["BadRequestException", "AccessDeniedException"]:
                # Not a delegated admin or org not configured
                return None
            raise

    async def _list_members(self, client: Any, detector_id: str) -> list[dict]:
        """List member accounts for a detector."""
        members = []
        try:
            paginator = client.get_paginator("list_members")
            for page in paginator.paginate(DetectorId=detector_id):
                for member in page.get("Members", []):
                    members.append(
                        {
                            "account_id": member.get("AccountId"),
                            "email": member.get("Email"),
                            "relationship_status": member.get("RelationshipStatus"),
                            "invited_at": (
                                member.get("InvitedAt").isoformat()
                                if member.get("InvitedAt")
                                else None
                            ),
                            "updated_at": (
                                member.get("UpdatedAt").isoformat()
                                if member.get("UpdatedAt")
                                else None
                            ),
                        }
                    )
        except ClientError:
            pass

        return members

    def _create_detection(
        self,
        detector_id: str,
        detector: dict,
        region: str,
        org_config: dict,
        members: list[dict],
        org_id: Optional[str],
    ) -> RawDetection:
        """Create a RawDetection from GuardDuty org configuration."""
        # Build description
        status = detector.get("Status", "UNKNOWN")
        member_count = len(members)
        enabled_members = sum(
            1 for m in members if m.get("relationship_status") == "Enabled"
        )

        description = (
            f"Organisation GuardDuty ({status}): "
            f"{enabled_members}/{member_count} members enabled"
        )

        # Get features
        features = detector.get("Features", [])
        feature_status = {
            f.get("Name"): f.get("Status") for f in features if f.get("Name")
        }

        # Get data sources (legacy)
        data_sources = detector.get("DataSources", {})

        # Build member account IDs list
        member_account_ids = [m["account_id"] for m in members if m.get("account_id")]

        return RawDetection(
            name=f"Org GuardDuty: {region}",
            detection_type=self.detection_type,
            source_arn=f"arn:aws:guardduty:{region}::detector/{detector_id}",
            region=region,
            raw_config={
                "detector_id": detector_id,
                "status": status,
                "finding_publishing_frequency": detector.get(
                    "FindingPublishingFrequency"
                ),
                "service_role": detector.get("ServiceRole"),
                "created_at": (
                    detector.get("CreatedAt").isoformat()
                    if detector.get("CreatedAt")
                    else None
                ),
                "updated_at": (
                    detector.get("UpdatedAt").isoformat()
                    if detector.get("UpdatedAt")
                    else None
                ),
                # Organisation config
                "org_config": org_config,
                "member_count": member_count,
                "enabled_member_count": enabled_members,
                "member_accounts": member_account_ids,
                # Features
                "features": feature_status,
                "data_sources": {
                    "s3_logs": data_sources.get("S3Logs", {}).get("Status"),
                    "kubernetes": data_sources.get("Kubernetes", {})
                    .get("AuditLogs", {})
                    .get("Status"),
                    "malware_protection": data_sources.get("MalwareProtection", {})
                    .get("ScanEc2InstanceWithFindings", {})
                    .get("EbsVolumes", {})
                    .get("Status"),
                },
                "org_id": org_id,
            },
            description=description,
            is_managed=True,  # GuardDuty is an AWS-managed service
        )
