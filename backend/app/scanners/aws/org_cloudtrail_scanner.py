"""AWS Organisation CloudTrail Scanner.

Scans for organisation-level CloudTrail trails that monitor
all accounts in an AWS Organisation.
"""

from typing import Any, Optional

from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


class OrgCloudTrailScanner(BaseScanner):
    """
    Scanner for organisation-level CloudTrail trails.

    Org trails are created in the management account and automatically
    apply to all member accounts, providing centralised logging.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.CLOUDWATCH_LOGS_INSIGHTS

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """
        Scan for organisation CloudTrail trails.

        Args:
            regions: Regions to scan (org trails can be multi-region)
            options: Optional settings including:
                - org_id: AWS Organisation ID
                - include_member_accounts: List of account IDs this detection covers

        Returns:
            List of RawDetection for org-level trails
        """
        detections = []
        options = options or {}
        org_id = options.get("org_id")

        # CloudTrail can be queried from any region, but we check the home region
        # Org trails are typically in us-east-1 or the management account's default region
        primary_region = regions[0] if regions else "us-east-1"

        try:
            client = self.session.client("cloudtrail", region_name=primary_region)

            # List all trails
            paginator = client.get_paginator("list_trails")
            for page in paginator.paginate():
                for trail_info in page.get("Trails", []):
                    trail_arn = trail_info.get("TrailARN")
                    home_region = trail_info.get("HomeRegion", primary_region)

                    # Get detailed trail info
                    try:
                        # Use the trail's home region for describe
                        regional_client = self.session.client(
                            "cloudtrail", region_name=home_region
                        )
                        trail_response = regional_client.describe_trails(
                            trailNameList=[trail_arn]
                        )
                        trails = trail_response.get("trailList", [])

                        for trail in trails:
                            # Check if this is an organisation trail
                            is_org_trail = trail.get("IsOrganizationTrail", False)

                            if is_org_trail:
                                detection = self._create_detection(
                                    trail, home_region, org_id
                                )
                                detections.append(detection)
                                self.logger.info(
                                    "discovered_org_trail",
                                    name=trail.get("Name"),
                                    region=home_region,
                                    is_multi_region=trail.get(
                                        "IsMultiRegionTrail", False
                                    ),
                                )

                    except ClientError as e:
                        self.logger.warning(
                            "failed_to_describe_trail",
                            trail_arn=trail_arn,
                            error=str(e),
                        )

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "AccessDeniedException":
                self.logger.warning(
                    "access_denied_cloudtrail",
                    region=primary_region,
                )
            else:
                self.logger.error(
                    "cloudtrail_scan_error",
                    error=str(e),
                )

        return detections

    def _create_detection(
        self, trail: dict, region: str, org_id: Optional[str]
    ) -> RawDetection:
        """Create a RawDetection from a CloudTrail trail."""
        trail_arn = trail.get("TrailARN", "")
        trail_name = trail.get("Name", "Unknown")

        # Build description
        features = []
        if trail.get("IsMultiRegionTrail"):
            features.append("multi-region")
        if trail.get("IncludeGlobalServiceEvents"):
            features.append("global-services")
        if trail.get("HasCustomEventSelectors"):
            features.append("custom-selectors")
        if trail.get("HasInsightSelectors"):
            features.append("insights-enabled")

        description = f"Organisation CloudTrail: {trail_name}"
        if features:
            description += f" ({', '.join(features)})"

        # Determine log destination
        log_groups = []
        if trail.get("CloudWatchLogsLogGroupArn"):
            log_group_arn = trail["CloudWatchLogsLogGroupArn"]
            # Extract log group name from ARN
            # arn:aws:logs:region:account:log-group:name:*
            parts = log_group_arn.split(":")
            if len(parts) >= 7:
                log_groups.append(parts[6])

        return RawDetection(
            name=f"Org CloudTrail: {trail_name}",
            detection_type=self.detection_type,
            source_arn=trail_arn,
            region=region,
            raw_config={
                "trail_name": trail_name,
                "trail_arn": trail_arn,
                "is_organization_trail": True,
                "is_multi_region_trail": trail.get("IsMultiRegionTrail", False),
                "include_global_service_events": trail.get(
                    "IncludeGlobalServiceEvents", False
                ),
                "s3_bucket_name": trail.get("S3BucketName"),
                "s3_key_prefix": trail.get("S3KeyPrefix"),
                "sns_topic_arn": trail.get("SnsTopicARN"),
                "cloudwatch_logs_log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                "kms_key_id": trail.get("KmsKeyId"),
                "has_custom_event_selectors": trail.get(
                    "HasCustomEventSelectors", False
                ),
                "has_insight_selectors": trail.get("HasInsightSelectors", False),
                "home_region": trail.get("HomeRegion"),
                "org_id": org_id,
            },
            log_groups=log_groups if log_groups else None,
            description=description,
            is_managed=False,  # Org trails are user-configured, not AWS-managed
        )
