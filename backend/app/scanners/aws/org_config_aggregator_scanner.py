"""AWS Config Aggregator Scanner.

Scans for AWS Config aggregators that collect configuration data
from multiple accounts and regions in an AWS Organisation.
"""

from typing import Any, Optional

from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


class OrgConfigAggregatorScanner(BaseScanner):
    """
    Scanner for AWS Config aggregators.

    Config aggregators can collect AWS Config data from:
    - All accounts in an organisation
    - Specific accounts
    - Specific regions

    This provides visibility into compliance and configuration
    across the entire organisation.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.CONFIG_RULE

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """
        Scan for Config aggregators.

        Args:
            regions: Regions to scan
            options: Optional settings including:
                - org_id: AWS Organisation ID

        Returns:
            List of RawDetection for Config aggregators
        """
        detections = []
        options = options or {}
        org_id = options.get("org_id")

        for region in regions:
            region_detections = await self._scan_region(region, org_id)
            detections.extend(region_detections)

        return detections

    async def _scan_region(
        self, region: str, org_id: Optional[str]
    ) -> list[RawDetection]:
        """Scan for Config aggregators in a specific region."""
        detections = []

        try:
            client = self.session.client("config", region_name=region)

            # List configuration aggregators
            paginator = client.get_paginator("describe_configuration_aggregators")
            for page in paginator.paginate():
                for aggregator in page.get("ConfigurationAggregators", []):
                    # Check if this aggregator covers the organisation
                    org_aggregation = aggregator.get("OrganizationAggregationSource")

                    if org_aggregation:
                        # This is an organisation-level aggregator
                        detection = self._create_org_aggregator_detection(
                            aggregator, region, org_id
                        )
                        detections.append(detection)

                        self.logger.info(
                            "discovered_org_config_aggregator",
                            name=aggregator.get("ConfigurationAggregatorName"),
                            region=region,
                            all_regions=org_aggregation.get("AllAwsRegions", False),
                        )
                    else:
                        # Check for multi-account aggregator
                        account_aggregation = aggregator.get(
                            "AccountAggregationSources", []
                        )
                        if account_aggregation:
                            detection = self._create_account_aggregator_detection(
                                aggregator, region, org_id
                            )
                            detections.append(detection)

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "AccessDeniedException":
                self.logger.warning("access_denied_config", region=region)
            else:
                self.logger.error(
                    "config_scan_error",
                    region=region,
                    error=str(e),
                )

        return detections

    def _create_org_aggregator_detection(
        self, aggregator: dict, region: str, org_id: Optional[str]
    ) -> RawDetection:
        """Create a detection for an organisation-level aggregator."""
        name = aggregator.get("ConfigurationAggregatorName", "Unknown")
        arn = aggregator.get("ConfigurationAggregatorArn", "")

        org_source = aggregator.get("OrganizationAggregationSource", {})
        all_regions = org_source.get("AllAwsRegions", False)
        aws_regions = org_source.get("AwsRegions", [])
        role_arn = org_source.get("RoleArn")

        # Build description
        if all_regions:
            region_desc = "all regions"
        else:
            region_desc = f"{len(aws_regions)} regions"

        description = f"Organisation Config Aggregator: {name} ({region_desc})"

        return RawDetection(
            name=f"Org Config Aggregator: {name}",
            detection_type=self.detection_type,
            source_arn=arn,
            region=region,
            raw_config={
                "aggregator_name": name,
                "aggregator_arn": arn,
                "aggregator_type": "organization",
                "all_aws_regions": all_regions,
                "aws_regions": aws_regions,
                "role_arn": role_arn,
                "creation_time": (
                    aggregator.get("CreationTime").isoformat()
                    if aggregator.get("CreationTime")
                    else None
                ),
                "last_updated_time": (
                    aggregator.get("LastUpdatedTime").isoformat()
                    if aggregator.get("LastUpdatedTime")
                    else None
                ),
                "org_id": org_id,
            },
            description=description,
            is_managed=False,
        )

    def _create_account_aggregator_detection(
        self, aggregator: dict, region: str, org_id: Optional[str]
    ) -> RawDetection:
        """Create a detection for a multi-account aggregator."""
        name = aggregator.get("ConfigurationAggregatorName", "Unknown")
        arn = aggregator.get("ConfigurationAggregatorArn", "")

        account_sources = aggregator.get("AccountAggregationSources", [])

        # Collect all account IDs and regions
        all_account_ids = []
        all_regions = set()
        covers_all_regions = False

        for source in account_sources:
            all_account_ids.extend(source.get("AccountIds", []))
            if source.get("AllAwsRegions"):
                covers_all_regions = True
            else:
                all_regions.update(source.get("AwsRegions", []))

        # Build description
        account_desc = f"{len(all_account_ids)} accounts"
        if covers_all_regions:
            region_desc = "all regions"
        else:
            region_desc = f"{len(all_regions)} regions"

        description = (
            f"Multi-Account Config Aggregator: {name} ({account_desc}, {region_desc})"
        )

        return RawDetection(
            name=f"Config Aggregator: {name}",
            detection_type=self.detection_type,
            source_arn=arn,
            region=region,
            raw_config={
                "aggregator_name": name,
                "aggregator_arn": arn,
                "aggregator_type": "account",
                "account_ids": all_account_ids,
                "all_aws_regions": covers_all_regions,
                "aws_regions": list(all_regions),
                "account_sources": [
                    {
                        "account_ids": s.get("AccountIds", []),
                        "all_aws_regions": s.get("AllAwsRegions", False),
                        "aws_regions": s.get("AwsRegions", []),
                    }
                    for s in account_sources
                ],
                "creation_time": (
                    aggregator.get("CreationTime").isoformat()
                    if aggregator.get("CreationTime")
                    else None
                ),
                "last_updated_time": (
                    aggregator.get("LastUpdatedTime").isoformat()
                    if aggregator.get("LastUpdatedTime")
                    else None
                ),
                "org_id": org_id,
            },
            description=description,
            is_managed=False,
        )
