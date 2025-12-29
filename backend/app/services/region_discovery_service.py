"""Region auto-discovery service for AWS and GCP.

This service discovers which regions have active resources or security
services enabled, allowing for intelligent multi-region scanning.
"""

import asyncio
from typing import Any, Optional

import boto3
import structlog

from app.core.service_registry import AWS_DEFAULT_REGIONS, GCP_REGIONS

logger = structlog.get_logger()


class RegionDiscoveryService:
    """Discovers active regions for cloud accounts."""

    def __init__(self) -> None:
        self.logger = logger.bind(service="RegionDiscoveryService")

    async def discover_aws_active_regions(
        self,
        session: boto3.Session,
        check_ec2: bool = True,
        check_guardduty: bool = True,
        check_cloudwatch: bool = True,
    ) -> list[str]:
        """Discover AWS regions with active resources or security services.

        This method uses multiple signals to determine which regions are in use:
        1. EC2 describe_regions to get enabled regions for the account
        2. GuardDuty detector presence
        3. CloudWatch Logs activity

        Args:
            session: boto3 session with credentials
            check_ec2: Check enabled regions via EC2
            check_guardduty: Check for GuardDuty detectors
            check_cloudwatch: Check for CloudWatch log groups

        Returns:
            List of region codes where activity was detected
        """
        active_regions: set[str] = set()

        # Step 1: Get enabled regions via EC2 (regions user has access to)
        enabled_regions = await self._get_enabled_regions(session)
        if not enabled_regions:
            # Fall back to default regions if describe_regions fails
            enabled_regions = AWS_DEFAULT_REGIONS.copy()

        self.logger.info(
            "enabled_regions_discovered",
            count=len(enabled_regions),
            regions=enabled_regions[:5],  # Log first 5
        )

        # Step 2: Check for activity in parallel across enabled regions
        tasks = []

        if check_guardduty:
            tasks.append(self._check_guardduty_regions(session, enabled_regions))

        if check_cloudwatch:
            tasks.append(self._check_cloudwatch_regions(session, enabled_regions))

        if check_ec2:
            tasks.append(self._check_ec2_regions(session, enabled_regions))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, set):
                    active_regions.update(result)
                elif isinstance(result, Exception):
                    self.logger.warning(
                        "region_check_failed",
                        error=str(result),
                    )

        # Always include the session's default region
        default_region = session.region_name or "us-east-1"
        if default_region in enabled_regions:
            active_regions.add(default_region)

        # Sort for consistent ordering
        result = sorted(list(active_regions))

        self.logger.info(
            "active_regions_discovered",
            count=len(result),
            regions=result,
        )

        return result

    async def _get_enabled_regions(self, session: boto3.Session) -> list[str]:
        """Get list of enabled regions for the AWS account.

        Uses EC2 describe_regions with 'opt-in-status' filter.
        """
        try:
            ec2 = session.client("ec2", region_name="us-east-1")

            # Run in thread pool as boto3 is synchronous
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: ec2.describe_regions(
                    Filters=[
                        {
                            "Name": "opt-in-status",
                            "Values": ["opt-in-not-required", "opted-in"],
                        }
                    ]
                ),
            )

            return [r["RegionName"] for r in response.get("Regions", [])]

        except Exception as e:
            self.logger.warning(
                "describe_regions_failed",
                error=str(e),
            )
            return []

    async def _check_guardduty_regions(
        self, session: boto3.Session, regions: list[str]
    ) -> set[str]:
        """Check which regions have GuardDuty enabled."""
        active = set()

        async def check_region(region: str) -> Optional[str]:
            try:
                client = session.client("guardduty", region_name=region)
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: client.list_detectors(MaxResults=1),
                )
                if response.get("DetectorIds"):
                    return region
            except Exception:
                pass
            return None

        # Check regions in parallel with concurrency limit
        semaphore = asyncio.Semaphore(10)

        async def bounded_check(region: str) -> Optional[str]:
            async with semaphore:
                return await check_region(region)

        tasks = [bounded_check(r) for r in regions]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                active.add(result)

        return active

    async def _check_cloudwatch_regions(
        self, session: boto3.Session, regions: list[str]
    ) -> set[str]:
        """Check which regions have CloudWatch log groups."""
        active = set()

        async def check_region(region: str) -> Optional[str]:
            try:
                client = session.client("logs", region_name=region)
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: client.describe_log_groups(limit=1),
                )
                if response.get("logGroups"):
                    return region
            except Exception:
                pass
            return None

        semaphore = asyncio.Semaphore(10)

        async def bounded_check(region: str) -> Optional[str]:
            async with semaphore:
                return await check_region(region)

        tasks = [bounded_check(r) for r in regions]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                active.add(result)

        return active

    async def _check_ec2_regions(
        self, session: boto3.Session, regions: list[str]
    ) -> set[str]:
        """Check which regions have EC2 instances or VPCs."""
        active = set()

        async def check_region(region: str) -> Optional[str]:
            try:
                ec2 = session.client("ec2", region_name=region)
                loop = asyncio.get_event_loop()

                # Check for VPCs (every region with resources will have VPCs)
                response = await loop.run_in_executor(
                    None,
                    lambda: ec2.describe_vpcs(MaxResults=5),
                )

                vpcs = response.get("Vpcs", [])
                # Filter out default VPCs only - if there's a non-default VPC, region is active
                for vpc in vpcs:
                    if not vpc.get("IsDefault", False):
                        return region

                # Also check for running instances
                response = await loop.run_in_executor(
                    None,
                    lambda: ec2.describe_instances(
                        Filters=[
                            {"Name": "instance-state-name", "Values": ["running"]}
                        ],
                        MaxResults=5,
                    ),
                )
                if response.get("Reservations"):
                    return region

            except Exception:
                pass
            return None

        semaphore = asyncio.Semaphore(10)

        async def bounded_check(region: str) -> Optional[str]:
            async with semaphore:
                return await check_region(region)

        tasks = [bounded_check(r) for r in regions]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                active.add(result)

        return active

    async def discover_gcp_active_regions(
        self,
        credentials: Any,
        project_id: str,
    ) -> list[str]:
        """Discover GCP regions with active resources.

        Uses Cloud Asset Inventory or Compute Engine API to find active regions.

        Args:
            credentials: Google credentials object
            project_id: GCP project ID

        Returns:
            List of region codes where activity was detected
        """
        active_regions: set[str] = set()

        try:
            # Import Google Cloud libraries
            from google.cloud import compute_v1
            from google.cloud import asset_v1

            # Try Asset Inventory first (more comprehensive)
            try:
                asset_client = asset_v1.AssetServiceClient(credentials=credentials)
                request = asset_v1.SearchAllResourcesRequest(
                    scope=f"projects/{project_id}",
                    asset_types=["compute.googleapis.com/Instance"],
                    page_size=100,
                )

                for resource in asset_client.search_all_resources(request=request):
                    # Extract region from resource location
                    location = resource.location
                    if location and "-" in location:
                        # Zone format: us-central1-a -> region: us-central1
                        region = "-".join(location.split("-")[:-1])
                        if region in GCP_REGIONS:
                            active_regions.add(region)

            except Exception as asset_error:
                self.logger.debug(
                    "asset_inventory_failed",
                    error=str(asset_error),
                )

            # Fall back to Compute Engine regions if Asset Inventory fails
            if not active_regions:
                compute_client = compute_v1.RegionsClient(credentials=credentials)
                request = compute_v1.ListRegionsRequest(project=project_id)

                for region in compute_client.list(request=request):
                    # Check if region has any quota usage (indicates activity)
                    if region.status == "UP":
                        active_regions.add(region.name)

        except ImportError:
            self.logger.warning(
                "gcp_libraries_not_installed",
                message="google-cloud-compute and google-cloud-asset required for GCP discovery",
            )
        except Exception as e:
            self.logger.error(
                "gcp_discovery_failed",
                error=str(e),
            )

        result = sorted(list(active_regions))

        self.logger.info(
            "gcp_active_regions_discovered",
            project_id=project_id,
            count=len(result),
            regions=result[:5] if result else [],
        )

        return result


# Singleton instance
region_discovery_service = RegionDiscoveryService()
