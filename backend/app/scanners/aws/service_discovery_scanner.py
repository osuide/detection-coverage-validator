"""AWS Service Discovery Scanner.

Discovers which AWS services have resources in a cloud account.
This enables service-aware coverage calculation by knowing which
services to check for detection coverage.
"""

from typing import Any, Optional

import structlog
from botocore.exceptions import ClientError

logger = structlog.get_logger()


class ServiceDiscoveryScanner:
    """Scan AWS account to discover which services have resources.

    Checks the Core 10 services to determine which ones have active
    resources in the account. This information is used to:
    1. Scope coverage calculations to relevant services only
    2. Avoid penalising coverage for unused services
    3. Provide more accurate compliance metrics
    """

    def __init__(self, session: Any):
        """Initialise scanner with boto3 session.

        Args:
            session: Boto3 session with credentials for the target account
        """
        self.session = session
        self.logger = logger.bind(scanner="ServiceDiscoveryScanner")

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[str]:
        """Discover which services have resources in the account.

        Checks all Core 10 services across specified regions.
        For global services (S3, Secrets Manager, ECR), only scans once.
        For regional services, scans each region.

        Args:
            regions: List of regions to scan
            options: Optional scan options

        Returns:
            List of normalised service names that have resources
        """
        discovered: set[str] = set()
        primary_region = regions[0] if regions else "eu-west-2"

        self.logger.info(
            "starting_service_discovery",
            regions=regions,
            primary_region=primary_region,
        )

        # Global services - scan once from primary region
        global_services = ["S3", "SecretsManager", "ECR"]
        for service in global_services:
            try:
                has_resources = await self._check_service(service, primary_region)
                if has_resources:
                    discovered.add(service)
                    self.logger.debug("service_discovered", service=service)
            except ClientError as e:
                self.logger.warning(
                    "service_check_error",
                    service=service,
                    error=str(e),
                )

        # Regional services - scan each region
        regional_services = ["EBS", "EFS", "RDS", "DynamoDB", "Redshift", "ElastiCache"]
        for region in regions:
            for service in regional_services:
                if service in discovered:
                    continue  # Already found, skip

                try:
                    has_resources = await self._check_service(service, region)
                    if has_resources:
                        discovered.add(service)
                        self.logger.debug(
                            "service_discovered",
                            service=service,
                            region=region,
                        )
                except ClientError as e:
                    self.logger.warning(
                        "service_check_error",
                        service=service,
                        region=region,
                        error=str(e),
                    )

        # CloudWatch Logs - check in each region (very common)
        for region in regions:
            if "CloudWatchLogs" in discovered:
                break
            try:
                has_resources = await self._check_service("CloudWatchLogs", region)
                if has_resources:
                    discovered.add("CloudWatchLogs")
                    self.logger.debug(
                        "service_discovered",
                        service="CloudWatchLogs",
                        region=region,
                    )
            except ClientError:
                pass

        result = sorted(discovered)
        self.logger.info(
            "service_discovery_complete",
            discovered_count=len(result),
            services=result,
        )
        return result

    async def _check_service(self, service: str, region: str) -> bool:
        """Check if a service has resources in the specified region.

        Args:
            service: Normalised service name (e.g., "S3")
            region: AWS region

        Returns:
            True if the service has at least one resource
        """
        if service == "S3":
            return await self._check_s3(region)
        elif service == "EBS":
            return await self._check_ebs(region)
        elif service == "EFS":
            return await self._check_efs(region)
        elif service == "RDS":
            return await self._check_rds(region)
        elif service == "DynamoDB":
            return await self._check_dynamodb(region)
        elif service == "Redshift":
            return await self._check_redshift(region)
        elif service == "ElastiCache":
            return await self._check_elasticache(region)
        elif service == "SecretsManager":
            return await self._check_secrets_manager(region)
        elif service == "CloudWatchLogs":
            return await self._check_cloudwatch_logs(region)
        elif service == "ECR":
            return await self._check_ecr(region)
        else:
            self.logger.warning("unknown_service", service=service)
            return False

    async def _check_s3(self, region: str) -> bool:
        """Check if account has S3 buckets."""
        client = self.session.client("s3", region_name=region)
        response = client.list_buckets()
        return len(response.get("Buckets", [])) > 0

    async def _check_ebs(self, region: str) -> bool:
        """Check if account has EBS volumes in this region."""
        client = self.session.client("ec2", region_name=region)
        response = client.describe_volumes(MaxResults=1)
        return len(response.get("Volumes", [])) > 0

    async def _check_efs(self, region: str) -> bool:
        """Check if account has EFS file systems in this region."""
        client = self.session.client("efs", region_name=region)
        response = client.describe_file_systems(MaxItems=1)
        return len(response.get("FileSystems", [])) > 0

    async def _check_rds(self, region: str) -> bool:
        """Check if account has RDS instances or clusters in this region."""
        client = self.session.client("rds", region_name=region)

        # Check DB instances
        instances = client.describe_db_instances(MaxRecords=20)
        if instances.get("DBInstances"):
            return True

        # Check DB clusters (Aurora)
        clusters = client.describe_db_clusters(MaxRecords=20)
        return len(clusters.get("DBClusters", [])) > 0

    async def _check_dynamodb(self, region: str) -> bool:
        """Check if account has DynamoDB tables in this region."""
        client = self.session.client("dynamodb", region_name=region)
        response = client.list_tables(Limit=1)
        return len(response.get("TableNames", [])) > 0

    async def _check_redshift(self, region: str) -> bool:
        """Check if account has Redshift clusters in this region."""
        client = self.session.client("redshift", region_name=region)
        response = client.describe_clusters(MaxRecords=20)
        return len(response.get("Clusters", [])) > 0

    async def _check_elasticache(self, region: str) -> bool:
        """Check if account has ElastiCache clusters in this region."""
        client = self.session.client("elasticache", region_name=region)

        # Check cache clusters
        clusters = client.describe_cache_clusters(MaxRecords=20)
        if clusters.get("CacheClusters"):
            return True

        # Check replication groups (Redis cluster mode)
        groups = client.describe_replication_groups(MaxRecords=20)
        return len(groups.get("ReplicationGroups", [])) > 0

    async def _check_secrets_manager(self, region: str) -> bool:
        """Check if account has Secrets Manager secrets."""
        client = self.session.client("secretsmanager", region_name=region)
        response = client.list_secrets(MaxResults=1)
        return len(response.get("SecretList", [])) > 0

    async def _check_cloudwatch_logs(self, region: str) -> bool:
        """Check if account has CloudWatch Log groups in this region."""
        client = self.session.client("logs", region_name=region)
        response = client.describe_log_groups(limit=1)
        return len(response.get("logGroups", [])) > 0

    async def _check_ecr(self, region: str) -> bool:
        """Check if account has ECR repositories."""
        client = self.session.client("ecr", region_name=region)
        response = client.describe_repositories(maxResults=1)
        return len(response.get("repositories", [])) > 0
