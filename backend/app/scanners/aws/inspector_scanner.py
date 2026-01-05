"""AWS Inspector scanner for vulnerability assessment findings.

Amazon Inspector is a vulnerability management service that continuously scans
AWS workloads for software vulnerabilities and unintended network exposure.

This scanner discovers:
- Inspector enabled status and configuration
- Coverage statistics (EC2, ECR, Lambda)
- Vulnerability findings by severity
- Finding categories and types

Inspector2 API is used (the current version, not Inspector Classic).
"""

from typing import Any, Optional
from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


# Inspector resource types that can be scanned
RESOURCE_TYPES = ["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"]

# Finding severity levels
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


class InspectorScanner(BaseScanner):
    """Scanner for AWS Inspector vulnerability findings.

    Inspector is a managed vulnerability assessment service. This scanner discovers:
    - Active Inspector scanning configurations
    - Coverage statistics (what's being scanned)
    - Finding summaries by severity and type

    Note: Inspector findings are vendor-managed detections that identify
    software vulnerabilities (CVEs) and network exposure issues.

    Detection categories:
    - Package Vulnerabilities - CVE-based findings in installed packages
    - Network Reachability - Unintended network exposure
    - Code Vulnerabilities - Lambda code security issues
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.INSPECTOR_FINDING

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan all regions for Inspector configurations in parallel."""
        return await self.scan_regions_parallel(regions, options)

    async def scan_region(
        self,
        region: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan a single region for Inspector configurations and findings."""
        detections = []
        client = self.session.client("inspector2", region_name=region)

        try:
            # Check if Inspector is enabled by getting account status
            try:
                status_response = await self.run_sync(
                    client.batch_get_account_status,
                    accountIds=[await self._get_account_id()],
                )
                accounts = status_response.get("accounts", [])
                if not accounts:
                    self.logger.info("inspector_not_enabled", region=region)
                    return []

                account_status = accounts[0]
                state = account_status.get("state", {})
                status = state.get("status", "DISABLED")

                if status not in ["ENABLED", "ENABLING"]:
                    self.logger.info(
                        "inspector_not_enabled",
                        region=region,
                        status=status,
                    )
                    return []

            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code in [
                    "AccessDeniedException",
                    "ResourceNotFoundException",
                ]:
                    self.logger.info(
                        "inspector_access_denied_or_not_enabled",
                        region=region,
                        error=error_code,
                    )
                    return []
                raise

            # Get coverage statistics
            coverage_stats = await self._get_coverage_statistics(client, region)

            # Get finding counts by severity
            finding_counts = await self._get_finding_counts(client, region)

            # Get finding type breakdown
            finding_types = await self._get_finding_types(client, region)

            # Create detection categories based on what's enabled
            detection_categories = self._build_detection_categories(
                account_status,
                coverage_stats,
                finding_counts,
                finding_types,
            )

            account_id = await self._get_account_id()

            for category in detection_categories:
                detection = RawDetection(
                    name=f"Inspector-{category['name']}",
                    detection_type=DetectionType.INSPECTOR_FINDING,
                    source_arn=f"arn:aws:inspector2:{region}:{account_id}:coverage/{category['resource_type']}",
                    region=region,
                    raw_config={
                        "category": category["name"],
                        "resource_type": category["resource_type"],
                        "description": category["description"],
                        "coverage": category.get("coverage", {}),
                        "finding_counts": category.get("finding_counts", {}),
                        "finding_types": category.get("finding_types", []),
                        "account_status": {
                            "status": status,
                            "resource_state": account_status.get("resourceState", {}),
                        },
                    },
                    description=category["description"],
                    is_managed=False,  # Only DO-NOT-DELETE- EventBridge rules show badge
                    target_services=category.get("target_services", []),
                )
                detections.append(detection)

            self.logger.info(
                "inspector_scan_complete",
                region=region,
                detection_count=len(detections),
                coverage=coverage_stats,
            )

        except ClientError as e:
            self.logger.warning(
                "inspector_scan_error",
                region=region,
                error=str(e),
            )

        return detections

    async def _get_account_id(self) -> str:
        """Get AWS account ID from STS."""
        try:
            sts = self.session.client("sts")
            identity = await self.run_sync(sts.get_caller_identity)
            return identity["Account"]
        except Exception:
            return "unknown"

    async def _get_coverage_statistics(
        self,
        client: Any,
        region: str,
    ) -> dict[str, Any]:
        """Get coverage statistics for each resource type."""
        coverage = {}

        try:
            # Get coverage statistics grouped by resource type
            response = await self.run_sync(
                client.list_coverage_statistics,
                groupBy="RESOURCE_TYPE",
            )

            for group in response.get("countsByGroup", []):
                resource_type = group.get("groupKey", "UNKNOWN")
                coverage[resource_type] = {
                    "count": group.get("count", 0),
                }

            # Get total counts
            coverage["total"] = response.get("totalCounts", {})

        except ClientError as e:
            self.logger.warning(
                "inspector_coverage_error",
                region=region,
                error=str(e),
            )

        return coverage

    async def _get_finding_counts(
        self,
        client: Any,
        region: str,
    ) -> dict[str, int]:
        """Get finding counts by severity."""
        counts = {}

        try:
            response = await self.run_sync(
                client.list_finding_aggregations,
                aggregationType="SEVERITY",
            )

            for agg in response.get("responses", []):
                severity_agg = agg.get("severityAggregation", {})
                severity = severity_agg.get("severityLabel", "UNKNOWN")
                count = severity_agg.get("count", 0)
                counts[severity] = count

        except ClientError as e:
            self.logger.warning(
                "inspector_finding_counts_error",
                region=region,
                error=str(e),
            )

        return counts

    async def _get_finding_types(
        self,
        client: Any,
        region: str,
    ) -> list[dict]:
        """Get finding type breakdown."""
        finding_types = []

        try:
            response = await self.run_sync(
                client.list_finding_aggregations,
                aggregationType="FINDING_TYPE",
            )

            for agg in response.get("responses", []):
                type_agg = agg.get("findingTypeAggregation", {})
                finding_types.append(
                    {
                        "type": type_agg.get("findingType", "UNKNOWN"),
                        "count": type_agg.get("count", 0),
                    }
                )

        except ClientError as e:
            self.logger.warning(
                "inspector_finding_types_error",
                region=region,
                error=str(e),
            )

        return finding_types

    def _build_detection_categories(
        self,
        account_status: dict,
        coverage_stats: dict,
        finding_counts: dict,
        finding_types: list,
    ) -> list[dict]:
        """Build detection categories based on Inspector configuration."""
        categories = []
        resource_state = account_status.get("resourceState", {})

        # EC2 Scanning
        ec2_state = resource_state.get("ec2", {})
        if ec2_state.get("status") == "ENABLED":
            ec2_coverage = coverage_stats.get("AWS_EC2_INSTANCE", {})
            categories.append(
                {
                    "name": "EC2-VulnerabilityScanning",
                    "resource_type": "EC2",
                    "description": "Scans EC2 instances for software vulnerabilities and CVEs",
                    "coverage": ec2_coverage,
                    "finding_counts": finding_counts,
                    "finding_types": [
                        "PACKAGE_VULNERABILITY",
                        "NETWORK_REACHABILITY",
                    ],
                    "target_services": ["EC2"],
                }
            )

        # ECR Scanning
        ecr_state = resource_state.get("ecr", {})
        if ecr_state.get("status") == "ENABLED":
            ecr_coverage = coverage_stats.get("AWS_ECR_CONTAINER_IMAGE", {})
            categories.append(
                {
                    "name": "ECR-ContainerScanning",
                    "resource_type": "ECR",
                    "description": "Scans container images in ECR for vulnerabilities",
                    "coverage": ecr_coverage,
                    "finding_counts": finding_counts,
                    "finding_types": [
                        "PACKAGE_VULNERABILITY",
                    ],
                    "target_services": ["ECR"],
                }
            )

        # Lambda Scanning
        lambda_state = resource_state.get("lambda", {})
        if lambda_state.get("status") == "ENABLED":
            lambda_coverage = coverage_stats.get("AWS_LAMBDA_FUNCTION", {})
            categories.append(
                {
                    "name": "Lambda-VulnerabilityScanning",
                    "resource_type": "LAMBDA",
                    "description": "Scans Lambda functions for package vulnerabilities",
                    "coverage": lambda_coverage,
                    "finding_counts": finding_counts,
                    "finding_types": [
                        "PACKAGE_VULNERABILITY",
                    ],
                    "target_services": ["Lambda"],
                }
            )

        # Lambda Code Scanning
        lambda_code_state = resource_state.get("lambdaCode", {})
        if lambda_code_state.get("status") == "ENABLED":
            categories.append(
                {
                    "name": "Lambda-CodeScanning",
                    "resource_type": "LAMBDA_CODE",
                    "description": "Scans Lambda function code for security vulnerabilities",
                    "coverage": {},
                    "finding_counts": finding_counts,
                    "finding_types": [
                        "CODE_VULNERABILITY",
                    ],
                    "target_services": ["Lambda"],
                }
            )

        return categories
