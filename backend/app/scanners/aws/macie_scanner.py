"""AWS Macie scanner for sensitive data discovery findings.

Amazon Macie is a data security service that uses machine learning and pattern
matching to discover and protect sensitive data stored in Amazon S3.

This scanner discovers:
- Macie enabled status and configuration
- Classification job configurations
- Sensitive data finding summaries
- S3 bucket security posture

Macie2 API is used (the current version, not Macie Classic).
"""

from typing import Any, Optional
from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


# Macie finding categories
FINDING_CATEGORIES = [
    "CLASSIFICATION",  # Sensitive data classification findings
    "POLICY",  # Policy findings (bucket security issues)
]

# Sensitive data categories Macie can detect
SENSITIVE_DATA_CATEGORIES = [
    "CREDENTIALS",  # AWS keys, passwords, tokens
    "FINANCIAL_INFORMATION",  # Credit cards, bank accounts
    "PERSONAL_INFORMATION",  # PII like SSN, names, addresses
    "CUSTOM_IDENTIFIER",  # Custom-defined sensitive data patterns
]


class MacieScanner(BaseScanner):
    """Scanner for AWS Macie sensitive data findings.

    Macie is a managed data security service. This scanner discovers:
    - Active Macie configurations
    - Automated sensitive data discovery status
    - Classification job configurations
    - Finding summaries by category and severity

    Note: Macie findings are vendor-managed detections that identify
    sensitive data exposure and S3 security issues.

    Detection categories:
    - Sensitive Data Discovery - PII, credentials, financial data in S3
    - Policy Findings - S3 bucket security misconfigurations
    - Automated Discovery - Continuous sensitive data scanning
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.MACIE_FINDING

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan all regions for Macie configurations in parallel."""
        return await self.scan_regions_parallel(regions, options)

    async def scan_region(
        self,
        region: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan a single region for Macie configurations and findings."""
        detections = []
        client = self.session.client("macie2", region_name=region)

        try:
            # Check if Macie is enabled
            try:
                session_response = await self.run_sync(client.get_macie_session)
                status = session_response.get("status", "DISABLED")

                if status != "ENABLED":
                    self.logger.info(
                        "macie_not_enabled",
                        region=region,
                        status=status,
                    )
                    return []

            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code in [
                    "AccessDeniedException",
                    "ResourceNotFoundException",
                    "Macie2Exception",
                ]:
                    self.logger.info(
                        "macie_access_denied_or_not_enabled",
                        region=region,
                        error=error_code,
                    )
                    return []
                raise

            account_id = await self._get_account_id()

            # Get automated discovery configuration
            auto_discovery = await self._get_automated_discovery_config(client, region)

            # Get classification jobs
            classification_jobs = await self._get_classification_jobs(client, region)

            # Get finding statistics
            finding_stats = await self._get_finding_statistics(client, region)

            # Get bucket statistics for security posture
            bucket_stats = await self._get_bucket_statistics(client, region)

            # Build detection categories
            detection_categories = self._build_detection_categories(
                session_response,
                auto_discovery,
                classification_jobs,
                finding_stats,
                bucket_stats,
            )

            for category in detection_categories:
                detection = RawDetection(
                    name=f"Macie-{category['name']}",
                    detection_type=DetectionType.MACIE_FINDING,
                    source_arn=f"arn:aws:macie2:{region}:{account_id}:classification-job/{category.get('job_id', 'auto-discovery')}",
                    region=region,
                    raw_config={
                        "category": category["name"],
                        "description": category["description"],
                        "finding_types": category.get("finding_types", []),
                        "configuration": category.get("configuration", {}),
                        "statistics": category.get("statistics", {}),
                        "macie_status": status,
                    },
                    description=category["description"],
                    is_managed=True,  # Macie is a managed service
                    target_services=["S3"],  # Macie primarily monitors S3
                )
                detections.append(detection)

            self.logger.info(
                "macie_scan_complete",
                region=region,
                detection_count=len(detections),
                auto_discovery_enabled=auto_discovery.get("status") == "ENABLED",
                job_count=len(classification_jobs),
            )

        except ClientError as e:
            self.logger.warning(
                "macie_scan_error",
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

    async def _get_automated_discovery_config(
        self,
        client: Any,
        region: str,
    ) -> dict[str, Any]:
        """Get automated sensitive data discovery configuration."""
        config = {"status": "DISABLED"}

        try:
            response = await self.run_sync(client.get_automated_discovery_configuration)
            config = {
                "status": response.get("status", "DISABLED"),
                "classification_scope_id": response.get("classificationScopeId"),
                "sensitivity_inspection_template_id": response.get(
                    "sensitivityInspectionTemplateId"
                ),
            }
        except ClientError as e:
            # Automated discovery might not be configured
            error_code = e.response["Error"]["Code"]
            if error_code != "ResourceNotFoundException":
                self.logger.warning(
                    "macie_auto_discovery_error",
                    region=region,
                    error=str(e),
                )

        return config

    async def _get_classification_jobs(
        self,
        client: Any,
        region: str,
    ) -> list[dict]:
        """Get classification job configurations."""
        jobs = []

        try:
            paginator = client.get_paginator("list_classification_jobs")

            def fetch_jobs() -> list[dict[str, Any]]:
                result: list[dict[str, Any]] = []
                for page in paginator.paginate():
                    for item in page.get("items", []):
                        result.append(
                            {
                                "job_id": item.get("jobId"),
                                "name": item.get("name"),
                                "job_type": item.get("jobType"),
                                "job_status": item.get("jobStatus"),
                                "created_at": str(item.get("createdAt", "")),
                                "bucket_criteria": item.get("bucketCriteria", {}),
                            }
                        )
                return result

            jobs = await self.run_sync(fetch_jobs)

        except ClientError as e:
            self.logger.warning(
                "macie_jobs_error",
                region=region,
                error=str(e),
            )

        return jobs

    async def _get_finding_statistics(
        self,
        client: Any,
        region: str,
    ) -> dict[str, Any]:
        """Get finding statistics by type and severity."""
        stats = {
            "by_severity": {},
            "by_type": {},
            "total_count": 0,
        }

        try:
            # Get findings grouped by severity
            severity_response = await self.run_sync(
                client.get_finding_statistics,
                groupBy="severity.description",
            )
            for group in severity_response.get("countsByGroup", []):
                severity = group.get("groupKey", "UNKNOWN")
                stats["by_severity"][severity] = group.get("count", 0)
                stats["total_count"] += group.get("count", 0)

            # Get findings grouped by type
            type_response = await self.run_sync(
                client.get_finding_statistics,
                groupBy="type",
            )
            for group in type_response.get("countsByGroup", []):
                finding_type = group.get("groupKey", "UNKNOWN")
                stats["by_type"][finding_type] = group.get("count", 0)

        except ClientError as e:
            self.logger.warning(
                "macie_finding_stats_error",
                region=region,
                error=str(e),
            )

        return stats

    async def _get_bucket_statistics(
        self,
        client: Any,
        region: str,
    ) -> dict[str, Any]:
        """Get S3 bucket security statistics."""
        stats = {
            "total_buckets": 0,
            "buckets_with_errors": 0,
            "publicly_accessible": 0,
            "unencrypted": 0,
            "shared_externally": 0,
        }

        try:
            response = await self.run_sync(client.get_bucket_statistics)

            stats["total_buckets"] = response.get("bucketCount", 0)
            stats["buckets_with_errors"] = response.get(
                "bucketCountByEffectivePermission", {}
            ).get("unknown", 0)

            # Public access statistics
            public_access = response.get("bucketCountByEffectivePermission", {})
            stats["publicly_accessible"] = (
                public_access.get("publiclyAccessible", 0)
                + public_access.get("publiclyReadable", 0)
                + public_access.get("publiclyWritable", 0)
            )

            # Encryption statistics
            encryption = response.get("bucketCountByEncryptionType", {})
            stats["unencrypted"] = encryption.get("unencrypted", 0)

            # Sharing statistics
            sharing = response.get("bucketCountBySharedAccessType", {})
            stats["shared_externally"] = sharing.get("external", 0) + sharing.get(
                "internal", 0
            )

        except ClientError as e:
            self.logger.warning(
                "macie_bucket_stats_error",
                region=region,
                error=str(e),
            )

        return stats

    def _build_detection_categories(
        self,
        session_response: dict,
        auto_discovery: dict,
        classification_jobs: list,
        finding_stats: dict,
        bucket_stats: dict,
    ) -> list[dict]:
        """Build detection categories based on Macie configuration."""
        categories = []

        # Automated Sensitive Data Discovery
        if auto_discovery.get("status") == "ENABLED":
            categories.append(
                {
                    "name": "AutomatedDiscovery",
                    "description": "Automated scanning for sensitive data across S3 buckets",
                    "finding_types": [
                        "SensitiveData:S3Object/Credentials",
                        "SensitiveData:S3Object/Financial",
                        "SensitiveData:S3Object/Personal",
                        "SensitiveData:S3Object/CustomIdentifier",
                    ],
                    "configuration": auto_discovery,
                    "statistics": finding_stats,
                }
            )

        # Classification Jobs (one detection per active job)
        active_jobs = [
            j for j in classification_jobs if j.get("job_status") == "RUNNING"
        ]
        if active_jobs:
            for job in active_jobs[:5]:  # Limit to 5 jobs to avoid too many detections
                categories.append(
                    {
                        "name": f"ClassificationJob-{job.get('name', job.get('job_id', 'unknown'))[:30]}",
                        "job_id": job.get("job_id"),
                        "description": "Classification job scanning S3 for sensitive data",
                        "finding_types": [
                            "SensitiveData:S3Object/Credentials",
                            "SensitiveData:S3Object/Financial",
                            "SensitiveData:S3Object/Personal",
                        ],
                        "configuration": job,
                        "statistics": finding_stats,
                    }
                )

        # Policy Findings (S3 bucket security)
        if bucket_stats.get("total_buckets", 0) > 0:
            categories.append(
                {
                    "name": "S3-SecurityPosture",
                    "description": "Monitors S3 bucket security configurations and access policies",
                    "finding_types": [
                        "Policy:IAMUser/S3BlockPublicAccessDisabled",
                        "Policy:IAMUser/S3BucketEncryptionDisabled",
                        "Policy:IAMUser/S3BucketPublic",
                        "Policy:IAMUser/S3BucketReplicatedExternally",
                        "Policy:IAMUser/S3BucketSharedExternally",
                    ],
                    "configuration": {
                        "buckets_monitored": bucket_stats.get("total_buckets", 0),
                    },
                    "statistics": {
                        "publicly_accessible": bucket_stats.get(
                            "publicly_accessible", 0
                        ),
                        "unencrypted": bucket_stats.get("unencrypted", 0),
                        "shared_externally": bucket_stats.get("shared_externally", 0),
                    },
                }
            )

        # Sensitive Data Categories (if any findings exist)
        if finding_stats.get("total_count", 0) > 0:
            # Credentials detection
            cred_count = finding_stats.get("by_type", {}).get(
                "SensitiveData:S3Object/Credentials", 0
            )
            if cred_count > 0:
                categories.append(
                    {
                        "name": "CredentialExposure",
                        "description": "Detects exposed credentials (AWS keys, passwords, tokens) in S3",
                        "finding_types": [
                            "SensitiveData:S3Object/Credentials",
                        ],
                        "statistics": {"finding_count": cred_count},
                    }
                )

            # PII detection
            pii_count = finding_stats.get("by_type", {}).get(
                "SensitiveData:S3Object/Personal", 0
            )
            if pii_count > 0:
                categories.append(
                    {
                        "name": "PIIExposure",
                        "description": "Detects exposed personally identifiable information (PII) in S3",
                        "finding_types": [
                            "SensitiveData:S3Object/Personal",
                        ],
                        "statistics": {"finding_count": pii_count},
                    }
                )

            # Financial data detection
            fin_count = finding_stats.get("by_type", {}).get(
                "SensitiveData:S3Object/Financial", 0
            )
            if fin_count > 0:
                categories.append(
                    {
                        "name": "FinancialDataExposure",
                        "description": "Detects exposed financial information (credit cards, bank accounts) in S3",
                        "finding_types": [
                            "SensitiveData:S3Object/Financial",
                        ],
                        "statistics": {"finding_count": fin_count},
                    }
                )

        return categories
