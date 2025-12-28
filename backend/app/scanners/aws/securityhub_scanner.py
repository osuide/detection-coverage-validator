"""AWS Security Hub scanner for aggregated security findings.

Supports both the legacy standards-based API and the new CSPM consolidated
controls API introduced in 2023. The scanner will automatically use the
CSPM API when available, falling back to the legacy API if permissions
are not granted.

CSPM API Benefits:
- Standard-agnostic control IDs (e.g., S3.1 instead of FSBP.S3.1)
- Single control ID across all standards
- Better control parameter support
- More consistent control metadata

Standard-Level Aggregation:
- Creates ONE detection per enabled Security Hub standard (FSBP, CIS, PCI-DSS)
- Instead of 500+ per-control detections, creates 3-5 standard-level detections
- Each detection contains all controls in raw_config.controls for drill-down
- Metrics: enabled_controls_count, disabled_controls_count, techniques_covered_count
"""

from typing import Any, Optional
from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


def _chunk_list(items: list, chunk_size: int) -> list[list]:
    """Split a list into chunks of specified size."""
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


# Standard ARN patterns for matching and grouping
# ARN format: arn:aws:securityhub:{region}::standards/{standard-name}/v/{version}
# or legacy: arn:aws:securityhub:::ruleset/{standard-name}/v/{version}
STANDARD_PATTERNS = {
    "aws-foundational-security-best-practices": {
        "id": "fsbp",
        "name": "AWS-Foundational-Best-Practices",
        "description": "AWS Foundational Security Best Practices - checks for security best practices across AWS services",
        "arn_patterns": [
            "standards/aws-foundational-security-best-practices",
        ],
    },
    "cis-aws-foundations-benchmark": {
        "id": "cis",
        "name": "CIS-AWS-Foundations",
        "description": "CIS AWS Foundations Benchmark - industry best practice security configuration baseline",
        "arn_patterns": [
            "standards/cis-aws-foundations-benchmark",
            "ruleset/cis-aws-foundations-benchmark",  # Legacy format
        ],
    },
    "pci-dss": {
        "id": "pci",
        "name": "PCI-DSS",
        "description": "PCI DSS - Payment Card Industry Data Security Standard compliance checks",
        "arn_patterns": [
            "standards/pci-dss",
        ],
    },
    "nist-800-53": {
        "id": "nist",
        "name": "NIST-800-53",
        "description": "NIST 800-53 - Security and privacy controls for federal information systems",
        "arn_patterns": [
            "standards/nist-800-53",
        ],
    },
    "nist-800-171": {
        "id": "nist171",
        "name": "NIST-800-171",
        "description": "NIST 800-171 - Protecting Controlled Unclassified Information in non-federal systems",
        "arn_patterns": [
            "standards/nist-800-171",
        ],
    },
    "aws-resource-tagging-standard": {
        "id": "tagging",
        "name": "AWS-Resource-Tagging",
        "description": "AWS Resource Tagging Standard - ensures resources are properly tagged",
        "arn_patterns": [
            "standards/aws-resource-tagging-standard",
        ],
    },
}


def _get_standard_id_from_arn(standards_arn: str) -> Optional[str]:
    """Extract standard ID from a standards ARN.

    Args:
        standards_arn: The ARN like 'arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0'

    Returns:
        Standard ID (e.g., 'fsbp', 'cis', 'nist') or None if not recognised
    """
    if not standards_arn:
        return None

    for standard_key, info in STANDARD_PATTERNS.items():
        for pattern in info.get("arn_patterns", []):
            if pattern in standards_arn:
                return info["id"]

    return None


class SecurityHubScanner(BaseScanner):
    """Scanner for AWS Security Hub enabled standards and insights.

    Security Hub aggregates findings from multiple AWS security services.
    This scanner discovers:
    - Enabled security standards (CIS, PCI-DSS, AWS Foundational)
    - Custom insights
    - Aggregated finding patterns
    - Consolidated security controls (via CSPM API)

    The scanner groups CSPM controls by security standard, creating one
    aggregated detection per standard instead of individual control detections.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.SECURITY_HUB

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan all regions for Security Hub configurations.

        We use the GetEnabledStandards API to discover which standards are
        enabled, then create ONE detection per enabled standard. This ensures
        we get proper standard names (CIS, NIST, PCI, FSBP) rather than trying
        to infer them from control IDs.

        For each enabled standard, we:
        1. Get enabled standards from the first region
        2. Get CSPM control data for detailed control info
        3. Create ONE detection per enabled standard

        Insights are scanned per-region as they may differ.
        """
        all_detections = []

        # Phase 1: Collect CSPM control data and enabled standards
        cspm_control_data: dict[str, dict] = {}  # control_id -> merged data
        enabled_standards: list[dict] = []  # List of enabled standard subscriptions
        cspm_scanned = False
        first_cspm_region = None
        first_client = None  # Store client for per-standard control queries
        hub_arn = ""

        for region in regions:
            try:
                client = self.session.client("securityhub", region_name=region)

                # Check if Security Hub is enabled
                try:
                    hub = client.describe_hub()
                    hub_arn = hub.get("HubArn", "")
                except ClientError as e:
                    error_code = e.response["Error"]["Code"]
                    if error_code in [
                        "AccessDeniedException",
                        "InvalidAccessException",
                        "ResourceNotFoundException",
                    ]:
                        self.logger.info("securityhub_not_enabled", region=region)
                        continue
                    raise

                # Get enabled standards (only once, from first region with Security Hub)
                if not enabled_standards:
                    enabled_standards = self._get_enabled_standards(client, region)
                    first_client = client  # Store for later per-standard queries
                    self.logger.info(
                        "securityhub_enabled_standards",
                        region=region,
                        standards_count=len(enabled_standards),
                        standards=[s.get("standard_id") for s in enabled_standards],
                    )

                # Get CSPM control status for this region
                region_status = self._get_cspm_control_status(client, region)

                if region_status:
                    if not cspm_scanned:
                        # First region with CSPM - store full control data
                        first_cspm_region = region
                        for control_id, control_data in region_status.items():
                            cspm_control_data[control_id] = {
                                **control_data,
                                "hub_arn": hub_arn,
                                "status_by_region": {region: control_data["status"]},
                            }
                        cspm_scanned = True
                        self.logger.info(
                            "securityhub_cspm_first_region",
                            region=region,
                            control_count=len(region_status),
                        )
                    else:
                        # Subsequent regions - just add status
                        for control_id, control_data in region_status.items():
                            if control_id in cspm_control_data:
                                cspm_control_data[control_id]["status_by_region"][
                                    region
                                ] = control_data["status"]
                        self.logger.info(
                            "securityhub_cspm_region_status",
                            region=region,
                            controls_with_status=len(region_status),
                        )

                # Scan insights per-region (they can differ)
                insights_detections = self._scan_insights(client, region, hub_arn)
                all_detections.extend(insights_detections)

                # If CSPM not available, fall back to legacy for this region
                if not region_status and not cspm_scanned:
                    standards_detections = self._scan_enabled_standards(
                        client, region, hub_arn
                    )
                    all_detections.extend(standards_detections)

            except ClientError as e:
                self.logger.warning(
                    "securityhub_scan_error", region=region, error=str(e)
                )

        # Phase 2: Create detections per standard
        if cspm_control_data:
            if enabled_standards:
                # Best path: Use actual enabled standards from GetEnabledStandards API
                grouped_detections = self._create_detections_per_enabled_standard(
                    cspm_control_data,
                    enabled_standards,
                    hub_arn,
                    first_cspm_region or regions[0],
                    client=first_client,  # Pass client for per-standard control queries
                )
                all_detections.extend(grouped_detections)

                self.logger.info(
                    "securityhub_cspm_complete",
                    total_controls=len(cspm_control_data),
                    standards_created=len(grouped_detections),
                    regions_scanned=len(regions),
                    method="enabled_standards_api",
                )
            else:
                # Fallback: GetEnabledStandards failed (permissions?), use inference
                self.logger.warning(
                    "securityhub_enabled_standards_fallback",
                    message="GetEnabledStandards returned empty, falling back to inference",
                    total_controls=len(cspm_control_data),
                )
                grouped_detections = self._create_grouped_standard_detections(
                    cspm_control_data,
                    None,  # client not needed for inference
                    first_cspm_region or regions[0],
                )
                all_detections.extend(grouped_detections)

        return all_detections

    def _group_controls_by_standard(
        self,
        cspm_control_data: dict[str, dict],
    ) -> dict[str, dict[str, dict]]:
        """Group CSPM controls by inferred security standard.

        AWS CSPM uses standard-agnostic control IDs. All controls use service-
        based IDs like S3.1, IAM.1, EC2.18 regardless of which standard they
        belong to. We categorise all service-prefixed controls under FSBP as
        it's the most comprehensive standard.

        Args:
            cspm_control_data: Dict of control_id -> control data

        Returns:
            Dict of standard_id -> {control_id -> control_data}
        """
        grouped: dict[str, dict[str, dict]] = {
            "fsbp": {},
            "cis": {},
            "pci": {},
            "nist": {},
            "other": {},
        }

        for control_id, control_data in cspm_control_data.items():
            inferred_standard = self._infer_standard_from_control_id(control_id)
            if inferred_standard:
                grouped[inferred_standard][control_id] = control_data
            else:
                grouped["other"][control_id] = control_data

        # Log grouping results
        self.logger.info(
            "controls_grouped_by_standard",
            fsbp_count=len(grouped["fsbp"]),
            cis_count=len(grouped["cis"]),
            pci_count=len(grouped["pci"]),
            nist_count=len(grouped["nist"]),
            other_count=len(grouped["other"]),
        )

        # Warn if any controls fell to 'other' - indicates missing service prefix
        if grouped["other"]:
            other_ids = list(grouped["other"].keys())[:10]
            self.logger.warning(
                "unrecognised_control_prefixes",
                message="Controls with unrecognised prefixes - update service_prefixes",
                sample_control_ids=other_ids,
                total_unrecognised=len(grouped["other"]),
            )

        # Remove empty standard groups
        return {k: v for k, v in grouped.items() if v}

    def _infer_standard_from_control_id(self, control_id: str) -> Optional[str]:
        """Infer standard from control ID prefix pattern.

        AWS CSPM uses standard-agnostic control IDs. All standards (FSBP, CIS,
        NIST, PCI) share the same service-based IDs like S3.1, IAM.1, EC2.18.
        We categorise all service-prefixed controls under FSBP.

        Pattern matching order:
        1. PCI.* prefix -> PCI (legacy format from pre-CSPM API)
        2. Numeric prefix (1.x, 2.x) -> CIS (legacy format from pre-CSPM API)
        3. Service prefix (S3.x, IAM.x) -> FSBP (standard CSPM format)

        Args:
            control_id: The CSPM control ID (e.g., "S3.1", "IAM.6", "EC2.18")

        Returns:
            Standard ID ('fsbp', 'cis', 'pci') or None if prefix unrecognised
        """
        control_upper = control_id.upper()

        # Legacy PCI prefix (pre-CSPM API format)
        if control_upper.startswith("PCI."):
            return "pci"

        # Legacy CIS pattern: starts with digit (pre-CSPM API format)
        # Modern CSPM uses service-based IDs for CIS too (e.g., S3.1 not 1.1)
        if control_id and control_id[0].isdigit():
            return "cis"

        # FSBP pattern: service prefix (e.g., S3.1, IAM.1, EC2.18)
        # AWS CSPM uses standard-agnostic control IDs - all standards (FSBP, CIS,
        # NIST, PCI) share the same service-based IDs. We categorise all service-
        # prefixed controls under FSBP as it's the most comprehensive standard.
        # Complete list from: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html
        if "." in control_id:
            prefix = control_id.split(".")[0].upper()
            # Complete AWS service prefixes (as of December 2025)
            # Organised alphabetically for maintainability
            service_prefixes = {
                # A
                "ACCOUNT",
                "ACM",
                "AMPLIFY",
                "APIGATEWAY",
                "APPCONFIG",
                "APPFLOW",
                "APPRUNNER",
                "APPSYNC",
                "ATHENA",
                "AUTOSCALING",
                # B
                "BACKUP",
                "BATCH",
                # C
                "CLOUDFORMATION",
                "CLOUDFRONT",
                "CLOUDTRAIL",
                "CLOUDWATCH",
                "CODEARTIFACT",
                "CODEBUILD",
                "CODEGURUPROFILER",
                "CODEGURUREVIEWER",
                "COGNITO",
                "CONFIG",
                "CONNECT",
                # D
                "DATAFIREHOSE",
                "DATASYNC",
                "DETECTIVE",
                "DMS",
                "DOCUMENTDB",
                "DYNAMODB",
                # E
                "EC2",
                "ECR",
                "ECS",
                "EFS",
                "EKS",
                "ELASTICACHE",
                "ELASTICBEANSTALK",
                "ELB",
                "EMR",
                "ES",
                "EVENTBRIDGE",
                # F
                "FRAUDDETECTOR",
                "FSX",
                # G
                "GLUE",
                "GLOBALACCELERATOR",
                "GUARDDUTY",
                # I
                "IAM",
                "INSPECTOR",
                "IOT",
                "IOTEVENTS",
                "IOTSITEWISE",
                "IOTTWINMAKER",
                "IOTWIRELESS",
                "IVS",
                # K
                "KEYSPACES",
                "KINESIS",
                "KMS",
                # L
                "LAMBDA",
                # M
                "MACIE",
                "MQ",
                "MSK",
                # N
                "NEPTUNE",
                "NETWORKFIREWALL",
                # O
                "OPENSEARCH",
                # P
                "PCA",
                # R
                "RDS",
                "REDSHIFT",
                "ROUTE53",
                # S
                "S3",
                "SAGEMAKER",
                "SECRETSMANAGER",
                "SECURITYHUB",
                "SNS",
                "SQS",
                "SSM",
                "STEPFUNCTIONS",
                # T
                "TRANSFER",
                # W
                "WAF",
            }
            if prefix in service_prefixes:
                return "fsbp"

        return None

    def _create_grouped_standard_detections(
        self,
        cspm_control_data: dict[str, dict],
        client: Any,
        region: str,
    ) -> list[RawDetection]:
        """Create one RawDetection per security standard with aggregated controls.

        Groups controls by inferred standard (based on control ID pattern) and
        creates one detection per standard.

        Args:
            cspm_control_data: Dict of control_id -> control data
            client: SecurityHub boto3 client (unused, kept for interface compat)
            region: The canonical region for these detections

        Returns:
            List of RawDetection objects, one per standard
        """
        detections = []

        # Group controls by inferred standard
        grouped_controls = self._group_controls_by_standard(cspm_control_data)

        for standard_id, controls in grouped_controls.items():
            if not controls:
                continue

            # Get standard metadata
            standard_info = self._get_standard_info_by_id(standard_id)

            # Calculate metrics - use status_by_region for accurate counts
            enabled_count = 0
            disabled_count = 0
            for control in controls.values():
                status_by_region = control.get("status_by_region", {})
                # A control is "enabled" if enabled in ANY region
                if any(s == "ENABLED" for s in status_by_region.values()):
                    enabled_count += 1
                else:
                    disabled_count += 1

            # Count unique MITRE techniques covered by this standard's controls
            techniques_covered = self._count_techniques_covered(controls)

            # Get hub ARN from first control and extract account ID
            hub_arn = next(iter(controls.values())).get("hub_arn", "")

            # Extract account ID from hub_arn for region-agnostic source_arn
            # hub_arn format: arn:aws:securityhub:REGION:ACCOUNT:hub/default
            account_id = "unknown"
            if hub_arn:
                arn_parts = hub_arn.split(":")
                if len(arn_parts) >= 5:
                    account_id = arn_parts[4]

            # Build controls list for raw_config
            controls_list = []
            for control_id, control_data in controls.items():
                # Determine overall status for this control
                status_by_region = control_data.get("status_by_region", {})
                overall_status = (
                    "ENABLED"
                    if any(s == "ENABLED" for s in status_by_region.values())
                    else "DISABLED"
                )

                controls_list.append(
                    {
                        "control_id": control_id,
                        "control_arn": control_data.get("control_arn"),
                        "title": control_data.get("title"),
                        "description": control_data.get("description"),
                        "status": overall_status,
                        "severity": control_data.get("severity"),
                        "update_status": control_data.get("update_status"),
                        "parameters": control_data.get("parameters", {}),
                        "remediation_url": control_data.get("remediation_url"),
                        "status_by_region": status_by_region,
                    }
                )

            # Use account ID + standard_id for region-agnostic source_arn
            # This ensures ONE detection per standard per account, not per region
            unique_source_arn = (
                f"arn:aws:securityhub:::account/{account_id}/standard/{standard_id}"
            )

            detection = RawDetection(
                name=f"SecurityHub-{standard_info['name']}",
                detection_type=DetectionType.SECURITY_HUB,
                source_arn=unique_source_arn,
                region=region,
                raw_config={
                    "hub_arn": hub_arn,
                    "standard_id": standard_id,
                    "standard_name": standard_info["name"],
                    "enabled_controls_count": enabled_count,
                    "disabled_controls_count": disabled_count,
                    "total_controls_count": len(controls),
                    "techniques_covered_count": len(techniques_covered),
                    "techniques_covered": list(techniques_covered),
                    "controls": controls_list,
                    "api_version": "cspm_aggregated",
                },
                description=standard_info["description"],
                is_managed=True,
            )
            detections.append(detection)

            self.logger.info(
                "securityhub_standard_grouped",
                standard=standard_id,
                total_controls=len(controls),
                enabled=enabled_count,
                disabled=disabled_count,
                techniques=len(techniques_covered),
            )

        return detections

    def _get_standard_info_by_id(self, standard_id: str) -> dict:
        """Get standard metadata by standard ID.

        Args:
            standard_id: The standard identifier (fsbp, cis, pci, nist, other)

        Returns:
            Dict with name and description
        """
        for pattern, info in STANDARD_PATTERNS.items():
            if info["id"] == standard_id:
                return {
                    "name": info["name"],
                    "description": info["description"],
                }

        # Default for 'other' or unknown - just use the ID as name
        # (detection name will add "SecurityHub-" prefix)
        return {
            "name": standard_id.upper(),
            "description": f"Security Hub controls for {standard_id}",
        }

    def _count_techniques_covered(self, controls: dict[str, dict]) -> set[str]:
        """Count unique MITRE techniques covered by a set of controls.

        Uses the securityhub_mappings module to look up technique mappings.
        Only counts techniques from ENABLED controls.

        Args:
            controls: Dict of control_id -> control_data

        Returns:
            Set of unique MITRE technique IDs
        """
        from app.mappers.securityhub_mappings import get_techniques_for_cspm_control

        techniques: set[str] = set()

        for control_id, control_data in controls.items():
            # Only count techniques from enabled controls
            status_by_region = control_data.get("status_by_region", {})
            if any(s == "ENABLED" for s in status_by_region.values()):
                mappings = get_techniques_for_cspm_control(control_id)
                for tech_id, _ in mappings:
                    techniques.add(tech_id)

        return techniques

    def _get_enabled_standards(
        self,
        client: Any,
        region: str,
    ) -> list[dict]:
        """Get enabled Security Hub standards using GetEnabledStandards API.

        This is the authoritative source for which standards are enabled.
        Returns a list of enabled standards with their metadata.

        Args:
            client: SecurityHub boto3 client
            region: AWS region

        Returns:
            List of dicts with standard_id, name, description, subscription_arn
        """
        enabled = []

        try:
            paginator = client.get_paginator("get_enabled_standards")

            for page in paginator.paginate():
                for subscription in page.get("StandardsSubscriptions", []):
                    standards_arn = subscription.get("StandardsArn", "")
                    status = subscription.get("StandardsStatus", "")

                    if status != "READY":
                        continue

                    # Determine standard ID from ARN
                    standard_id = _get_standard_id_from_arn(standards_arn)
                    if not standard_id:
                        # Unknown standard - create ID from ARN
                        if "/" in standards_arn:
                            standard_id = standards_arn.split("/")[-2].replace("-", "_")
                        else:
                            standard_id = "unknown"

                    # Get standard metadata
                    standard_info = self._get_standard_info_by_id(standard_id)

                    enabled.append(
                        {
                            "standard_id": standard_id,
                            "standards_arn": standards_arn,
                            "subscription_arn": subscription.get(
                                "StandardsSubscriptionArn", ""
                            ),
                            "name": standard_info["name"],
                            "description": standard_info["description"],
                            "status": status,
                        }
                    )

        except ClientError as e:
            self.logger.warning(
                "securityhub_get_enabled_standards_error",
                region=region,
                error=str(e),
            )

        return enabled

    def _get_standard_controls(
        self,
        client: Any,
        subscription_arn: str,
    ) -> list[dict]:
        """Get controls for a specific Security Hub standard.

        Uses the DescribeStandardsControls API to get the ACTUAL controls
        for a specific standard (CIS, NIST, FSBP, etc. each have different controls).

        Args:
            client: SecurityHub boto3 client
            subscription_arn: The StandardsSubscriptionArn for the standard

        Returns:
            List of control dicts with control_id, title, status, severity, etc.
        """
        controls = []

        try:
            paginator = client.get_paginator("describe_standards_controls")

            for page in paginator.paginate(StandardsSubscriptionArn=subscription_arn):
                for control in page.get("Controls", []):
                    # Extract control ID from ARN
                    # Format: arn:aws:securityhub:region:account:control/standard/rule-id
                    control_arn = control.get("StandardsControlArn", "")
                    control_id = ""
                    if control_arn:
                        parts = control_arn.split("/")
                        if len(parts) >= 3:
                            control_id = parts[-1]  # e.g., "CIS.1.1" or "IAM.1"

                    controls.append(
                        {
                            "control_id": control_id,
                            "control_arn": control_arn,
                            "title": control.get("Title"),
                            "description": control.get("Description"),
                            "status": control.get("ControlStatus"),  # ENABLED/DISABLED
                            "severity": control.get("SeverityRating"),
                            "disabled_reason": control.get("DisabledReason"),
                            "related_requirements": control.get(
                                "RelatedRequirements", []
                            ),
                            "remediation_url": control.get("RemediationUrl"),
                        }
                    )

            self.logger.info(
                "securityhub_standard_controls_fetched",
                subscription_arn=subscription_arn[:80],  # Truncate for logging
                control_count=len(controls),
            )

        except ClientError as e:
            self.logger.warning(
                "securityhub_describe_standards_controls_error",
                subscription_arn=subscription_arn[:80],
                error=str(e),
            )

        return controls

    def _create_detections_per_enabled_standard(
        self,
        cspm_control_data: dict[str, dict],
        enabled_standards: list[dict],
        hub_arn: str,
        region: str,
        client: Any = None,
    ) -> list[RawDetection]:
        """Create ONE detection per ENABLED Security Hub standard.

        Uses the DescribeStandardsControls API to get the ACTUAL controls for
        each standard (they differ between CIS, NIST, FSBP, etc.).

        Args:
            cspm_control_data: Dict of control_id -> control data from CSPM API
            enabled_standards: List of enabled standards from GetEnabledStandards
            hub_arn: The Security Hub ARN
            region: The canonical region for these detections
            client: SecurityHub boto3 client (optional, for getting per-standard controls)

        Returns:
            List of RawDetection objects, one per enabled standard
        """
        detections = []

        # Extract account ID from hub_arn for region-agnostic source_arn
        # hub_arn format: arn:aws:securityhub:REGION:ACCOUNT:hub/default
        account_id = "unknown"
        if hub_arn:
            arn_parts = hub_arn.split(":")
            if len(arn_parts) >= 5:
                account_id = arn_parts[4]

        for standard in enabled_standards:
            standard_id = standard.get("standard_id", "unknown")
            standard_name = standard.get("name", standard_id.upper())
            standard_description = standard.get(
                "description", f"Security Hub {standard_name}"
            )
            subscription_arn = standard.get("subscription_arn", "")

            # Get controls for THIS specific standard using legacy API
            standard_controls = []
            if client and subscription_arn:
                standard_controls = self._get_standard_controls(
                    client, subscription_arn
                )

            # Calculate metrics from the actual controls for this standard
            enabled_count = 0
            disabled_count = 0
            controls_list = []

            if standard_controls:
                # Use the per-standard controls from DescribeStandardsControls
                for control in standard_controls:
                    if control.get("status") == "ENABLED":
                        enabled_count += 1
                    else:
                        disabled_count += 1

                    # Extract control ID for CSPM enrichment
                    control_id = control.get("control_id", "")
                    # Try to get CSPM data for this control (enhanced details)
                    cspm_data = cspm_control_data.get(control_id, {})

                    controls_list.append(
                        {
                            "control_id": control_id,
                            "control_arn": control.get("control_arn"),
                            "title": control.get("title"),
                            "description": control.get("description"),
                            "status": control.get("status"),
                            "severity": control.get("severity"),
                            "disabled_reason": control.get("disabled_reason"),
                            "related_requirements": control.get(
                                "related_requirements", []
                            ),
                            # Enrich with CSPM data if available
                            "parameters": cspm_data.get("parameters", {}),
                            "remediation_url": cspm_data.get("remediation_url"),
                        }
                    )

                # Count techniques from this standard's controls only
                standard_control_ids = {c.get("control_id") for c in standard_controls}
                filtered_cspm = {
                    k: v
                    for k, v in cspm_control_data.items()
                    if k in standard_control_ids
                }
                techniques_covered = self._count_techniques_covered(filtered_cspm)
            else:
                # Fallback: no per-standard data, use all CSPM controls
                for control in cspm_control_data.values():
                    status_by_region = control.get("status_by_region", {})
                    if any(s == "ENABLED" for s in status_by_region.values()):
                        enabled_count += 1
                    else:
                        disabled_count += 1
                techniques_covered = self._count_techniques_covered(cspm_control_data)
                controls_list = []  # Don't include all controls in fallback

            # Use account ID + standard_id for region-agnostic source_arn
            # This ensures ONE detection per standard per account, not per region
            unique_source_arn = (
                f"arn:aws:securityhub:::account/{account_id}/standard/{standard_id}"
            )

            detection = RawDetection(
                name=f"SecurityHub-{standard_name}",
                detection_type=DetectionType.SECURITY_HUB,
                source_arn=unique_source_arn,
                region=region,
                raw_config={
                    "hub_arn": hub_arn,
                    "standard_id": standard_id,
                    "standard_name": standard_name,
                    "standards_arn": standard.get("standards_arn"),
                    "subscription_arn": subscription_arn,
                    "enabled_controls_count": enabled_count,
                    "disabled_controls_count": disabled_count,
                    "total_controls_count": enabled_count + disabled_count,
                    "techniques_covered_count": len(techniques_covered),
                    "techniques_covered": list(techniques_covered),
                    "controls": controls_list,
                    "api_version": "cspm_per_enabled_standard",
                },
                description=standard_description,
                is_managed=True,
            )
            detections.append(detection)

            self.logger.info(
                "securityhub_standard_detection_created",
                standard=standard_id,
                name=standard_name,
                total_controls=len(cspm_control_data),
                enabled=enabled_count,
                disabled=disabled_count,
                techniques=len(techniques_covered),
            )

        return detections

    def _get_cspm_control_status(
        self,
        client: Any,
        region: str,
    ) -> dict[str, dict]:
        """Get CSPM control status for a region.

        Returns a dict of control_id -> control data including status.
        Returns empty dict if CSPM API is not available.
        """
        controls = {}

        try:
            # Get control definitions
            control_ids = []
            paginator = client.get_paginator("list_security_control_definitions")

            for page in paginator.paginate():
                for control_def in page.get("SecurityControlDefinitions", []):
                    control_ids.append(control_def["SecurityControlId"])

            if not control_ids:
                return {}

            # Batch get control details
            for batch in _chunk_list(control_ids, 100):
                try:
                    response = client.batch_get_security_controls(
                        SecurityControlIds=batch
                    )

                    for control in response.get("SecurityControls", []):
                        control_id = control.get("SecurityControlId", "")
                        controls[control_id] = {
                            "control_id": control_id,
                            "control_arn": control.get("SecurityControlArn"),
                            "title": control.get("Title"),
                            "description": control.get("Description"),
                            "status": control.get("SecurityControlStatus"),
                            "severity": control.get("SeverityRating"),
                            "update_status": control.get("UpdateStatus"),
                            "parameters": control.get("Parameters", {}),
                            "remediation_url": control.get("RemediationUrl"),
                        }

                except ClientError:
                    # If batch fails, continue with next batch
                    pass

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ["AccessDeniedException", "InvalidInputException"]:
                return {}
            raise

        return controls

    async def scan_region(
        self,
        region: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan a single region for Security Hub configurations.

        NOTE: For CSPM controls, use scan() instead which properly
        aggregates status_by_region across all regions.

        This method is kept for backward compatibility and for scanning
        insights and legacy standards in a single region.
        """
        detections = []
        client = self.session.client("securityhub", region_name=region)

        try:
            # Check if Security Hub is enabled
            hub = client.describe_hub()
            hub_arn = hub.get("HubArn", "")

            # Get CSPM controls for this region
            region_status = self._get_cspm_control_status(client, region)

            if region_status:
                # Create grouped standard detections (single-region status only)
                # First, update status_by_region for each control
                for control_id, data in region_status.items():
                    data["status_by_region"] = {region: data.get("status")}
                    data["hub_arn"] = hub_arn

                grouped_detections = self._create_grouped_standard_detections(
                    region_status, client, region
                )
                detections.extend(grouped_detections)
            else:
                # Fall back to legacy standards-based API
                standards_detections = self._scan_enabled_standards(
                    client, region, hub_arn
                )
                detections.extend(standards_detections)

            # Scan custom insights
            insights_detections = self._scan_insights(client, region, hub_arn)
            detections.extend(insights_detections)

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "AccessDeniedException":
                self.logger.warning("securityhub_access_denied", region=region)
            elif error_code in ["InvalidAccessException", "ResourceNotFoundException"]:
                self.logger.info("securityhub_not_enabled", region=region)
            else:
                raise

        return detections

    def _get_control_associations(
        self,
        client: Any,
        control_id: str,
    ) -> list[dict]:
        """Get standard associations for a control.

        Returns which standards this control is associated with and
        whether it's enabled or disabled in each standard.
        """
        associations = []

        try:
            paginator = client.get_paginator("list_standards_control_associations")

            for page in paginator.paginate(SecurityControlId=control_id):
                for assoc in page.get("StandardsControlAssociationSummaries", []):
                    associations.append(
                        {
                            "standards_arn": assoc.get("StandardsArn"),
                            "association_status": assoc.get("AssociationStatus"),
                            "related_requirements": assoc.get(
                                "RelatedRequirements", []
                            ),
                            "updated_at": (
                                assoc.get("UpdatedAt").isoformat()
                                if assoc.get("UpdatedAt")
                                else None
                            ),
                        }
                    )

        except ClientError:
            # If we can't get associations, continue without them
            pass

        return associations

    def _scan_enabled_standards(
        self,
        client: Any,
        region: str,
        hub_arn: str,
    ) -> list[RawDetection]:
        """Scan enabled security standards (legacy API)."""
        detections = []

        try:
            paginator = client.get_paginator("get_enabled_standards")

            for page in paginator.paginate():
                for subscription in page.get("StandardsSubscriptions", []):
                    standard_arn = subscription.get("StandardsArn", "")
                    status = subscription.get("StandardsStatus", "")

                    # Get standard details
                    standard_info = self._get_standard_info(standard_arn)

                    if status == "READY":
                        # Get controls for this standard
                        controls = self._get_standard_controls(
                            client, subscription.get("StandardsSubscriptionArn", "")
                        )

                        detection = RawDetection(
                            name=f"SecurityHub-{standard_info['name']}",
                            detection_type=DetectionType.SECURITY_HUB,
                            source_arn=subscription.get("StandardsSubscriptionArn", ""),
                            region=region,
                            raw_config={
                                "hub_arn": hub_arn,
                                "standard_arn": standard_arn,
                                "standard_name": standard_info["name"],
                                "standards_subscription_arn": subscription.get(
                                    "StandardsSubscriptionArn"
                                ),
                                "status": status,
                                "enabled_controls_count": len(
                                    [c for c in controls if c["status"] == "ENABLED"]
                                ),
                                "disabled_controls_count": len(
                                    [c for c in controls if c["status"] == "DISABLED"]
                                ),
                                "total_controls_count": len(controls),
                                "controls": controls,
                            },
                            description=standard_info["description"],
                            is_managed=True,
                        )
                        detections.append(detection)

        except ClientError as e:
            self.logger.warning(
                "securityhub_standards_error", region=region, error=str(e)
            )

        return detections

    def _get_standard_controls(
        self,
        client: Any,
        standards_subscription_arn: str,
    ) -> list[dict]:
        """Get all controls for an enabled standard."""
        controls = []

        try:
            paginator = client.get_paginator("describe_standards_controls")

            for page in paginator.paginate(
                StandardsSubscriptionArn=standards_subscription_arn
            ):
                for control in page.get("Controls", []):
                    controls.append(
                        {
                            "control_id": control.get("ControlId"),
                            "control_arn": control.get("StandardsControlArn"),
                            "title": control.get("Title"),
                            "description": control.get("Description"),
                            "status": control.get("ControlStatus"),
                            "severity": control.get("SeverityRating"),
                            "disabled_reason": control.get("DisabledReason"),
                            "related_requirements": control.get(
                                "RelatedRequirements", []
                            ),
                        }
                    )

        except ClientError:
            pass

        return controls

    def _get_standard_info(self, standard_arn: str) -> dict:
        """Get human-readable info for a security standard."""
        standards = {
            "aws-foundational-security-best-practices": {
                "name": "AWS-Foundational-Best-Practices",
                "description": "AWS Foundational Security Best Practices - checks for security best practices across AWS services",
            },
            "cis-aws-foundations-benchmark": {
                "name": "CIS-AWS-Foundations",
                "description": "CIS AWS Foundations Benchmark - industry best practice security configuration baseline",
            },
            "pci-dss": {
                "name": "PCI-DSS",
                "description": "PCI DSS - Payment Card Industry Data Security Standard compliance checks",
            },
            "nist-800-53": {
                "name": "NIST-800-53",
                "description": "NIST 800-53 - Security and privacy controls for federal information systems",
            },
        }

        # Extract standard identifier from ARN
        for key in standards.keys():
            if key in standard_arn.lower():
                return standards[key]

        return {
            "name": (
                standard_arn.split("/")[-1] if "/" in standard_arn else standard_arn
            ),
            "description": f"Security Hub standard: {standard_arn}",
        }

    def _scan_insights(
        self,
        client: Any,
        region: str,
        hub_arn: str,
    ) -> list[RawDetection]:
        """Scan Security Hub custom insights."""
        detections = []

        try:
            paginator = client.get_paginator("get_insights")

            for page in paginator.paginate():
                for insight in page.get("Insights", []):
                    insight_arn = insight.get("InsightArn", "")
                    name = insight.get("Name", "")
                    filters = insight.get("Filters", {})
                    group_by = insight.get("GroupByAttribute", "")

                    # Determine if this is a custom or managed insight
                    is_managed = "arn:aws:securityhub:::insight/" in insight_arn

                    detection = RawDetection(
                        name=f"SecurityHub-Insight-{name}",
                        detection_type=DetectionType.SECURITY_HUB,
                        source_arn=insight_arn,
                        region=region,
                        raw_config={
                            "hub_arn": hub_arn,
                            "insight_arn": insight_arn,
                            "insight_name": name,
                            "filters": filters,
                            "group_by_attribute": group_by,
                            "is_managed_insight": is_managed,
                        },
                        description=self._generate_insight_description(
                            name, filters, group_by
                        ),
                        is_managed=is_managed,
                    )
                    detections.append(detection)

        except ClientError as e:
            self.logger.warning(
                "securityhub_insights_error", region=region, error=str(e)
            )

        return detections

    def _generate_insight_description(
        self,
        name: str,
        filters: dict,
        group_by: str,
    ) -> str:
        """Generate a description for a Security Hub insight."""
        description_parts = [f"Security Hub insight '{name}'"]

        if group_by:
            description_parts.append(f"grouped by {group_by}")

        # Add filter information
        filter_descriptions = []
        for filter_key, filter_value in filters.items():
            if isinstance(filter_value, list) and filter_value:
                values = [
                    str(v.get("Value", v)) for v in filter_value if isinstance(v, dict)
                ]
                if values:
                    filter_descriptions.append(f"{filter_key}: {', '.join(values[:3])}")

        if filter_descriptions:
            description_parts.append(
                f"filtering on {'; '.join(filter_descriptions[:5])}"
            )

        return " - ".join(description_parts)
