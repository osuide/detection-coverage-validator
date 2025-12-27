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


# Standard ARN patterns for grouping
STANDARD_PATTERNS = {
    "aws-foundational-security-best-practices": {
        "id": "fsbp",
        "name": "AWS-Foundational-Best-Practices",
        "description": "AWS Foundational Security Best Practices - checks for security best practices across AWS services",
    },
    "cis-aws-foundations-benchmark": {
        "id": "cis",
        "name": "CIS-AWS-Foundations",
        "description": "CIS AWS Foundations Benchmark - industry best practice security configuration baseline",
    },
    "pci-dss": {
        "id": "pci",
        "name": "PCI-DSS",
        "description": "PCI DSS - Payment Card Industry Data Security Standard compliance checks",
    },
    "nist-800-53": {
        "id": "nist",
        "name": "NIST-800-53",
        "description": "NIST 800-53 - Security and privacy controls for federal information systems",
    },
}


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

        CSPM control DEFINITIONS are global, but STATUS can vary by region.
        We:
        1. Get control definitions from the first region (global)
        2. Get control STATUS from ALL regions
        3. Group controls by security standard
        4. Create ONE detection per standard with aggregated metrics

        Insights are scanned per-region as they may differ.
        """
        all_detections = []

        # Phase 1: Collect CSPM control data across all regions
        cspm_control_data: dict[str, dict] = {}  # control_id -> merged data
        cspm_scanned = False
        first_cspm_region = None
        first_client = None

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

                # Get CSPM control status for this region
                region_status = self._get_cspm_control_status(client, region)

                if region_status:
                    if not cspm_scanned:
                        # First region with CSPM - store full control data
                        first_cspm_region = region
                        first_client = client
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

        # Phase 2: Group CSPM controls by standard and create aggregated detections
        if cspm_control_data and first_client:
            grouped_detections = self._create_grouped_standard_detections(
                cspm_control_data,
                first_client,
                first_cspm_region,
            )
            all_detections.extend(grouped_detections)

            self.logger.info(
                "securityhub_cspm_complete",
                total_controls=len(cspm_control_data),
                standards_created=len(grouped_detections),
                regions_scanned=len(regions),
            )

        return all_detections

    def _group_controls_by_standard(
        self,
        cspm_control_data: dict[str, dict],
    ) -> dict[str, dict[str, dict]]:
        """Group CSPM controls by their associated security standard.

        Uses control ID prefix patterns to infer standard:
        - S3.x, IAM.x, EC2.x -> FSBP (service prefix with number)
        - 1.x, 2.x, 3.x -> CIS (numeric section.control)
        - PCI.x -> PCI-DSS (explicit PCI prefix)

        Args:
            cspm_control_data: Dict of control_id -> control data

        Returns:
            Dict of standard_id -> {control_id -> control_data}
            Standard IDs are: 'fsbp', 'cis', 'pci', 'nist', 'other'
        """
        grouped: dict[str, dict[str, dict]] = {
            "fsbp": {},
            "cis": {},
            "pci": {},
            "nist": {},
            "other": {},  # Controls without standard associations
        }

        # Track sample control IDs for debugging
        sample_controls = list(cspm_control_data.keys())[:10]
        self.logger.debug(
            "grouping_controls_sample",
            sample_control_ids=sample_controls,
            total_controls=len(cspm_control_data),
        )

        for control_id, control_data in cspm_control_data.items():
            # Infer standard from control ID prefix
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

        # Remove empty standard groups
        return {k: v for k, v in grouped.items() if v}

    def _infer_standard_from_control_id(self, control_id: str) -> Optional[str]:
        """Infer standard from control ID prefix pattern.

        CSPM control IDs follow patterns like:
        - S3.1, IAM.1, EC2.18 -> FSBP (service prefix with number)
        - 1.1, 2.3, 3.14 -> CIS (numeric section.control)
        - PCI.IAM.1 -> PCI-DSS (explicit PCI prefix)

        Args:
            control_id: The CSPM control ID

        Returns:
            Standard ID or None if cannot be inferred
        """
        control_upper = control_id.upper()

        # Explicit PCI prefix
        if control_upper.startswith("PCI."):
            return "pci"

        # CIS pattern: starts with digit (e.g., 1.1, 2.3)
        if control_id and control_id[0].isdigit():
            return "cis"

        # FSBP pattern: service prefix (e.g., S3.1, IAM.1, EC2.18)
        # Most common pattern for service-based controls
        if "." in control_id:
            prefix = control_id.split(".")[0].upper()
            # Common AWS service prefixes
            service_prefixes = {
                "S3",
                "IAM",
                "EC2",
                "RDS",
                "ECS",
                "EKS",
                "EFS",
                "KMS",
                "LAMBDA",
                "DYNAMODB",
                "REDSHIFT",
                "ELASTICACHE",
                "ES",
                "OPENSEARCH",
                "APIGATEWAY",
                "CLOUDTRAIL",
                "CONFIG",
                "GUARDDUTY",
                "SECRETSMANAGER",
                "SNS",
                "SQS",
                "SSM",
                "WAF",
                "ELB",
                "AUTOSCALING",
                "CODEBUILD",
                "ACCOUNT",
                "ACM",
                "CLOUDFRONT",
                "CLOUDWATCH",
                "DOCDB",
                "ECR",
                "EMR",
                "KINESIS",
                "MACIE",
                "MQ",
                "MSK",
                "NEPTUNE",
                "NETWORKFIREWALL",
                "SAGEMAKER",
                "STEPFUNCTIONS",
                "TRANSFER",
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

        Args:
            cspm_control_data: Dict of control_id -> control data
            client: SecurityHub boto3 client
            region: The canonical region for these detections

        Returns:
            List of RawDetection objects, one per standard
        """
        detections = []

        # Group controls by standard
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

            # Get hub ARN from first control
            hub_arn = next(iter(controls.values())).get("hub_arn", "")

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

            # Use unique source_arn per standard to prevent overwriting
            # Format: hub_arn#standard_id (e.g., arn:aws:securityhub:...:hub/default#fsbp)
            unique_source_arn = f"{hub_arn}#{standard_id}"

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
