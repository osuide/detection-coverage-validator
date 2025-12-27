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
"""

from typing import Any, Optional
from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


def _chunk_list(items: list, chunk_size: int) -> list[list]:
    """Split a list into chunks of specified size."""
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


class SecurityHubScanner(BaseScanner):
    """Scanner for AWS Security Hub enabled standards and insights.

    Security Hub aggregates findings from multiple AWS security services.
    This scanner discovers:
    - Enabled security standards (CIS, PCI-DSS, AWS Foundational)
    - Custom insights
    - Aggregated finding patterns
    - Consolidated security controls (via CSPM API)
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
        3. Create ONE detection per control with status_by_region map

        Insights are scanned per-region as they may differ.
        """
        all_detections = []

        # Phase 1: Collect CSPM control data across all regions
        cspm_control_data: dict[str, dict] = {}  # control_id -> merged data
        cspm_scanned = False
        first_cspm_region = None

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

        # Phase 2: Create CSPM detections with merged status_by_region
        if cspm_control_data:
            for control_id, data in cspm_control_data.items():
                detection = RawDetection(
                    name=f"SecurityHub-Control-{control_id}",
                    detection_type=DetectionType.SECURITY_HUB,
                    source_arn=data.get("control_arn", ""),
                    region=first_cspm_region,  # Use first region as canonical
                    raw_config={
                        "hub_arn": data.get("hub_arn"),
                        "control_id": control_id,
                        "control_arn": data.get("control_arn"),
                        "title": data.get("title"),
                        "severity": data.get("severity"),
                        "update_status": data.get("update_status"),
                        "parameters": data.get("parameters", {}),
                        "remediation_url": data.get("remediation_url"),
                        "status_by_region": data.get("status_by_region", {}),
                        "api_version": "cspm",
                    },
                    description=data.get("description", ""),
                    is_managed=True,
                )
                all_detections.append(detection)

            self.logger.info(
                "securityhub_cspm_complete",
                total_controls=len(cspm_control_data),
                regions_scanned=len(regions),
            )

        return all_detections

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
                # Create detections (single-region status only)
                for control_id, data in region_status.items():
                    detection = RawDetection(
                        name=f"SecurityHub-Control-{control_id}",
                        detection_type=DetectionType.SECURITY_HUB,
                        source_arn=data.get("control_arn", ""),
                        region=region,
                        raw_config={
                            "hub_arn": hub_arn,
                            "control_id": control_id,
                            "control_arn": data.get("control_arn"),
                            "title": data.get("title"),
                            "severity": data.get("severity"),
                            "update_status": data.get("update_status"),
                            "parameters": data.get("parameters", {}),
                            "remediation_url": data.get("remediation_url"),
                            "status_by_region": {region: data.get("status")},
                            "api_version": "cspm",
                        },
                        description=data.get("description", ""),
                        is_managed=True,
                    )
                    detections.append(detection)
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
        """Scan enabled security standards."""
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
