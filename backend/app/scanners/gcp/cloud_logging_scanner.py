"""GCP Cloud Logging scanner following 04-PARSER-AGENT.md design.

Discovers log-based metrics and saved queries that can be used as detections.
"""

from typing import Any, Optional

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


class CloudLoggingScanner(BaseScanner):
    """Scanner for GCP Cloud Logging log-based metrics and saved queries.

    Discovers log-based metrics which are used to create alerts based on
    matching log entries - commonly used for security monitoring.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_CLOUD_LOGGING

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan GCP project for Cloud Logging metrics and queries.

        Note: GCP logging is global (not regional), so we scan once for the project.
        The regions parameter is kept for interface compatibility.
        """
        all_detections = []
        project_id = options.get("project_id") if options else None

        if not project_id:
            self.logger.error("project_id_required")
            return []

        self.logger.info("scanning_gcp_logging", project_id=project_id)

        try:
            # Import GCP client libraries
            from google.cloud import logging_v2
            from google.api_core.exceptions import GoogleAPIError, PermissionDenied

            # Create logging client using the session credentials
            client = logging_v2.MetricsServiceV2Client(credentials=self.session)

            # Scan log-based metrics
            metrics_detections = await self._scan_log_metrics(client, project_id)
            all_detections.extend(metrics_detections)

            self.logger.info(
                "gcp_logging_scan_complete",
                project_id=project_id,
                metrics_count=len(metrics_detections),
            )

        except PermissionDenied as e:
            self.logger.warning(
                "gcp_permission_denied", project_id=project_id, error=str(e)
            )
        except GoogleAPIError as e:
            self.logger.error("gcp_api_error", project_id=project_id, error=str(e))
        except ImportError:
            self.logger.error("gcp_client_not_installed")

        return all_detections

    async def _scan_log_metrics(
        self,
        client: Any,
        project_id: str,
    ) -> list[RawDetection]:
        """Scan for log-based metrics in the project."""
        detections = []

        try:
            # List all log-based metrics in the project
            parent = f"projects/{project_id}"
            request = {"parent": parent}

            for metric in client.list_log_metrics(request=request):
                detection = self._parse_log_metric(metric, project_id)
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.error("log_metrics_scan_error", error=str(e))

        return detections

    def _parse_log_metric(
        self,
        metric: Any,
        project_id: str,
    ) -> Optional[RawDetection]:
        """Parse a GCP log-based metric into RawDetection.

        Log-based metrics are defined with a filter that matches log entries.
        They are commonly used to create alerts for security events.
        """
        metric_name = metric.name
        filter_string = metric.filter
        description = metric.description or ""

        # Build resource name (GCP equivalent of ARN)
        resource_name = f"projects/{project_id}/metrics/{metric_name}"

        # Check if this appears to be security-relevant
        if not self._is_security_relevant(metric_name, filter_string, description):
            return None

        return RawDetection(
            name=metric_name,
            detection_type=DetectionType.GCP_CLOUD_LOGGING,
            source_arn=resource_name,  # Using source_arn for GCP resource name
            region="global",  # Cloud Logging is global
            raw_config={
                "name": metric_name,
                "filter": filter_string,
                "description": description,
                "metricDescriptor": {
                    "metricKind": (
                        str(metric.metric_descriptor.metric_kind)
                        if metric.metric_descriptor
                        else None
                    ),
                    "valueType": (
                        str(metric.metric_descriptor.value_type)
                        if metric.metric_descriptor
                        else None
                    ),
                },
                "labelExtractors": (
                    dict(metric.label_extractors) if metric.label_extractors else {}
                ),
                "bucketOptions": (
                    str(metric.bucket_options) if metric.bucket_options else None
                ),
                "version": str(metric.version) if hasattr(metric, "version") else None,
            },
            query_pattern=filter_string,
            description=description or f"GCP log-based metric: {metric_name}",
            is_managed=False,
        )

    def _is_security_relevant(
        self,
        name: str,
        filter_string: str,
        description: str,
    ) -> bool:
        """Check if a log metric is security-relevant based on filter and name."""
        # Security-relevant GCP log types
        security_log_types = [
            "cloudaudit.googleapis.com",
            "data_access",
            "admin_activity",
            "system_event",
            "policy_violation",
        ]

        # Security-relevant keywords
        security_keywords = [
            "security",
            "unauthorized",
            "denied",
            "failed",
            "anomaly",
            "suspicious",
            "threat",
            "attack",
            "violation",
            "breach",
            "alert",
            "iam",
            "permission",
            "authentication",
            "login",
            "access",
            "credential",
            "delete",
            "modify",
            "create",
            "admin",
            "privilege",
        ]

        # Security-relevant GCP audit log methods
        security_methods = [
            "SetIamPolicy",
            "CreateServiceAccountKey",
            "DeleteServiceAccountKey",
            "CreateRole",
            "DeleteRole",
            "UpdateRole",
            "CreateBucket",
            "DeleteBucket",
            "SetBucketIamPolicy",
            "CreateInstance",
            "DeleteInstance",
            "StopInstance",
            "SetFirewallRule",
            "DeleteFirewallRule",
        ]

        combined_text = f"{name} {filter_string} {description}".lower()

        # Check for security log types
        for log_type in security_log_types:
            if log_type.lower() in combined_text:
                return True

        # Check for security keywords
        for keyword in security_keywords:
            if keyword in combined_text:
                return True

        # Check for security-relevant methods in the filter
        for method in security_methods:
            if method.lower() in combined_text:
                return True

        return False


class CloudLoggingQueryScanner(BaseScanner):
    """Scanner for saved Cloud Logging queries.

    Note: GCP doesn't have a native "saved queries" API like CloudWatch Logs Insights.
    Log-based metrics are the primary mechanism for persistent log analysis.
    This scanner is provided for future extensibility.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_CLOUD_LOGGING

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Placeholder for future saved query scanning."""
        # GCP Log Analytics (BigQuery-based) queries could be added here
        return []
