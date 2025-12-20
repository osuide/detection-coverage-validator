"""GCP Security Command Center scanner following 04-PARSER-AGENT.md design.

Discovers SCC notification configs and findings that represent managed detections.
"""

from typing import Any, Optional

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


class SecurityCommandCenterScanner(BaseScanner):
    """Scanner for GCP Security Command Center findings and notification configs.

    Security Command Center provides managed threat detection similar to AWS GuardDuty.
    This scanner discovers:
    - NotificationConfigs (alert configurations)
    - Active finding categories (what SCC is detecting)
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_SECURITY_COMMAND_CENTER

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan GCP organization/project for Security Command Center configs.

        Note: SCC is organization-level, not regional.
        """
        all_detections = []
        organization_id = options.get("organization_id") if options else None
        project_id = options.get("project_id") if options else None

        if not organization_id and not project_id:
            self.logger.error("organization_or_project_required")
            return []

        parent = (
            f"organizations/{organization_id}"
            if organization_id
            else f"projects/{project_id}"
        )

        self.logger.info("scanning_scc", parent=parent)

        try:
            from google.cloud import securitycenter_v1
            from google.api_core.exceptions import GoogleAPIError, PermissionDenied

            # Create SCC client
            client = securitycenter_v1.SecurityCenterClient(credentials=self.session)

            # Scan notification configs
            notification_detections = await self._scan_notification_configs(
                client, parent
            )
            all_detections.extend(notification_detections)

            # Scan for active finding sources (managed detections)
            source_detections = await self._scan_finding_sources(client, parent)
            all_detections.extend(source_detections)

            self.logger.info(
                "scc_scan_complete",
                parent=parent,
                notification_count=len(notification_detections),
                source_count=len(source_detections),
            )

        except PermissionDenied as e:
            self.logger.warning("scc_permission_denied", parent=parent, error=str(e))
        except GoogleAPIError as e:
            self.logger.error("scc_api_error", parent=parent, error=str(e))
        except ImportError:
            self.logger.error("scc_client_not_installed")

        return all_detections

    async def _scan_notification_configs(
        self,
        client: Any,
        parent: str,
    ) -> list[RawDetection]:
        """Scan for SCC notification configurations."""
        detections = []

        try:
            # List notification configs
            request = {"parent": parent}

            for config in client.list_notification_configs(request=request):
                detection = self._parse_notification_config(config, parent)
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.error("notification_config_scan_error", error=str(e))

        return detections

    def _parse_notification_config(
        self,
        config: Any,
        parent: str,
    ) -> Optional[RawDetection]:
        """Parse an SCC notification config into RawDetection."""
        config_name = config.name
        description = config.description or ""
        pubsub_topic = config.pubsub_topic
        streaming_config = config.streaming_config

        # Extract filter from streaming config
        filter_string = ""
        if streaming_config:
            filter_string = streaming_config.filter or ""

        return RawDetection(
            name=config_name.split("/")[-1],  # Extract short name
            detection_type=DetectionType.GCP_SECURITY_COMMAND_CENTER,
            source_arn=config_name,
            region="global",
            raw_config={
                "name": config_name,
                "description": description,
                "pubsubTopic": pubsub_topic,
                "streamingConfig": (
                    {
                        "filter": filter_string,
                    }
                    if streaming_config
                    else None
                ),
                "serviceAccount": (
                    config.service_account
                    if hasattr(config, "service_account")
                    else None
                ),
            },
            query_pattern=filter_string,
            description=description or f"SCC notification config: {config_name}",
            is_managed=True,
        )

    async def _scan_finding_sources(
        self,
        client: Any,
        parent: str,
    ) -> list[RawDetection]:
        """Scan for SCC finding sources (managed detection capabilities)."""
        detections = []

        try:
            # List sources (finding producers)
            request = {"parent": parent}

            for source in client.list_sources(request=request):
                detection = self._parse_finding_source(source, parent)
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.error("finding_sources_scan_error", error=str(e))

        return detections

    def _parse_finding_source(
        self,
        source: Any,
        parent: str,
    ) -> Optional[RawDetection]:
        """Parse an SCC finding source into RawDetection.

        Sources include:
        - Built-in sources (Security Health Analytics, Event Threat Detection, etc.)
        - Third-party integrations
        - Custom sources
        """
        source_name = source.name
        display_name = source.display_name or source_name.split("/")[-1]
        description = source.description or ""

        return RawDetection(
            name=display_name,
            detection_type=DetectionType.GCP_SECURITY_COMMAND_CENTER,
            source_arn=source_name,
            region="global",
            raw_config={
                "name": source_name,
                "displayName": display_name,
                "description": description,
                "canonicalName": (
                    source.canonical_name if hasattr(source, "canonical_name") else None
                ),
            },
            description=description or f"SCC finding source: {display_name}",
            is_managed=True,  # SCC sources are managed detections
        )


# SCC Finding Types to MITRE ATT&CK mapping (vendor-provided)
# Based on Google Cloud Security Command Center documentation
SCC_FINDING_MITRE_MAPPING = {
    # Event Threat Detection findings
    "MALWARE": ["T1204"],
    "CRYPTOMINING": ["T1496"],
    "OUTGOING_INTRUSION": ["T1048"],
    "INCOMING_INTRUSION": ["T1190"],
    "REVERSE_SHELL": ["T1059"],
    "SUSPICIOUS_LOGIN": ["T1078"],
    "BRUTE_FORCE": ["T1110"],
    "SSH_BRUTE_FORCE": ["T1110.001"],
    "PERSISTENCE": ["T1098", "T1136"],
    "DEFENSE_EVASION": ["T1562"],
    "INITIAL_ACCESS": ["T1078", "T1199"],
    "DISCOVERY": ["T1580", "T1526"],
    "LATERAL_MOVEMENT": ["T1550"],
    "EXFILTRATION": ["T1537"],
    "CREDENTIAL_ACCESS": ["T1552", "T1528"],
    # Security Health Analytics findings
    "MFA_NOT_ENFORCED": ["T1078"],
    "ADMIN_SERVICE_ACCOUNT": ["T1078.004"],
    "SERVICE_ACCOUNT_KEY_NOT_ROTATED": ["T1528"],
    "OVER_PRIVILEGED_SERVICE_ACCOUNT": ["T1078.004"],
    "PUBLIC_BUCKET": ["T1530"],
    "PUBLIC_IP_ADDRESS": ["T1190"],
    "OPEN_FIREWALL": ["T1190"],
    "OPEN_SSH_PORT": ["T1021.004"],
    "OPEN_RDP_PORT": ["T1021.001"],
    "WEAK_SSL_POLICY": ["T1557"],
    "SQL_NO_ROOT_PASSWORD": ["T1078"],
    "SQL_PUBLIC_IP": ["T1190"],
    # Web Security Scanner findings
    "XSS": ["T1189"],
    "SQL_INJECTION": ["T1190"],
    "MIXED_CONTENT": ["T1557"],
    "OUTDATED_LIBRARY": ["T1190"],
}
