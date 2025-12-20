"""GCP Organisation-Level Security Command Center Scanner.

Scans for organisation-level SCC configurations including:
- Notification configs at org level
- SCC settings and modules
- Finding sources across the organisation
- Security posture (if enabled)
"""

from typing import Any, Optional

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


class OrgSecurityCommandCenterScanner(BaseScanner):
    """Scanner for organisation-level Security Command Center configurations.

    At the organisation level, SCC provides:
    - Centralised view of security findings across all projects
    - Organisation-level notification configs
    - Security Health Analytics for all resources
    - Event Threat Detection across the org
    - Container Threat Detection for all GKE clusters
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_SECURITY_COMMAND_CENTER

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for organisation-level SCC configurations.

        Args:
            regions: Not used (SCC is global)
            options: Must include 'organization_id'
                - organization_id: GCP organisation ID

        Returns:
            List of RawDetection for org-level SCC configs
        """
        detections = []
        options = options or {}
        org_id = options.get("organization_id")

        if not org_id:
            self.logger.error("organization_id_required")
            return []

        try:
            from google.cloud import securitycenter_v1
            from google.api_core.exceptions import PermissionDenied

            client = securitycenter_v1.SecurityCenterClient(credentials=self.session)

            parent = f"organizations/{org_id}"

            # Scan notification configs at org level
            notification_detections = await self._scan_notification_configs(
                client, parent, org_id
            )
            detections.extend(notification_detections)

            # Scan finding sources (managed detection modules)
            source_detections = await self._scan_finding_sources(client, parent, org_id)
            detections.extend(source_detections)

            # Scan big query exports (log export configurations)
            export_detections = await self._scan_bigquery_exports(
                client, parent, org_id
            )
            detections.extend(export_detections)

            # Scan mute configs (suppression rules)
            mute_detections = await self._scan_mute_configs(client, parent, org_id)
            detections.extend(mute_detections)

            self.logger.info(
                "org_scc_scan_complete",
                org_id=org_id,
                notification_count=len(notification_detections),
                source_count=len(source_detections),
                export_count=len(export_detections),
                mute_count=len(mute_detections),
            )

        except PermissionDenied as e:
            self.logger.warning(
                "permission_denied_org_scc",
                org_id=org_id,
                error=str(e),
            )
        except Exception as e:
            self.logger.error(
                "org_scc_scan_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    async def _scan_notification_configs(
        self, client, parent: str, org_id: str
    ) -> list[RawDetection]:
        """Scan for organisation-level notification configurations."""
        detections = []

        try:
            request = {"parent": parent}

            for config in client.list_notification_configs(request=request):
                detection = self._create_notification_detection(config, org_id)
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.warning(
                "scan_org_notification_configs_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    def _create_notification_detection(
        self, config, org_id: str
    ) -> Optional[RawDetection]:
        """Create a RawDetection from an SCC notification config."""
        config_name = config.name
        short_name = config_name.split("/")[-1]
        description = config.description or ""
        pubsub_topic = config.pubsub_topic

        # Extract filter from streaming config
        filter_string = ""
        if config.streaming_config:
            filter_string = config.streaming_config.filter or ""

        return RawDetection(
            name=f"Org SCC Notification: {short_name}",
            detection_type=self.detection_type,
            source_arn=config_name,
            region="global",
            raw_config={
                "name": config_name,
                "short_name": short_name,
                "description": description,
                "pubsub_topic": pubsub_topic,
                "filter": filter_string,
                "service_account": (
                    config.service_account
                    if hasattr(config, "service_account")
                    else None
                ),
                "scope": "organization",
                "org_id": org_id,
            },
            query_pattern=filter_string,
            description=description or f"Org SCC notification: {short_name}",
            is_managed=True,
        )

    async def _scan_finding_sources(
        self, client, parent: str, org_id: str
    ) -> list[RawDetection]:
        """Scan for SCC finding sources at organisation level."""
        detections = []

        try:
            request = {"parent": parent}

            for source in client.list_sources(request=request):
                detection = self._create_source_detection(source, org_id)
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.warning(
                "scan_org_finding_sources_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    def _create_source_detection(self, source, org_id: str) -> Optional[RawDetection]:
        """Create a RawDetection from an SCC finding source."""
        source_name = source.name
        display_name = source.display_name or source_name.split("/")[-1]
        description = source.description or ""

        # Identify managed Google sources
        is_managed = any(
            name in display_name.lower()
            for name in [
                "security health analytics",
                "event threat detection",
                "container threat detection",
                "virtual machine threat detection",
                "web security scanner",
            ]
        )

        return RawDetection(
            name=f"Org SCC Source: {display_name}",
            detection_type=self.detection_type,
            source_arn=source_name,
            region="global",
            raw_config={
                "name": source_name,
                "display_name": display_name,
                "description": description,
                "canonical_name": (
                    source.canonical_name if hasattr(source, "canonical_name") else None
                ),
                "scope": "organization",
                "org_id": org_id,
            },
            description=description or f"SCC finding source: {display_name}",
            is_managed=is_managed,
        )

    async def _scan_bigquery_exports(
        self, client, parent: str, org_id: str
    ) -> list[RawDetection]:
        """Scan for BigQuery export configurations."""
        detections = []

        try:
            request = {"parent": parent}

            for export in client.list_big_query_exports(request=request):
                detection = self._create_export_detection(export, org_id)
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.warning(
                "scan_org_bq_exports_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    def _create_export_detection(self, export, org_id: str) -> Optional[RawDetection]:
        """Create a RawDetection from a BigQuery export config."""
        export_name = export.name
        short_name = export_name.split("/")[-1]
        dataset = export.dataset
        description = export.description or ""
        filter_string = export.filter or ""

        return RawDetection(
            name=f"Org SCC BQ Export: {short_name}",
            detection_type=self.detection_type,
            source_arn=export_name,
            region="global",
            raw_config={
                "name": export_name,
                "short_name": short_name,
                "dataset": dataset,
                "description": description,
                "filter": filter_string,
                "create_time": (
                    export.create_time.isoformat()
                    if hasattr(export, "create_time") and export.create_time
                    else None
                ),
                "update_time": (
                    export.update_time.isoformat()
                    if hasattr(export, "update_time") and export.update_time
                    else None
                ),
                "scope": "organization",
                "org_id": org_id,
            },
            query_pattern=filter_string,
            description=description or f"SCC BigQuery export to {dataset}",
            is_managed=False,
        )

    async def _scan_mute_configs(
        self, client, parent: str, org_id: str
    ) -> list[RawDetection]:
        """Scan for mute configurations (finding suppression rules)."""
        detections = []

        try:
            request = {"parent": parent}

            for mute_config in client.list_mute_configs(request=request):
                detection = self._create_mute_detection(mute_config, org_id)
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.warning(
                "scan_org_mute_configs_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    def _create_mute_detection(
        self, mute_config, org_id: str
    ) -> Optional[RawDetection]:
        """Create a RawDetection from a mute configuration.

        Mute configs are important as they can suppress security findings.
        Tracking them helps ensure legitimate findings aren't being hidden.
        """
        config_name = mute_config.name
        short_name = config_name.split("/")[-1]
        description = mute_config.description or ""
        filter_string = mute_config.filter or ""

        return RawDetection(
            name=f"Org SCC Mute Config: {short_name}",
            detection_type=self.detection_type,
            source_arn=config_name,
            region="global",
            raw_config={
                "name": config_name,
                "short_name": short_name,
                "description": description,
                "filter": filter_string,
                "create_time": (
                    mute_config.create_time.isoformat()
                    if hasattr(mute_config, "create_time") and mute_config.create_time
                    else None
                ),
                "update_time": (
                    mute_config.update_time.isoformat()
                    if hasattr(mute_config, "update_time") and mute_config.update_time
                    else None
                ),
                "scope": "organization",
                "org_id": org_id,
                "is_mute_config": True,
            },
            query_pattern=filter_string,
            description=f"SCC mute config: {description or short_name}",
            is_managed=False,
        )


class SCCSecurityPostureScanner(BaseScanner):
    """Scanner for GCP Security Posture configurations.

    Security Posture is a feature that allows defining and enforcing
    security policies across the organisation.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_SECURITY_COMMAND_CENTER

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for Security Posture deployments.

        Args:
            regions: Not used
            options: Must include 'organization_id'

        Returns:
            List of RawDetection for security postures
        """
        detections = []
        options = options or {}
        org_id = options.get("organization_id")

        if not org_id:
            self.logger.error("organization_id_required")
            return []

        try:
            # Security Posture API is relatively new
            # Using securityposture_v1 if available
            from google.cloud import securityposture_v1
            from google.api_core.exceptions import PermissionDenied

            client = securityposture_v1.SecurityPostureClient(credentials=self.session)

            parent = f"organizations/{org_id}/locations/global"

            # List postures
            request = {"parent": parent}
            for posture in client.list_postures(request=request):
                detection = self._create_posture_detection(posture, org_id)
                if detection:
                    detections.append(detection)

            # List posture deployments
            for deployment in client.list_posture_deployments(request=request):
                detection = self._create_deployment_detection(deployment, org_id)
                if detection:
                    detections.append(detection)

            self.logger.info(
                "security_posture_scan_complete",
                org_id=org_id,
                count=len(detections),
            )

        except ImportError:
            self.logger.info("security_posture_api_not_available")
        except PermissionDenied as e:
            self.logger.warning(
                "permission_denied_security_posture",
                org_id=org_id,
                error=str(e),
            )
        except Exception as e:
            self.logger.warning(
                "security_posture_scan_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    def _create_posture_detection(self, posture, org_id: str) -> Optional[RawDetection]:
        """Create a RawDetection from a security posture."""
        posture_name = posture.name
        short_name = posture_name.split("/")[-1]
        description = posture.description or ""

        return RawDetection(
            name=f"Security Posture: {short_name}",
            detection_type=self.detection_type,
            source_arn=posture_name,
            region="global",
            raw_config={
                "name": posture_name,
                "short_name": short_name,
                "description": description,
                "state": str(posture.state) if hasattr(posture, "state") else None,
                "revision_id": (
                    posture.revision_id if hasattr(posture, "revision_id") else None
                ),
                "policy_sets_count": (
                    len(posture.policy_sets) if posture.policy_sets else 0
                ),
                "scope": "organization",
                "org_id": org_id,
            },
            description=description or f"Security posture: {short_name}",
            is_managed=False,
        )

    def _create_deployment_detection(
        self, deployment, org_id: str
    ) -> Optional[RawDetection]:
        """Create a RawDetection from a posture deployment."""
        deployment_name = deployment.name
        short_name = deployment_name.split("/")[-1]
        description = deployment.description or ""
        target_resource = deployment.target_resource or ""

        return RawDetection(
            name=f"Posture Deployment: {short_name}",
            detection_type=self.detection_type,
            source_arn=deployment_name,
            region="global",
            raw_config={
                "name": deployment_name,
                "short_name": short_name,
                "description": description,
                "target_resource": target_resource,
                "state": (
                    str(deployment.state) if hasattr(deployment, "state") else None
                ),
                "posture_id": (
                    deployment.posture_id if hasattr(deployment, "posture_id") else None
                ),
                "posture_revision_id": (
                    deployment.posture_revision_id
                    if hasattr(deployment, "posture_revision_id")
                    else None
                ),
                "scope": "organization",
                "org_id": org_id,
            },
            description=f"Posture deployment to {target_resource}",
            is_managed=False,
        )
