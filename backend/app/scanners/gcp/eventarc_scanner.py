"""GCP Eventarc scanner following 04-PARSER-AGENT.md design.

Discovers Eventarc triggers that respond to cloud events (similar to EventBridge).
"""

from typing import Any, Optional

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


class EventarcScanner(BaseScanner):
    """Scanner for GCP Eventarc triggers.

    Eventarc enables event-driven architectures by connecting GCP services
    to event handlers. Security-relevant triggers include:
    - Audit log event triggers
    - Pub/Sub event triggers for security topics
    - Direct event triggers for GCP service events
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_EVENTARC

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan GCP project for Eventarc triggers."""
        all_detections = []
        project_id = options.get("project_id") if options else None

        if not project_id:
            self.logger.error("project_id_required")
            return []

        self.logger.info("scanning_eventarc", project_id=project_id)

        try:
            from google.cloud import eventarc_v1
            from google.api_core.exceptions import GoogleAPIError, PermissionDenied

            # Create Eventarc client
            client = eventarc_v1.EventarcClient(credentials=self.session)

            # Eventarc triggers are regional, scan each region
            for region in regions:
                try:
                    region_detections = await self._scan_region_triggers(
                        client, project_id, region
                    )
                    all_detections.extend(region_detections)
                except PermissionDenied:
                    self.logger.warning("eventarc_permission_denied", region=region)
                except Exception as e:
                    self.logger.error("eventarc_region_error", region=region, error=str(e))

            self.logger.info(
                "eventarc_scan_complete",
                project_id=project_id,
                trigger_count=len(all_detections),
            )

        except ImportError:
            self.logger.error("eventarc_client_not_installed")
        except GoogleAPIError as e:
            self.logger.error("eventarc_api_error", error=str(e))

        return all_detections

    async def _scan_region_triggers(
        self,
        client: Any,
        project_id: str,
        region: str,
    ) -> list[RawDetection]:
        """Scan for Eventarc triggers in a specific region."""
        detections = []

        try:
            parent = f"projects/{project_id}/locations/{region}"
            request = {"parent": parent}

            for trigger in client.list_triggers(request=request):
                detection = self._parse_trigger(trigger, project_id, region)
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.error("trigger_scan_error", region=region, error=str(e))

        return detections

    def _parse_trigger(
        self,
        trigger: Any,
        project_id: str,
        region: str,
    ) -> Optional[RawDetection]:
        """Parse an Eventarc trigger into RawDetection."""
        trigger_name = trigger.name
        short_name = trigger_name.split("/")[-1]

        # Extract event filters (matching criteria)
        event_filters = []
        matching_criteria = []

        if trigger.event_filters:
            for event_filter in trigger.event_filters:
                filter_dict = {
                    "attribute": event_filter.attribute,
                    "value": event_filter.value,
                    "operator": event_filter.operator if hasattr(event_filter, 'operator') else "=",
                }
                event_filters.append(filter_dict)
                matching_criteria.append(f"{event_filter.attribute}={event_filter.value}")

        # Extract destination info
        destination = {}
        if trigger.destination:
            if trigger.destination.cloud_run:
                destination = {
                    "type": "cloud_run",
                    "service": trigger.destination.cloud_run.service,
                    "path": trigger.destination.cloud_run.path,
                    "region": trigger.destination.cloud_run.region,
                }
            elif trigger.destination.cloud_function:
                destination = {
                    "type": "cloud_function",
                    "function": trigger.destination.cloud_function,
                }
            elif trigger.destination.gke:
                destination = {
                    "type": "gke",
                    "cluster": trigger.destination.gke.cluster,
                    "service": trigger.destination.gke.service,
                }
            elif trigger.destination.workflow:
                destination = {
                    "type": "workflow",
                    "workflow": trigger.destination.workflow,
                }

        # Check if security-relevant
        if not self._is_security_relevant(event_filters, trigger_name):
            return None

        return RawDetection(
            name=short_name,
            detection_type=DetectionType.GCP_EVENTARC,
            source_arn=trigger_name,
            region=region,
            raw_config={
                "name": trigger_name,
                "uid": trigger.uid if hasattr(trigger, 'uid') else None,
                "eventFilters": event_filters,
                "serviceAccount": trigger.service_account if hasattr(trigger, 'service_account') else None,
                "destination": destination,
                "transport": {
                    "pubsub": {
                        "topic": trigger.transport.pubsub.topic if trigger.transport and trigger.transport.pubsub else None,
                    }
                } if trigger.transport else None,
                "channel": trigger.channel if hasattr(trigger, 'channel') else None,
            },
            event_pattern={"eventFilters": event_filters} if event_filters else None,
            description=f"Eventarc trigger: {short_name} - {', '.join(matching_criteria)}",
            is_managed=False,
        )

    def _is_security_relevant(
        self,
        event_filters: list[dict],
        trigger_name: str,
    ) -> bool:
        """Check if an Eventarc trigger is security-relevant."""
        # Security-relevant GCP event types
        security_event_types = [
            "google.cloud.audit.log.v1.written",
            "google.cloud.securitycenter.v1.finding.created",
            "google.cloud.securitycenter.v1.finding.updated",
            "google.cloud.iam.v1.serviceAccount.keyCreated",
            "google.cloud.iam.v1.serviceAccount.deleted",
            "google.cloud.storage.object.v1.finalized",
            "google.cloud.storage.object.v1.deleted",
            "google.cloud.compute.instance.v1.insert",
            "google.cloud.compute.instance.v1.delete",
            "google.cloud.compute.firewall.v1.insert",
            "google.cloud.compute.firewall.v1.delete",
        ]

        # Security-relevant audit log service names
        security_service_names = [
            "iam.googleapis.com",
            "cloudresourcemanager.googleapis.com",
            "compute.googleapis.com",
            "storage.googleapis.com",
            "secretmanager.googleapis.com",
            "bigquery.googleapis.com",
            "container.googleapis.com",
            "cloudfunctions.googleapis.com",
            "run.googleapis.com",
            "sqladmin.googleapis.com",
        ]

        # Security keywords in trigger name
        security_keywords = [
            "security",
            "alert",
            "audit",
            "monitor",
            "detect",
            "iam",
            "access",
            "auth",
            "threat",
            "incident",
        ]

        # Check event type
        for filter_item in event_filters:
            attribute = filter_item.get("attribute", "")
            value = filter_item.get("value", "")

            # Check for security event types
            if attribute == "type" and any(evt in value for evt in security_event_types):
                return True

            # Check for security service names in audit logs
            if attribute == "serviceName" and any(svc in value for svc in security_service_names):
                return True

            # Check for security methods
            if attribute == "methodName":
                security_methods = [
                    "SetIamPolicy", "CreateServiceAccountKey", "DeleteServiceAccountKey",
                    "CreateRole", "DeleteRole", "CreateInstance", "DeleteInstance",
                    "Insert", "Delete", "Update", "Patch",
                ]
                if any(method.lower() in value.lower() for method in security_methods):
                    return True

        # Check trigger name for security keywords
        trigger_name_lower = trigger_name.lower()
        if any(kw in trigger_name_lower for kw in security_keywords):
            return True

        return False


# GCP Event Types to MITRE ATT&CK mapping
EVENTARC_EVENT_MITRE_MAPPING = {
    # Audit Log Events
    "google.cloud.audit.log.v1.written": {
        "iam.googleapis.com": {
            "CreateServiceAccountKey": ["T1098.001"],
            "DeleteServiceAccountKey": ["T1098.001"],
            "SetIamPolicy": ["T1098.003"],
            "CreateRole": ["T1098.003"],
            "DeleteRole": ["T1098.003"],
        },
        "compute.googleapis.com": {
            "instances.insert": ["T1578.002"],
            "instances.delete": ["T1485"],
            "firewalls.insert": ["T1562.007"],
            "firewalls.delete": ["T1562.007"],
            "snapshots.create": ["T1578.001"],
        },
        "storage.googleapis.com": {
            "buckets.create": ["T1530"],
            "buckets.delete": ["T1485"],
            "objects.delete": ["T1485"],
            "buckets.setIamPolicy": ["T1537"],
        },
        "cloudresourcemanager.googleapis.com": {
            "SetIamPolicy": ["T1098.003"],
        },
    },
    # Direct Events
    "google.cloud.storage.object.v1.finalized": ["T1530"],
    "google.cloud.storage.object.v1.deleted": ["T1485"],
    "google.cloud.compute.instance.v1.insert": ["T1578.002"],
    "google.cloud.compute.instance.v1.delete": ["T1485"],
}
