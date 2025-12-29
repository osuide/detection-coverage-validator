"""GCP Organisation Log Sink Scanner.

Scans for organisation-level and folder-level log sinks that
aggregate logs across multiple projects.
"""

from typing import TYPE_CHECKING, Any, Optional

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection

if TYPE_CHECKING:
    from google.cloud.logging_v2 import ConfigServiceV2Client
    from google.cloud.logging_v2.types import LogSink
    from google.cloud.resourcemanager_v3 import FoldersClient
    from google.cloud.resourcemanager_v3.types import Folder


class OrgLogSinkScanner(BaseScanner):
    """Scanner for organisation-level and folder-level log sinks.

    Organisation log sinks can export logs from all projects in the
    organisation to a centralised destination (BigQuery, Cloud Storage,
    Pub/Sub, or another project's log bucket).

    These provide organisation-wide visibility similar to AWS
    Organisation CloudTrail.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_CLOUD_LOGGING

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for organisation and folder-level log sinks.

        Args:
            regions: Not used (GCP logging is global)
            options: Must include either 'organization_id' or 'folder_ids'
                - organization_id: GCP organisation ID (numeric)
                - folder_ids: List of folder IDs to scan
                - include_folders: Whether to scan folders (default True)

        Returns:
            List of RawDetection for org-level log sinks
        """
        detections = []
        options = options or {}
        org_id = options.get("organization_id")
        folder_ids = options.get("folder_ids", [])
        include_folders = options.get("include_folders", True)

        if not org_id and not folder_ids:
            self.logger.error("organization_id_or_folder_ids_required")
            return []

        try:
            from google.cloud import logging_v2
            from google.api_core.exceptions import GoogleAPIError, PermissionDenied

            client = logging_v2.ConfigServiceV2Client(credentials=self.session)

            # Scan organisation-level sinks
            if org_id:
                org_detections = await self._scan_org_sinks(client, org_id)
                detections.extend(org_detections)

                self.logger.info(
                    "discovered_org_log_sinks",
                    org_id=org_id,
                    count=len(org_detections),
                )

                # Discover and scan folder sinks if enabled
                if include_folders:
                    folder_detections = await self._scan_folder_sinks_recursive(
                        client, org_id
                    )
                    detections.extend(folder_detections)

            # Scan specific folders if provided
            for folder_id in folder_ids:
                folder_detections = await self._scan_folder_sinks(
                    client, folder_id, org_id
                )
                detections.extend(folder_detections)

        except PermissionDenied as e:
            self.logger.warning(
                "permission_denied_org_log_sinks",
                org_id=org_id,
                error=str(e),
            )
        except GoogleAPIError as e:
            self.logger.error(
                "gcp_api_error_org_log_sinks",
                org_id=org_id,
                error=str(e),
            )
        except ImportError:
            self.logger.error("gcp_logging_client_not_installed")

        return detections

    async def _scan_org_sinks(
        self, client: "ConfigServiceV2Client", org_id: str
    ) -> list[RawDetection]:
        """Scan for organisation-level log sinks."""
        detections = []

        try:
            parent = f"organizations/{org_id}"
            request = {"parent": parent}

            for sink in client.list_sinks(request=request):
                detection = self._create_sink_detection(
                    sink=sink,
                    parent_type="organization",
                    parent_id=org_id,
                    org_id=org_id,
                )
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.error(
                "scan_org_sinks_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    async def _scan_folder_sinks_recursive(
        self, client: "ConfigServiceV2Client", org_id: str
    ) -> list[RawDetection]:
        """Discover and scan all folder-level sinks in the organisation."""
        detections = []

        try:
            from google.cloud import resourcemanager_v3

            rm_client = resourcemanager_v3.FoldersClient(credentials=self.session)

            # Get all folders in the organisation
            folders = await self._list_all_folders(rm_client, org_id)

            for folder in folders:
                folder_id = folder.name.split("/")[1]
                folder_detections = await self._scan_folder_sinks(
                    client, folder_id, org_id
                )
                detections.extend(folder_detections)

        except Exception as e:
            self.logger.warning(
                "scan_folder_sinks_recursive_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    async def _list_all_folders(
        self, rm_client: "FoldersClient", org_id: str
    ) -> list["Folder"]:
        """List all folders in the organisation recursively."""
        all_folders: list["Folder"] = []

        async def list_children(parent: str) -> None:
            try:
                request = {"parent": parent}
                for folder in rm_client.list_folders(request=request):
                    all_folders.append(folder)
                    await list_children(folder.name)
            except Exception as e:
                self.logger.warning(
                    "list_folders_failed",
                    parent=parent,
                    error=str(e),
                )

        await list_children(f"organizations/{org_id}")
        return all_folders

    async def _scan_folder_sinks(
        self, client: "ConfigServiceV2Client", folder_id: str, org_id: Optional[str]
    ) -> list[RawDetection]:
        """Scan for folder-level log sinks."""
        detections = []

        try:
            parent = f"folders/{folder_id}"
            request = {"parent": parent}

            for sink in client.list_sinks(request=request):
                detection = self._create_sink_detection(
                    sink=sink,
                    parent_type="folder",
                    parent_id=folder_id,
                    org_id=org_id,
                )
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.warning(
                "scan_folder_sinks_failed",
                folder_id=folder_id,
                error=str(e),
            )

        return detections

    def _create_sink_detection(
        self,
        sink: "LogSink",
        parent_type: str,
        parent_id: str,
        org_id: Optional[str],
    ) -> Optional[RawDetection]:
        """Create a RawDetection from a log sink."""
        sink_name = sink.name.split("/")[-1]
        destination = sink.destination
        filter_string = sink.filter or ""

        # Determine destination type
        dest_type = "unknown"
        if destination.startswith("bigquery.googleapis.com"):
            dest_type = "bigquery"
        elif destination.startswith("storage.googleapis.com"):
            dest_type = "cloud_storage"
        elif destination.startswith("pubsub.googleapis.com"):
            dest_type = "pubsub"
        elif destination.startswith("logging.googleapis.com"):
            dest_type = "log_bucket"

        # Build description
        scope = "Organisation" if parent_type == "organization" else "Folder"
        description = f"{scope} Log Sink: {sink_name} " f"(exports to {dest_type})"

        # Check if this includes all child resources
        include_children = getattr(sink, "include_children", False)

        return RawDetection(
            name=f"{scope} Sink: {sink_name}",
            detection_type=self.detection_type,
            source_arn=sink.name,
            region="global",
            raw_config={
                "name": sink.name,
                "short_name": sink_name,
                "destination": destination,
                "destination_type": dest_type,
                "filter": filter_string,
                "include_children": include_children,
                "parent_type": parent_type,
                "parent_id": parent_id,
                "disabled": sink.disabled if hasattr(sink, "disabled") else False,
                "writer_identity": sink.writer_identity,
                "create_time": (
                    sink.create_time.isoformat()
                    if hasattr(sink, "create_time") and sink.create_time
                    else None
                ),
                "update_time": (
                    sink.update_time.isoformat()
                    if hasattr(sink, "update_time") and sink.update_time
                    else None
                ),
                "org_id": org_id,
            },
            query_pattern=filter_string,
            description=description,
            is_managed=False,  # User-configured
        )


class OrgLogBucketScanner(BaseScanner):
    """Scanner for organisation-level log buckets.

    Organisation log buckets can be used to aggregate logs
    from multiple projects with retention and access controls.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_CLOUD_LOGGING

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for organisation-level log buckets."""
        detections = []
        options = options or {}
        org_id = options.get("organization_id")

        if not org_id:
            self.logger.error("organization_id_required")
            return []

        try:
            from google.cloud import logging_v2
            from google.api_core.exceptions import PermissionDenied

            client = logging_v2.ConfigServiceV2Client(credentials=self.session)

            # List log buckets at organisation level
            parent = f"organizations/{org_id}/locations/global"
            request = {"parent": parent}

            for bucket in client.list_buckets(request=request):
                detection = self._create_bucket_detection(bucket, org_id)
                if detection:
                    detections.append(detection)

            self.logger.info(
                "discovered_org_log_buckets",
                org_id=org_id,
                count=len(detections),
            )

        except PermissionDenied as e:
            self.logger.warning(
                "permission_denied_org_log_buckets",
                org_id=org_id,
                error=str(e),
            )
        except Exception as e:
            self.logger.error(
                "scan_org_log_buckets_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    def _create_bucket_detection(
        self, bucket: Any, org_id: str
    ) -> Optional[RawDetection]:
        """Create a RawDetection from a log bucket."""
        bucket_name = bucket.name.split("/")[-1]

        # Skip default buckets as they're not custom configurations
        if bucket_name in ["_Default", "_Required"]:
            return None

        retention_days = bucket.retention_days

        description = (
            f"Organisation Log Bucket: {bucket_name} "
            f"(retention: {retention_days} days)"
        )

        return RawDetection(
            name=f"Org Log Bucket: {bucket_name}",
            detection_type=self.detection_type,
            source_arn=bucket.name,
            region="global",
            raw_config={
                "name": bucket.name,
                "short_name": bucket_name,
                "retention_days": retention_days,
                "locked": bucket.locked if hasattr(bucket, "locked") else False,
                "lifecycle_state": (
                    str(bucket.lifecycle_state)
                    if hasattr(bucket, "lifecycle_state")
                    else None
                ),
                "analytics_enabled": (
                    bucket.analytics_enabled
                    if hasattr(bucket, "analytics_enabled")
                    else False
                ),
                "create_time": (
                    bucket.create_time.isoformat()
                    if hasattr(bucket, "create_time") and bucket.create_time
                    else None
                ),
                "update_time": (
                    bucket.update_time.isoformat()
                    if hasattr(bucket, "update_time") and bucket.update_time
                    else None
                ),
                "org_id": org_id,
            },
            description=description,
            is_managed=False,
        )
