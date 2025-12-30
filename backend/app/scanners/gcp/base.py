"""Base scanner for GCP services with Workload Identity Federation support.

This module provides the base class for all GCP scanners, implementing:
- Async/await pattern with run_sync() for non-blocking GCP SDK calls
- Workload Identity Federation credential integration
- Rate limiting and parallel region scanning
- Structured logging

Security:
- All GCP SDK calls are offloaded to a thread pool to prevent event loop blocking
- Credentials are obtained via WIF (no stored keys)
- Read-only operations only
"""

import asyncio
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from typing import Any, Callable, Optional, TypeVar

import structlog
from google.auth import credentials as ga_credentials

from app.models.detection import DetectionType
from app.scanners.rate_limiter import get_rate_limiter

logger = structlog.get_logger()

# Shared thread pool for GCP SDK calls across all scanners
# GCP SDK is synchronous - this prevents blocking the async event loop
_gcp_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="gcp-scanner-")

# Maximum concurrent projects/locations to scan in parallel
MAX_CONCURRENT_LOCATIONS = 5

T = TypeVar("T")


@dataclass
class RawGCPDetection:
    """Raw detection data from a GCP scanner.

    Normalised representation before database storage.
    """

    name: str
    detection_type: DetectionType
    source_id: str  # GCP resource name (equivalent to ARN)
    location: str  # Region/zone or 'global'
    project_id: str
    raw_config: dict[str, Any]

    # Parsed fields
    filter_expression: Optional[str] = None  # Log filter, alert condition, etc.
    description: Optional[str] = None

    # Service awareness - which GCP services this detection monitors
    target_services: Optional[list[str]] = (
        None  # e.g., ["Cloud Storage", "Compute Engine"]
    )

    # Evaluation/compliance data
    evaluation_summary: Optional[dict[str, Any]] = None

    # Metadata
    is_managed: bool = False  # True for SCC built-in, Chronicle curated rules
    discovered_at: datetime = None

    def __post_init__(self) -> None:
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow()

    @property
    def source_arn(self) -> str:
        """Alias for source_id to maintain compatibility with RawDetection."""
        return self.source_id


class BaseGCPScanner(ABC):
    """Abstract base class for GCP detection scanners.

    All GCP scanners inherit from this class which provides:
    - Credential management via WIF
    - Non-blocking async pattern with run_sync()
    - Parallel location scanning with rate limiting
    - Structured logging

    Usage:
        class CloudLoggingScanner(BaseGCPScanner):
            @property
            def detection_type(self) -> DetectionType:
                return DetectionType.GCP_CLOUD_LOGGING

            async def scan(self, locations, options=None):
                # Implementation
                pass
    """

    def __init__(
        self,
        credentials: ga_credentials.Credentials,
        project_id: str,
    ) -> None:
        """Initialise scanner with GCP credentials.

        Args:
            credentials: GCP credentials obtained via WIF
            project_id: GCP project ID to scan
        """
        self.credentials = credentials
        self.project_id = project_id
        self.logger = logger.bind(
            scanner=self.__class__.__name__,
            project_id=project_id,
        )

    async def run_sync(
        self,
        func: Callable[..., T],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Run a synchronous function without blocking the event loop.

        GCP SDK calls are synchronous. This method offloads them to a thread pool,
        allowing the async event loop to continue processing HTTP requests.

        Usage:
            # Instead of: response = client.list_log_metrics(parent=parent)
            response = await self.run_sync(client.list_log_metrics, parent=parent)

            # With lambda for complex calls:
            items = await self.run_sync(lambda: list(client.list_items(parent=p)))

        Args:
            func: The synchronous function to call
            *args: Positional arguments to pass to the function
            **kwargs: Keyword arguments to pass to the function

        Returns:
            The result from the synchronous function
        """
        loop = asyncio.get_event_loop()
        if kwargs:
            func = partial(func, **kwargs)
        return await loop.run_in_executor(_gcp_executor, func, *args)

    @property
    @abstractmethod
    def detection_type(self) -> DetectionType:
        """The type of detection this scanner discovers."""
        pass

    @property
    def is_global_service(self) -> bool:
        """Whether this scanner targets a global (non-regional) service.

        Override in subclass to return True for global services like
        Organisation Policy or SCC at organisation level.
        """
        return False

    @property
    def service_key(self) -> str:
        """Service key for rate limiter lookup.

        Override in subclass if different from class name inference.
        """
        name = self.__class__.__name__
        if name.endswith("Scanner"):
            name = name[:-7]
        return f"gcp_{name.lower()}"

    @abstractmethod
    async def scan(
        self,
        locations: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawGCPDetection]:
        """Scan for detections in the specified locations.

        Args:
            locations: List of GCP locations to scan (e.g., ['us-central1', 'europe-west2'])
            options: Optional scanner-specific options (e.g., organisation_id)

        Returns:
            List of discovered RawGCPDetection objects
        """
        pass

    async def scan_location(
        self,
        location: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawGCPDetection]:
        """Scan a single location. Override for location-specific logic."""
        return []

    async def scan_locations_parallel(
        self,
        locations: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawGCPDetection]:
        """Scan multiple locations in parallel with rate limiting.

        Helper method for scanners that operate per-location (region/zone).

        Args:
            locations: List of GCP locations to scan
            options: Optional scanner-specific options

        Returns:
            Combined list of RawGCPDetection objects from all locations
        """
        if not locations:
            return []

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_LOCATIONS)
        rate_limiter = await get_rate_limiter(self.service_key)

        async def scan_location_with_limits(location: str) -> list[RawGCPDetection]:
            async with semaphore:
                async with rate_limiter:
                    try:
                        return await self.scan_location(location, options)
                    except Exception as e:
                        self.logger.warning(
                            "location_scan_failed",
                            location=location,
                            error=str(e),
                        )
                        return []

        results = await asyncio.gather(
            *[scan_location_with_limits(loc) for loc in locations],
            return_exceptions=False,
        )

        all_detections: list[RawGCPDetection] = []
        for location_detections in results:
            all_detections.extend(location_detections)

        self.logger.info(
            "parallel_location_scan_complete",
            total_locations=len(locations),
            total_detections=len(all_detections),
        )

        return all_detections

    def build_parent(self, location: Optional[str] = None) -> str:
        """Build GCP parent resource string.

        Args:
            location: Optional location (region/zone). If None, returns project-level parent.

        Returns:
            Parent resource string (e.g., 'projects/my-project/locations/us-central1')
        """
        if location:
            return f"projects/{self.project_id}/locations/{location}"
        return f"projects/{self.project_id}"

    def extract_name_from_resource(self, resource_name: str) -> str:
        """Extract the short name from a full GCP resource name.

        Args:
            resource_name: Full resource name (e.g., 'projects/p/locations/l/triggers/my-trigger')

        Returns:
            Short name (e.g., 'my-trigger')
        """
        if "/" in resource_name:
            return resource_name.split("/")[-1]
        return resource_name


def convert_gcp_to_raw_detection(gcp_detection: RawGCPDetection) -> Any:
    """Convert RawGCPDetection to the common RawDetection format.

    This allows GCP detections to flow through the existing detection
    processing pipeline.

    Args:
        gcp_detection: GCP-specific detection

    Returns:
        RawDetection compatible with the processing pipeline
    """
    from app.scanners.base import RawDetection

    return RawDetection(
        name=gcp_detection.name,
        detection_type=gcp_detection.detection_type,
        source_arn=gcp_detection.source_id,  # GCP resource name
        region=gcp_detection.location,
        raw_config={
            **gcp_detection.raw_config,
            "project_id": gcp_detection.project_id,
        },
        query_pattern=gcp_detection.filter_expression,
        description=gcp_detection.description,
        target_services=gcp_detection.target_services,
        evaluation_summary=gcp_detection.evaluation_summary,
        is_managed=gcp_detection.is_managed,
        discovered_at=gcp_detection.discovered_at,
    )
