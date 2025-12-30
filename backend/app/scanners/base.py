"""Base scanner interface following 04-PARSER-AGENT.md design."""

import asyncio
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from typing import Any, Callable, Optional, TypeVar
import structlog

from app.models.detection import DetectionType
from app.scanners.rate_limiter import get_rate_limiter

logger = structlog.get_logger()

# Shared thread pool for boto3 calls across all scanners
# This prevents blocking the async event loop during AWS API calls
_boto3_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="boto3-")

# Maximum concurrent regions to scan in parallel (to prevent overwhelming AWS)
MAX_CONCURRENT_REGIONS = 5

T = TypeVar("T")


@dataclass
class RawDetection:
    """Raw detection data from a cloud scanner."""

    name: str
    detection_type: DetectionType
    source_arn: str
    region: str
    raw_config: dict[str, Any]

    # Parsed fields
    query_pattern: Optional[str] = None
    event_pattern: Optional[dict[str, Any]] = None
    log_groups: Optional[list[str]] = None
    description: Optional[str] = None

    # Service awareness - which cloud services this detection monitors
    target_services: Optional[list[str]] = None  # e.g., ["S3", "RDS", "DynamoDB"]

    # Evaluation/compliance data (type-specific)
    # For Config Rules: {"type": "config_compliance", "compliance_type": "NON_COMPLIANT", ...}
    # For CloudWatch Alarms: {"type": "alarm_state", "state": "ALARM", ...}
    evaluation_summary: Optional[dict[str, Any]] = None

    # Metadata
    is_managed: bool = False
    discovered_at: datetime = field(default_factory=datetime.utcnow)


class BaseScanner(ABC):
    """Abstract base class for cloud detection scanners.

    Following the design from 04-PARSER-AGENT.md:
    - Each scanner handles one detection type
    - Returns normalized RawDetection objects
    - Handles pagination and rate limiting internally

    Scanners can be either global or regional:
    - Global scanners scan once from a designated region (e.g., IAM from us-east-1)
    - Regional scanners scan each specified region independently
    """

    def __init__(self, session: Any):
        """Initialize scanner with boto3/cloud session."""
        self.session = session
        self.logger = logger.bind(scanner=self.__class__.__name__)

    async def run_sync(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Run a synchronous function (like boto3 calls) without blocking the event loop.

        This offloads the synchronous call to a thread pool, allowing the async
        event loop to continue processing HTTP requests during long AWS API calls.

        Usage:
            # Instead of: response = client.list_rules()
            response = await self.run_sync(client.list_rules)

            # With arguments:
            response = await self.run_sync(client.get_rule, Name=rule_name)

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
        return await loop.run_in_executor(_boto3_executor, func, *args)

    @property
    @abstractmethod
    def detection_type(self) -> DetectionType:
        """The type of detection this scanner discovers."""
        pass

    @property
    def is_global_service(self) -> bool:
        """Whether this scanner targets a global (non-regional) service.

        Override in subclass to return True for global services like IAM.
        Global services are scanned once from global_scan_region.
        """
        return False

    @property
    def global_scan_region(self) -> str:
        """Region to use when scanning a global service.

        Only used when is_global_service is True.
        Override in subclass if different from default.
        """
        return "us-east-1"

    @property
    def service_key(self) -> str:
        """Service key for the service registry lookup.

        Override in subclass if different from class name inference.
        """
        # Default: derive from class name, e.g., GuardDutyScanner -> guardduty
        name = self.__class__.__name__
        if name.endswith("Scanner"):
            name = name[:-7]
        return name.lower()

    @abstractmethod
    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for detections in the specified regions.

        Args:
            regions: List of AWS regions to scan
            options: Optional scanner-specific options

        Returns:
            List of discovered RawDetection objects
        """
        pass

    async def scan_region(
        self,
        region: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan a single region. Override for region-specific logic."""
        return []

    async def scan_regions_parallel(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan multiple regions in parallel with rate limiting.

        This helper method allows scanners to easily parallelise region scanning
        while respecting rate limits and concurrency constraints.

        Usage in subclass scan() method:
            async def scan(self, regions, options=None):
                if self.is_global_service:
                    return await self.scan_region(self.global_scan_region, options)
                return await self.scan_regions_parallel(regions, options)

        Args:
            regions: List of AWS regions to scan
            options: Optional scanner-specific options

        Returns:
            Combined list of RawDetection objects from all regions
        """
        if not regions:
            return []

        # Use semaphore to limit concurrent region scans
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REGIONS)

        # Get rate limiter for this scanner's service
        rate_limiter = await get_rate_limiter(self.service_key)

        async def scan_region_with_limits(region: str) -> list[RawDetection]:
            """Scan a single region with rate limiting and concurrency control."""
            async with semaphore:
                async with rate_limiter:
                    try:
                        return await self.scan_region(region, options)
                    except Exception as e:
                        self.logger.warning(
                            "region_scan_failed",
                            region=region,
                            error=str(e),
                        )
                        return []

        # Run all region scans concurrently (semaphore limits actual concurrency)
        results = await asyncio.gather(
            *[scan_region_with_limits(region) for region in regions],
            return_exceptions=False,
        )

        # Flatten results from all regions
        all_detections: list[RawDetection] = []
        for region_detections in results:
            all_detections.extend(region_detections)

        self.logger.info(
            "parallel_region_scan_complete",
            total_regions=len(regions),
            total_detections=len(all_detections),
        )

        return all_detections

    def normalize_arn(self, arn: str) -> str:
        """Normalize ARN format."""
        return arn.strip()

    def extract_name_from_arn(self, arn: str) -> str:
        """Extract resource name from ARN."""
        parts = arn.split(":")
        if len(parts) >= 6:
            resource = parts[-1]
            if "/" in resource:
                return resource.split("/")[-1]
            return resource
        return arn
