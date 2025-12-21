"""Base scanner interface following 04-PARSER-AGENT.md design."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
import structlog

from app.models.detection import DetectionType

logger = structlog.get_logger()


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
