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
