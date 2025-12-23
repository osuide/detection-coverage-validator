"""Service-aware coverage calculator.

Calculates detection coverage based on which cloud services have resources
in the account vs which services are monitored by detections.

This enables more accurate compliance coverage by checking if detections
exist for ALL services where data resides, not just if ANY detection exists.
"""

from dataclasses import dataclass, field
from typing import Optional
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_account import CloudAccount
from app.models.detection import Detection, DetectionStatus
from app.scanners.aws.service_mappings import CORE_SERVICES

logger = structlog.get_logger()


@dataclass
class ServiceCoverageResult:
    """Coverage result for a single technique across services."""

    technique_id: str
    in_scope_services: list[str]  # Services with resources in account
    covered_services: list[str]  # Services with detection coverage
    uncovered_services: list[str]  # Services without detection coverage
    coverage_percent: float  # Percent of in-scope services covered
    detections_by_service: dict[str, list[str]] = field(
        default_factory=dict
    )  # service -> detection names


@dataclass
class ControlServiceCoverage:
    """Service coverage summary for a compliance control."""

    control_id: str
    in_scope_services: list[str]  # Services with resources in account
    covered_services: list[str]  # Services with ANY detection coverage
    uncovered_services: list[str]  # Services without coverage
    coverage_percent: float
    technique_coverage: list[ServiceCoverageResult] = field(default_factory=list)


class ServiceCoverageCalculator:
    """Calculate service-aware coverage for compliance controls.

    For each technique mapped to a control, checks if detections exist
    for the services that are both:
    1. Required by the control (via cloud_context.aws_services)
    2. Present in the account (via discovered_services)

    Coverage = (covered_services ∩ in_scope_services) / in_scope_services
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(component="ServiceCoverageCalculator")

    async def get_account_services(self, cloud_account_id: UUID) -> list[str]:
        """Get the list of services that have resources in this account.

        Args:
            cloud_account_id: The cloud account UUID

        Returns:
            List of normalised service names present in the account
        """
        result = await self.db.execute(
            select(CloudAccount.discovered_services).where(
                CloudAccount.id == cloud_account_id
            )
        )
        discovered = result.scalar_one_or_none()

        if discovered:
            return discovered

        # If not discovered yet, assume all core services are in scope
        # This provides conservative coverage estimates until discovery runs
        return CORE_SERVICES.copy()

    async def get_detection_services(
        self,
        cloud_account_id: UUID,
        technique_id: Optional[str] = None,
    ) -> dict[str, list[str]]:
        """Get mapping of services to detection names for this account.

        Args:
            cloud_account_id: The cloud account UUID
            technique_id: Optional - filter to detections for this technique

        Returns:
            Dict mapping service name to list of detection names
        """
        # Query active detections with their target_services
        query = select(Detection).where(
            Detection.cloud_account_id == cloud_account_id,
            Detection.status == DetectionStatus.ACTIVE,
            Detection.target_services.isnot(None),
        )

        result = await self.db.execute(query)
        detections = result.scalars().all()

        # Build service -> detection names mapping
        services_map: dict[str, list[str]] = {}
        for detection in detections:
            if detection.target_services:
                for service in detection.target_services:
                    if service not in services_map:
                        services_map[service] = []
                    services_map[service].append(detection.name)

        return services_map

    async def calculate_technique_coverage(
        self,
        cloud_account_id: UUID,
        technique_id: str,
        required_services: list[str],
    ) -> ServiceCoverageResult:
        """Calculate service coverage for a single technique.

        Args:
            cloud_account_id: The cloud account UUID
            technique_id: MITRE technique ID (e.g., "T1530")
            required_services: Services this technique applies to

        Returns:
            ServiceCoverageResult with covered/uncovered services
        """
        # Get services present in account
        account_services = await self.get_account_services(cloud_account_id)

        # In-scope = intersection of required and present
        in_scope = sorted(set(required_services) & set(account_services))

        if not in_scope:
            # No overlap between required and present services
            return ServiceCoverageResult(
                technique_id=technique_id,
                in_scope_services=[],
                covered_services=[],
                uncovered_services=[],
                coverage_percent=100.0,  # N/A - consider fully covered
            )

        # Get detection coverage by service
        detection_services = await self.get_detection_services(cloud_account_id)

        # Calculate coverage
        covered = []
        uncovered = []
        detections_by_service = {}

        for service in in_scope:
            if service in detection_services:
                covered.append(service)
                detections_by_service[service] = detection_services[service]
            else:
                uncovered.append(service)

        coverage_percent = (len(covered) / len(in_scope)) * 100 if in_scope else 100.0

        return ServiceCoverageResult(
            technique_id=technique_id,
            in_scope_services=in_scope,
            covered_services=sorted(covered),
            uncovered_services=sorted(uncovered),
            coverage_percent=round(coverage_percent, 1),
            detections_by_service=detections_by_service,
        )

    async def calculate_control_coverage(
        self,
        cloud_account_id: UUID,
        control_id: str,
        technique_ids: list[str],
        control_required_services: list[str],
    ) -> ControlServiceCoverage:
        """Calculate aggregate service coverage for a control.

        Args:
            cloud_account_id: The cloud account UUID
            control_id: Compliance control ID (e.g., "3.5")
            technique_ids: MITRE technique IDs mapped to this control
            control_required_services: Services defined in cloud_context.aws_services

        Returns:
            ControlServiceCoverage with aggregate coverage metrics
        """
        # Get services present in account
        account_services = await self.get_account_services(cloud_account_id)

        # In-scope = intersection of control services and account services
        in_scope = sorted(set(control_required_services) & set(account_services))

        if not in_scope:
            return ControlServiceCoverage(
                control_id=control_id,
                in_scope_services=[],
                covered_services=[],
                uncovered_services=[],
                coverage_percent=100.0,  # N/A - no relevant services
            )

        # Get all detection services
        detection_services = await self.get_detection_services(cloud_account_id)

        # Calculate per-service coverage
        covered = set()
        for service in in_scope:
            if service in detection_services:
                covered.add(service)

        uncovered = set(in_scope) - covered
        coverage_percent = (len(covered) / len(in_scope)) * 100 if in_scope else 100.0

        return ControlServiceCoverage(
            control_id=control_id,
            in_scope_services=in_scope,
            covered_services=sorted(covered),
            uncovered_services=sorted(uncovered),
            coverage_percent=round(coverage_percent, 1),
        )
