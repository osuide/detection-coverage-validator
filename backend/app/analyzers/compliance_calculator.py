"""Compliance coverage calculator.

Calculates compliance framework coverage from MITRE ATT&CK technique coverage.
Supports service-aware coverage when cloud_account_id is provided.
"""

from dataclasses import dataclass, field
from typing import Optional
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.compliance import (
    ComplianceFramework,
    ComplianceControl,
)
from app.models.mitre import Technique
from app.analyzers.service_coverage_calculator import (
    ServiceCoverageCalculator,
    ServiceCoverageResult,
)

logger = structlog.get_logger()

# Fixed thresholds per plan
COVERED_THRESHOLD = 0.8  # 80% of mapped techniques covered = control covered
PARTIAL_THRESHOLD = 0.4  # 40% of mapped techniques covered = control partial


@dataclass
class ControlCoverageInfo:
    """Coverage information for a single control."""

    control_id: str
    control_name: str
    control_family: str
    priority: Optional[str]
    status: str  # "covered", "partial", "uncovered", "not_applicable"
    coverage_percent: float
    mapped_technique_count: int
    covered_technique_count: int
    missing_techniques: list[str] = field(default_factory=list)
    cloud_applicability: Optional[str] = None  # "highly_relevant", etc.
    cloud_context: Optional[dict] = None
    # Service-aware coverage fields
    service_coverage_percent: Optional[float] = None  # % of in-scope services covered
    in_scope_services: list[str] = field(
        default_factory=list
    )  # Services with resources
    covered_services: list[str] = field(
        default_factory=list
    )  # Services with detections
    uncovered_services: list[str] = field(
        default_factory=list
    )  # Services without detections
    technique_service_coverage: list[ServiceCoverageResult] = field(
        default_factory=list
    )  # Per-technique service breakdown


@dataclass
class FamilyCoverageInfo:
    """Coverage information for a control family."""

    family: str
    total: int
    covered: int
    partial: int
    uncovered: int
    not_assessable: int  # Controls that cannot be assessed via cloud scanning
    assessable: int  # Controls that CAN be assessed via cloud scanning
    percent: float
    cloud_applicability: Optional[str] = None  # Dominant type or "mixed"
    shared_responsibility: Optional[str] = None  # Dominant type or "mixed"
    applicability_breakdown: Optional[dict] = (
        None  # e.g., {"highly_relevant": 10, "informational": 2}
    )
    responsibility_breakdown: Optional[dict] = (
        None  # e.g., {"customer": 8, "shared": 4}
    )


@dataclass
class CloudCoverageMetrics:
    """Cloud-specific coverage metrics."""

    cloud_detectable_total: int  # Controls that are cloud-detectable
    cloud_detectable_covered: int
    cloud_coverage_percent: float  # Cloud detection coverage only
    customer_responsibility_total: int  # Customer responsibility controls
    customer_responsibility_covered: int
    provider_managed_total: int  # Provider responsibility controls
    not_assessable_total: int = 0  # Controls that cannot be assessed via cloud scanning


@dataclass
class ServiceCoverageMetrics:
    """Service-aware coverage metrics across all controls."""

    total_in_scope_services: int  # Unique services with resources in account
    total_covered_services: int  # Unique services with detection coverage
    service_coverage_percent: float  # Overall service coverage
    uncovered_services: list[str]  # Services without detection coverage


@dataclass
class ComplianceCoverageResult:
    """Complete compliance coverage calculation result."""

    framework_id: str
    framework_name: str
    framework_version: str
    total_controls: int
    covered_controls: int
    partial_controls: int
    uncovered_controls: int
    coverage_percent: float
    cloud_metrics: CloudCoverageMetrics  # Cloud-specific analytics
    family_coverage: dict[str, FamilyCoverageInfo]
    control_details: list[ControlCoverageInfo]
    top_gaps: list[ControlCoverageInfo]
    # Service-aware coverage metrics
    service_metrics: Optional[ServiceCoverageMetrics] = None


class ComplianceCoverageCalculator:
    """Calculate compliance coverage from MITRE technique coverage."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(component="ComplianceCoverageCalculator")

    async def calculate(
        self,
        framework_id: UUID,
        technique_coverage: dict[str, str],  # technique_id (str) -> status
        cloud_account_id: Optional[UUID] = None,  # For service-aware coverage
    ) -> ComplianceCoverageResult:
        """Calculate compliance coverage for a framework.

        Args:
            framework_id: The compliance framework UUID
            technique_coverage: Dict mapping MITRE technique IDs to coverage status
                                ("covered", "partial", "uncovered")
            cloud_account_id: Optional cloud account UUID for service-aware coverage.
                              When provided, coverage is calculated based on which
                              services have detection coverage, not just techniques.

        Returns:
            ComplianceCoverageResult with full coverage breakdown
        """
        self.logger.info(
            "calculating_compliance_coverage",
            framework_id=str(framework_id),
            technique_count=len(technique_coverage),
            service_aware=cloud_account_id is not None,
        )

        # Initialize service coverage calculator if cloud_account_id provided
        service_calc: Optional[ServiceCoverageCalculator] = None
        if cloud_account_id:
            service_calc = ServiceCoverageCalculator(self.db)

        # Get framework
        framework = await self.db.get(ComplianceFramework, framework_id)
        if not framework:
            raise ValueError(f"Framework {framework_id} not found")

        # Get all controls with their technique mappings
        controls_result = await self.db.execute(
            select(ComplianceControl)
            .where(ComplianceControl.framework_id == framework_id)
            .options(selectinload(ComplianceControl.technique_mappings))
            .order_by(ComplianceControl.display_order)
        )
        controls = controls_result.scalars().all()

        # Build technique ID lookup (UUID -> technique_id string)
        technique_ids = await self._get_technique_id_map()

        # Calculate coverage for each control
        control_details: list[ControlCoverageInfo] = []
        family_stats: dict[str, dict] = {}

        for control in controls:
            # Get mapped technique IDs
            mapped_technique_uuids = [
                m.technique_id for m in control.technique_mappings
            ]
            mapped_technique_ids = [
                technique_ids.get(str(uuid))
                for uuid in mapped_technique_uuids
                if str(uuid) in technique_ids
            ]

            # Check if control is assessable via cloud scanning
            # Informational and provider_responsibility controls cannot be
            # assessed by the DCV tool - they require human/organisational review
            is_not_assessable = control.cloud_applicability in (
                "informational",
                "provider_responsibility",
            )

            # Calculate coverage
            if is_not_assessable:
                # Control cannot be assessed via cloud scanning
                # (e.g., security training, physical security)
                coverage_info = ControlCoverageInfo(
                    control_id=control.control_id,
                    control_name=control.name,
                    control_family=control.control_family,
                    priority=control.priority,
                    status="not_assessable",
                    coverage_percent=0.0,
                    mapped_technique_count=len(mapped_technique_ids),
                    covered_technique_count=0,
                    missing_techniques=[],
                    cloud_applicability=control.cloud_applicability,
                    cloud_context=control.cloud_context,
                )
            elif not mapped_technique_ids:
                # No technique mappings - not applicable
                coverage_info = ControlCoverageInfo(
                    control_id=control.control_id,
                    control_name=control.name,
                    control_family=control.control_family,
                    priority=control.priority,
                    status="not_applicable",
                    coverage_percent=0.0,
                    mapped_technique_count=0,
                    covered_technique_count=0,
                    missing_techniques=[],
                    cloud_applicability=control.cloud_applicability,
                    cloud_context=control.cloud_context,
                )
            else:
                covered_count = 0
                missing = []

                for tech_id in mapped_technique_ids:
                    if tech_id and technique_coverage.get(tech_id) == "covered":
                        covered_count += 1
                    elif tech_id:
                        missing.append(tech_id)

                coverage_pct = covered_count / len(mapped_technique_ids)

                if coverage_pct >= COVERED_THRESHOLD:
                    status = "covered"
                elif coverage_pct >= PARTIAL_THRESHOLD:
                    status = "partial"
                else:
                    status = "uncovered"

                # Calculate service coverage if enabled and control has aws_services
                service_coverage_pct: Optional[float] = None
                in_scope_services: list[str] = []
                covered_services: list[str] = []
                uncovered_services: list[str] = []

                if service_calc and cloud_account_id:
                    # Extract required services from cloud_context
                    control_required_services: list[str] = []
                    if control.cloud_context and isinstance(
                        control.cloud_context, dict
                    ):
                        control_required_services = control.cloud_context.get(
                            "aws_services", []
                        )

                    if control_required_services:
                        # Calculate service coverage for this control
                        service_result = await service_calc.calculate_control_coverage(
                            cloud_account_id=cloud_account_id,
                            control_id=control.control_id,
                            technique_ids=[t for t in mapped_technique_ids if t],
                            control_required_services=control_required_services,
                        )
                        service_coverage_pct = service_result.coverage_percent
                        in_scope_services = service_result.in_scope_services
                        covered_services = service_result.covered_services
                        uncovered_services = service_result.uncovered_services

                        # Adjust status based on service coverage
                        # If technique coverage is high but service coverage is low,
                        # downgrade the status
                        if (
                            service_coverage_pct is not None
                            and service_coverage_pct < 100
                        ):
                            effective_coverage = (
                                coverage_pct + (service_coverage_pct / 100)
                            ) / 2
                            if effective_coverage < PARTIAL_THRESHOLD:
                                status = "uncovered"
                            elif effective_coverage < COVERED_THRESHOLD:
                                status = "partial"

                coverage_info = ControlCoverageInfo(
                    control_id=control.control_id,
                    control_name=control.name,
                    control_family=control.control_family,
                    priority=control.priority,
                    status=status,
                    coverage_percent=coverage_pct,
                    mapped_technique_count=len(mapped_technique_ids),
                    covered_technique_count=covered_count,
                    missing_techniques=missing[:5],  # Limit to 5
                    cloud_applicability=control.cloud_applicability,
                    cloud_context=control.cloud_context,
                    service_coverage_percent=service_coverage_pct,
                    in_scope_services=in_scope_services,
                    covered_services=covered_services,
                    uncovered_services=uncovered_services,
                )

            control_details.append(coverage_info)

            # Update family stats
            family = control.control_family
            if family not in family_stats:
                family_stats[family] = {
                    "total": 0,
                    "covered": 0,
                    "partial": 0,
                    "uncovered": 0,
                    "not_assessable": 0,
                    "assessable": 0,  # Track assessable controls separately
                    "applicability_counts": {},  # Track all applicability types
                    "responsibility_counts": {},  # Track responsibility types
                }

            # Track cloud applicability distribution for this family
            applicability = control.cloud_applicability or "highly_relevant"
            family_stats[family]["applicability_counts"][applicability] = (
                family_stats[family]["applicability_counts"].get(applicability, 0) + 1
            )

            # Track shared responsibility distribution
            shared_resp = None
            if control.cloud_context and isinstance(control.cloud_context, dict):
                shared_resp = control.cloud_context.get("shared_responsibility")
            if shared_resp:
                family_stats[family]["responsibility_counts"][shared_resp] = (
                    family_stats[family]["responsibility_counts"].get(shared_resp, 0)
                    + 1
                )

            family_stats[family]["total"] += 1
            if coverage_info.status == "covered":
                family_stats[family]["covered"] += 1
                family_stats[family]["assessable"] += 1
            elif coverage_info.status == "partial":
                family_stats[family]["partial"] += 1
                family_stats[family]["assessable"] += 1
            elif coverage_info.status == "uncovered":
                family_stats[family]["uncovered"] += 1
                family_stats[family]["assessable"] += 1
            elif coverage_info.status == "not_assessable":
                family_stats[family]["not_assessable"] += 1
            # not_applicable doesn't count towards any bucket

        # Build family coverage
        family_coverage: dict[str, FamilyCoverageInfo] = {}
        for family, stats in family_stats.items():
            total = stats["total"]
            covered = stats["covered"]
            not_assessable = stats["not_assessable"]
            assessable = stats["assessable"]

            # Calculate percent based on assessable controls only
            assessable_total = total - not_assessable

            # Determine dominant cloud_applicability
            # If family has multiple types, mark as "mixed"
            app_counts = stats.get("applicability_counts", {})
            if len(app_counts) == 0:
                dominant_applicability = None
            elif len(app_counts) == 1:
                dominant_applicability = list(app_counts.keys())[0]
            else:
                # Multiple types - find dominant or mark as mixed
                sorted_apps = sorted(
                    app_counts.items(), key=lambda x: x[1], reverse=True
                )
                top_app, top_count = sorted_apps[0]
                # If >80% are one type, use that; otherwise "mixed"
                if top_count / total >= 0.8:
                    dominant_applicability = top_app
                else:
                    dominant_applicability = "mixed"

            # Determine dominant shared_responsibility
            resp_counts = stats.get("responsibility_counts", {})
            if len(resp_counts) == 0:
                dominant_responsibility = None
            elif len(resp_counts) == 1:
                dominant_responsibility = list(resp_counts.keys())[0]
            else:
                sorted_resps = sorted(
                    resp_counts.items(), key=lambda x: x[1], reverse=True
                )
                top_resp, top_count = sorted_resps[0]
                if top_count / total >= 0.8:
                    dominant_responsibility = top_resp
                else:
                    dominant_responsibility = "mixed"

            family_coverage[family] = FamilyCoverageInfo(
                family=family,
                total=total,
                covered=covered,
                partial=stats["partial"],
                uncovered=stats["uncovered"],
                not_assessable=not_assessable,
                assessable=assessable,
                percent=(
                    (covered / assessable_total * 100) if assessable_total > 0 else 0
                ),
                cloud_applicability=dominant_applicability,
                shared_responsibility=dominant_responsibility,
                applicability_breakdown=app_counts if len(app_counts) > 1 else None,
                responsibility_breakdown=resp_counts if len(resp_counts) > 1 else None,
            )

        # Calculate totals - exclude not_applicable AND not_assessable from main totals
        # not_assessable controls cannot be evaluated via cloud scanning
        assessable_controls = [
            c
            for c in control_details
            if c.status not in ("not_applicable", "not_assessable")
        ]
        total_controls = len(assessable_controls)
        covered_controls = len([c for c in control_details if c.status == "covered"])
        partial_controls = len([c for c in control_details if c.status == "partial"])
        uncovered_controls = len(
            [c for c in control_details if c.status == "uncovered"]
        )
        not_assessable_controls = len(
            [c for c in control_details if c.status == "not_assessable"]
        )

        coverage_percent = (
            (covered_controls / total_controls * 100) if total_controls > 0 else 0
        )

        # Calculate cloud-specific metrics
        cloud_detectable = [
            c
            for c in control_details
            if c.status != "not_applicable"
            and c.cloud_applicability in ("highly_relevant", "moderately_relevant")
        ]
        cloud_detectable_covered = len(
            [c for c in cloud_detectable if c.status == "covered"]
        )
        cloud_coverage_pct = (
            (cloud_detectable_covered / len(cloud_detectable) * 100)
            if cloud_detectable
            else 0
        )

        # Customer responsibility controls (not provider_responsibility)
        customer_controls = [
            c
            for c in control_details
            if c.status != "not_applicable"
            and c.cloud_applicability != "provider_responsibility"
        ]
        customer_covered = len([c for c in customer_controls if c.status == "covered"])

        # Provider managed controls
        provider_controls = [
            c
            for c in control_details
            if c.cloud_applicability == "provider_responsibility"
        ]

        cloud_metrics = CloudCoverageMetrics(
            cloud_detectable_total=len(cloud_detectable),
            cloud_detectable_covered=cloud_detectable_covered,
            cloud_coverage_percent=cloud_coverage_pct,
            customer_responsibility_total=len(customer_controls),
            customer_responsibility_covered=customer_covered,
            provider_managed_total=len(provider_controls),
            not_assessable_total=not_assessable_controls,
        )

        # Get top gaps (uncovered + partial, sorted by priority then coverage)
        # IMPORTANT: Exclude not_assessable controls from gaps - they cannot be
        # addressed via cloud detections (e.g., security training, physical security)
        priority_order = {"P1": 0, "P2": 1, "P3": 2, None: 3}
        gaps = [
            c
            for c in control_details
            if c.status in ("uncovered", "partial")
            and c.cloud_applicability in ("highly_relevant", "moderately_relevant")
        ]
        # Sort by: highly_relevant first, then priority (P1 > P2 > P3), then coverage %
        applicability_order = {"highly_relevant": 0, "moderately_relevant": 1}
        gaps.sort(
            key=lambda c: (
                applicability_order.get(c.cloud_applicability, 2),
                priority_order.get(c.priority, 3),
                c.coverage_percent,
            )
        )
        top_gaps = gaps[:10]  # Top 10 gaps

        # Calculate aggregate service coverage metrics
        service_metrics: Optional[ServiceCoverageMetrics] = None
        if cloud_account_id:
            # Aggregate unique services across all controls
            all_in_scope: set[str] = set()
            all_covered: set[str] = set()
            for c in control_details:
                all_in_scope.update(c.in_scope_services)
                all_covered.update(c.covered_services)

            all_uncovered = sorted(all_in_scope - all_covered)
            svc_pct = (
                (len(all_covered) / len(all_in_scope) * 100) if all_in_scope else 100.0
            )

            service_metrics = ServiceCoverageMetrics(
                total_in_scope_services=len(all_in_scope),
                total_covered_services=len(all_covered),
                service_coverage_percent=round(svc_pct, 1),
                uncovered_services=all_uncovered,
            )

        result = ComplianceCoverageResult(
            framework_id=framework.framework_id,
            framework_name=framework.name,
            framework_version=framework.version,
            total_controls=total_controls,
            covered_controls=covered_controls,
            partial_controls=partial_controls,
            uncovered_controls=uncovered_controls,
            coverage_percent=coverage_percent,
            cloud_metrics=cloud_metrics,
            family_coverage=family_coverage,
            control_details=control_details,
            top_gaps=top_gaps,
            service_metrics=service_metrics,
        )

        self.logger.info(
            "compliance_coverage_calculated",
            framework_id=framework.framework_id,
            coverage_percent=coverage_percent,
            covered=covered_controls,
            partial=partial_controls,
            uncovered=uncovered_controls,
            service_coverage_percent=(
                service_metrics.service_coverage_percent if service_metrics else None
            ),
            uncovered_services=(
                service_metrics.uncovered_services if service_metrics else None
            ),
        )

        return result

    async def _get_technique_id_map(self) -> dict[str, str]:
        """Get mapping from technique UUID to technique_id string."""
        result = await self.db.execute(select(Technique.id, Technique.technique_id))
        return {str(row[0]): row[1] for row in result.fetchall()}

    async def calculate_for_all_frameworks(
        self,
        technique_coverage: dict[str, str],
        cloud_account_id: Optional[UUID] = None,
    ) -> list[ComplianceCoverageResult]:
        """Calculate coverage for all active compliance frameworks.

        Args:
            technique_coverage: Dict mapping MITRE technique IDs to coverage status
            cloud_account_id: Optional cloud account UUID for service-aware coverage

        Returns:
            List of ComplianceCoverageResult for each framework
        """
        # Get all active frameworks
        result = await self.db.execute(
            select(ComplianceFramework).where(ComplianceFramework.is_active.is_(True))
        )
        frameworks = result.scalars().all()

        results = []
        for framework in frameworks:
            coverage = await self.calculate(
                framework.id, technique_coverage, cloud_account_id
            )
            results.append(coverage)

        return results
