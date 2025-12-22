"""Compliance coverage calculator.

Calculates compliance framework coverage from MITRE ATT&CK technique coverage.
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


@dataclass
class FamilyCoverageInfo:
    """Coverage information for a control family."""

    family: str
    total: int
    covered: int
    partial: int
    uncovered: int
    percent: float


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
    family_coverage: dict[str, FamilyCoverageInfo]
    control_details: list[ControlCoverageInfo]
    top_gaps: list[ControlCoverageInfo]


class ComplianceCoverageCalculator:
    """Calculate compliance coverage from MITRE technique coverage."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(component="ComplianceCoverageCalculator")

    async def calculate(
        self,
        framework_id: UUID,
        technique_coverage: dict[str, str],  # technique_id (str) -> status
    ) -> ComplianceCoverageResult:
        """Calculate compliance coverage for a framework.

        Args:
            framework_id: The compliance framework UUID
            technique_coverage: Dict mapping MITRE technique IDs to coverage status
                                ("covered", "partial", "uncovered")

        Returns:
            ComplianceCoverageResult with full coverage breakdown
        """
        self.logger.info(
            "calculating_compliance_coverage",
            framework_id=str(framework_id),
            technique_count=len(technique_coverage),
        )

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

            # Calculate coverage
            if not mapped_technique_ids:
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
                }

            family_stats[family]["total"] += 1
            if coverage_info.status == "covered":
                family_stats[family]["covered"] += 1
            elif coverage_info.status == "partial":
                family_stats[family]["partial"] += 1
            elif coverage_info.status == "uncovered":
                family_stats[family]["uncovered"] += 1
            # not_applicable doesn't count

        # Build family coverage
        family_coverage: dict[str, FamilyCoverageInfo] = {}
        for family, stats in family_stats.items():
            total = stats["total"]
            covered = stats["covered"]
            family_coverage[family] = FamilyCoverageInfo(
                family=family,
                total=total,
                covered=covered,
                partial=stats["partial"],
                uncovered=stats["uncovered"],
                percent=(covered / total * 100) if total > 0 else 0,
            )

        # Calculate totals
        total_controls = len(
            [c for c in control_details if c.status != "not_applicable"]
        )
        covered_controls = len([c for c in control_details if c.status == "covered"])
        partial_controls = len([c for c in control_details if c.status == "partial"])
        uncovered_controls = len(
            [c for c in control_details if c.status == "uncovered"]
        )

        coverage_percent = (
            (covered_controls / total_controls * 100) if total_controls > 0 else 0
        )

        # Get top gaps (uncovered + partial, sorted by priority then coverage)
        priority_order = {"P1": 0, "P2": 1, "P3": 2, None: 3}
        gaps = [c for c in control_details if c.status in ("uncovered", "partial")]
        gaps.sort(key=lambda c: (priority_order.get(c.priority, 3), c.coverage_percent))
        top_gaps = gaps[:10]  # Top 10 gaps

        result = ComplianceCoverageResult(
            framework_id=framework.framework_id,
            framework_name=framework.name,
            framework_version=framework.version,
            total_controls=total_controls,
            covered_controls=covered_controls,
            partial_controls=partial_controls,
            uncovered_controls=uncovered_controls,
            coverage_percent=coverage_percent,
            family_coverage=family_coverage,
            control_details=control_details,
            top_gaps=top_gaps,
        )

        self.logger.info(
            "compliance_coverage_calculated",
            framework_id=framework.framework_id,
            coverage_percent=coverage_percent,
            covered=covered_controls,
            partial=partial_controls,
            uncovered=uncovered_controls,
        )

        return result

    async def _get_technique_id_map(self) -> dict[str, str]:
        """Get mapping from technique UUID to technique_id string."""
        result = await self.db.execute(select(Technique.id, Technique.technique_id))
        return {str(row[0]): row[1] for row in result.fetchall()}

    async def calculate_for_all_frameworks(
        self,
        technique_coverage: dict[str, str],
    ) -> list[ComplianceCoverageResult]:
        """Calculate coverage for all active compliance frameworks.

        Args:
            technique_coverage: Dict mapping MITRE technique IDs to coverage status

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
            coverage = await self.calculate(framework.id, technique_coverage)
            results.append(coverage)

        return results
