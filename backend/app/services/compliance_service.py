"""Compliance coverage service.

Manages compliance framework coverage calculations and storage.
"""

from typing import Optional
from uuid import UUID

import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.compliance import (
    ComplianceFramework,
    ComplianceControl,
    ControlTechniqueMapping,
    ComplianceCoverageSnapshot,
)
from app.models.coverage import CoverageSnapshot
from app.models.mitre import Technique
from app.analyzers.compliance_calculator import (
    ComplianceCoverageCalculator,
)

logger = structlog.get_logger()


class ComplianceService:
    """Service for compliance coverage operations."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(service="ComplianceService")

    async def get_frameworks(
        self, active_only: bool = True
    ) -> list[ComplianceFramework]:
        """Get all compliance frameworks.

        Args:
            active_only: If True, only return active frameworks

        Returns:
            List of ComplianceFramework objects
        """
        query = select(ComplianceFramework)
        if active_only:
            query = query.where(ComplianceFramework.is_active.is_(True))
        query = query.order_by(ComplianceFramework.name)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_framework(self, framework_id: str) -> Optional[ComplianceFramework]:
        """Get a framework by its framework_id.

        Args:
            framework_id: The framework identifier (e.g., "nist-800-53-r5")

        Returns:
            The framework or None if not found
        """
        result = await self.db.execute(
            select(ComplianceFramework).where(
                ComplianceFramework.framework_id == framework_id
            )
        )
        return result.scalar_one_or_none()

    async def get_framework_controls(
        self, framework_id: str
    ) -> list[ComplianceControl]:
        """Get all controls for a framework.

        Args:
            framework_id: The framework identifier

        Returns:
            List of ComplianceControl objects
        """
        # Get framework UUID first
        framework = await self.get_framework(framework_id)
        if not framework:
            return []

        result = await self.db.execute(
            select(ComplianceControl)
            .where(ComplianceControl.framework_id == framework.id)
            .options(selectinload(ComplianceControl.technique_mappings))
            .order_by(ComplianceControl.display_order)
        )
        return list(result.scalars().all())

    async def get_control_techniques(
        self, control_id: UUID
    ) -> list[ControlTechniqueMapping]:
        """Get technique mappings for a control.

        Args:
            control_id: The control UUID

        Returns:
            List of ControlTechniqueMapping objects
        """
        result = await self.db.execute(
            select(ControlTechniqueMapping)
            .where(ControlTechniqueMapping.control_id == control_id)
            .options(selectinload(ControlTechniqueMapping.technique))
        )
        return list(result.scalars().all())

    async def calculate_compliance_coverage(
        self,
        cloud_account_id: UUID,
        coverage_snapshot_id: UUID,
    ) -> list[ComplianceCoverageSnapshot]:
        """Calculate and store compliance coverage for all frameworks.

        Called after MITRE coverage is calculated.

        Args:
            cloud_account_id: The cloud account UUID
            coverage_snapshot_id: The MITRE coverage snapshot UUID

        Returns:
            List of created ComplianceCoverageSnapshot objects
        """
        self.logger.info(
            "calculating_compliance_coverage",
            account_id=str(cloud_account_id),
            coverage_snapshot_id=str(coverage_snapshot_id),
        )

        # Get the MITRE coverage snapshot to extract technique coverage
        coverage_snapshot = await self.db.get(CoverageSnapshot, coverage_snapshot_id)
        if not coverage_snapshot:
            self.logger.error(
                "coverage_snapshot_not_found",
                coverage_snapshot_id=str(coverage_snapshot_id),
            )
            return []

        # Build technique coverage dict from the tactic_coverage data
        # We need to get the actual technique details from the coverage snapshot
        technique_coverage = await self._extract_technique_coverage(
            cloud_account_id, coverage_snapshot
        )

        # Get all active frameworks
        frameworks = await self.get_frameworks(active_only=True)
        if not frameworks:
            self.logger.info("no_active_frameworks")
            return []

        # Calculate coverage for each framework
        calculator = ComplianceCoverageCalculator(self.db)
        snapshots = []

        for framework in frameworks:
            try:
                result = await calculator.calculate(framework.id, technique_coverage)

                # Build family coverage dict for storage
                family_coverage = {
                    name: {
                        "family": info.family,
                        "total": info.total,
                        "covered": info.covered,
                        "partial": info.partial,
                        "uncovered": info.uncovered,
                        "not_assessable": info.not_assessable,
                        "percent": info.percent,
                        "cloud_applicability": info.cloud_applicability,
                        "shared_responsibility": info.shared_responsibility,
                    }
                    for name, info in result.family_coverage.items()
                }

                # Build cloud metrics dict for storage
                cloud_metrics = {
                    "cloud_detectable_total": result.cloud_metrics.cloud_detectable_total,
                    "cloud_detectable_covered": result.cloud_metrics.cloud_detectable_covered,
                    "cloud_coverage_percent": result.cloud_metrics.cloud_coverage_percent,
                    "customer_responsibility_total": result.cloud_metrics.customer_responsibility_total,
                    "customer_responsibility_covered": result.cloud_metrics.customer_responsibility_covered,
                    "provider_managed_total": result.cloud_metrics.provider_managed_total,
                    "not_assessable_total": result.cloud_metrics.not_assessable_total,
                }

                # Build top gaps list for storage
                top_gaps = [
                    {
                        "control_id": gap.control_id,
                        "control_name": gap.control_name,
                        "control_family": gap.control_family,
                        "priority": gap.priority,
                        "coverage_percent": gap.coverage_percent,
                        "missing_techniques": gap.missing_techniques,
                        "cloud_applicability": gap.cloud_applicability,
                        "cloud_context": gap.cloud_context,
                    }
                    for gap in result.top_gaps
                ]

                # Create snapshot
                snapshot = ComplianceCoverageSnapshot(
                    cloud_account_id=cloud_account_id,
                    framework_id=framework.id,
                    coverage_snapshot_id=coverage_snapshot_id,
                    total_controls=result.total_controls,
                    covered_controls=result.covered_controls,
                    partial_controls=result.partial_controls,
                    uncovered_controls=result.uncovered_controls,
                    coverage_percent=result.coverage_percent,
                    family_coverage=family_coverage,
                    top_gaps=top_gaps,
                    cloud_metrics=cloud_metrics,
                )
                self.db.add(snapshot)
                snapshots.append(snapshot)

                self.logger.info(
                    "compliance_snapshot_created",
                    framework_id=framework.framework_id,
                    coverage_percent=result.coverage_percent,
                )

            except Exception as e:
                self.logger.error(
                    "compliance_calculation_failed",
                    framework_id=framework.framework_id,
                    error=str(e),
                )
                continue

        await self.db.flush()

        self.logger.info(
            "compliance_coverage_complete",
            account_id=str(cloud_account_id),
            frameworks_processed=len(snapshots),
        )

        return snapshots

    async def _extract_technique_coverage(
        self,
        cloud_account_id: UUID,
        coverage_snapshot: CoverageSnapshot,
    ) -> dict[str, str]:
        """Extract technique coverage status from MITRE coverage data.

        Returns a dict mapping technique_id (e.g., "T1078") to status
        ("covered", "partial", "uncovered").
        """
        # Get all techniques
        result = await self.db.execute(select(Technique))
        techniques = result.scalars().all()

        # Build coverage dict - start with all uncovered
        technique_coverage: dict[str, str] = {
            t.technique_id: "uncovered" for t in techniques
        }

        # The coverage snapshot has top_gaps which tells us uncovered/partial
        # But we also need to look at the detection mappings
        # For now, we'll use a heuristic based on the gaps

        # Get technique IDs from gaps (these are uncovered or partial)
        uncovered_or_partial = set()
        for gap in coverage_snapshot.top_gaps or []:
            tech_id = gap.get("technique_id")
            if tech_id:
                uncovered_or_partial.add(tech_id)

        # For each tactic, we know covered/partial/uncovered counts
        # But we need the actual technique IDs

        # We can approximate: if total_covered > 0, mark some techniques as covered
        # This is imperfect - in production we'd query the actual detection mappings

        # Get techniques with detections (these are covered or partial)
        from app.models.mapping import DetectionMapping
        from app.models.detection import Detection, DetectionStatus

        # Query active detections with mappings
        mappings_result = await self.db.execute(
            select(
                DetectionMapping.technique_id,
                func.max(DetectionMapping.confidence).label("max_confidence"),
            )
            .join(Detection, Detection.id == DetectionMapping.detection_id)
            .where(
                Detection.cloud_account_id == cloud_account_id,
                Detection.status == DetectionStatus.ACTIVE,
            )
            .group_by(DetectionMapping.technique_id)
        )

        # Build UUID to technique_id map
        technique_uuid_to_id = {t.id: t.technique_id for t in techniques}

        for row in mappings_result.fetchall():
            technique_uuid = row[0]
            max_confidence = row[1]

            tech_id = technique_uuid_to_id.get(technique_uuid)
            if not tech_id:
                continue

            # Determine status based on confidence
            if max_confidence >= 0.6:
                technique_coverage[tech_id] = "covered"
            elif max_confidence >= 0.4:
                technique_coverage[tech_id] = "partial"
            # else stays uncovered

        return technique_coverage

    async def get_compliance_summary(self, cloud_account_id: UUID) -> list[dict]:
        """Get compliance coverage summary for all frameworks.

        Args:
            cloud_account_id: The cloud account UUID

        Returns:
            List of coverage summaries per framework
        """
        # Get latest snapshot for each framework
        subquery = (
            select(
                ComplianceCoverageSnapshot.framework_id,
                func.max(ComplianceCoverageSnapshot.created_at).label("latest"),
            )
            .where(ComplianceCoverageSnapshot.cloud_account_id == cloud_account_id)
            .group_by(ComplianceCoverageSnapshot.framework_id)
            .subquery()
        )

        result = await self.db.execute(
            select(ComplianceCoverageSnapshot)
            .join(
                subquery,
                (ComplianceCoverageSnapshot.framework_id == subquery.c.framework_id)
                & (ComplianceCoverageSnapshot.created_at == subquery.c.latest),
            )
            .options(selectinload(ComplianceCoverageSnapshot.framework))
        )

        snapshots = result.scalars().all()

        summaries = []
        for snapshot in snapshots:
            # Extract cloud coverage percent from stored metrics
            cloud_coverage = None
            if snapshot.cloud_metrics:
                cloud_coverage = snapshot.cloud_metrics.get("cloud_coverage_percent")

            summaries.append(
                {
                    "framework_id": snapshot.framework.framework_id,
                    "framework_name": snapshot.framework.name,
                    "coverage_percent": snapshot.coverage_percent,
                    "covered_controls": snapshot.covered_controls,
                    "total_controls": snapshot.total_controls,
                    "cloud_coverage_percent": cloud_coverage,
                }
            )

        return summaries

    async def get_framework_coverage(
        self,
        cloud_account_id: UUID,
        framework_id: str,
    ) -> Optional[ComplianceCoverageSnapshot]:
        """Get latest compliance coverage for a specific framework.

        Args:
            cloud_account_id: The cloud account UUID
            framework_id: The framework identifier (e.g., "nist-800-53-r5")

        Returns:
            The latest ComplianceCoverageSnapshot or None
        """
        framework = await self.get_framework(framework_id)
        if not framework:
            return None

        result = await self.db.execute(
            select(ComplianceCoverageSnapshot)
            .where(
                ComplianceCoverageSnapshot.cloud_account_id == cloud_account_id,
                ComplianceCoverageSnapshot.framework_id == framework.id,
            )
            .options(selectinload(ComplianceCoverageSnapshot.framework))
            .order_by(ComplianceCoverageSnapshot.created_at.desc())
            .limit(1)
        )

        return result.scalar_one_or_none()

    async def enrich_gap_techniques(self, technique_ids: list[str]) -> list[dict]:
        """Enrich technique IDs with names and template availability.

        Args:
            technique_ids: List of MITRE technique IDs (e.g., ["T1078", "T1136"])

        Returns:
            List of enriched technique details with names and template status
        """
        if not technique_ids:
            return []

        from app.data.remediation_templates.template_loader import get_template

        # Query technique names from database
        result = await self.db.execute(
            select(Technique).where(Technique.technique_id.in_(technique_ids))
        )
        techniques = result.scalars().all()

        # Build lookup map
        technique_map = {t.technique_id: t for t in techniques}

        enriched = []
        for tech_id in technique_ids:
            technique = technique_map.get(tech_id)
            template = get_template(tech_id)

            enriched.append(
                {
                    "technique_id": tech_id,
                    "technique_name": technique.name if technique else tech_id,
                    "has_template": template is not None,
                    "tactic_ids": template.tactic_ids if template else [],
                }
            )

        return enriched

    async def get_controls_by_status(
        self,
        cloud_account_id: UUID,
        framework_id: str,
    ) -> tuple[dict, dict]:
        """Get controls grouped by coverage status and cloud category.

        Returns:
            Tuple of (controls_by_status, controls_by_cloud_category)
        """
        from app.analyzers.compliance_calculator import (
            COVERED_THRESHOLD,
            PARTIAL_THRESHOLD,
        )

        # Get the framework
        result = await self.db.execute(
            select(ComplianceFramework).where(
                ComplianceFramework.framework_id == framework_id
            )
        )
        framework = result.scalar_one_or_none()
        if not framework:
            return {}, {}

        # Get covered technique UUIDs from active detection mappings
        from app.models.mapping import DetectionMapping
        from app.models.detection import Detection, DetectionStatus

        mappings_result = await self.db.execute(
            select(DetectionMapping.technique_id)
            .join(Detection, Detection.id == DetectionMapping.detection_id)
            .where(
                Detection.cloud_account_id == cloud_account_id,
                Detection.status == DetectionStatus.ACTIVE,
            )
            .distinct()
        )
        covered_technique_uuids = {row[0] for row in mappings_result.fetchall()}

        # Get all controls with their technique mappings
        controls_result = await self.db.execute(
            select(ComplianceControl)
            .where(ComplianceControl.framework_id == framework.id)
            .options(selectinload(ComplianceControl.technique_mappings))
        )
        controls = controls_result.scalars().all()

        # Group controls by status
        by_status = {
            "covered": [],
            "partial": [],
            "uncovered": [],
            "not_assessable": [],
        }
        by_cloud = {
            "cloud_detectable": [],
            "customer_responsibility": [],
            "provider_managed": [],
            "not_assessable": [],
        }

        for control in controls:
            # Get mapped technique UUIDs
            mapped_technique_uuids = [
                m.technique_id for m in control.technique_mappings
            ]

            # Determine if assessable via cloud scanning
            is_not_assessable = control.cloud_applicability in (
                "informational",
                "provider_responsibility",
            )

            # Get cloud context for shared responsibility
            cloud_context = control.cloud_context or {}
            shared_resp = cloud_context.get("shared_responsibility", "customer")

            # Calculate coverage
            if is_not_assessable or not mapped_technique_uuids:
                status = "not_assessable"
                coverage_pct = 0.0
                covered_count = 0
            else:
                covered_count = sum(
                    1
                    for t_uuid in mapped_technique_uuids
                    if t_uuid in covered_technique_uuids
                )
                coverage_pct = (
                    covered_count / len(mapped_technique_uuids) * 100
                    if mapped_technique_uuids
                    else 0.0
                )

                if coverage_pct >= COVERED_THRESHOLD * 100:
                    status = "covered"
                elif coverage_pct >= PARTIAL_THRESHOLD * 100:
                    status = "partial"
                else:
                    status = "uncovered"

            # Build control item
            control_item = {
                "control_id": control.control_id,
                "control_name": control.name,
                "control_family": control.control_family,
                "priority": control.priority,
                "coverage_percent": round(coverage_pct, 1),
                "mapped_techniques": len(mapped_technique_uuids),
                "covered_techniques": covered_count,
                "cloud_applicability": control.cloud_applicability,
                "shared_responsibility": shared_resp,
            }

            # Add to status group
            by_status[status].append(control_item)

            # Add to cloud category group
            if is_not_assessable:
                by_cloud["not_assessable"].append(control_item)
            elif shared_resp == "provider":
                by_cloud["provider_managed"].append(control_item)
            elif shared_resp == "customer":
                by_cloud["customer_responsibility"].append(control_item)
                by_cloud["cloud_detectable"].append(control_item)
            else:  # shared
                by_cloud["customer_responsibility"].append(control_item)
                by_cloud["cloud_detectable"].append(control_item)

        # Sort each group by priority then control_id
        def sort_key(c):
            priority_order = {"P1": 0, "P2": 1, "P3": 2, None: 3}
            return (priority_order.get(c.get("priority"), 3), c.get("control_id", ""))

        for status_list in by_status.values():
            status_list.sort(key=sort_key)
        for cloud_list in by_cloud.values():
            cloud_list.sort(key=sort_key)

        return by_status, by_cloud
