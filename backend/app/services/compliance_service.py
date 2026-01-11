"""Compliance coverage service.

Manages compliance framework coverage calculations and storage.
"""

from typing import Any, Optional
from uuid import UUID
from datetime import datetime, timedelta

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

# In-memory cache for framework IDs (lightweight, rarely changes)
# Format: {framework_id: (framework_uuid, cached_at)}
_framework_id_cache: dict[str, tuple[UUID, datetime]] = {}
_FRAMEWORK_CACHE_TTL = timedelta(hours=1)


def _get_cached_framework_uuid(framework_id: str) -> Optional[UUID]:
    """Get framework UUID from cache if valid."""
    if framework_id in _framework_id_cache:
        uuid, cached_at = _framework_id_cache[framework_id]
        if datetime.utcnow() - cached_at < _FRAMEWORK_CACHE_TTL:
            return uuid
        # Expired, remove from cache
        del _framework_id_cache[framework_id]
    return None


def _cache_framework_uuid(framework_id: str, uuid: UUID) -> None:
    """Cache framework UUID for quick lookups."""
    _framework_id_cache[framework_id] = (uuid, datetime.utcnow())


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
        frameworks = list(result.scalars().all())

        # Cache framework IDs for faster lookups
        for fw in frameworks:
            _cache_framework_uuid(fw.framework_id, fw.id)

        return frameworks

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
        cloud_only: bool = True,
    ) -> list[ComplianceCoverageSnapshot]:
        """Calculate and store compliance coverage for all frameworks.

        Called after MITRE coverage is calculated.

        Args:
            cloud_account_id: The cloud account UUID
            coverage_snapshot_id: The MITRE coverage snapshot UUID
            cloud_only: If True (default), only include cloud-relevant techniques
                        in coverage calculations. Non-cloud techniques are excluded.

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
        # Pass cloud_account_id for service-aware coverage calculation
        calculator = ComplianceCoverageCalculator(self.db)
        snapshots = []

        for framework in frameworks:
            try:
                result = await calculator.calculate(
                    framework.id, technique_coverage, cloud_account_id, cloud_only
                )

                # Build family coverage dict for storage
                family_coverage = {
                    name: {
                        "family": info.family,
                        "total": info.total,
                        "covered": info.covered,
                        "partial": info.partial,
                        "uncovered": info.uncovered,
                        "not_assessable": info.not_assessable,
                        "assessable": info.assessable,
                        "percent": info.percent,
                        "cloud_applicability": info.cloud_applicability,
                        "shared_responsibility": info.shared_responsibility,
                        "applicability_breakdown": info.applicability_breakdown,
                        "responsibility_breakdown": info.responsibility_breakdown,
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
                    # Cloud-only filtering transparency
                    "cloud_only_filter": result.cloud_only_filter,
                    "total_techniques_mapped": result.total_techniques_mapped,
                    "cloud_techniques_mapped": result.cloud_techniques_mapped,
                    "non_cloud_techniques_filtered": result.non_cloud_techniques_filtered,
                }

                # Add service metrics if available
                if result.service_metrics:
                    cloud_metrics["service_coverage"] = {
                        "total_in_scope_services": result.service_metrics.total_in_scope_services,
                        "total_covered_services": result.service_metrics.total_covered_services,
                        "service_coverage_percent": result.service_metrics.service_coverage_percent,
                        "uncovered_services": result.service_metrics.uncovered_services,
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
                        # Service coverage fields
                        "service_coverage_percent": gap.service_coverage_percent,
                        "in_scope_services": gap.in_scope_services,
                        "covered_services": gap.covered_services,
                        "uncovered_services": gap.uncovered_services,
                        # Family grouping fields
                        "related_gaps_count": gap.related_gaps_count,
                        "related_gap_ids": gap.related_gap_ids,
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
        from app.core.config import settings

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

            # Determine status based on confidence (60% = covered per user docs)
            if max_confidence >= settings.confidence_threshold_covered:
                technique_coverage[tech_id] = "covered"
            elif max_confidence >= settings.confidence_threshold_partial:
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

    async def get_control_coverage_detail(
        self,
        control_id: str,
        framework_id: str,
        cloud_account_id: UUID,
    ) -> Optional[dict]:
        """Get detailed coverage breakdown for a single control.

        Shows which techniques are covered vs. uncovered and what detections
        provide the coverage.

        Args:
            control_id: The control ID (e.g., "1", "AC-2")
            framework_id: The framework identifier (e.g., "cis-controls-v8")
            cloud_account_id: The cloud account UUID

        Returns:
            Detailed coverage breakdown or None if control not found
        """
        from app.models.mapping import DetectionMapping
        from app.models.detection import Detection, DetectionStatus
        from app.data.remediation_templates.template_loader import get_template
        from app.core.config import settings

        # Import control-level thresholds (used for control coverage %, not technique confidence)
        from app.analyzers.compliance_calculator import (
            COVERED_THRESHOLD,
            PARTIAL_THRESHOLD,
        )

        # Get the framework
        framework = await self.get_framework(framework_id)
        if not framework:
            return None

        # Get the control with technique mappings
        result = await self.db.execute(
            select(ComplianceControl)
            .where(
                ComplianceControl.control_id == control_id,
                ComplianceControl.framework_id == framework.id,
            )
            .options(
                selectinload(ComplianceControl.technique_mappings).selectinload(
                    ControlTechniqueMapping.technique
                )
            )
        )
        control = result.scalar_one_or_none()
        if not control:
            return None

        # Get all detection mappings for this account
        mappings_result = await self.db.execute(
            select(
                DetectionMapping.technique_id,
                DetectionMapping.confidence,
                Detection.id.label("detection_id"),
                Detection.name.label("detection_name"),
                Detection.detection_type.label("detection_source"),
            )
            .join(Detection, Detection.id == DetectionMapping.detection_id)
            .where(
                Detection.cloud_account_id == cloud_account_id,
                Detection.status == DetectionStatus.ACTIVE,
            )
        )
        detection_rows = mappings_result.fetchall()

        # Build detection lookup: technique_uuid -> list of (detection_info, confidence)
        detection_by_technique: dict[UUID, list[dict]] = {}
        for row in detection_rows:
            tech_uuid = row[0]
            if tech_uuid not in detection_by_technique:
                detection_by_technique[tech_uuid] = []
            detection_by_technique[tech_uuid].append(
                {
                    "id": row[2],
                    "name": row[3],
                    "source": row[4].value if hasattr(row[4], "value") else str(row[4]),
                    "confidence": row[1],
                }
            )

        # Deduplicate detections by name within each technique (same rule in multiple
        # regions creates duplicate entries). Keep highest confidence per unique name.
        for tech_uuid in detection_by_technique:
            detections = detection_by_technique[tech_uuid]
            # Sort by confidence descending so highest confidence comes first
            detections.sort(key=lambda d: d["confidence"], reverse=True)
            # Deduplicate by name, keeping first (highest confidence)
            seen_names: set[str] = set()
            unique_detections = []
            for d in detections:
                if d["name"] not in seen_names:
                    seen_names.add(d["name"])
                    unique_detections.append(d)
            detection_by_technique[tech_uuid] = unique_detections

        # Get acknowledged/risk_accepted gaps for this account
        from app.models.gap import CoverageGap, GapStatus
        from app.models.user import User

        acknowledged_statuses = [GapStatus.ACKNOWLEDGED, GapStatus.RISK_ACCEPTED]
        gaps_result = await self.db.execute(
            select(
                CoverageGap.technique_id,
                CoverageGap.status,
                CoverageGap.risk_acceptance_reason,
                CoverageGap.risk_accepted_at,
                User.email.label("accepted_by_email"),
            )
            .outerjoin(User, CoverageGap.risk_accepted_by == User.id)
            .where(
                CoverageGap.cloud_account_id == cloud_account_id,
                CoverageGap.status.in_(acknowledged_statuses),
            )
        )
        gap_rows = gaps_result.fetchall()

        # Build gap lookup: technique_id (string) -> gap info
        acknowledged_gaps: dict[str, dict] = {}
        for row in gap_rows:
            tech_id = row[0]  # technique_id is a string like "T1078"
            acknowledged_gaps[tech_id] = {
                "status": row[1].value if hasattr(row[1], "value") else str(row[1]),
                "reason": row[2],
                "accepted_at": row[3],
                "accepted_by": row[4],
            }

        # Build technique details
        techniques_detail = []
        covered_count = 0
        acknowledged_gap_technique_ids: list[str] = []

        for mapping in control.technique_mappings:
            technique = mapping.technique
            if not technique:
                continue

            # Get detections for this technique
            detections = detection_by_technique.get(technique.id, [])

            # Calculate max confidence
            max_confidence = max((d["confidence"] for d in detections), default=0)

            # Determine status using technique-level thresholds (0.6/0.4 from settings)
            # NOT control-level thresholds (0.8/0.4 from compliance_calculator)
            if max_confidence >= settings.confidence_threshold_covered:
                status = "covered"
                covered_count += 1
            elif max_confidence >= settings.confidence_threshold_partial:
                status = "partial"
            else:
                status = "uncovered"

            # Check for remediation template
            template = get_template(technique.technique_id)

            # Check for acknowledged gap
            gap_info = acknowledged_gaps.get(technique.technique_id)
            acknowledged_gap = None
            if gap_info:
                acknowledged_gap_technique_ids.append(technique.technique_id)
                acknowledged_gap = {
                    "status": gap_info["status"],
                    "reason": gap_info["reason"],
                    "accepted_by": gap_info["accepted_by"],
                    "accepted_at": gap_info["accepted_at"],
                }

            techniques_detail.append(
                {
                    "technique_id": technique.technique_id,
                    "technique_name": technique.name,
                    "status": status,
                    "confidence": max_confidence if detections else None,
                    "detections": [
                        {
                            "id": d["id"],
                            "name": d["name"],
                            "source": d["source"],
                            "confidence": d["confidence"],
                        }
                        for d in sorted(
                            detections, key=lambda x: x["confidence"], reverse=True
                        )
                    ],
                    "has_template": template is not None,
                    "acknowledged_gap": acknowledged_gap,
                }
            )

        # Sort by status (covered first, then partial, then uncovered)
        status_order = {"covered": 0, "partial": 1, "uncovered": 2}
        techniques_detail.sort(key=lambda t: status_order.get(t["status"], 3))

        # Calculate overall coverage
        total_techniques = len(control.technique_mappings)
        coverage_pct = (
            (covered_count / total_techniques * 100) if total_techniques > 0 else 0
        )

        # Determine overall status
        if total_techniques == 0:
            overall_status = "not_assessable"
        elif coverage_pct >= COVERED_THRESHOLD * 100:
            overall_status = "covered"
        elif coverage_pct >= PARTIAL_THRESHOLD * 100:
            overall_status = "partial"
        else:
            overall_status = "uncovered"

        # Build human-readable rationale
        # "Covered" means detection confidence >= 60% (settings.confidence_threshold_covered)
        if total_techniques == 0:
            rationale = "No MITRE techniques mapped to this control"
        elif covered_count == total_techniques:
            rationale = (
                f"All {total_techniques} mapped techniques have adequate "
                f"detection coverage (60%+)"
            )
        elif covered_count == 0:
            rationale = (
                f"None of the {total_techniques} mapped techniques have "
                f"adequate detection coverage (60%+)"
            )
        else:
            rationale = (
                f"{covered_count} of {total_techniques} mapped techniques "
                f"have adequate detection coverage (60%+)"
            )

        # Build cloud context
        cloud_context = None
        if control.cloud_context:
            cloud_context = {
                "aws_services": control.cloud_context.get("aws_services", []),
                "gcp_services": control.cloud_context.get("gcp_services", []),
                "shared_responsibility": control.cloud_context.get(
                    "shared_responsibility", "customer"
                ),
                "detection_guidance": control.cloud_context.get("detection_guidance"),
            }

        return {
            "control_id": control.control_id,
            "control_name": control.name,
            "control_family": control.control_family,
            "description": control.description,
            "priority": control.priority,
            "status": overall_status,
            "coverage_percent": round(coverage_pct, 1),
            "coverage_rationale": rationale,
            "mapped_techniques": total_techniques,
            "covered_techniques": covered_count,
            "cloud_applicability": control.cloud_applicability,
            "cloud_context": cloud_context,
            "techniques": techniques_detail,
            "acknowledged_gaps_count": len(acknowledged_gap_technique_ids),
            "acknowledged_gap_techniques": acknowledged_gap_technique_ids,
        }

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

        # Get technique coverage status from active detection mappings
        # Using settings.confidence_threshold_covered (0.6) and
        # settings.confidence_threshold_partial (0.4) for technique-level coverage
        from app.models.mapping import DetectionMapping
        from app.models.detection import Detection, DetectionStatus
        from app.core.config import settings

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

        # Build technique status lookup using technique-level thresholds (0.6/0.4)
        technique_status: dict[UUID, str] = {}
        for row in mappings_result.fetchall():
            technique_uuid = row[0]
            max_confidence = row[1]
            if max_confidence >= settings.confidence_threshold_covered:
                technique_status[technique_uuid] = "covered"
            elif max_confidence >= settings.confidence_threshold_partial:
                technique_status[technique_uuid] = "partial"
            # else not in dict = uncovered

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
            # Note: provider_responsibility is assessable but managed by provider
            is_not_assessable = control.cloud_applicability == "informational"
            is_provider_managed = (
                control.cloud_applicability == "provider_responsibility"
            )

            # Get cloud context for shared responsibility
            cloud_context = control.cloud_context or {}
            shared_resp = cloud_context.get("shared_responsibility", "customer")

            # Calculate coverage using same logic as compliance calculator
            # Only count techniques with "covered" status (confidence >= 0.6)
            if is_not_assessable or is_provider_managed or not mapped_technique_uuids:
                # Provider-managed controls show as "covered" (provider handles them)
                # Not assessable controls show as "not_assessable"
                status = "covered" if is_provider_managed else "not_assessable"
                coverage_pct = 100.0 if is_provider_managed else 0.0
                covered_count = (
                    len(mapped_technique_uuids) if is_provider_managed else 0
                )
            else:
                covered_count = sum(
                    1
                    for t_uuid in mapped_technique_uuids
                    if technique_status.get(t_uuid) == "covered"
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
            # Priority: not_assessable > provider_managed > customer/shared
            if is_not_assessable:
                by_cloud["not_assessable"].append(control_item)
            elif is_provider_managed:
                # Controls with cloud_applicability == "provider_responsibility"
                by_cloud["provider_managed"].append(control_item)
            elif shared_resp == "customer":
                by_cloud["customer_responsibility"].append(control_item)
                by_cloud["cloud_detectable"].append(control_item)
            else:  # shared
                by_cloud["customer_responsibility"].append(control_item)
                by_cloud["cloud_detectable"].append(control_item)

        # Sort each group by priority then control_id
        def sort_key(c: dict[str, Any]) -> tuple[int, str]:
            priority_order = {"P1": 0, "P2": 1, "P3": 2, None: 3}
            return (priority_order.get(c.get("priority"), 3), c.get("control_id", ""))

        for status_list in by_status.values():
            status_list.sort(key=sort_key)
        for cloud_list in by_cloud.values():
            cloud_list.sort(key=sort_key)

        return by_status, by_cloud
