"""Coverage calculator following 06-ANALYSIS-AGENT.md design."""

from dataclasses import dataclass
from uuid import UUID
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.detection import Detection, DetectionStatus
from app.models.mapping import DetectionMapping
from app.models.mitre import Technique
from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


@dataclass
class TechniqueCoverageInfo:
    """Coverage information for a single technique."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    status: str  # "covered", "partial", "uncovered"
    detection_count: int
    max_confidence: float
    avg_confidence: float


@dataclass
class TacticCoverageInfo:
    """Coverage information for a single tactic."""

    tactic_id: str
    tactic_name: str
    total_techniques: int
    covered: int
    partial: int
    uncovered: int
    percent: float


@dataclass
class CoverageResult:
    """Complete coverage calculation result."""

    total_techniques: int
    covered_techniques: int
    partial_techniques: int
    uncovered_techniques: int
    coverage_percent: float
    average_confidence: float
    tactic_coverage: dict[str, TacticCoverageInfo]
    technique_details: list[TechniqueCoverageInfo]
    total_detections: int
    active_detections: int
    mapped_detections: int


class CoverageCalculator:
    """Calculates MITRE ATT&CK coverage from detection mappings.

    Coverage rules from 00-MASTER-ORCHESTRATOR.md:
    - >= 0.6 confidence = "covered"
    - 0.4-0.6 confidence = "partial"
    - < 0.4 confidence = "uncovered"
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(component="CoverageCalculator")
        self.covered_threshold = settings.confidence_threshold_covered
        self.partial_threshold = settings.confidence_threshold_partial

    async def calculate(
        self,
        cloud_account_id: UUID,
    ) -> CoverageResult:
        """Calculate coverage for a cloud account.

        Args:
            cloud_account_id: The cloud account to calculate coverage for

        Returns:
            CoverageResult with complete coverage analysis
        """
        self.logger.info("calculating_coverage", account_id=str(cloud_account_id))

        # Get all techniques
        techniques = await self._get_all_techniques()

        # Get all mappings for this account's detections
        mappings = await self._get_account_mappings(cloud_account_id)

        # Get detection counts
        detection_counts = await self._get_detection_counts(cloud_account_id)

        # Build technique coverage map
        technique_coverage = self._build_technique_coverage(techniques, mappings)

        # Calculate tactic-level coverage
        tactic_coverage = self._calculate_tactic_coverage(technique_coverage)

        # Calculate overall metrics
        covered = sum(1 for t in technique_coverage if t.status == "covered")
        partial = sum(1 for t in technique_coverage if t.status == "partial")
        uncovered = sum(1 for t in technique_coverage if t.status == "uncovered")
        total = len(technique_coverage)

        coverage_percent = (covered / total * 100) if total > 0 else 0.0

        # Average confidence across covered/partial techniques
        confidences = [
            t.max_confidence
            for t in technique_coverage
            if t.status in ("covered", "partial")
        ]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        result = CoverageResult(
            total_techniques=total,
            covered_techniques=covered,
            partial_techniques=partial,
            uncovered_techniques=uncovered,
            coverage_percent=round(coverage_percent, 2),
            average_confidence=round(avg_confidence, 3),
            tactic_coverage=tactic_coverage,
            technique_details=technique_coverage,
            total_detections=detection_counts["total"],
            active_detections=detection_counts["active"],
            mapped_detections=detection_counts["mapped"],
        )

        self.logger.info(
            "coverage_calculated",
            account_id=str(cloud_account_id),
            coverage=coverage_percent,
            covered=covered,
            partial=partial,
            uncovered=uncovered,
        )

        return result

    async def _get_all_techniques(self) -> list[Technique]:
        """Get all MITRE techniques from database."""
        result = await self.db.execute(
            select(Technique).options(selectinload(Technique.tactic))
        )
        return list(result.scalars().unique().all())

    async def _get_account_mappings(
        self,
        cloud_account_id: UUID,
    ) -> list[DetectionMapping]:
        """Get all mappings for detections in this account."""
        result = await self.db.execute(
            select(DetectionMapping)
            .join(Detection)
            .options(
                selectinload(DetectionMapping.technique).selectinload(Technique.tactic)
            )
            .where(Detection.cloud_account_id == cloud_account_id)
            .where(Detection.status == DetectionStatus.ACTIVE)
        )
        return list(result.scalars().unique().all())

    async def _get_detection_counts(
        self,
        cloud_account_id: UUID,
    ) -> dict[str, int]:
        """Get detection counts for the account."""
        # Total detections
        total_result = await self.db.execute(
            select(Detection).where(Detection.cloud_account_id == cloud_account_id)
        )
        total = len(total_result.scalars().all())

        # Active detections
        active_result = await self.db.execute(
            select(Detection)
            .where(Detection.cloud_account_id == cloud_account_id)
            .where(Detection.status == DetectionStatus.ACTIVE)
        )
        active = len(active_result.scalars().all())

        # Mapped detections (with at least one mapping)
        mapped_result = await self.db.execute(
            select(Detection)
            .join(DetectionMapping)
            .where(Detection.cloud_account_id == cloud_account_id)
            .distinct()
        )
        mapped = len(mapped_result.scalars().unique().all())

        return {"total": total, "active": active, "mapped": mapped}

    def _build_technique_coverage(
        self,
        techniques: list[Technique],
        mappings: list[DetectionMapping],
    ) -> list[TechniqueCoverageInfo]:
        """Build coverage info for each technique."""
        # Group mappings by technique
        technique_mappings: dict[str, list[DetectionMapping]] = {}
        for mapping in mappings:
            if mapping.technique:
                tid = mapping.technique.technique_id
                if tid not in technique_mappings:
                    technique_mappings[tid] = []
                technique_mappings[tid].append(mapping)

        coverage_info = []
        for technique in techniques:
            tid = technique.technique_id
            tech_mappings = technique_mappings.get(tid, [])

            if tech_mappings:
                max_conf = max(m.confidence for m in tech_mappings)
                avg_conf = sum(m.confidence for m in tech_mappings) / len(tech_mappings)

                if max_conf >= self.covered_threshold:
                    status = "covered"
                elif max_conf >= self.partial_threshold:
                    status = "partial"
                else:
                    status = "uncovered"
            else:
                max_conf = 0.0
                avg_conf = 0.0
                status = "uncovered"

            coverage_info.append(
                TechniqueCoverageInfo(
                    technique_id=tid,
                    technique_name=technique.name,
                    tactic_id=technique.tactic.tactic_id if technique.tactic else "",
                    tactic_name=technique.tactic.name if technique.tactic else "",
                    status=status,
                    detection_count=len(tech_mappings),
                    max_confidence=max_conf,
                    avg_confidence=avg_conf,
                )
            )

        return coverage_info

    def _calculate_tactic_coverage(
        self,
        technique_coverage: list[TechniqueCoverageInfo],
    ) -> dict[str, TacticCoverageInfo]:
        """Calculate per-tactic coverage from technique coverage."""
        tactic_stats: dict[str, dict] = {}

        for tech in technique_coverage:
            tid = tech.tactic_id
            if tid not in tactic_stats:
                tactic_stats[tid] = {
                    "name": tech.tactic_name,
                    "total": 0,
                    "covered": 0,
                    "partial": 0,
                    "uncovered": 0,
                }

            tactic_stats[tid]["total"] += 1
            tactic_stats[tid][tech.status] += 1

        result = {}
        for tactic_id, stats in tactic_stats.items():
            total = stats["total"]
            covered = stats["covered"]
            percent = (covered / total * 100) if total > 0 else 0.0

            result[tactic_id] = TacticCoverageInfo(
                tactic_id=tactic_id,
                tactic_name=stats["name"],
                total_techniques=total,
                covered=covered,
                partial=stats["partial"],
                uncovered=stats["uncovered"],
                percent=round(percent, 2),
            )

        return result
