"""Coverage calculation service."""

from uuid import UUID
import structlog

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.coverage import CoverageSnapshot
from app.analyzers.coverage_calculator import CoverageCalculator
from app.analyzers.gap_analyzer import GapAnalyzer
from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class CoverageService:
    """Service for calculating and storing coverage snapshots."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(service="CoverageService")

    async def calculate_coverage(
        self,
        cloud_account_id: UUID,
        scan_id: UUID = None,
    ) -> CoverageSnapshot:
        """Calculate and store a coverage snapshot.

        Args:
            cloud_account_id: The cloud account to calculate coverage for
            scan_id: Optional scan ID that triggered this calculation

        Returns:
            The created CoverageSnapshot
        """
        self.logger.info(
            "calculating_coverage",
            account_id=str(cloud_account_id),
        )

        # Calculate coverage
        calculator = CoverageCalculator(self.db)
        result = await calculator.calculate(cloud_account_id)

        # Analyze gaps
        gap_analyzer = GapAnalyzer()
        gaps = gap_analyzer.analyze_gaps(result.technique_details, limit=20)

        # Build tactic coverage dict
        tactic_coverage = {}
        for tactic_id, info in result.tactic_coverage.items():
            tactic_coverage[tactic_id] = {
                "name": info.tactic_name,
                "covered": info.covered,
                "partial": info.partial,
                "uncovered": info.uncovered,
                "total": info.total_techniques,
                "percent": info.percent,
            }

        # Build top gaps list
        top_gaps = []
        for gap in gaps:
            top_gaps.append({
                "technique_id": gap.technique_id,
                "name": gap.technique_name,
                "tactic_id": gap.tactic_id,
                "tactic_name": gap.tactic_name,
                "priority": gap.priority,
                "reason": gap.reason,
                "data_sources": gap.data_sources,
            })

        # Create snapshot
        snapshot = CoverageSnapshot(
            cloud_account_id=cloud_account_id,
            total_techniques=result.total_techniques,
            covered_techniques=result.covered_techniques,
            partial_techniques=result.partial_techniques,
            uncovered_techniques=result.uncovered_techniques,
            coverage_percent=result.coverage_percent,
            average_confidence=result.average_confidence,
            tactic_coverage=tactic_coverage,
            total_detections=result.total_detections,
            active_detections=result.active_detections,
            mapped_detections=result.mapped_detections,
            top_gaps=top_gaps,
            mitre_version=settings.mitre_attack_version,
            scan_id=scan_id,
        )

        self.db.add(snapshot)
        await self.db.flush()
        await self.db.refresh(snapshot)

        self.logger.info(
            "coverage_snapshot_created",
            account_id=str(cloud_account_id),
            coverage=result.coverage_percent,
            snapshot_id=str(snapshot.id),
        )

        return snapshot
