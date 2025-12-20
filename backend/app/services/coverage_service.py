"""Coverage calculation service."""

from uuid import UUID
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.coverage import CoverageSnapshot, OrgCoverageSnapshot
from app.models.cloud_account import CloudAccount
from app.models.cloud_organization import CloudOrganization
from app.analyzers.coverage_calculator import CoverageCalculator, OrgCoverageCalculator
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

        # Get cloud account to determine provider
        account = await self.db.get(CloudAccount, cloud_account_id)
        cloud_provider = account.provider.value if account else None

        # Calculate coverage
        calculator = CoverageCalculator(self.db)
        result = await calculator.calculate(cloud_account_id)

        # Analyze gaps - no limit to show full coverage picture
        # Pass cloud provider to filter strategies
        gap_analyzer = GapAnalyzer()
        gaps = gap_analyzer.analyze_gaps(
            result.technique_details,
            cloud_provider=cloud_provider,
        )

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

        # Build top gaps list with enhanced remediation data
        top_gaps = []
        for gap in gaps:
            gap_data = {
                "technique_id": gap.technique_id,
                "name": gap.technique_name,
                "tactic_id": gap.tactic_id,
                "tactic_name": gap.tactic_name,
                "priority": gap.priority,
                "reason": gap.reason,
                "data_sources": gap.data_sources,
                "recommended_detections": gap.recommended_detections,
                # Enhanced template data
                "has_template": gap.has_template,
                "severity_score": gap.severity_score,
                "threat_actors": gap.threat_actors,
                "business_impact": gap.business_impact,
                "quick_win_strategy": gap.quick_win_strategy,
                "total_effort_hours": gap.total_effort_hours,
                "mitre_url": gap.mitre_url,
            }

            # Add recommended strategies if available
            if gap.recommended_strategies:
                gap_data["recommended_strategies"] = [
                    {
                        "strategy_id": s.strategy_id,
                        "name": s.name,
                        "detection_type": s.detection_type,
                        "aws_service": s.aws_service,
                        "implementation_effort": s.implementation_effort,
                        "estimated_time": s.estimated_time,
                        "detection_coverage": s.detection_coverage,
                        "has_query": s.has_query,
                        "has_cloudformation": s.has_cloudformation,
                        "has_terraform": s.has_terraform,
                        # GCP support
                        "gcp_service": s.gcp_service,
                        "cloud_provider": s.cloud_provider,
                        "has_gcp_query": s.has_gcp_query,
                        "has_gcp_terraform": s.has_gcp_terraform,
                    }
                    for s in gap.recommended_strategies
                ]

            top_gaps.append(gap_data)

        # Create snapshot with org contribution fields
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
            # Org contribution fields
            org_detection_count=result.org_detection_count,
            org_covered_techniques=result.org_covered_techniques,
            account_only_techniques=result.account_only_techniques,
            org_only_techniques=result.org_only_techniques,
            overlap_techniques=result.overlap_techniques,
            coverage_breakdown=result.coverage_breakdown,
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

    async def calculate_org_coverage(
        self,
        cloud_organization_id: UUID,
    ) -> OrgCoverageSnapshot:
        """Calculate and store aggregate coverage for a cloud organisation.

        Args:
            cloud_organization_id: The cloud organisation to calculate coverage for

        Returns:
            The created OrgCoverageSnapshot
        """
        self.logger.info(
            "calculating_org_coverage",
            cloud_org_id=str(cloud_organization_id),
        )

        # Verify org exists
        org_result = await self.db.execute(
            select(CloudOrganization).where(
                CloudOrganization.id == cloud_organization_id
            )
        )
        cloud_org = org_result.scalar_one_or_none()
        if not cloud_org:
            raise ValueError(f"Cloud organisation {cloud_organization_id} not found")

        # Calculate aggregate coverage
        calculator = OrgCoverageCalculator(self.db)
        result = await calculator.calculate(cloud_organization_id)

        # Build per-account coverage dict for storage
        per_account_coverage = {
            str(account_id): coverage
            for account_id, coverage in result.per_account_coverage.items()
        }

        # Create org coverage snapshot
        snapshot = OrgCoverageSnapshot(
            cloud_organization_id=cloud_organization_id,
            total_member_accounts=result.total_member_accounts,
            connected_accounts=result.connected_accounts,
            total_techniques=result.total_techniques,
            union_covered_techniques=result.union_covered_techniques,
            minimum_covered_techniques=result.minimum_covered_techniques,
            average_coverage_percent=result.average_coverage_percent,
            union_coverage_percent=result.union_coverage_percent,
            minimum_coverage_percent=result.minimum_coverage_percent,
            org_detection_count=result.org_detection_count,
            org_covered_techniques=result.org_covered_techniques,
            per_account_coverage=per_account_coverage,
            tactic_coverage=result.tactic_coverage,
            mitre_version=settings.mitre_attack_version,
        )

        self.db.add(snapshot)
        await self.db.flush()
        await self.db.refresh(snapshot)

        self.logger.info(
            "org_coverage_snapshot_created",
            cloud_org_id=str(cloud_organization_id),
            union_coverage=result.union_coverage_percent,
            minimum_coverage=result.minimum_coverage_percent,
            snapshot_id=str(snapshot.id),
        )

        return snapshot
