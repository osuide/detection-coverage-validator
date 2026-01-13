"""Advanced analytics service.

Provides trend analysis, insights, and recommendations
based on coverage data.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, TypedDict
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_account import CloudAccount
from app.models.coverage import CoverageSnapshot
from app.models.detection import Detection, DetectionType, DetectionStatus
from app.models.mapping import DetectionMapping
from app.models.mitre import Technique, Tactic


class TrendDataPoint(TypedDict):
    """Trend data point structure."""

    date: str
    coverage_percent: float
    covered_techniques: int
    total_techniques: int
    average_confidence: float


class DetectionTypeEffectiveness(TypedDict):
    """Detection effectiveness by type."""

    detection_type: str
    total_detections: int
    active_detections: int
    techniques_covered: int
    effectiveness_rate: float


class TacticBreakdown(TypedDict):
    """Tactic breakdown structure."""

    tactic_id: str
    tactic_name: str
    total_techniques: int
    covered_techniques: int
    coverage_percent: float
    priority_score: int


class AnalyticsService:
    """Service for advanced coverage analytics."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def _validate_account_ownership(
        self,
        organization_id: UUID,
        cloud_account_id: UUID,
    ) -> None:
        """Validate cloud account belongs to organisation.

        SECURITY: Prevents cross-tenant IDOR by ensuring the requested
        cloud_account_id actually belongs to the authenticated organisation.

        Args:
            organization_id: The authenticated user's organisation
            cloud_account_id: The requested cloud account ID

        Raises:
            ValueError: If account doesn't exist or doesn't belong to org
        """
        result = await self.db.execute(
            select(CloudAccount.id).where(
                CloudAccount.id == cloud_account_id,
                CloudAccount.organization_id == organization_id,
            )
        )
        if not result.scalar_one_or_none():
            raise ValueError("Account not found or access denied")

    async def get_coverage_trends(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
        allowed_account_ids: Optional[list[UUID]] = None,
        days: int = 30,
    ) -> dict:
        """Get coverage trend analysis over time.

        Args:
            organization_id: Organization to analyze
            cloud_account_id: Optional filter by account
            allowed_account_ids: Optional ACL filter (list of allowed account IDs)
            days: Number of days to analyze

        Returns:
            Coverage trend data with statistics
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # SECURITY: Validate account ownership to prevent cross-tenant IDOR
        if cloud_account_id:
            await self._validate_account_ownership(organization_id, cloud_account_id)
            account_ids = [cloud_account_id]
        else:
            # Build query for all org accounts
            query = select(CloudAccount.id).where(
                CloudAccount.organization_id == organization_id
            )
            # SECURITY: Apply allowed_account_ids ACL filter
            if allowed_account_ids is not None:
                query = query.where(CloudAccount.id.in_(allowed_account_ids))
            accounts_result = await self.db.execute(query)
            account_ids = [row[0] for row in accounts_result.all()]

        if not account_ids:
            return {
                "trend_data": [],
                "statistics": {},
                "recommendations": [],
            }

        # Get snapshots
        snapshots_result = await self.db.execute(
            select(CoverageSnapshot)
            .where(
                CoverageSnapshot.cloud_account_id.in_(account_ids),
                CoverageSnapshot.created_at >= cutoff,
            )
            .order_by(CoverageSnapshot.created_at)
        )
        snapshots = snapshots_result.scalars().all()

        # Build trend data
        trend_data: list[TrendDataPoint] = []
        for snapshot in snapshots:
            trend_data.append(
                TrendDataPoint(
                    date=snapshot.created_at.isoformat(),
                    coverage_percent=float(snapshot.coverage_percent),
                    covered_techniques=int(snapshot.covered_techniques),
                    total_techniques=int(snapshot.total_techniques),
                    average_confidence=float(snapshot.average_confidence or 0),
                )
            )

        # Calculate statistics
        if trend_data:
            first_coverage = trend_data[0]["coverage_percent"]
            last_coverage = trend_data[-1]["coverage_percent"]
            change = last_coverage - first_coverage

            avg_coverage = sum(d["coverage_percent"] for d in trend_data) / len(
                trend_data
            )
            max_coverage = max(d["coverage_percent"] for d in trend_data)
            min_coverage = min(d["coverage_percent"] for d in trend_data)

            # Determine trend direction
            if change > 5:
                trend_direction = "improving"
            elif change < -5:
                trend_direction = "declining"
            else:
                trend_direction = "stable"

            statistics = {
                "start_coverage": round(first_coverage, 2),
                "end_coverage": round(last_coverage, 2),
                "change_percent": round(change, 2),
                "average_coverage": round(avg_coverage, 2),
                "max_coverage": round(max_coverage, 2),
                "min_coverage": round(min_coverage, 2),
                "trend_direction": trend_direction,
                "data_points": len(trend_data),
            }
        else:
            statistics = {}

        return {
            "trend_data": trend_data,
            "statistics": statistics,
            "period_days": days,
        }

    async def get_gap_prioritization(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
        allowed_account_ids: Optional[list[UUID]] = None,
        limit: int = 20,
    ) -> list[dict]:
        """Get prioritised gap analysis with impact scores.

        Args:
            organization_id: Organization to analyze
            cloud_account_id: Optional filter by account
            allowed_account_ids: Optional ACL filter (list of allowed account IDs)
            limit: Maximum gaps to return

        Returns:
            List of prioritised gaps with impact analysis
        """
        # SECURITY: Validate account ownership to prevent cross-tenant IDOR
        if cloud_account_id:
            await self._validate_account_ownership(organization_id, cloud_account_id)
            account_ids = [cloud_account_id]
        else:
            query = select(CloudAccount.id).where(
                CloudAccount.organization_id == organization_id
            )
            # SECURITY: Apply allowed_account_ids ACL filter
            if allowed_account_ids is not None:
                query = query.where(CloudAccount.id.in_(allowed_account_ids))
            accounts_result = await self.db.execute(query)
            account_ids = [row[0] for row in accounts_result.all()]

        if not account_ids:
            return []

        # Get uncovered techniques
        # First, get all covered technique IDs
        covered_query = (
            select(func.distinct(DetectionMapping.technique_id))
            .select_from(DetectionMapping)
            .join(Detection, DetectionMapping.detection_id == Detection.id)
            .where(Detection.cloud_account_id.in_(account_ids))
        )
        covered_result = await self.db.execute(covered_query)
        covered_technique_ids = [row[0] for row in covered_result.all()]

        # Get uncovered techniques with tactic info
        uncovered_query = (
            select(Technique, Tactic)
            .join(Tactic, Technique.tactic_id == Tactic.id)
            .where(
                Technique.is_deprecated == False,  # noqa
                (
                    ~Technique.id.in_(covered_technique_ids)
                    if covered_technique_ids
                    else True
                ),
            )
        )
        uncovered_result = await self.db.execute(uncovered_query)
        uncovered = uncovered_result.all()

        # Score and prioritise gaps
        gaps = []
        for technique, tactic in uncovered:
            # Calculate priority score based on:
            # - Tactic position in kill chain
            # - Data source availability
            # - Related techniques coverage

            tactic_score = self._get_tactic_priority_score(tactic.tactic_id)
            impact_score = min(100, tactic_score * 10)

            priority = self._determine_priority(impact_score)

            gaps.append(
                {
                    "technique_id": technique.technique_id,
                    "technique_name": technique.name,
                    "tactic_id": tactic.tactic_id,
                    "tactic_name": tactic.name,
                    "impact_score": impact_score,
                    "priority": priority,
                    "description": (
                        technique.description[:200] if technique.description else None
                    ),
                }
            )

        # Sort by impact score
        gaps.sort(key=lambda x: x["impact_score"], reverse=True)
        return gaps[:limit]

    def _get_tactic_priority_score(self, tactic_id: str) -> int:
        """Get priority score based on tactic position in kill chain."""
        # Higher scores for tactics that indicate active threat
        tactic_scores = {
            "TA0001": 6,  # Initial Access
            "TA0002": 7,  # Execution
            "TA0003": 8,  # Persistence
            "TA0004": 9,  # Privilege Escalation
            "TA0005": 7,  # Defense Evasion
            "TA0006": 8,  # Credential Access
            "TA0007": 5,  # Discovery
            "TA0008": 9,  # Lateral Movement
            "TA0009": 6,  # Collection
            "TA0010": 10,  # Exfiltration
            "TA0011": 10,  # Command and Control
            "TA0040": 10,  # Impact
            "TA0042": 4,  # Resource Development
            "TA0043": 3,  # Reconnaissance
        }
        return tactic_scores.get(tactic_id, 5)

    def _determine_priority(self, impact_score: int) -> str:
        """Determine priority level from impact score."""
        if impact_score >= 90:
            return "critical"
        elif impact_score >= 70:
            return "high"
        elif impact_score >= 50:
            return "medium"
        else:
            return "low"

    async def get_detection_effectiveness(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
        allowed_account_ids: Optional[list[UUID]] = None,
    ) -> dict:
        """Analyze detection effectiveness by type and coverage.

        Args:
            organization_id: Organization to analyze
            cloud_account_id: Optional filter by account
            allowed_account_ids: Optional ACL filter (list of allowed account IDs)

        Returns:
            Detection effectiveness analysis
        """
        # SECURITY: Validate account ownership to prevent cross-tenant IDOR
        if cloud_account_id:
            await self._validate_account_ownership(organization_id, cloud_account_id)
            account_ids = [cloud_account_id]
        else:
            query = select(CloudAccount.id).where(
                CloudAccount.organization_id == organization_id
            )
            # SECURITY: Apply allowed_account_ids ACL filter
            if allowed_account_ids is not None:
                query = query.where(CloudAccount.id.in_(allowed_account_ids))
            accounts_result = await self.db.execute(query)
            account_ids = [row[0] for row in accounts_result.all()]

        if not account_ids:
            return {"by_type": [], "summary": {}}

        # Get detections grouped by type
        by_type: list[DetectionTypeEffectiveness] = []
        for detection_type in DetectionType:
            count_result = await self.db.execute(
                select(func.count(Detection.id)).where(
                    Detection.cloud_account_id.in_(account_ids),
                    Detection.detection_type == detection_type,
                )
            )
            total = int(count_result.scalar() or 0)

            active_result = await self.db.execute(
                select(func.count(Detection.id)).where(
                    Detection.cloud_account_id.in_(account_ids),
                    Detection.detection_type == detection_type,
                    Detection.status == DetectionStatus.ACTIVE,
                )
            )
            active = int(active_result.scalar() or 0)

            # Count techniques covered by this type
            techniques_result = await self.db.execute(
                select(func.count(func.distinct(DetectionMapping.technique_id)))
                .select_from(DetectionMapping)
                .join(Detection, DetectionMapping.detection_id == Detection.id)
                .where(
                    Detection.cloud_account_id.in_(account_ids),
                    Detection.detection_type == detection_type,
                )
            )
            techniques_covered = int(techniques_result.scalar() or 0)

            if total > 0:
                by_type.append(
                    DetectionTypeEffectiveness(
                        detection_type=detection_type.value,
                        total_detections=total,
                        active_detections=active,
                        techniques_covered=techniques_covered,
                        effectiveness_rate=(
                            round((active / total) * 100, 2) if total > 0 else 0.0
                        ),
                    )
                )

        # Calculate summary
        total_detections = sum(d["total_detections"] for d in by_type)
        total_active = sum(d["active_detections"] for d in by_type)
        total_techniques = sum(d["techniques_covered"] for d in by_type)

        summary = {
            "total_detections": total_detections,
            "active_detections": total_active,
            "total_techniques_covered": total_techniques,
            "overall_effectiveness": (
                round((total_active / total_detections) * 100, 2)
                if total_detections > 0
                else 0
            ),
        }

        return {
            "by_type": sorted(
                by_type, key=lambda x: x["techniques_covered"], reverse=True
            ),
            "summary": summary,
        }

    async def get_recommendations(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
        allowed_account_ids: Optional[list[UUID]] = None,
        limit: int = 10,
    ) -> list[dict]:
        """Generate actionable recommendations.

        Args:
            organization_id: Organization to analyze
            cloud_account_id: Optional filter by account
            allowed_account_ids: Optional ACL filter (list of allowed account IDs)
            limit: Maximum recommendations

        Returns:
            List of actionable recommendations
        """
        recommendations = []

        # Get coverage trends
        trends = await self.get_coverage_trends(
            organization_id, cloud_account_id, allowed_account_ids, days=7
        )

        # Get effectiveness
        effectiveness = await self.get_detection_effectiveness(
            organization_id, cloud_account_id, allowed_account_ids
        )

        # Get gaps
        gaps = await self.get_gap_prioritization(
            organization_id, cloud_account_id, allowed_account_ids, limit=5
        )

        # Generate recommendations based on analysis
        stats = trends.get("statistics", {})

        # Coverage trend recommendations
        if stats.get("trend_direction") == "declining":
            recommendations.append(
                {
                    "type": "coverage_trend",
                    "priority": "high",
                    "title": "Coverage Declining",
                    "message": f"Coverage has dropped {abs(stats.get('change_percent', 0)):.1f}% in the last week. Review recent changes.",
                    "action": "Review recently removed or disabled detections.",
                }
            )

        # Low coverage recommendations
        if stats.get("end_coverage", 0) < 30:
            recommendations.append(
                {
                    "type": "low_coverage",
                    "priority": "critical",
                    "title": "Low Detection Coverage",
                    "message": f"Current coverage is only {stats.get('end_coverage', 0):.1f}%. Consider enabling managed services.",
                    "action": "Enable GuardDuty or Security Command Center for immediate coverage.",
                }
            )

        # Gap-based recommendations
        for gap in gaps[:3]:
            recommendations.append(
                {
                    "type": "gap",
                    "priority": gap["priority"],
                    "title": f"Missing Coverage: {gap['technique_id']}",
                    "message": f"{gap['technique_name']} ({gap['tactic_name']}) is not covered.",
                    "action": f"Add detection for {gap['technique_id']} to cover {gap['tactic_name']} activity.",
                }
            )

        # Detection type recommendations
        by_type = effectiveness.get("by_type", [])
        for det_type in by_type:
            if det_type["effectiveness_rate"] < 50 and det_type["total_detections"] > 0:
                recommendations.append(
                    {
                        "type": "effectiveness",
                        "priority": "medium",
                        "title": f"Low Effectiveness: {det_type['detection_type']}",
                        "message": f"Only {det_type['effectiveness_rate']:.0f}% of {det_type['detection_type']} detections are active.",
                        "action": "Review disabled or errored detections and resolve issues.",
                    }
                )

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))

        return recommendations[:limit]

    async def get_tactic_breakdown(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
        allowed_account_ids: Optional[list[UUID]] = None,
    ) -> list[dict]:
        """Get coverage breakdown by MITRE ATT&CK tactic.

        Args:
            organization_id: Organization to analyze
            cloud_account_id: Optional filter by account
            allowed_account_ids: Optional ACL filter (list of allowed account IDs)

        Returns:
            List of tactics with coverage percentages
        """
        # SECURITY: Validate account ownership to prevent cross-tenant IDOR
        if cloud_account_id:
            await self._validate_account_ownership(organization_id, cloud_account_id)
            account_ids = [cloud_account_id]
        else:
            query = select(CloudAccount.id).where(
                CloudAccount.organization_id == organization_id
            )
            # SECURITY: Apply allowed_account_ids ACL filter
            if allowed_account_ids is not None:
                query = query.where(CloudAccount.id.in_(allowed_account_ids))
            accounts_result = await self.db.execute(query)
            account_ids = [row[0] for row in accounts_result.all()]

        # Get all tactics
        tactics_result = await self.db.execute(select(Tactic))
        tactics = tactics_result.scalars().all()

        breakdown: list[TacticBreakdown] = []
        for tactic in tactics:
            # Total techniques in tactic
            total_result = await self.db.execute(
                select(func.count(Technique.id)).where(
                    Technique.tactic_id == tactic.id,
                    Technique.is_deprecated == False,  # noqa
                )
            )
            total = int(total_result.scalar() or 0)

            # Covered techniques
            if account_ids:
                covered_result = await self.db.execute(
                    select(func.count(func.distinct(DetectionMapping.technique_id)))
                    .select_from(DetectionMapping)
                    .join(Detection, DetectionMapping.detection_id == Detection.id)
                    .join(Technique, DetectionMapping.technique_id == Technique.id)
                    .where(
                        Detection.cloud_account_id.in_(account_ids),
                        Technique.tactic_id == tactic.id,
                    )
                )
                covered = int(covered_result.scalar() or 0)
            else:
                covered = 0

            percent = (covered / total * 100) if total > 0 else 0.0

            breakdown.append(
                TacticBreakdown(
                    tactic_id=tactic.tactic_id,
                    tactic_name=tactic.name,
                    total_techniques=total,
                    covered_techniques=covered,
                    coverage_percent=round(percent, 2),
                    priority_score=self._get_tactic_priority_score(tactic.tactic_id),
                )
            )

        # Sort by priority score
        breakdown.sort(key=lambda x: x["priority_score"], reverse=True)
        return breakdown
