"""Coverage drift detection service.

Tracks coverage changes over time and detects significant drops or changes
in security detection coverage.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_account import CloudAccount
from app.models.coverage_history import CoverageHistory, CoverageAlert, DriftSeverity
from app.models.detection import Detection
from app.models.mapping import DetectionMapping
from app.models.mitre import Technique


# Drift thresholds
DRIFT_CRITICAL_THRESHOLD = 10.0  # >10% drop is critical
DRIFT_WARNING_THRESHOLD = 5.0  # >5% drop is warning


class DriftDetectionService:
    """Service for detecting coverage drift over time."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def record_coverage_snapshot(
        self,
        cloud_account_id: UUID,
        scan_id: Optional[UUID] = None,
    ) -> CoverageHistory:
        """Record a coverage snapshot after a scan.

        Args:
            cloud_account_id: Account to record coverage for
            scan_id: Optional scan that triggered this record

        Returns:
            New CoverageHistory record
        """
        # Get current coverage
        current_coverage = await self._calculate_coverage(cloud_account_id)

        # Get previous snapshot
        previous = await self._get_latest_snapshot(cloud_account_id)

        # Calculate drift
        drift_info = self._calculate_drift(previous, current_coverage)

        # Create new snapshot
        snapshot = CoverageHistory(
            cloud_account_id=cloud_account_id,
            scan_id=scan_id,
            total_techniques=current_coverage["total_techniques"],
            covered_techniques=current_coverage["covered_techniques"],
            coverage_percent=current_coverage["coverage_percent"],
            coverage_delta=drift_info["delta"],
            techniques_added=drift_info["added"],
            techniques_removed=drift_info["removed"],
            drift_severity=drift_info["severity"],
            coverage_by_tactic=current_coverage.get("by_tactic"),
            recorded_at=datetime.now(timezone.utc),
        )

        self.db.add(snapshot)

        # Create alert if significant drift detected
        if drift_info["severity"] in [DriftSeverity.WARNING, DriftSeverity.CRITICAL]:
            await self._create_drift_alert(cloud_account_id, snapshot, drift_info)

        await self.db.commit()
        await self.db.refresh(snapshot)

        return snapshot

    async def _calculate_coverage(self, cloud_account_id: UUID) -> dict:
        """Calculate current coverage for an account."""
        # Get total MITRE techniques count
        total_result = await self.db.execute(
            select(func.count(Technique.id)).where(Technique.is_deprecated.is_(False))
        )
        total_techniques = total_result.scalar() or 0

        # Get covered techniques count
        covered_query = (
            select(func.count(func.distinct(DetectionMapping.technique_id)))
            .select_from(DetectionMapping)
            .join(Detection, DetectionMapping.detection_id == Detection.id)
            .where(Detection.cloud_account_id == cloud_account_id)
        )
        covered_result = await self.db.execute(covered_query)
        covered_techniques = covered_result.scalar() or 0

        # Get covered technique IDs
        technique_ids_query = (
            select(func.distinct(Technique.technique_id))
            .select_from(DetectionMapping)
            .join(Detection, DetectionMapping.detection_id == Detection.id)
            .join(Technique, DetectionMapping.technique_id == Technique.id)
            .where(Detection.cloud_account_id == cloud_account_id)
        )
        technique_ids_result = await self.db.execute(technique_ids_query)
        technique_ids = [row[0] for row in technique_ids_result.all()]

        # Calculate coverage by tactic
        tactic_coverage = await self._get_coverage_by_tactic(cloud_account_id)

        coverage_percent = (
            (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0
        )

        return {
            "total_techniques": total_techniques,
            "covered_techniques": covered_techniques,
            "coverage_percent": round(coverage_percent, 2),
            "technique_ids": technique_ids,
            "by_tactic": tactic_coverage,
        }

    async def _get_coverage_by_tactic(self, cloud_account_id: UUID) -> dict:
        """Get coverage breakdown by tactic."""
        # Get covered techniques by tactic
        query = (
            select(Technique.tactic_id, func.count(func.distinct(Technique.id)))
            .select_from(DetectionMapping)
            .join(Detection, DetectionMapping.detection_id == Detection.id)
            .join(Technique, DetectionMapping.technique_id == Technique.id)
            .where(Detection.cloud_account_id == cloud_account_id)
            .group_by(Technique.tactic_id)
        )
        result = await self.db.execute(query)
        covered_by_tactic = {row[0]: row[1] for row in result.all()}

        # Get total by tactic
        total_query = (
            select(Technique.tactic_id, func.count(Technique.id))
            .where(Technique.is_deprecated == False)  # noqa
            .group_by(Technique.tactic_id)
        )
        total_result = await self.db.execute(total_query)
        total_by_tactic = {row[0]: row[1] for row in total_result.all()}

        # Calculate percentages
        # CRITICAL: Convert UUID keys to strings for JSONB serialization
        # PostgreSQL JSONB columns cannot have UUID keys
        coverage = {}
        for tactic_id, total in total_by_tactic.items():
            covered = covered_by_tactic.get(tactic_id, 0)
            coverage[str(tactic_id)] = {
                "total": total,
                "covered": covered,
                "percent": round((covered / total * 100) if total > 0 else 0, 2),
            }

        return coverage

    async def _get_latest_snapshot(
        self, cloud_account_id: UUID
    ) -> Optional[CoverageHistory]:
        """Get the most recent coverage snapshot."""
        result = await self.db.execute(
            select(CoverageHistory)
            .where(CoverageHistory.cloud_account_id == cloud_account_id)
            .order_by(desc(CoverageHistory.recorded_at))
            .limit(1)
        )
        return result.scalar_one_or_none()

    def _calculate_drift(
        self, previous: Optional[CoverageHistory], current: dict
    ) -> dict:
        """Calculate drift between previous and current coverage."""
        if not previous:
            return {
                "delta": 0.0,
                "added": current.get("technique_ids", []),
                "removed": [],
                "severity": DriftSeverity.NONE,
            }

        delta = current["coverage_percent"] - previous.coverage_percent
        current_techniques = set(current.get("technique_ids", []))

        # Get previous technique IDs from historical data
        # We need to reconstruct from the snapshot
        prev_techniques_result = self._get_previous_techniques(previous)

        added = list(current_techniques - prev_techniques_result)
        removed = list(prev_techniques_result - current_techniques)

        # Determine severity
        if delta <= -DRIFT_CRITICAL_THRESHOLD:
            severity = DriftSeverity.CRITICAL
        elif delta <= -DRIFT_WARNING_THRESHOLD:
            severity = DriftSeverity.WARNING
        elif removed:
            severity = DriftSeverity.INFO
        else:
            severity = DriftSeverity.NONE

        return {
            "delta": round(delta, 2),
            "added": added,
            "removed": removed,
            "severity": severity,
        }

    def _get_previous_techniques(self, snapshot: CoverageHistory) -> set:
        """Reconstruct technique set from previous snapshot."""
        # Start with current techniques
        current = set()

        # Apply the inverse of changes to get previous state
        if snapshot.techniques_added:
            current.update(snapshot.techniques_added)
        if snapshot.techniques_removed:
            current -= set(snapshot.techniques_removed)

        return current

    async def _create_drift_alert(
        self,
        cloud_account_id: UUID,
        snapshot: CoverageHistory,
        drift_info: dict,
    ) -> None:
        """Create an alert for significant coverage drift."""
        # Get organization ID from account
        account_result = await self.db.execute(
            select(CloudAccount).where(CloudAccount.id == cloud_account_id)
        )
        account = account_result.scalar_one_or_none()
        if not account or not account.organization_id:
            return

        severity = drift_info["severity"]
        delta = drift_info["delta"]
        removed = drift_info["removed"]

        if severity == DriftSeverity.CRITICAL:
            title = f"Critical Coverage Drop: {abs(delta):.1f}% decrease"
            message = (
                f"Coverage dropped from {snapshot.coverage_percent - delta:.1f}% "
                f"to {snapshot.coverage_percent:.1f}%. "
                f"{len(removed)} technique(s) are no longer covered."
            )
            alert_type = "coverage_drop_critical"
        elif severity == DriftSeverity.WARNING:
            title = f"Coverage Drop Warning: {abs(delta):.1f}% decrease"
            message = (
                f"Coverage dropped from {snapshot.coverage_percent - delta:.1f}% "
                f"to {snapshot.coverage_percent:.1f}%."
            )
            alert_type = "coverage_drop_warning"
        else:
            title = f"Coverage Changed: {len(removed)} technique(s) removed"
            message = f"The following techniques are no longer covered: {', '.join(removed[:5])}"
            if len(removed) > 5:
                message += f" and {len(removed) - 5} more"
            alert_type = "technique_removed"

        alert = CoverageAlert(
            organization_id=account.organization_id,
            cloud_account_id=cloud_account_id,
            coverage_history_id=snapshot.id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            details={
                "delta": delta,
                "previous_percent": snapshot.coverage_percent - delta,
                "current_percent": snapshot.coverage_percent,
                "techniques_removed": removed,
                "techniques_added": drift_info["added"],
            },
        )

        self.db.add(alert)

    async def get_coverage_history(
        self,
        cloud_account_id: UUID,
        organization_id: UUID,
        days: int = 30,
    ) -> list[dict]:
        """Get coverage history for an account.

        Args:
            cloud_account_id: Account to get history for
            organization_id: Organization for access control
            days: Number of days of history

        Returns:
            List of coverage snapshots
        """
        # Verify account belongs to organization
        account_result = await self.db.execute(
            select(CloudAccount).where(
                CloudAccount.id == cloud_account_id,
                CloudAccount.organization_id == organization_id,
            )
        )
        if not account_result.scalar_one_or_none():
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        result = await self.db.execute(
            select(CoverageHistory)
            .where(
                CoverageHistory.cloud_account_id == cloud_account_id,
                CoverageHistory.recorded_at >= cutoff,
            )
            .order_by(CoverageHistory.recorded_at.asc())
        )
        snapshots = result.scalars().all()

        return [
            {
                "id": str(s.id),
                "recorded_at": s.recorded_at.isoformat(),
                "coverage_percent": s.coverage_percent,
                "covered_techniques": s.covered_techniques,
                "total_techniques": s.total_techniques,
                "coverage_delta": s.coverage_delta,
                "drift_severity": s.drift_severity.value,
                "techniques_added_count": len(s.techniques_added or []),
                "techniques_removed_count": len(s.techniques_removed or []),
            }
            for s in snapshots
        ]

    async def get_drift_alerts(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
        acknowledged: Optional[bool] = None,
        days: int = 30,
    ) -> list[dict]:
        """Get coverage drift alerts for an organization.

        Args:
            organization_id: Organization to get alerts for
            cloud_account_id: Optional filter by account
            acknowledged: Optional filter by acknowledged status
            days: Number of days of history

        Returns:
            List of alerts
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        query = select(CoverageAlert).where(
            CoverageAlert.organization_id == organization_id,
            CoverageAlert.created_at >= cutoff,
        )

        if cloud_account_id:
            query = query.where(CoverageAlert.cloud_account_id == cloud_account_id)

        if acknowledged is not None:
            query = query.where(CoverageAlert.is_acknowledged == acknowledged)

        query = query.order_by(desc(CoverageAlert.created_at))

        result = await self.db.execute(query)
        alerts = result.scalars().all()

        return [
            {
                "id": str(a.id),
                "cloud_account_id": (
                    str(a.cloud_account_id) if a.cloud_account_id else None
                ),
                "alert_type": a.alert_type,
                "severity": a.severity.value,
                "title": a.title,
                "message": a.message,
                "details": a.details,
                "is_acknowledged": a.is_acknowledged,
                "acknowledged_at": (
                    a.acknowledged_at.isoformat() if a.acknowledged_at else None
                ),
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ]

    async def acknowledge_alert(
        self,
        alert_id: UUID,
        organization_id: UUID,
        user_id: UUID,
    ) -> bool:
        """Acknowledge a drift alert.

        Args:
            alert_id: Alert to acknowledge
            organization_id: Organization for access control
            user_id: User acknowledging the alert

        Returns:
            True if acknowledged, False if not found
        """
        result = await self.db.execute(
            select(CoverageAlert).where(
                CoverageAlert.id == alert_id,
                CoverageAlert.organization_id == organization_id,
            )
        )
        alert = result.scalar_one_or_none()

        if not alert:
            return False

        alert.is_acknowledged = True
        alert.acknowledged_at = datetime.now(timezone.utc)
        alert.acknowledged_by = user_id

        await self.db.commit()
        return True

    async def get_drift_summary(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
    ) -> dict:
        """Get drift summary statistics.

        Args:
            organization_id: Organization to summarize
            cloud_account_id: Optional filter by account

        Returns:
            Drift summary statistics
        """
        # Base query for alerts
        base_query = select(CoverageAlert).where(
            CoverageAlert.organization_id == organization_id
        )
        if cloud_account_id:
            base_query = base_query.where(
                CoverageAlert.cloud_account_id == cloud_account_id
            )

        # Count by severity
        severity_counts = {}
        for severity in DriftSeverity:
            count_query = select(func.count(CoverageAlert.id)).where(
                CoverageAlert.organization_id == organization_id,
                CoverageAlert.severity == severity,
                CoverageAlert.is_acknowledged == False,  # noqa
            )
            if cloud_account_id:
                count_query = count_query.where(
                    CoverageAlert.cloud_account_id == cloud_account_id
                )
            result = await self.db.execute(count_query)
            severity_counts[severity.value] = result.scalar() or 0

        # Recent trend (last 7 days)
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        trend_query = (
            select(CoverageHistory)
            .join(CloudAccount, CoverageHistory.cloud_account_id == CloudAccount.id)
            .where(
                CloudAccount.organization_id == organization_id,
                CoverageHistory.recorded_at >= week_ago,
            )
            .order_by(desc(CoverageHistory.recorded_at))
        )
        if cloud_account_id:
            trend_query = trend_query.where(
                CoverageHistory.cloud_account_id == cloud_account_id
            )

        trend_result = await self.db.execute(trend_query)
        recent_snapshots = trend_result.scalars().all()

        # Calculate trend
        if len(recent_snapshots) >= 2:
            latest = recent_snapshots[0]
            oldest = recent_snapshots[-1]
            trend = latest.coverage_percent - oldest.coverage_percent
        else:
            trend = 0.0

        return {
            "unacknowledged_alerts": severity_counts,
            "total_unacknowledged": sum(severity_counts.values()),
            "coverage_trend_7d": round(trend, 2),
            "snapshots_last_7d": len(recent_snapshots),
        }
