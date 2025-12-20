"""Gap management service for remediation tracking workflow."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.orm import Session
import structlog

from app.models.gap import CoverageGap, GapHistory, GapStatus, GapPriority

logger = structlog.get_logger()


class GapService:
    """Service for managing coverage gaps and remediation workflow."""

    def __init__(self, db: Session):
        self.db = db
        self.logger = logger.bind(component="GapService")

    async def create_gap(
        self,
        cloud_account_id: uuid.UUID,
        organization_id: uuid.UUID,
        technique_id: str,
        technique_name: str,
        tactic_id: str,
        tactic_name: str,
        priority: GapPriority,
        reason: Optional[str] = None,
        data_sources: Optional[list] = None,
        recommended_detections: Optional[list] = None,
        scan_id: Optional[uuid.UUID] = None,
    ) -> CoverageGap:
        """Create a new coverage gap.

        Checks for existing gap to avoid duplicates.
        """
        # Check for existing gap
        existing = await self.get_gap_by_technique(
            cloud_account_id=cloud_account_id,
            technique_id=technique_id,
        )

        if existing:
            self.logger.info(
                "gap_already_exists",
                technique_id=technique_id,
                gap_id=str(existing.id),
            )
            return existing

        gap = CoverageGap(
            cloud_account_id=cloud_account_id,
            organization_id=organization_id,
            technique_id=technique_id,
            technique_name=technique_name,
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            priority=priority,
            status=GapStatus.OPEN,
            reason=reason,
            data_sources=data_sources,
            recommended_detections=recommended_detections,
            scan_id=scan_id,
            first_identified_at=datetime.utcnow(),
        )

        self.db.add(gap)
        self.db.commit()
        self.db.refresh(gap)

        # Create initial history entry
        await self._create_history(
            gap_id=gap.id,
            previous_status=None,
            new_status=GapStatus.OPEN,
            change_reason="Gap first identified",
        )

        self.logger.info(
            "gap_created",
            gap_id=str(gap.id),
            technique_id=technique_id,
            priority=priority.value,
        )

        return gap

    async def get_gap_by_technique(
        self,
        cloud_account_id: uuid.UUID,
        technique_id: str,
    ) -> Optional[CoverageGap]:
        """Get gap by account and technique ID."""
        stmt = select(CoverageGap).where(
            and_(
                CoverageGap.cloud_account_id == cloud_account_id,
                CoverageGap.technique_id == technique_id,
                CoverageGap.status.not_in([GapStatus.REMEDIATED]),
            )
        )
        result = self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_gaps_by_account(
        self,
        cloud_account_id: uuid.UUID,
        status: Optional[GapStatus] = None,
        priority: Optional[GapPriority] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CoverageGap]:
        """Get gaps for an account with optional filtering."""
        stmt = select(CoverageGap).where(
            CoverageGap.cloud_account_id == cloud_account_id
        )

        if status:
            stmt = stmt.where(CoverageGap.status == status)

        if priority:
            stmt = stmt.where(CoverageGap.priority == priority)

        stmt = (
            stmt.order_by(
                CoverageGap.priority,
                CoverageGap.first_identified_at.desc(),
            )
            .limit(limit)
            .offset(offset)
        )

        result = self.db.execute(stmt)
        return result.scalars().all()

    async def get_gaps_by_organization(
        self,
        organization_id: uuid.UUID,
        status: Optional[GapStatus] = None,
        limit: int = 100,
    ) -> list[CoverageGap]:
        """Get all gaps for an organization."""
        stmt = select(CoverageGap).where(CoverageGap.organization_id == organization_id)

        if status:
            stmt = stmt.where(CoverageGap.status == status)

        stmt = stmt.order_by(
            CoverageGap.priority,
            CoverageGap.first_identified_at.desc(),
        ).limit(limit)

        result = self.db.execute(stmt)
        return result.scalars().all()

    async def update_status(
        self,
        gap_id: uuid.UUID,
        new_status: GapStatus,
        changed_by: Optional[uuid.UUID] = None,
        change_reason: Optional[str] = None,
        remediation_notes: Optional[str] = None,
    ) -> CoverageGap:
        """Update gap status with history tracking.

        Validates status transitions:
        - OPEN -> ACKNOWLEDGED, RISK_ACCEPTED
        - ACKNOWLEDGED -> IN_PROGRESS, RISK_ACCEPTED
        - IN_PROGRESS -> REMEDIATED, RISK_ACCEPTED, ACKNOWLEDGED (rollback)
        - REMEDIATED -> can't change
        - RISK_ACCEPTED -> OPEN (to re-open)
        """
        gap = self.db.get(CoverageGap, gap_id)
        if not gap:
            raise ValueError(f"Gap not found: {gap_id}")

        old_status = gap.status

        # Validate transition
        if not self._is_valid_transition(old_status, new_status):
            raise ValueError(
                f"Invalid status transition: {old_status.value} -> {new_status.value}"
            )

        # Update gap
        gap.status = new_status
        gap.status_changed_at = datetime.utcnow()

        if remediation_notes:
            gap.remediation_notes = remediation_notes

        self.db.commit()
        self.db.refresh(gap)

        # Create history entry
        await self._create_history(
            gap_id=gap_id,
            previous_status=old_status,
            new_status=new_status,
            changed_by=changed_by,
            change_reason=change_reason,
        )

        self.logger.info(
            "gap_status_updated",
            gap_id=str(gap_id),
            old_status=old_status.value,
            new_status=new_status.value,
        )

        return gap

    async def acknowledge_gap(
        self,
        gap_id: uuid.UUID,
        acknowledged_by: uuid.UUID,
        notes: Optional[str] = None,
    ) -> CoverageGap:
        """Acknowledge a gap (team is aware)."""
        return await self.update_status(
            gap_id=gap_id,
            new_status=GapStatus.ACKNOWLEDGED,
            changed_by=acknowledged_by,
            change_reason="Gap acknowledged",
            remediation_notes=notes,
        )

    async def start_remediation(
        self,
        gap_id: uuid.UUID,
        started_by: uuid.UUID,
        assigned_to: Optional[uuid.UUID] = None,
        due_date: Optional[datetime] = None,
        notes: Optional[str] = None,
    ) -> CoverageGap:
        """Start remediation work on a gap."""
        gap = await self.update_status(
            gap_id=gap_id,
            new_status=GapStatus.IN_PROGRESS,
            changed_by=started_by,
            change_reason="Remediation started",
            remediation_notes=notes,
        )

        # Update assignment
        if assigned_to:
            gap.assigned_to = assigned_to
        if due_date:
            gap.remediation_due_date = due_date

        self.db.commit()
        self.db.refresh(gap)

        return gap

    async def mark_remediated(
        self,
        gap_id: uuid.UUID,
        remediated_by: uuid.UUID,
        detection_id: Optional[uuid.UUID] = None,
        notes: Optional[str] = None,
    ) -> CoverageGap:
        """Mark a gap as remediated (detection deployed)."""
        gap = await self.update_status(
            gap_id=gap_id,
            new_status=GapStatus.REMEDIATED,
            changed_by=remediated_by,
            change_reason="Gap remediated - detection deployed",
            remediation_notes=notes,
        )

        if detection_id:
            gap.remediated_detection_id = detection_id
            self.db.commit()
            self.db.refresh(gap)

        return gap

    async def accept_risk(
        self,
        gap_id: uuid.UUID,
        accepted_by: uuid.UUID,
        reason: str,
    ) -> CoverageGap:
        """Accept risk for a gap (will not remediate)."""
        gap = await self.update_status(
            gap_id=gap_id,
            new_status=GapStatus.RISK_ACCEPTED,
            changed_by=accepted_by,
            change_reason=f"Risk accepted: {reason}",
        )

        gap.risk_acceptance_reason = reason
        gap.risk_accepted_by = accepted_by
        gap.risk_accepted_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(gap)

        return gap

    async def reopen_gap(
        self,
        gap_id: uuid.UUID,
        reopened_by: uuid.UUID,
        reason: str,
    ) -> CoverageGap:
        """Reopen a previously risk-accepted gap."""
        gap = self.db.get(CoverageGap, gap_id)
        if not gap:
            raise ValueError(f"Gap not found: {gap_id}")

        if gap.status != GapStatus.RISK_ACCEPTED:
            raise ValueError("Only risk-accepted gaps can be reopened")

        return await self.update_status(
            gap_id=gap_id,
            new_status=GapStatus.OPEN,
            changed_by=reopened_by,
            change_reason=f"Gap reopened: {reason}",
        )

    async def get_gap_history(
        self,
        gap_id: uuid.UUID,
    ) -> list[GapHistory]:
        """Get status change history for a gap."""
        stmt = (
            select(GapHistory)
            .where(GapHistory.gap_id == gap_id)
            .order_by(GapHistory.changed_at.desc())
        )

        result = self.db.execute(stmt)
        return result.scalars().all()

    async def get_gap_statistics(
        self,
        organization_id: uuid.UUID,
    ) -> dict:
        """Get gap statistics for an organization."""
        gaps = await self.get_gaps_by_organization(
            organization_id=organization_id,
            limit=10000,  # Get all gaps for stats
        )

        stats = {
            "total": len(gaps),
            "by_status": {
                "open": 0,
                "acknowledged": 0,
                "in_progress": 0,
                "remediated": 0,
                "risk_accepted": 0,
            },
            "by_priority": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "active": 0,  # Not remediated or risk-accepted
        }

        for gap in gaps:
            stats["by_status"][gap.status.value] += 1
            stats["by_priority"][gap.priority.value] += 1

            if gap.status not in [GapStatus.REMEDIATED, GapStatus.RISK_ACCEPTED]:
                stats["active"] += 1

        return stats

    def _is_valid_transition(
        self,
        old_status: GapStatus,
        new_status: GapStatus,
    ) -> bool:
        """Check if status transition is valid."""
        valid_transitions = {
            GapStatus.OPEN: [GapStatus.ACKNOWLEDGED, GapStatus.RISK_ACCEPTED],
            GapStatus.ACKNOWLEDGED: [GapStatus.IN_PROGRESS, GapStatus.RISK_ACCEPTED],
            GapStatus.IN_PROGRESS: [
                GapStatus.REMEDIATED,
                GapStatus.RISK_ACCEPTED,
                GapStatus.ACKNOWLEDGED,  # Rollback
            ],
            GapStatus.REMEDIATED: [],  # Terminal state
            GapStatus.RISK_ACCEPTED: [GapStatus.OPEN],  # Can reopen
        }

        return new_status in valid_transitions.get(old_status, [])

    async def _create_history(
        self,
        gap_id: uuid.UUID,
        previous_status: Optional[GapStatus],
        new_status: GapStatus,
        changed_by: Optional[uuid.UUID] = None,
        change_reason: Optional[str] = None,
    ) -> GapHistory:
        """Create a gap history entry."""
        history = GapHistory(
            gap_id=gap_id,
            previous_status=previous_status,
            new_status=new_status,
            changed_by=changed_by,
            change_reason=change_reason,
        )

        self.db.add(history)
        self.db.commit()
        self.db.refresh(history)

        return history
