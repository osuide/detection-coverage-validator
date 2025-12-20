"""Scan limit service for tracking and enforcing weekly scan limits."""

from datetime import datetime
from typing import Optional, Tuple
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.billing import Subscription, TIER_LIMITS
from app.models.fingerprint import OrganisationScanTracking

logger = structlog.get_logger()


class ScanLimitService:
    """Service for managing scan limits and tracking."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_subscription(self, organization_id: UUID) -> Optional[Subscription]:
        """Get subscription for an organisation."""
        result = await self.db.execute(
            select(Subscription).where(Subscription.organization_id == organization_id)
        )
        return result.scalar_one_or_none()

    async def _get_or_create_tracking(
        self, organization_id: UUID
    ) -> OrganisationScanTracking:
        """Get or create scan tracking record for an organisation."""
        result = await self.db.execute(
            select(OrganisationScanTracking).where(
                OrganisationScanTracking.organization_id == organization_id
            )
        )
        tracking = result.scalar_one_or_none()

        if not tracking:
            tracking = OrganisationScanTracking(organization_id=organization_id)
            self.db.add(tracking)
            await self.db.flush()

        return tracking

    async def can_scan(
        self, organization_id: UUID
    ) -> Tuple[bool, Optional[str], Optional[datetime]]:
        """Check if an organisation can perform a scan.

        Args:
            organization_id: The organisation ID

        Returns:
            (can_scan, reason_if_blocked, next_available_at)
        """
        # Check if scan limits are disabled (for staging/testing)
        settings = get_settings()
        if settings.disable_scan_limits:
            logger.debug(
                "scan_limits_disabled",
                organization_id=str(organization_id),
            )
            return True, None, None

        subscription = await self._get_subscription(organization_id)

        if not subscription:
            logger.warning(
                "scan_check_no_subscription",
                organization_id=str(organization_id),
            )
            return False, "No active subscription found", None

        # Get tier limits
        tier_limits = TIER_LIMITS.get(subscription.tier, {})
        weekly_limit = tier_limits.get("weekly_scans_allowed")
        reset_interval = tier_limits.get("scan_reset_interval_days", 7)

        # None or negative means unlimited
        if weekly_limit is None or weekly_limit < 0:
            return True, None, None

        # Get tracking record
        tracking = await self._get_or_create_tracking(organization_id)

        # Check if week has expired and reset if needed
        if tracking.is_week_expired(reset_interval):
            tracking.reset_week()
            await self.db.commit()
            return True, None, None

        # Check if limit reached
        if tracking.weekly_scan_count >= weekly_limit:
            next_available = tracking.get_next_scan_available_at(reset_interval)
            logger.info(
                "scan_limit_reached",
                organization_id=str(organization_id),
                used=tracking.weekly_scan_count,
                limit=weekly_limit,
                next_available=next_available.isoformat() if next_available else None,
            )
            return (
                False,
                f"Weekly scan limit ({weekly_limit}) reached. Upgrade for unlimited scans.",
                next_available,
            )

        return True, None, None

    async def record_scan(self, organization_id: UUID) -> None:
        """Record that a scan was performed.

        Args:
            organization_id: The organisation ID
        """
        subscription = await self._get_subscription(organization_id)
        if not subscription:
            return

        # Get tier limits for reset interval
        tier_limits = TIER_LIMITS.get(subscription.tier, {})
        reset_interval = tier_limits.get("scan_reset_interval_days", 7)

        tracking = await self._get_or_create_tracking(organization_id)
        tracking.record_scan(reset_interval)

        await self.db.commit()

        logger.info(
            "scan_recorded",
            organization_id=str(organization_id),
            weekly_count=tracking.weekly_scan_count,
            total_count=tracking.total_scans,
        )

    async def get_scan_status(self, organization_id: UUID) -> dict:
        """Get scan usage status for an organisation.

        Args:
            organization_id: The organisation ID

        Returns:
            {
                "can_scan": bool,
                "scans_used": int,
                "scans_allowed": int | None,
                "unlimited": bool,
                "next_available_at": str | None,
                "week_resets_at": str | None,
                "total_scans": int,
            }
        """
        # Check if scan limits are disabled (for staging/testing)
        settings = get_settings()
        if settings.disable_scan_limits:
            tracking = await self._get_or_create_tracking(organization_id)
            return {
                "can_scan": True,
                "scans_used": tracking.weekly_scan_count,
                "scans_allowed": None,  # Unlimited
                "unlimited": True,
                "next_available_at": None,
                "week_resets_at": None,
                "total_scans": tracking.total_scans,
            }

        subscription = await self._get_subscription(organization_id)

        if not subscription:
            return {
                "can_scan": False,
                "scans_used": 0,
                "scans_allowed": 0,
                "unlimited": False,
                "next_available_at": None,
                "week_resets_at": None,
                "total_scans": 0,
            }

        # Get tier limits
        tier_limits = TIER_LIMITS.get(subscription.tier, {})
        weekly_limit = tier_limits.get("weekly_scans_allowed")
        reset_interval = tier_limits.get("scan_reset_interval_days", 7)

        # None or negative means unlimited
        unlimited = weekly_limit is None or weekly_limit < 0

        # Get tracking record
        tracking = await self._get_or_create_tracking(organization_id)

        # Check if week has expired
        scans_used = tracking.weekly_scan_count
        if tracking.is_week_expired(reset_interval):
            scans_used = 0

        # Calculate next available and week reset
        next_available = None
        week_resets_at = None
        can_scan = True

        if not unlimited and weekly_limit is not None:
            if scans_used >= weekly_limit:
                can_scan = False
                next_available = tracking.get_next_scan_available_at(reset_interval)
            week_resets_at = tracking.get_next_scan_available_at(reset_interval)

        return {
            "can_scan": can_scan,
            "scans_used": scans_used,
            "scans_allowed": weekly_limit,
            "unlimited": unlimited,
            "next_available_at": (
                next_available.isoformat() if next_available else None
            ),
            "week_resets_at": (week_resets_at.isoformat() if week_resets_at else None),
            "total_scans": tracking.total_scans,
        }

    async def reset_expired_windows(self) -> int:
        """Reset scan counts for all expired windows.

        This is intended to be called by a scheduled task.

        Returns:
            Number of records reset
        """
        result = await self.db.execute(select(OrganisationScanTracking))
        all_tracking = result.scalars().all()

        reset_count = 0
        for tracking in all_tracking:
            # Get subscription to determine reset interval
            sub_result = await self.db.execute(
                select(Subscription).where(
                    Subscription.organization_id == tracking.organization_id
                )
            )
            subscription = sub_result.scalar_one_or_none()

            if not subscription:
                continue

            tier_limits = TIER_LIMITS.get(subscription.tier, {})
            reset_interval = tier_limits.get("scan_reset_interval_days", 7)

            if tracking.is_week_expired(reset_interval):
                tracking.reset_week()
                reset_count += 1

        if reset_count > 0:
            await self.db.commit()
            logger.info("scan_windows_reset", count=reset_count)

        return reset_count
