"""Template access monitoring service.

Detects and alerts on bulk template access patterns that may indicate
scraping attempts or intellectual property theft.

Security response:
- 15 unique techniques/5 min: Alert (logged for review)
- 25 unique techniques/5 min: Account suspended until admin review
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID
import structlog

from redis import asyncio as aioredis
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings

logger = structlog.get_logger()

# Thresholds for bulk access detection
# With ~264 templates total, these thresholds detect clear scraping patterns
BULK_ACCESS_THRESHOLDS = {
    # Alert threshold (logged for review)
    "alert_threshold": 15,
    # Suspend threshold (account disabled until admin review)
    "suspend_threshold": 25,
    # Time window in seconds
    "time_window_seconds": 300,  # 5 minutes
    # Alert cooldown - don't re-alert for same user within this period
    "alert_cooldown_seconds": 3600,  # 1 hour
}


class TemplateAccessMonitor:
    """Monitors template access patterns and alerts on suspicious activity."""

    def __init__(self) -> None:
        self._redis: Optional[aioredis.Redis] = None

    async def _get_redis(self) -> aioredis.Redis:
        """Get or create Redis connection."""
        if self._redis is None:
            settings = get_settings()
            self._redis = await aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
        return self._redis

    def _get_access_key(self, user_id: UUID, org_id: UUID) -> str:
        """Get Redis key for tracking user's template accesses."""
        return f"template_access:{org_id}:{user_id}"

    def _get_alert_key(self, user_id: UUID, org_id: UUID) -> str:
        """Get Redis key for alert cooldown tracking."""
        return f"template_alert:{org_id}:{user_id}"

    async def record_access(
        self,
        user_id: UUID,
        org_id: UUID,
        technique_id: str,
        endpoint: str,
        client_ip: Optional[str] = None,
        db: Optional[AsyncSession] = None,
    ) -> None:
        """Record a template access and check for bulk access patterns.

        Args:
            user_id: The user accessing the template
            org_id: The user's organisation
            technique_id: The MITRE technique ID accessed
            endpoint: The API endpoint used
            client_ip: Client IP address (if available)
            db: Database session for suspension actions (optional)
        """
        try:
            redis = await self._get_redis()
            access_key = self._get_access_key(user_id, org_id)
            now = datetime.now(timezone.utc)
            window = BULK_ACCESS_THRESHOLDS["time_window_seconds"]

            # Add this access to the sorted set (score = timestamp)
            access_entry = f"{technique_id}:{now.isoformat()}"
            await redis.zadd(access_key, {access_entry: now.timestamp()})

            # Remove entries outside the time window
            cutoff = now.timestamp() - window
            await redis.zremrangebyscore(access_key, "-inf", cutoff)

            # Set expiry on the key
            await redis.expire(access_key, window * 2)

            # Get unique techniques accessed in window
            all_accesses = await redis.zrange(access_key, 0, -1)
            unique_techniques = set()
            for access in all_accesses:
                tech_id = access.split(":")[0]
                unique_techniques.add(tech_id)

            unique_count = len(unique_techniques)

            # Log the access
            logger.info(
                "template_access",
                user_id=str(user_id),
                org_id=str(org_id),
                technique_id=technique_id,
                endpoint=endpoint,
                client_ip=client_ip,
                unique_in_window=unique_count,
            )

            # Check thresholds and take appropriate action
            suspend_threshold = BULK_ACCESS_THRESHOLDS["suspend_threshold"]
            alert_threshold = BULK_ACCESS_THRESHOLDS["alert_threshold"]

            if unique_count >= suspend_threshold:
                # Suspend until admin review
                await self._suspend_user(
                    user_id=user_id,
                    org_id=org_id,
                    unique_count=unique_count,
                    client_ip=client_ip,
                    db=db,
                )
            elif unique_count >= alert_threshold:
                # Alert only
                await self._trigger_bulk_access_alert(
                    user_id=user_id,
                    org_id=org_id,
                    unique_count=unique_count,
                    client_ip=client_ip,
                    window_seconds=window,
                )

        except Exception as e:
            # Don't let monitoring failures break the API
            logger.warning(
                "template_access_monitor_error",
                error=str(e),
                user_id=str(user_id),
                technique_id=technique_id,
            )

    async def _trigger_bulk_access_alert(
        self,
        user_id: UUID,
        org_id: UUID,
        unique_count: int,
        client_ip: Optional[str],
        window_seconds: int,
    ) -> None:
        """Trigger an alert for bulk template access.

        Uses a cooldown to prevent alert fatigue.
        """
        try:
            redis = await self._get_redis()
            alert_key = self._get_alert_key(user_id, org_id)
            cooldown = BULK_ACCESS_THRESHOLDS["alert_cooldown_seconds"]

            # Check if we've already alerted recently
            last_alert = await redis.get(alert_key)
            if last_alert:
                logger.debug(
                    "bulk_access_alert_suppressed",
                    user_id=str(user_id),
                    reason="cooldown_active",
                )
                return

            # Set cooldown
            await redis.setex(alert_key, cooldown, datetime.utcnow().isoformat())

            # Log the alert (this will be picked up by log aggregation/SIEM)
            logger.warning(
                "bulk_template_access_detected",
                alert_type="security",
                severity="medium",
                user_id=str(user_id),
                org_id=str(org_id),
                unique_techniques_accessed=unique_count,
                time_window_seconds=window_seconds,
                client_ip=client_ip,
                message=(
                    f"User {user_id} accessed {unique_count} unique templates "
                    f"in {window_seconds} seconds - possible scraping attempt"
                ),
                recommended_action="Review user activity and consider rate limiting",
            )

            # TODO: Integrate with alerting system (e.g., PagerDuty, Slack, email)
            # await self._send_alert_notification(...)

        except Exception as e:
            logger.error(
                "bulk_access_alert_error",
                error=str(e),
                user_id=str(user_id),
            )

    async def _suspend_user(
        self,
        user_id: UUID,
        org_id: UUID,
        unique_count: int,
        client_ip: Optional[str],
        db: Optional[AsyncSession] = None,
    ) -> None:
        """Suspend a user for bulk template access.

        Sets is_active=False - requires admin review to reactivate.

        Args:
            user_id: User to suspend
            org_id: User's organisation
            unique_count: Number of unique techniques accessed
            client_ip: Client IP address
            db: Database session (required for suspension)
        """
        try:
            redis = await self._get_redis()
            alert_key = self._get_alert_key(user_id, org_id)
            cooldown = BULK_ACCESS_THRESHOLDS["alert_cooldown_seconds"]

            # Check if we've already suspended recently (prevent duplicate actions)
            last_action = await redis.get(f"{alert_key}:suspended")
            if last_action:
                logger.debug(
                    "suspension_skipped",
                    user_id=str(user_id),
                    reason="already_suspended",
                )
                return

            # Set cooldown for suspension action
            await redis.setex(
                f"{alert_key}:suspended",
                cooldown,
                datetime.now(timezone.utc).isoformat(),
            )

            window = BULK_ACCESS_THRESHOLDS["time_window_seconds"]

            if db is None:
                # No database session - log warning and alert only
                logger.error(
                    "suspension_failed_no_db",
                    user_id=str(user_id),
                    message="Cannot suspend user - no database session provided",
                )
                # Still trigger the alert
                await self._trigger_bulk_access_alert(
                    user_id=user_id,
                    org_id=org_id,
                    unique_count=unique_count,
                    client_ip=client_ip,
                    window_seconds=window,
                )
                return

            # Import here to avoid circular imports
            from app.models.user import User, AuditEventType, AuditLog

            # Suspend user until admin review
            await db.execute(
                update(User).where(User.id == user_id).values(is_active=False)
            )

            # Create audit log
            audit_log = AuditLog(
                organization_id=org_id,
                user_id=user_id,
                event_type=AuditEventType.USER_SUSPENDED,
                resource_type="user",
                resource_id=str(user_id),
                ip_address=client_ip,
                details={
                    "reason": "bulk_template_access_scraping",
                    "unique_techniques_accessed": unique_count,
                    "time_window_seconds": window,
                    "requires_admin_review": True,
                },
            )
            db.add(audit_log)
            await db.commit()

            logger.critical(
                "user_suspended_for_scraping",
                alert_type="security",
                severity="critical",
                user_id=str(user_id),
                org_id=str(org_id),
                unique_techniques_accessed=unique_count,
                time_window_seconds=window,
                client_ip=client_ip,
                message=(
                    f"User {user_id} SUSPENDED - accessed {unique_count} unique "
                    f"templates in {window}s (possible scraping attack). "
                    "Admin review required to reactivate."
                ),
                recommended_action="Review user activity in audit logs",
            )

        except Exception as e:
            logger.error(
                "user_suspension_error",
                error=str(e),
                user_id=str(user_id),
            )

    async def get_user_access_stats(
        self,
        user_id: UUID,
        org_id: UUID,
    ) -> dict:
        """Get access statistics for a user (for admin dashboards).

        Returns:
            Dict with access counts and unique techniques accessed
        """
        try:
            redis = await self._get_redis()
            access_key = self._get_access_key(user_id, org_id)
            window = BULK_ACCESS_THRESHOLDS["time_window_seconds"]

            # Clean up old entries
            now = datetime.now(timezone.utc)
            cutoff = now.timestamp() - window
            await redis.zremrangebyscore(access_key, "-inf", cutoff)

            # Get all accesses in window
            all_accesses = await redis.zrange(access_key, 0, -1)
            unique_techniques = set()
            for access in all_accesses:
                tech_id = access.split(":")[0]
                unique_techniques.add(tech_id)

            return {
                "total_accesses_in_window": len(all_accesses),
                "unique_techniques_in_window": len(unique_techniques),
                "time_window_seconds": window,
                "alert_threshold": BULK_ACCESS_THRESHOLDS["alert_threshold"],
                "suspend_threshold": BULK_ACCESS_THRESHOLDS["suspend_threshold"],
            }

        except Exception as e:
            logger.warning(
                "get_user_access_stats_error",
                error=str(e),
                user_id=str(user_id),
            )
            return {}

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None


# Global instance
_monitor: Optional[TemplateAccessMonitor] = None


def get_template_access_monitor() -> TemplateAccessMonitor:
    """Get the global template access monitor instance."""
    global _monitor
    if _monitor is None:
        _monitor = TemplateAccessMonitor()
    return _monitor
