"""Device fingerprint service for abuse detection and prevention."""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List
from uuid import UUID

import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.fingerprint import DeviceFingerprint, DeviceFingerprintAssociation
from app.models.user import User

logger = structlog.get_logger()

# Rate limiting constants
MAX_REGISTRATIONS_PER_FINGERPRINT_PER_DAY = 3
ABUSE_SCORE_THRESHOLD = 50  # Score above which to flag for review


class FingerprintService:
    """Service for managing device fingerprints and abuse detection."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_fingerprint(
        self, fingerprint_hash: str
    ) -> Optional[DeviceFingerprint]:
        """Get a fingerprint by its hash."""
        result = await self.db.execute(
            select(DeviceFingerprint).where(
                DeviceFingerprint.fingerprint_hash == fingerprint_hash
            )
        )
        return result.scalar_one_or_none()

    async def record_fingerprint(
        self,
        fingerprint_hash: str,
        user_id: UUID,
        organization_id: Optional[UUID],
        ip_address: Optional[str],
    ) -> DeviceFingerprint:
        """Record a fingerprint observation.

        Creates the fingerprint if it doesn't exist, then creates or updates
        the association with the user/org.

        Args:
            fingerprint_hash: SHA-256 hash of the fingerprint
            user_id: The user ID
            organization_id: The organisation ID (optional)
            ip_address: Client IP address (optional)

        Returns:
            The fingerprint record
        """
        now = datetime.now(timezone.utc)

        # Get or create fingerprint
        fingerprint = await self.get_fingerprint(fingerprint_hash)

        if not fingerprint:
            fingerprint = DeviceFingerprint(
                fingerprint_hash=fingerprint_hash,
                first_seen_at=now,
                last_seen_at=now,
            )
            self.db.add(fingerprint)
            await self.db.flush()

            logger.info(
                "fingerprint_created",
                fingerprint_id=str(fingerprint.id),
                fingerprint_hash=fingerprint_hash[:16] + "...",
            )
        else:
            fingerprint.last_seen_at = now

        # Check for existing association
        result = await self.db.execute(
            select(DeviceFingerprintAssociation).where(
                DeviceFingerprintAssociation.fingerprint_id == fingerprint.id,
                DeviceFingerprintAssociation.user_id == user_id,
            )
        )
        association = result.scalar_one_or_none()

        if association:
            # Update existing association
            association.record_seen(ip_address)
        else:
            # Create new association
            association = DeviceFingerprintAssociation(
                fingerprint_id=fingerprint.id,
                user_id=user_id,
                organization_id=organization_id,
                ip_address=ip_address,
                first_seen_at=now,
                last_seen_at=now,
            )
            self.db.add(association)

            # Update fingerprint counts
            fingerprint.associated_user_count += 1
            if organization_id:
                # Check if this org is already associated
                org_check = await self.db.execute(
                    select(func.count(DeviceFingerprintAssociation.id)).where(
                        DeviceFingerprintAssociation.fingerprint_id == fingerprint.id,
                        DeviceFingerprintAssociation.organization_id == organization_id,
                    )
                )
                if org_check.scalar() == 0:
                    fingerprint.associated_org_count += 1

            logger.info(
                "fingerprint_association_created",
                fingerprint_id=str(fingerprint.id),
                user_id=str(user_id),
                org_id=str(organization_id) if organization_id else None,
            )

        # Recalculate abuse score
        fingerprint.abuse_score = fingerprint.calculate_abuse_score()

        # Auto-flag if abuse score is high
        if (
            fingerprint.abuse_score >= ABUSE_SCORE_THRESHOLD
            and not fingerprint.is_flagged
        ):
            fingerprint.is_flagged = True
            fingerprint.flag_reason = "Auto-flagged: high abuse score"
            logger.warning(
                "fingerprint_auto_flagged",
                fingerprint_id=str(fingerprint.id),
                abuse_score=fingerprint.abuse_score,
                user_count=fingerprint.associated_user_count,
                org_count=fingerprint.associated_org_count,
            )

        await self.db.commit()
        return fingerprint

    async def check_registration_allowed(
        self,
        fingerprint_hash: str,
        ip_address: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Check if registration is allowed from this device.

        Rate limits registrations to prevent abuse:
        - Max 3 registrations per fingerprint per 24 hours
        - Flagged fingerprints are allowed but logged

        Args:
            fingerprint_hash: SHA-256 hash of the fingerprint
            ip_address: Client IP address (for logging)

        Returns:
            (allowed, reason) - True if allowed, False with reason if blocked
        """
        fingerprint = await self.get_fingerprint(fingerprint_hash)

        if not fingerprint:
            # New fingerprint, always allowed
            return True, None

        # Check registrations in last 24 hours from this fingerprint
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        result = await self.db.execute(
            select(func.count(DeviceFingerprintAssociation.id)).where(
                DeviceFingerprintAssociation.fingerprint_id == fingerprint.id,
                DeviceFingerprintAssociation.created_at >= cutoff,
            )
        )
        recent_registrations = result.scalar() or 0

        if recent_registrations >= MAX_REGISTRATIONS_PER_FINGERPRINT_PER_DAY:
            logger.warning(
                "registration_rate_limited",
                fingerprint_id=str(fingerprint.id),
                recent_count=recent_registrations,
                ip_address=ip_address,
            )
            return (
                False,
                "Too many account registrations from this device. Please try again later.",
            )

        # Allow but log if fingerprint is flagged
        if fingerprint.is_flagged:
            logger.warning(
                "registration_from_flagged_device",
                fingerprint_id=str(fingerprint.id),
                flag_reason=fingerprint.flag_reason,
                ip_address=ip_address,
            )

        return True, None

    async def get_users_by_fingerprint(
        self,
        fingerprint_hash: str,
    ) -> List[User]:
        """Get all users associated with a fingerprint.

        Args:
            fingerprint_hash: SHA-256 hash of the fingerprint

        Returns:
            List of User objects
        """
        fingerprint = await self.get_fingerprint(fingerprint_hash)
        if not fingerprint:
            return []

        result = await self.db.execute(
            select(User)
            .join(DeviceFingerprintAssociation)
            .where(DeviceFingerprintAssociation.fingerprint_id == fingerprint.id)
        )
        return list(result.scalars().all())

    async def get_fingerprints_by_user(
        self,
        user_id: UUID,
    ) -> List[DeviceFingerprint]:
        """Get all fingerprints associated with a user.

        Args:
            user_id: The user ID

        Returns:
            List of DeviceFingerprint objects
        """
        result = await self.db.execute(
            select(DeviceFingerprint)
            .join(DeviceFingerprintAssociation)
            .where(DeviceFingerprintAssociation.user_id == user_id)
        )
        return list(result.scalars().all())

    async def flag_fingerprint(
        self,
        fingerprint_id: UUID,
        reason: str,
        admin_notes: Optional[str] = None,
    ) -> Optional[DeviceFingerprint]:
        """Flag a fingerprint as suspicious.

        Args:
            fingerprint_id: The fingerprint ID
            reason: Reason for flagging
            admin_notes: Optional admin notes

        Returns:
            The updated fingerprint, or None if not found
        """
        result = await self.db.execute(
            select(DeviceFingerprint).where(DeviceFingerprint.id == fingerprint_id)
        )
        fingerprint = result.scalar_one_or_none()

        if not fingerprint:
            return None

        fingerprint.is_flagged = True
        fingerprint.flag_reason = reason
        if admin_notes:
            fingerprint.admin_notes = admin_notes
        fingerprint.abuse_score = 100  # Max score when manually flagged

        await self.db.commit()

        logger.info(
            "fingerprint_flagged",
            fingerprint_id=str(fingerprint_id),
            reason=reason,
        )

        return fingerprint

    async def unflag_fingerprint(
        self,
        fingerprint_id: UUID,
        admin_notes: Optional[str] = None,
    ) -> Optional[DeviceFingerprint]:
        """Remove flag from a fingerprint.

        Args:
            fingerprint_id: The fingerprint ID
            admin_notes: Optional admin notes

        Returns:
            The updated fingerprint, or None if not found
        """
        result = await self.db.execute(
            select(DeviceFingerprint).where(DeviceFingerprint.id == fingerprint_id)
        )
        fingerprint = result.scalar_one_or_none()

        if not fingerprint:
            return None

        fingerprint.is_flagged = False
        fingerprint.flag_reason = None
        if admin_notes:
            fingerprint.admin_notes = admin_notes
        fingerprint.abuse_score = fingerprint.calculate_abuse_score()

        await self.db.commit()

        logger.info(
            "fingerprint_unflagged",
            fingerprint_id=str(fingerprint_id),
        )

        return fingerprint

    async def get_suspicious_fingerprints(
        self,
        min_abuse_score: int = ABUSE_SCORE_THRESHOLD,
        is_flagged: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[DeviceFingerprint], int]:
        """Get fingerprints with high abuse scores.

        Args:
            min_abuse_score: Minimum abuse score to include
            is_flagged: Filter by flagged status (None = all)
            limit: Maximum results to return
            offset: Offset for pagination

        Returns:
            (fingerprints, total_count)
        """
        query = select(DeviceFingerprint).where(
            DeviceFingerprint.abuse_score >= min_abuse_score
        )

        if is_flagged is not None:
            query = query.where(DeviceFingerprint.is_flagged == is_flagged)

        # Get total count
        count_result = await self.db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        # Get paginated results
        query = query.order_by(DeviceFingerprint.abuse_score.desc())
        query = query.limit(limit).offset(offset)

        result = await self.db.execute(query)
        fingerprints = list(result.scalars().all())

        return fingerprints, total
