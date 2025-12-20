"""Device fingerprint and scan tracking models for abuse prevention."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class DeviceFingerprint(Base):
    """Stores device fingerprint hashes for abuse detection.

    Fingerprints are SHA-256 hashes of browser/device characteristics.
    Used to detect when multiple accounts are created from the same device.
    """

    __tablename__ = "device_fingerprints"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    fingerprint_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    # Timestamps
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Association counts (denormalised for quick queries)
    associated_user_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    associated_org_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    # Abuse detection
    abuse_score: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )  # 0-100, higher = more suspicious
    is_flagged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    flag_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    admin_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    associations = relationship(
        "DeviceFingerprintAssociation", back_populates="fingerprint", lazy="dynamic"
    )

    def update_last_seen(self) -> None:
        """Update last seen timestamp."""
        self.last_seen_at = datetime.now(timezone.utc)

    def calculate_abuse_score(self) -> int:
        """Calculate abuse score based on associations.

        Factors:
        - >2 users = suspicious (+20 per extra user)
        - >2 orgs = more suspicious (+30 per extra org)
        - Flagged = maximum score
        """
        if self.is_flagged:
            return 100

        score = 0

        # Multiple users from same device
        if self.associated_user_count > 2:
            score += (self.associated_user_count - 2) * 20

        # Multiple orgs from same device
        if self.associated_org_count > 2:
            score += (self.associated_org_count - 2) * 30

        return min(score, 100)


class DeviceFingerprintAssociation(Base):
    """Links device fingerprints to users and organisations.

    Tracks when a fingerprint is seen with a particular user/org combination.
    """

    __tablename__ = "device_fingerprint_associations"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )

    fingerprint_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("device_fingerprints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # IP address (IPv6 compatible - max 45 chars)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Timestamps
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    seen_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    fingerprint = relationship("DeviceFingerprint", back_populates="associations")
    user = relationship("User", backref="fingerprint_associations")
    organization = relationship("Organization", backref="fingerprint_associations")

    def record_seen(self, ip_address: Optional[str] = None) -> None:
        """Record that this association was seen again."""
        self.last_seen_at = datetime.now(timezone.utc)
        self.seen_count += 1
        if ip_address:
            self.ip_address = ip_address


class OrganisationScanTracking(Base):
    """Tracks scan usage for organisations with weekly limits.

    Uses a rolling 7-day window from the first scan of the week.
    """

    __tablename__ = "organisation_scan_tracking"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    # Weekly tracking
    weekly_scan_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    week_start_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Lifetime stats
    total_scans: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    organization = relationship("Organization", backref="scan_tracking")

    def is_week_expired(self, reset_interval_days: int = 7) -> bool:
        """Check if the current week window has expired."""
        if not self.week_start_at:
            return True

        now = datetime.now(timezone.utc)
        elapsed = now - self.week_start_at
        return elapsed.days >= reset_interval_days

    def reset_week(self) -> None:
        """Reset the weekly counter for a new week."""
        self.weekly_scan_count = 0
        self.week_start_at = datetime.now(timezone.utc)

    def record_scan(self, reset_interval_days: int = 7) -> None:
        """Record a scan, resetting the week if expired."""
        now = datetime.now(timezone.utc)

        # Reset if week expired
        if self.is_week_expired(reset_interval_days):
            self.reset_week()

        # Start week on first scan
        if not self.week_start_at:
            self.week_start_at = now

        self.weekly_scan_count += 1
        self.total_scans += 1
        self.last_scan_at = now
        self.updated_at = now

    def get_next_scan_available_at(
        self, reset_interval_days: int = 7
    ) -> Optional[datetime]:
        """Get when the next scan will be available if currently blocked."""
        if not self.week_start_at:
            return None

        from datetime import timedelta

        return self.week_start_at + timedelta(days=reset_interval_days)
