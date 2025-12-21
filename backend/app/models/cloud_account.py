"""Cloud account model."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    String,
    DateTime,
    Enum as SQLEnum,
    Text,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.core.database import Base


class CloudProvider(str, enum.Enum):
    """Supported cloud providers."""

    AWS = "aws"
    GCP = "gcp"


class RegionScanMode(str, enum.Enum):
    """Region scanning mode for cloud accounts."""

    ALL = "all"  # Scan all available regions (with optional exclusions)
    SELECTED = "selected"  # Scan only explicitly selected regions
    AUTO = "auto"  # Auto-discover and scan active regions


class CloudAccount(Base):
    """Represents a cloud account to be scanned."""

    __tablename__ = "cloud_accounts"
    __table_args__ = (
        # Unique constraint per organisation - same cloud account can be
        # connected by different organisations (e.g., consultants scanning clients)
        UniqueConstraint(
            "organization_id", "account_id", name="uq_cloud_accounts_org_account"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Link to cloud organisation (AWS Org or GCP Org) if discovered via org connection
    cloud_organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[CloudProvider] = mapped_column(
        SQLEnum(CloudProvider, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    # Account ID is unique per organisation, not globally
    # (multiple orgs can scan the same AWS/GCP account)
    account_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    regions: Mapped[dict] = mapped_column(JSONB, default=list)
    # Multi-region scanning configuration
    # Structure: {mode, regions, excluded_regions, discovered_regions, auto_discovered_at}
    region_config: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    credentials_arn: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    organization = relationship("Organization", back_populates="cloud_accounts")
    cloud_organization = relationship(
        "CloudOrganization", back_populates="cloud_accounts"
    )
    org_membership = relationship(
        "CloudOrganizationMember", back_populates="cloud_account", uselist=False
    )
    detections = relationship(
        "Detection",
        back_populates="cloud_account",
        foreign_keys="Detection.cloud_account_id",
    )
    scans = relationship("Scan", back_populates="cloud_account")
    schedules = relationship("ScanSchedule", back_populates="cloud_account")
    alerts = relationship("AlertConfig", back_populates="cloud_account")
    coverage_history = relationship(
        "CoverageHistory", back_populates="cloud_account", cascade="all, delete-orphan"
    )
    custom_detections = relationship(
        "CustomDetection", back_populates="cloud_account", cascade="all, delete-orphan"
    )
    coverage_gaps = relationship(
        "CoverageGap", back_populates="cloud_account", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<CloudAccount {self.name} ({self.provider.value}:{self.account_id})>"

    def get_region_scan_mode(self) -> RegionScanMode:
        """Get the current region scanning mode."""
        if not self.region_config:
            return RegionScanMode.SELECTED
        mode = self.region_config.get("mode", "selected")
        return RegionScanMode(mode)

    def get_effective_regions(self, all_regions: list[str]) -> list[str]:
        """Get the effective list of regions to scan based on configuration.

        Args:
            all_regions: List of all available regions for this provider

        Returns:
            List of regions to scan
        """
        mode = self.get_region_scan_mode()

        if mode == RegionScanMode.ALL:
            # Scan all regions except exclusions
            excluded = set(self.region_config.get("excluded_regions", []))
            return [r for r in all_regions if r not in excluded]

        elif mode == RegionScanMode.AUTO:
            # Use auto-discovered regions, fall back to selected
            discovered = self.region_config.get("discovered_regions", [])
            if discovered:
                return discovered
            # Fall through to selected mode

        # SELECTED mode or fallback
        config_regions = (
            self.region_config.get("regions", []) if self.region_config else []
        )
        return config_regions or self.regions or []

    def set_auto_discovered_regions(self, regions: list[str]) -> None:
        """Update the auto-discovered regions.

        Args:
            regions: List of discovered active regions
        """
        from datetime import datetime, timezone

        if not self.region_config:
            self.region_config = {"mode": "auto"}

        self.region_config["discovered_regions"] = regions
        self.region_config["auto_discovered_at"] = datetime.now(
            timezone.utc
        ).isoformat()

    def get_default_region(self) -> str:
        """Get the default region for this account's provider."""
        if self.provider == CloudProvider.AWS:
            return "eu-west-2"  # A13E's primary region
        elif self.provider == CloudProvider.GCP:
            return "europe-west2"  # GCP equivalent
        return "us-east-1"
