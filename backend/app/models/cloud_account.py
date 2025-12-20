"""Cloud account model."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Enum as SQLEnum, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.core.database import Base


class CloudProvider(str, enum.Enum):
    """Supported cloud providers."""

    AWS = "aws"
    GCP = "gcp"


class CloudAccount(Base):
    """Represents a cloud account to be scanned."""

    __tablename__ = "cloud_accounts"

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
    account_id: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    regions: Mapped[dict] = mapped_column(JSONB, default=list)
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

    def __repr__(self) -> str:
        return f"<CloudAccount {self.name} ({self.provider.value}:{self.account_id})>"
