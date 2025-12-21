"""Cloud organisation models for AWS Organisations and GCP Organisations."""

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.cloud_account import CloudProvider


class CloudOrganizationStatus(str, enum.Enum):
    """Status of a cloud organisation connection."""

    DISCOVERED = "discovered"  # Org found but not yet connected
    CONNECTING = "connecting"  # Connection in progress
    CONNECTED = "connected"  # Fully connected and scannable
    PARTIAL = "partial"  # Some accounts connected, others pending
    ERROR = "error"  # Connection error
    DISCONNECTED = "disconnected"  # Previously connected, now disconnected


class CloudOrganizationMemberStatus(str, enum.Enum):
    """Status of a member account/project within an organisation."""

    DISCOVERED = "discovered"  # Found during org discovery
    PENDING = "pending"  # Awaiting user action to connect
    CONNECTING = "connecting"  # Connection in progress
    CONNECTED = "connected"  # Successfully connected as CloudAccount
    SKIPPED = "skipped"  # User chose not to connect
    ERROR = "error"  # Failed to connect
    SUSPENDED = "suspended"  # Account is suspended in the cloud org


class CloudOrganization(Base):
    """
    Represents a cloud organisation (AWS Organisation or GCP Organisation).

    A cloud organisation contains multiple member accounts/projects that can
    be discovered and optionally connected for scanning.
    """

    __tablename__ = "cloud_organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Link to our tenant organisation
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Cloud provider and org identifier
    provider: Mapped[CloudProvider] = mapped_column(
        SQLEnum(CloudProvider, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    cloud_org_id: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )  # AWS: o-xxxxx, GCP: organizations/123456

    # Organisation details
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    root_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    master_account_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )  # AWS management account or GCP billing account

    # Connection status
    status: Mapped[CloudOrganizationStatus] = mapped_column(
        SQLEnum(
            CloudOrganizationStatus,
            values_callable=lambda x: [e.value for e in x],
            name="cloud_organization_status",  # Must match migration enum name
        ),
        default=CloudOrganizationStatus.DISCOVERED,
        index=True,
    )

    # Credentials for scanning (ARN for cross-account role, or service account key)
    credentials_arn: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # AWS-specific: delegated admin account IDs for GuardDuty, Security Hub, etc.
    delegated_admins: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Org metadata from cloud provider
    org_metadata: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Statistics
    total_accounts_discovered: Mapped[int] = mapped_column(default=0)
    total_accounts_connected: Mapped[int] = mapped_column(default=0)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    connected_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    organization = relationship("Organization", back_populates="cloud_organizations")
    members = relationship(
        "CloudOrganizationMember",
        back_populates="cloud_organization",
        cascade="all, delete-orphan",
    )
    cloud_accounts = relationship("CloudAccount", back_populates="cloud_organization")
    org_detections = relationship(
        "Detection",
        back_populates="cloud_organization",
        foreign_keys="Detection.cloud_organization_id",
    )

    def __repr__(self) -> str:
        return f"<CloudOrganization {self.name} ({self.provider.value}:{self.cloud_org_id})>"


class CloudOrganizationMember(Base):
    """
    Represents a member account/project within a cloud organisation.

    Tracks discovered accounts before they are connected as CloudAccount records.
    This allows users to see all accounts in their org and select which to connect.
    """

    __tablename__ = "cloud_organization_members"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Link to parent cloud organisation
    cloud_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Link to CloudAccount once connected (nullable until connected)
    cloud_account_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Account/Project identifier in the cloud
    member_account_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # AWS account ID or GCP project ID
    member_name: Mapped[str] = mapped_column(String(255), nullable=False)
    member_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Hierarchy path for OUs/Folders (materialised path pattern)
    # e.g., "Root/Production/WebServices" or "folders/123/folders/456"
    hierarchy_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    parent_id: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )  # Parent OU/Folder ID

    # Status
    status: Mapped[CloudOrganizationMemberStatus] = mapped_column(
        SQLEnum(
            CloudOrganizationMemberStatus,
            values_callable=lambda x: [e.value for e in x],
            name="cloud_organization_member_status",  # Must match migration enum name
        ),
        default=CloudOrganizationMemberStatus.DISCOVERED,
        index=True,
    )

    # AWS-specific: account status in the org
    join_method: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )  # INVITED, CREATED
    joined_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # GCP-specific: project state
    lifecycle_state: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )  # ACTIVE, DELETE_REQUESTED, etc.

    # Error tracking
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Account metadata from cloud provider
    member_metadata: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    connected_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    cloud_organization = relationship("CloudOrganization", back_populates="members")
    cloud_account = relationship("CloudAccount", back_populates="org_membership")

    def __repr__(self) -> str:
        return (
            f"<CloudOrganizationMember {self.member_name} ({self.member_account_id})>"
        )
