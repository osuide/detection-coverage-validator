"""MITRE ATT&CK Threat Intelligence models."""

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Text, ForeignKey, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class SyncStatus(str, enum.Enum):
    """Status of a MITRE data sync operation."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SyncTriggerType(str, enum.Enum):
    """How a sync was triggered."""

    MANUAL = "manual"
    SCHEDULED = "scheduled"


class RelatedType(str, enum.Enum):
    """Type of entity related to a technique."""

    GROUP = "group"
    CAMPAIGN = "campaign"
    SOFTWARE = "software"


class SoftwareType(str, enum.Enum):
    """Type of software."""

    MALWARE = "malware"
    TOOL = "tool"


class MitreThreatGroup(Base):
    """MITRE ATT&CK Threat Group (G####)."""

    __tablename__ = "mitre_threat_groups"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    stix_id: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False
    )  # e.g., "intrusion-set--..."
    external_id: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # e.g., "G0007"
    name: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )  # e.g., "APT28"
    aliases: Mapped[list] = mapped_column(
        JSONB, default=list
    )  # ["Fancy Bear", "Sofacy"]
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    external_references: Mapped[list] = mapped_column(
        JSONB, default=list
    )  # URLs, citations
    mitre_version: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<MitreThreatGroup {self.external_id}: {self.name}>"

    @property
    def mitre_url(self) -> str:
        """Get the MITRE ATT&CK URL for this group."""
        return f"https://attack.mitre.org/groups/{self.external_id}/"


class MitreCampaign(Base):
    """MITRE ATT&CK Campaign (C####)."""

    __tablename__ = "mitre_campaigns"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    stix_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    external_id: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # e.g., "C0001"
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    external_references: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_version: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<MitreCampaign {self.external_id}: {self.name}>"

    @property
    def mitre_url(self) -> str:
        """Get the MITRE ATT&CK URL for this campaign."""
        return f"https://attack.mitre.org/campaigns/{self.external_id}/"


class MitreSoftware(Base):
    """MITRE ATT&CK Software - Malware (S####) or Tool (S####)."""

    __tablename__ = "mitre_software"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    stix_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    external_id: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # e.g., "S0001"
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    software_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # "malware" or "tool"
    aliases: Mapped[list] = mapped_column(JSONB, default=list)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    platforms: Mapped[list] = mapped_column(
        JSONB, default=list
    )  # ["Windows", "Linux", "macOS"]
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    external_references: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_version: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<MitreSoftware {self.external_id}: {self.name} ({self.software_type})>"

    @property
    def mitre_url(self) -> str:
        """Get the MITRE ATT&CK URL for this software."""
        return f"https://attack.mitre.org/software/{self.external_id}/"


class MitreTechniqueRelationship(Base):
    """Relationship between a technique and a group/campaign/software."""

    __tablename__ = "mitre_technique_relationships"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    technique_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("techniques.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    related_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # group, campaign, software
    related_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )  # FK to respective table
    relationship_type: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )  # "uses", etc.
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # Context of use
    external_references: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_version: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    # Relationship to technique
    technique = relationship("Technique", backref="threat_relationships")

    def __repr__(self) -> str:
        return f"<MitreTechniqueRelationship {self.technique_id} -> {self.related_type}:{self.related_id}>"


class MitreCampaignAttribution(Base):
    """Attribution relationship between a campaign and a threat group.

    Represents MITRE's 'attributed-to' relationship: a campaign is
    attributed to (conducted by) a threat group.
    """

    __tablename__ = "mitre_campaign_attributions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("mitre_campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("mitre_threat_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    external_references: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_version: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    # Relationships
    campaign = relationship("MitreCampaign", backref="attributions")
    group = relationship("MitreThreatGroup", backref="campaign_attributions")

    def __repr__(self) -> str:
        return f"<MitreCampaignAttribution campaign={self.campaign_id} -> group={self.group_id}>"


class MitreSyncHistory(Base):
    """History of MITRE data sync operations."""

    __tablename__ = "mitre_sync_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # pending, running, completed, failed
    mitre_version: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    stix_version: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    triggered_by_admin_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.id", ondelete="SET NULL"),
        nullable=True,
    )
    trigger_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # manual, scheduled
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)  # {"groups_added": 5, ...}
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    # Relationship to admin user
    triggered_by = relationship("AdminUser", backref="mitre_syncs")

    def __repr__(self) -> str:
        return f"<MitreSyncHistory {self.id} status={self.status}>"

    @property
    def duration_seconds(self) -> Optional[int]:
        """Calculate sync duration in seconds."""
        if self.completed_at and self.started_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None


class MitreDataVersion(Base):
    """Current MITRE data version and statistics (single row table)."""

    __tablename__ = "mitre_data_version"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    mitre_version: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # e.g., "16.0"
    stix_version: Mapped[str] = mapped_column(String(16), nullable=False)  # e.g., "2.1"
    last_sync_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_sync_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("mitre_sync_history.id", ondelete="SET NULL"),
        nullable=True,
    )
    total_groups: Mapped[int] = mapped_column(Integer, default=0)
    total_campaigns: Mapped[int] = mapped_column(Integer, default=0)
    total_software: Mapped[int] = mapped_column(Integer, default=0)
    total_relationships: Mapped[int] = mapped_column(Integer, default=0)
    source_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationship to last sync
    last_sync = relationship("MitreSyncHistory")

    def __repr__(self) -> str:
        return f"<MitreDataVersion {self.mitre_version} (STIX {self.stix_version})>"
