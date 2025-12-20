"""MITRE ATT&CK models."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Text, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Tactic(Base):
    """MITRE ATT&CK Tactic (TA####)."""

    __tablename__ = "tactics"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tactic_id: Mapped[str] = mapped_column(
        String(16), nullable=False, unique=True, index=True
    )  # e.g., TA0001
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    short_name: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # e.g., "initial-access"
    display_order: Mapped[int] = mapped_column(Integer, default=0)
    mitre_version: Mapped[str] = mapped_column(String(16), default="14.1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    # Relationships
    techniques = relationship("Technique", back_populates="tactic")

    def __repr__(self) -> str:
        return f"<Tactic {self.tactic_id}: {self.name}>"


class Technique(Base):
    """MITRE ATT&CK Technique (T####) or Sub-technique (T####.###)."""

    __tablename__ = "techniques"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    technique_id: Mapped[str] = mapped_column(
        String(16), nullable=False, unique=True, index=True
    )  # e.g., T1078 or T1078.004
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Tactic relationship (technique belongs to one or more tactics, but we use primary)
    tactic_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tactics.id"), nullable=False
    )

    # Parent technique for sub-techniques
    parent_technique_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("techniques.id"), nullable=True
    )

    # Platform applicability
    platforms: Mapped[list] = mapped_column(
        JSONB, default=list
    )  # ["AWS", "Azure", "GCP"]

    # Cloud-specific data sources
    data_sources: Mapped[list] = mapped_column(JSONB, default=list)

    # Detection guidance from MITRE
    detection_guidance: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    mitre_version: Mapped[str] = mapped_column(String(16), default="14.1")
    is_subtechnique: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    tactic = relationship("Tactic", back_populates="techniques")
    parent_technique = relationship(
        "Technique", remote_side=[id], backref="subtechniques"
    )
    mappings = relationship("DetectionMapping", back_populates="technique")

    def __repr__(self) -> str:
        return f"<Technique {self.technique_id}: {self.name}>"
