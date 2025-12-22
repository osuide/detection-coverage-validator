"""Compliance framework models.

Maps MITRE ATT&CK techniques to compliance framework controls (NIST 800-53, CIS, etc.).
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Text, ForeignKey, Float, Boolean, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ComplianceFramework(Base):
    """A compliance framework (e.g., NIST 800-53, CIS Controls)."""

    __tablename__ = "compliance_frameworks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    framework_id: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )  # e.g., "nist-800-53-r5", "cis-v8"
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    controls = relationship(
        "ComplianceControl", back_populates="framework", cascade="all, delete-orphan"
    )
    coverage_snapshots = relationship(
        "ComplianceCoverageSnapshot",
        back_populates="framework",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ComplianceFramework {self.framework_id}: {self.name}>"


class ComplianceControl(Base):
    """An individual control within a compliance framework."""

    __tablename__ = "compliance_controls"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_frameworks.id"), nullable=False
    )
    control_id: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # e.g., "AC-2", "1.1"
    control_family: Mapped[str] = mapped_column(
        String(128), nullable=False
    )  # e.g., "Access Control"
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    priority: Mapped[Optional[str]] = mapped_column(
        String(8), nullable=True
    )  # "P1", "P2", "P3" or null

    # Cloud applicability metadata
    cloud_applicability: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True, default="highly_relevant"
    )  # "highly_relevant", "moderately_relevant", "informational", "provider_responsibility"

    # Cloud context (JSONB) - AWS/GCP service mappings and shared responsibility
    # Structure: {
    #   "aws_services": ["IAM", "CloudTrail"],
    #   "gcp_services": ["Cloud IAM", "Cloud Audit Logs"],
    #   "shared_responsibility": "customer" | "shared" | "provider",
    #   "detection_guidance": "Monitor IAM events in CloudTrail..."
    # }
    cloud_context: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # For nested controls (e.g., AC-2(1) is enhancement of AC-2)
    parent_control_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_controls.id"), nullable=True
    )
    is_enhancement: Mapped[bool] = mapped_column(Boolean, default=False)

    # Display order within framework
    display_order: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    # Relationships
    framework = relationship("ComplianceFramework", back_populates="controls")
    parent_control = relationship(
        "ComplianceControl", remote_side=[id], backref="enhancements"
    )
    technique_mappings = relationship(
        "ControlTechniqueMapping",
        back_populates="control",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ComplianceControl {self.control_id}: {self.name}>"


class ControlTechniqueMapping(Base):
    """Maps a compliance control to MITRE ATT&CK techniques.

    Many-to-many relationship: one control can map to many techniques,
    and one technique can be addressed by many controls.
    """

    __tablename__ = "control_technique_mappings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_controls.id"),
        nullable=False,
        index=True,
    )
    technique_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("techniques.id"), nullable=False, index=True
    )

    # Mapping metadata
    mapping_source: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # "mitre_ctid", "cis_official"
    mapping_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # "detects", "mitigates", "protects"
    source_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    # Relationships
    control = relationship("ComplianceControl", back_populates="technique_mappings")
    technique = relationship("Technique", backref="compliance_mappings")

    def __repr__(self) -> str:
        return f"<ControlTechniqueMapping {self.control_id} -> {self.technique_id}>"


class ComplianceCoverageSnapshot(Base):
    """Point-in-time compliance coverage for a cloud account.

    Calculated from the underlying MITRE technique coverage.
    """

    __tablename__ = "compliance_coverage_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cloud_accounts.id"), nullable=False, index=True
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_frameworks.id"),
        nullable=False,
        index=True,
    )
    coverage_snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coverage_snapshots.id"),
        nullable=False,
        index=True,
    )

    # Overall metrics
    total_controls: Mapped[int] = mapped_column(Integer, nullable=False)
    covered_controls: Mapped[int] = mapped_column(Integer, nullable=False)
    partial_controls: Mapped[int] = mapped_column(Integer, nullable=False)
    uncovered_controls: Mapped[int] = mapped_column(Integer, nullable=False)
    coverage_percent: Mapped[float] = mapped_column(Float, nullable=False)

    # Per-control family breakdown (JSONB)
    # Structure: {"Access Control": {"total": 10, "covered": 5, "partial": 2, "uncovered": 3, "percent": 50.0}}
    family_coverage: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Top uncovered controls (JSONB)
    # Structure: [{"control_id": "AC-2", "name": "...", "priority": "P1", "coverage_percent": 0.2, "missing_techniques": ["T1078"]}]
    top_gaps: Mapped[list] = mapped_column(JSONB, default=list)

    # Cloud-specific coverage metrics (JSONB)
    # Structure: {"cloud_detectable_total": 45, "cloud_detectable_covered": 38, "cloud_coverage_percent": 84.4, ...}
    cloud_metrics: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    # Relationships
    cloud_account = relationship("CloudAccount", backref="compliance_snapshots")
    framework = relationship("ComplianceFramework", back_populates="coverage_snapshots")
    coverage_snapshot = relationship("CoverageSnapshot", backref="compliance_snapshots")

    def __repr__(self) -> str:
        return f"<ComplianceCoverageSnapshot {self.framework_id} - {self.coverage_percent:.1f}%>"
