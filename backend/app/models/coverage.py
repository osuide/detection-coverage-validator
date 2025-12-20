"""Coverage snapshot model."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, Float, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class CoverageSnapshot(Base):
    """Point-in-time coverage metrics for a cloud account."""

    __tablename__ = "coverage_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cloud_accounts.id"), nullable=False, index=True
    )

    # Overall metrics
    total_techniques: Mapped[int] = mapped_column(Integer, default=0)
    covered_techniques: Mapped[int] = mapped_column(Integer, default=0)
    partial_techniques: Mapped[int] = mapped_column(Integer, default=0)
    uncovered_techniques: Mapped[int] = mapped_column(Integer, default=0)

    coverage_percent: Mapped[float] = mapped_column(Float, default=0.0)
    average_confidence: Mapped[float] = mapped_column(Float, default=0.0)

    # Per-tactic breakdown stored as JSONB
    # Structure: {tactic_id: {covered: N, partial: N, uncovered: N, percent: F}}
    tactic_coverage: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Detection counts
    total_detections: Mapped[int] = mapped_column(Integer, default=0)
    active_detections: Mapped[int] = mapped_column(Integer, default=0)
    mapped_detections: Mapped[int] = mapped_column(Integer, default=0)

    # Organisation-level detection contribution
    org_detection_count: Mapped[int] = mapped_column(Integer, default=0)
    org_covered_techniques: Mapped[int] = mapped_column(Integer, default=0)
    account_only_techniques: Mapped[int] = mapped_column(Integer, default=0)
    org_only_techniques: Mapped[int] = mapped_column(Integer, default=0)
    overlap_techniques: Mapped[int] = mapped_column(Integer, default=0)

    # Coverage breakdown showing account vs org contribution
    # Structure: {account_only: N, org_only: N, both: N, total_covered: N, cloud_organization_id: str}
    coverage_breakdown: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Gap analysis stored as JSONB
    # Structure: [{technique_id, name, tactic, priority, reason}]
    top_gaps: Mapped[list] = mapped_column(JSONB, default=list)

    # MITRE version this snapshot is based on
    mitre_version: Mapped[str] = mapped_column(String(16), default="14.1")

    # Metadata
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, index=True
    )

    def __repr__(self) -> str:
        return (
            f"<CoverageSnapshot {self.cloud_account_id} ({self.coverage_percent:.1f}%)>"
        )


class OrgCoverageSnapshot(Base):
    """Point-in-time aggregate coverage metrics for a cloud organisation."""

    __tablename__ = "org_coverage_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cloud_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_organizations.id"),
        nullable=False,
        index=True,
    )

    # Account counts
    total_member_accounts: Mapped[int] = mapped_column(Integer, default=0)
    connected_accounts: Mapped[int] = mapped_column(Integer, default=0)

    # Aggregate coverage metrics
    total_techniques: Mapped[int] = mapped_column(Integer, default=0)
    union_covered_techniques: Mapped[int] = mapped_column(Integer, default=0)
    minimum_covered_techniques: Mapped[int] = mapped_column(Integer, default=0)
    average_coverage_percent: Mapped[float] = mapped_column(Float, default=0.0)

    # Coverage percentages
    union_coverage_percent: Mapped[float] = mapped_column(Float, default=0.0)
    minimum_coverage_percent: Mapped[float] = mapped_column(Float, default=0.0)

    # Org-level detection summary
    org_detection_count: Mapped[int] = mapped_column(Integer, default=0)
    org_covered_techniques: Mapped[int] = mapped_column(Integer, default=0)

    # Per-account breakdown stored as JSONB
    # Structure: {account_id: coverage_percent}
    per_account_coverage: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Per-tactic aggregate coverage stored as JSONB
    # Structure: {tactic_id: {union_covered: N, minimum_covered: N, total: N, ...}}
    tactic_coverage: Mapped[dict] = mapped_column(JSONB, default=dict)

    # MITRE version this snapshot is based on
    mitre_version: Mapped[str] = mapped_column(String(16), default="14.1")

    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, index=True
    )

    def __repr__(self) -> str:
        return (
            f"<OrgCoverageSnapshot {self.cloud_organization_id} "
            f"(union: {self.union_coverage_percent:.1f}%, "
            f"min: {self.minimum_coverage_percent:.1f}%)>"
        )
