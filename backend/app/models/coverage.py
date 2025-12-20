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
