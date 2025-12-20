"""Detection to MITRE ATT&CK mapping model."""

import uuid
from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import String, DateTime, Enum as SQLEnum, Text, ForeignKey, Float
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class MappingSource(str, enum.Enum):
    """How the mapping was determined."""

    PATTERN_MATCH = "pattern_match"
    NLP = "nlp"
    MANUAL = "manual"
    VENDOR = "vendor"  # GuardDuty, etc.


class DetectionMapping(Base):
    """Maps a detection to one or more MITRE ATT&CK techniques."""

    __tablename__ = "detection_mappings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detections.id"), nullable=False, index=True
    )
    technique_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("techniques.id"), nullable=False, index=True
    )

    # Confidence scoring
    confidence: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0 to 1.0
    mapping_source: Mapped[MappingSource] = mapped_column(
        SQLEnum(MappingSource, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )

    # Explanation of why this mapping was made
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Pattern that matched (for pattern_match source)
    matched_indicators: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)

    # For vendor mappings, track the original vendor technique ID
    vendor_mapping_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Staleness tracking
    is_stale: Mapped[bool] = mapped_column(default=False)
    last_validated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    detection = relationship("Detection", back_populates="mappings")
    technique = relationship("Technique", back_populates="mappings")

    def __repr__(self) -> str:
        return f"<DetectionMapping {self.detection_id} -> {self.technique_id} ({self.confidence:.2f})>"
