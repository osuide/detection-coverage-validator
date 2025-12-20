"""Custom detection model for user-uploaded detection rules."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class CustomDetectionFormat(str, enum.Enum):
    """Supported detection rule formats."""

    SIGMA = "sigma"
    YARA = "yara"
    SNORT = "snort"
    SURICATA = "suricata"
    SPL = "spl"  # Splunk Processing Language
    KQL = "kql"  # Kusto Query Language
    ELASTICSEARCH = "elasticsearch"
    CLOUDWATCH = "cloudwatch"
    CUSTOM = "custom"


class CustomDetectionStatus(str, enum.Enum):
    """Status of custom detection processing."""

    PENDING = "pending"
    PROCESSING = "processing"
    MAPPED = "mapped"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"


class CustomDetection(Base):
    """User-uploaded custom detection rule."""

    __tablename__ = "custom_detections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), index=True
    )
    cloud_account_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_accounts.id"),
        nullable=True,
        index=True,
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), index=True
    )

    # Detection metadata
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    format: Mapped[CustomDetectionFormat] = mapped_column(
        SQLEnum(CustomDetectionFormat), nullable=False
    )
    status: Mapped[CustomDetectionStatus] = mapped_column(
        SQLEnum(CustomDetectionStatus),
        nullable=False,
        default=CustomDetectionStatus.PENDING,
    )

    # Rule content
    rule_content: Mapped[str] = mapped_column(Text, nullable=False)
    rule_metadata: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Mapping results
    mapped_techniques: Mapped[Optional[list]] = mapped_column(
        ARRAY(String), nullable=True
    )
    mapping_confidence: Mapped[Optional[float]] = mapped_column(nullable=True)
    mapping_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Processing info
    processing_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    processed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    # Tags and categorisation
    tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    data_sources: Mapped[Optional[list]] = mapped_column(ARRAY(String), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    organization = relationship("Organization", back_populates="custom_detections")
    cloud_account = relationship("CloudAccount", back_populates="custom_detections")
    user = relationship("User")


class CustomDetectionBatch(Base):
    """Batch upload of custom detections."""

    __tablename__ = "custom_detection_batches"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), index=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), index=True
    )

    # Batch info
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    format: Mapped[CustomDetectionFormat] = mapped_column(
        SQLEnum(CustomDetectionFormat), nullable=False
    )
    total_rules: Mapped[int] = mapped_column(default=0)
    processed_rules: Mapped[int] = mapped_column(default=0)
    successful_rules: Mapped[int] = mapped_column(default=0)
    failed_rules: Mapped[int] = mapped_column(default=0)

    # Status
    status: Mapped[CustomDetectionStatus] = mapped_column(
        SQLEnum(CustomDetectionStatus),
        nullable=False,
        default=CustomDetectionStatus.PENDING,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps
    started_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )
