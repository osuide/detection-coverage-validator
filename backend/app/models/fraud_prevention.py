"""Fraud prevention models for protecting the free tier from abuse."""

import hashlib
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.core.database import Base


class CloudAccountGlobalRegistry(Base):
    """Tracks cloud accounts globally to prevent free-tier abuse.

    When a cloud account is first connected by a free-tier org, it's registered here.
    Subsequent free-tier orgs attempting to connect the same account are blocked.
    Paid tiers can connect any account (e.g., consultants scanning client accounts).
    """

    __tablename__ = "cloud_account_global_registry"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    account_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    provider: Mapped[str] = mapped_column(String(10), nullable=False)
    first_registered_org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False
    )
    first_registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    registration_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="1"
    )
    is_free_tier_locked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class FreeEmailCloudAccountBinding(Base):
    """Permanently binds an email to the cloud accounts they've used on free tier.

    Prevents "cloud account cycling" where a user:
    1. Registers with email A → connects AWS account X → scans → deletes
    2. Registers with email A → connects AWS account Y → scans → deletes
    3. Repeats to scan unlimited cloud accounts for free

    Once an email has connected a cloud account on free tier, that email
    can ONLY ever connect that same cloud account on free tier (even after
    account deletion and re-registration).

    To connect different cloud accounts, they must upgrade to paid tier.
    """

    __tablename__ = "free_email_cloud_account_bindings"

    __table_args__ = (
        # One email can only bind to one cloud account on free tier
        UniqueConstraint("email_hash", name="uq_email_cloud_binding"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )

    # SHA-256 hash of lowercase email
    email_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # The cloud account this email is bound to
    cloud_account_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    provider: Mapped[str] = mapped_column(String(10), nullable=False)

    # When this binding was created
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    @staticmethod
    def compute_email_hash(email: str) -> str:
        """Compute SHA-256 hash of email for comparison."""
        return hashlib.sha256(email.lower().strip().encode()).hexdigest()
