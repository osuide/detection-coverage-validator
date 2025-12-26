"""Organization security settings models."""

from datetime import datetime
from typing import Optional, List
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class OrganizationSecuritySettings(Base):
    """Organization security settings model."""

    __tablename__ = "organization_security_settings"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # MFA Settings
    require_mfa: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_grace_period_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=7
    )

    # Session Settings
    session_timeout_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1440
    )  # 24 hours
    idle_timeout_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60
    )

    # Auth Methods - includes all common providers by default
    # Users can restrict to specific methods via security settings
    allowed_auth_methods: Mapped[List[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: ["password", "google", "github", "cognito"],
    )

    # Password Policy
    password_min_length: Mapped[int] = mapped_column(
        Integer, nullable=False, default=12
    )
    password_require_uppercase: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    password_require_lowercase: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    password_require_number: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    password_require_special: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    # Lockout Policy
    max_failed_login_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=5
    )
    lockout_duration_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30
    )

    # IP Allowlist (null = allow all)
    ip_allowlist: Mapped[Optional[List[str]]] = mapped_column(JSONB, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    organization = relationship("Organization", back_populates="security_settings")

    def is_auth_method_allowed(self, method: str) -> bool:
        """Check if an authentication method is allowed."""
        return method in (self.allowed_auth_methods or ["password"])

    def is_ip_allowed(self, ip_address: str) -> bool:
        """Check if an IP address is allowed."""
        if not self.ip_allowlist:
            return True  # No allowlist = allow all

        import ipaddress

        try:
            client_ip = ipaddress.ip_address(ip_address)
            for allowed in self.ip_allowlist:
                try:
                    # Check if it's a network (CIDR) or single IP
                    if "/" in allowed:
                        network = ipaddress.ip_network(allowed, strict=False)
                        if client_ip in network:
                            return True
                    else:
                        if client_ip == ipaddress.ip_address(allowed):
                            return True
                except ValueError:
                    continue
            return False
        except ValueError:
            return False


class VerifiedDomain(Base):
    """Verified domain model for organization email domains."""

    __tablename__ = "verified_domains"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    domain: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    verification_token: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    verification_method: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # dns_txt, dns_cname, meta_tag

    verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    auto_join_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    sso_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    organization = relationship("Organization", back_populates="verified_domains_rel")

    @property
    def is_verified(self) -> bool:
        """Check if domain is verified."""
        return self.verified_at is not None
