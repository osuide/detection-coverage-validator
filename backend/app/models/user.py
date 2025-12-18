"""User and authentication models."""

import uuid
import enum
import secrets
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import String, DateTime, Boolean, Text, Integer, ForeignKey, Index, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class UserRole(str, enum.Enum):
    """User roles within an organization."""
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class MembershipStatus(str, enum.Enum):
    """Status of organization membership."""
    ACTIVE = "active"
    PENDING = "pending"
    SUSPENDED = "suspended"
    REMOVED = "removed"


class User(Base):
    """User account."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Email verification
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verification_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    email_verification_sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # MFA
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mfa_backup_codes: Mapped[Optional[List[str]]] = mapped_column(JSONB, nullable=True)

    # OAuth
    oauth_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    oauth_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Profile
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    timezone: Mapped[str] = mapped_column(String(50), default="UTC")

    # Password reset
    password_reset_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password_reset_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Account status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    memberships = relationship(
        "OrganizationMember",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="[OrganizationMember.user_id]"
    )
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_users_oauth", "oauth_provider", "oauth_id"),
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"


class Organization(Base):
    """Organization (tenant)."""

    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)

    # Settings
    logo_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    primary_domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    verified_domains: Mapped[Optional[List[str]]] = mapped_column(JSONB, default=list)

    # Security policies
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_auth_methods: Mapped[List[str]] = mapped_column(JSONB, default=["email_password"])
    session_timeout_minutes: Mapped[int] = mapped_column(Integer, default=1440)  # 24 hours

    # SSO Configuration
    sso_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    sso_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    sso_config: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Subscription
    plan: Mapped[str] = mapped_column(String(50), default="free")
    plan_seats: Mapped[int] = mapped_column(Integer, default=5)
    trial_ends_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    cloud_accounts = relationship("CloudAccount", back_populates="organization")
    api_keys = relationship("APIKey", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Organization {self.name} ({self.slug})>"


class OrganizationMember(Base):
    """Organization membership (links users to organizations)."""

    __tablename__ = "organization_members"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )

    # For pending invitations
    invited_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    invite_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    invite_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    invited_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    invited_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Role and status
    role: Mapped[UserRole] = mapped_column(
        SQLEnum(UserRole, values_callable=lambda x: [e.value for e in x], name='userrole', create_type=False),
        default=UserRole.MEMBER
    )
    status: Mapped[MembershipStatus] = mapped_column(
        SQLEnum(MembershipStatus, values_callable=lambda x: [e.value for e in x], name='membershipstatus', create_type=False),
        default=MembershipStatus.PENDING
    )

    # Cloud account access (for member/viewer roles)
    # If null, has access to all accounts; otherwise, only these account IDs
    allowed_account_ids: Mapped[Optional[List[str]]] = mapped_column(JSONB, nullable=True)

    # Timestamps
    joined_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    organization = relationship("Organization", back_populates="members")
    user = relationship("User", back_populates="memberships", foreign_keys=[user_id])
    invited_by_user = relationship("User", foreign_keys=[invited_by])

    __table_args__ = (
        Index("ix_org_members_org_user", "organization_id", "user_id", unique=True),
        Index("ix_org_members_invite_token", "invite_token"),
    )

    def __repr__(self) -> str:
        if self.user_id:
            return f"<OrganizationMember user={self.user_id} org={self.organization_id} role={self.role.value}>"
        return f"<OrganizationMember invite={self.invite_email} org={self.organization_id}>"


class UserSession(Base):
    """User session for tracking active sessions."""

    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True
    )

    # Token
    refresh_token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    # Session metadata
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    device_info: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    user = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index("ix_sessions_user_active", "user_id", "is_active"),
        Index("ix_sessions_expires", "expires_at"),
    )

    def __repr__(self) -> str:
        return f"<UserSession user={self.user_id} active={self.is_active}>"


class APIKey(Base):
    """API key for programmatic access."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    created_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Key details
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False)  # e.g., "dcv_live_abc123"
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    # Permissions
    scopes: Mapped[List[str]] = mapped_column(JSONB, default=list)  # e.g., ["read:accounts", "write:scans"]

    # Restrictions
    ip_allowlist: Mapped[Optional[List[str]]] = mapped_column(JSONB, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Usage tracking
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    usage_count: Mapped[int] = mapped_column(Integer, default=0)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    organization = relationship("Organization", back_populates="api_keys")
    created_by = relationship("User", foreign_keys=[created_by_id])
    revoked_by = relationship("User", foreign_keys=[revoked_by_id])

    __table_args__ = (
        Index("ix_api_keys_org", "organization_id"),
        Index("ix_api_keys_prefix", "key_prefix"),
    )

    @staticmethod
    def generate_key() -> tuple[str, str]:
        """Generate a new API key. Returns (full_key, prefix)."""
        prefix = f"dcv_live_{secrets.token_hex(4)}"
        secret = secrets.token_hex(24)
        full_key = f"{prefix}_{secret}"
        return full_key, prefix

    def __repr__(self) -> str:
        return f"<APIKey {self.name} ({self.key_prefix}...)>"


class AuditLogAction(str, enum.Enum):
    """Types of audit log actions."""
    # Auth
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_LOGIN_FAILED = "user.login_failed"
    USER_MFA_ENABLED = "user.mfa_enabled"
    USER_MFA_DISABLED = "user.mfa_disabled"
    USER_PASSWORD_CHANGED = "user.password_changed"
    USER_PASSWORD_RESET = "user.password_reset"

    # User management
    USER_INVITE = "user.invite"
    USER_INVITE_ACCEPTED = "user.invite_accepted"
    USER_ROLE_CHANGED = "user.role_changed"
    USER_REMOVED = "user.removed"
    USER_SUSPENDED = "user.suspended"

    # Member management
    MEMBER_INVITED = "member.invited"
    MEMBER_JOINED = "member.joined"
    MEMBER_ROLE_CHANGED = "member.role_changed"
    MEMBER_REMOVED = "member.removed"

    # Organization
    ORG_CREATED = "org.created"
    ORG_SETTINGS_UPDATED = "org.settings_updated"
    ORG_SSO_CONFIGURED = "org.sso_configured"

    # API Keys
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"

    # Cloud Accounts
    ACCOUNT_CREATED = "account.created"
    ACCOUNT_UPDATED = "account.updated"
    ACCOUNT_DELETED = "account.deleted"
    ACCOUNT_CREDENTIALS_UPDATED = "account.credentials_updated"

    # Scans
    SCAN_TRIGGERED = "scan.triggered"
    SCAN_COMPLETED = "scan.completed"

    # Detections
    DETECTION_MAPPING_UPDATED = "detection.mapping_updated"


class AuditLog(Base):
    """Audit log for tracking all significant actions."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Action details
    action: Mapped[AuditLogAction] = mapped_column(
        SQLEnum(AuditLogAction, values_callable=lambda x: [e.value for e in x], name='auditlogaction', create_type=False),
        nullable=False
    )
    resource_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Context
    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Result
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    # Relationships
    organization = relationship("Organization", back_populates="audit_logs")
    user = relationship("User")

    __table_args__ = (
        Index("ix_audit_logs_org_created", "organization_id", "created_at"),
        Index("ix_audit_logs_user", "user_id"),
        Index("ix_audit_logs_action", "action"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog {self.action.value} by user={self.user_id}>"
