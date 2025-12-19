"""Admin user models for platform management.

Security Design:
1. Admin users are separate from regular users (different table)
2. Hardware MFA (WebAuthn) preferred, TOTP as backup
3. IP allowlist enforcement at middleware level
4. Immutable audit logging with hash chain integrity
5. Role-based access with granular permissions
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AdminRole(str, enum.Enum):
    """Admin role hierarchy with different permission levels."""

    SUPER_ADMIN = "super_admin"       # Full access (CEO/CTO only)
    PLATFORM_ADMIN = "platform_admin"  # Operations, no billing
    SECURITY_ADMIN = "security_admin"  # Security events only
    SUPPORT_ADMIN = "support_admin"    # Read-only, impersonation
    BILLING_ADMIN = "billing_admin"    # Billing only
    READONLY_ADMIN = "readonly_admin"  # Dashboards only


class ApprovalStatus(str, enum.Enum):
    """Status of admin approval requests."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class IncidentSeverity(str, enum.Enum):
    """Severity level for security incidents."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, enum.Enum):
    """Status of security incidents."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# Permission matrix for admin roles
ADMIN_PERMISSIONS = {
    AdminRole.SUPER_ADMIN: ["*"],  # All permissions

    AdminRole.PLATFORM_ADMIN: [
        "org:read", "org:update", "org:suspend",
        "user:read", "user:disable",
        "metrics:read",
        "audit:read",
        "system:health",
    ],

    AdminRole.SECURITY_ADMIN: [
        "audit:read", "audit:export",
        "security:incidents",
        "user:disable",  # Emergency response
        "org:suspend",   # Emergency response
        "metrics:security",
    ],

    AdminRole.SUPPORT_ADMIN: [
        "org:read",
        "user:read",
        "user:impersonate",  # With additional controls
        "audit:read:own",    # Only their actions
    ],

    AdminRole.BILLING_ADMIN: [
        "billing:read", "billing:update",
        "subscription:read", "subscription:update",
        "invoice:read", "invoice:generate",
    ],

    AdminRole.READONLY_ADMIN: [
        "metrics:read",
        "org:read",
        "system:health",
    ],
}

# Actions requiring additional verification
SENSITIVE_ACTIONS = {
    # Action: (requires_reauth, requires_approval, max_per_day)
    "org:delete": (True, True, 1),        # Needs 2nd admin approval
    "user:delete": (True, True, 5),       # Needs 2nd admin approval
    "org:suspend": (True, False, 10),     # Re-auth only
    "user:impersonate": (True, False, 5), # Time-limited (30 min)
    "export:all_data": (True, True, 1),   # Needs approval
    "admin:create": (True, True, 1),      # Super admin only + approval
    "admin:delete": (True, True, 1),      # Super admin only + approval
    "billing:refund": (True, False, 10),  # Re-auth only
}


def has_permission(role: AdminRole, permission: str) -> bool:
    """Check if a role has a specific permission."""
    role_permissions = ADMIN_PERMISSIONS.get(role, [])

    # Super admin has all permissions
    if "*" in role_permissions:
        return True

    # Check exact match
    if permission in role_permissions:
        return True

    # Check wildcard patterns (e.g., "org:*" matches "org:read")
    for perm in role_permissions:
        if perm.endswith(":*"):
            prefix = perm[:-1]  # Remove "*"
            if permission.startswith(prefix):
                return True

    return False


class AdminUser(Base):
    """Admin user account for platform management.

    Separate from regular users for security isolation.
    """

    __tablename__ = "admin_users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[AdminRole] = mapped_column(
        SQLEnum(
            AdminRole,
            name="admin_role",
            create_type=False,
            values_callable=lambda x: [e.value for e in x]
        ),
        nullable=False,
        default=AdminRole.READONLY_ADMIN
    )

    # Profile
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # MFA - TOTP secret encrypted with KMS
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret_encrypted: Mapped[Optional[bytes]] = mapped_column(nullable=True)

    # WebAuthn credentials (array of credential IDs)
    webauthn_credentials: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=list, nullable=True
    )

    # Security status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    requires_password_change: Mapped[bool] = mapped_column(Boolean, default=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("admin_users.id"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_password_change: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    created_by = relationship("AdminUser", remote_side=[id], foreign_keys=[created_by_id])
    sessions = relationship("AdminSession", back_populates="admin", cascade="all, delete-orphan")

    @property
    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until

    @property
    def permissions(self) -> list[str]:
        """Get list of permissions for this admin."""
        return ADMIN_PERMISSIONS.get(self.role, [])

    def has_permission(self, permission: str) -> bool:
        """Check if admin has a specific permission."""
        return has_permission(self.role, permission)

    def __repr__(self) -> str:
        return f"<AdminUser {self.email} role={self.role.value}>"


class AdminSession(Base):
    """Admin session with context binding for security."""

    __tablename__ = "admin_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    admin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Session context (for binding)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # IPv6 max length
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    device_fingerprint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    geo_location: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Tokens
    refresh_token_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Timing
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Last authentication (for re-auth checks)
    last_auth_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    terminated_reason: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # 'logout', 'expired', 'superseded', 'admin_action'

    # Relationships
    admin = relationship("AdminUser", back_populates="sessions")

    @property
    def is_valid(self) -> bool:
        """Check if session is still valid."""
        if not self.is_active:
            return False
        return datetime.now(timezone.utc) < self.expires_at

    def __repr__(self) -> str:
        return f"<AdminSession {self.id} admin={self.admin_id}>"


class AdminAuditLog(Base):
    """Immutable audit log for admin actions.

    Uses hash chain for integrity verification.
    """

    __tablename__ = "admin_audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Who
    admin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.id"),
        nullable=False,
        index=True
    )
    admin_email: Mapped[str] = mapped_column(String(255), nullable=False)  # Denormalized
    admin_role: Mapped[AdminRole] = mapped_column(
        SQLEnum(
            AdminRole,
            name="admin_role",
            create_type=False,
            values_callable=lambda x: [e.value for e in x]
        ),
        nullable=False
    )

    # What
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    resource_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Context
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    device_fingerprint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    geo_location: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # Request
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, default=uuid.uuid4
    )
    request_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    request_method: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    request_body_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # SHA-256

    # Response
    response_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Additional context
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approval_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    impersonating_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # Timing
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )

    # Integrity
    log_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    previous_log_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    def __repr__(self) -> str:
        return f"<AdminAuditLog {self.action} by {self.admin_email}>"


class AdminApprovalRequest(Base):
    """Approval requests for sensitive admin actions."""

    __tablename__ = "admin_approval_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Requestor
    requestor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.id"),
        nullable=False,
        index=True
    )

    # Action details
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    # Status
    status: Mapped[ApprovalStatus] = mapped_column(
        SQLEnum(
            ApprovalStatus,
            name="approval_status",
            create_type=False,
            values_callable=lambda x: [e.value for e in x]
        ),
        nullable=False,
        default=ApprovalStatus.PENDING
    )

    # Approver
    approver_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.id"),
        nullable=True
    )
    approver_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timing
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    requestor = relationship("AdminUser", foreign_keys=[requestor_id])
    approver = relationship("AdminUser", foreign_keys=[approver_id])

    @property
    def is_expired(self) -> bool:
        """Check if request has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    def __repr__(self) -> str:
        return f"<AdminApprovalRequest {self.action} status={self.status.value}>"


class AdminImpersonationSession(Base):
    """Track admin impersonation of users."""

    __tablename__ = "admin_impersonation_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    admin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.id"),
        nullable=False,
        index=True
    )
    admin_session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_sessions.id"),
        nullable=False
    )

    # Target
    target_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False
    )
    target_org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False
    )

    # Audit
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    ended_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    max_duration_minutes: Mapped[int] = mapped_column(Integer, default=30)

    # Actions taken during impersonation
    actions_log: Mapped[Optional[dict]] = mapped_column(JSONB, default=list, nullable=True)

    # Relationships
    admin = relationship("AdminUser")
    admin_session = relationship("AdminSession")

    @property
    def is_active(self) -> bool:
        """Check if impersonation is still active."""
        if self.ended_at:
            return False
        max_end = self.started_at.replace(
            tzinfo=timezone.utc
        ) + timezone.timedelta(minutes=self.max_duration_minutes)
        return datetime.now(timezone.utc) < max_end

    def __repr__(self) -> str:
        return f"<AdminImpersonation admin={self.admin_id} user={self.target_user_id}>"


class SecurityIncident(Base):
    """Security incidents detected by the platform."""

    __tablename__ = "security_incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Classification
    severity: Mapped[IncidentSeverity] = mapped_column(
        SQLEnum(
            IncidentSeverity,
            name="incident_severity",
            create_type=False,
            values_callable=lambda x: [e.value for e in x]
        ),
        nullable=False,
        index=True
    )
    incident_type: Mapped[str] = mapped_column(String(100), nullable=False)

    # Affected entities
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=True,
        index=True
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )

    # Details
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Auto-actions
    auto_actions_taken: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=list, nullable=True
    )

    # Status
    status: Mapped[IncidentStatus] = mapped_column(
        SQLEnum(
            IncidentStatus,
            name="incident_status",
            create_type=False,
            values_callable=lambda x: [e.value for e in x]
        ),
        nullable=False,
        default=IncidentStatus.OPEN,
        index=True
    )

    # Handling
    assigned_to_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.id"),
        nullable=True
    )
    resolved_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.id"),
        nullable=True
    )
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timing
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    assigned_to = relationship("AdminUser", foreign_keys=[assigned_to_id])
    resolved_by = relationship("AdminUser", foreign_keys=[resolved_by_id])

    def __repr__(self) -> str:
        return f"<SecurityIncident {self.incident_type} severity={self.severity.value}>"


class AdminIPAllowlist(Base):
    """IP allowlist for admin portal access."""

    __tablename__ = "admin_ip_allowlist"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # IP can be single address or CIDR
    ip_address: Mapped[str] = mapped_column(String(43), unique=True, nullable=False)  # CIDR max
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Audit
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.id"),
        nullable=True
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )  # NULL = never expires

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationships
    created_by = relationship("AdminUser")

    @property
    def is_valid(self) -> bool:
        """Check if IP is currently valid (active and not expired)."""
        if not self.is_active:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    def __repr__(self) -> str:
        return f"<AdminIPAllowlist {self.ip_address}>"
