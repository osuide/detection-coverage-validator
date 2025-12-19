"""Platform settings models for encrypted secrets and configuration."""

import enum
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class SettingCategory(str, enum.Enum):
    """Categories for platform settings."""
    BILLING = "billing"  # Stripe, payment processors
    AUTH = "auth"  # OAuth secrets, SSO config
    EMAIL = "email"  # SMTP, email service providers
    CLOUD = "cloud"  # AWS, GCP service account keys
    FEATURE = "feature"  # Feature flags
    GENERAL = "general"  # Other settings


class PlatformSetting(Base):
    """Platform-wide settings including encrypted secrets.

    Security:
    - Secrets are encrypted at rest using Fernet (app-level) or KMS
    - Only super_admin can modify billing/auth secrets
    - All changes are audit logged
    - Secrets are never returned in API responses (only masked hints)
    """
    __tablename__ = "platform_settings"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)

    # For secrets - encrypted value
    value_encrypted: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    # For non-secret values - plain text
    value_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Metadata
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False, default="general")

    # Audit
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_by_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("admin_users.id"), nullable=True
    )

    __table_args__ = (
        Index("ix_platform_settings_key", "key"),
        Index("ix_platform_settings_category", "category"),
    )

    @property
    def masked_value(self) -> Optional[str]:
        """Return masked value for secrets, full value for non-secrets."""
        if self.is_secret:
            if self.value_encrypted:
                return "••••••••••••" + " (encrypted)"
            return None
        return self.value_text


class PlatformSettingAudit(Base):
    """Audit log for platform setting changes.

    Tracks all modifications to platform settings for compliance.
    """
    __tablename__ = "platform_settings_audit"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    setting_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("platform_settings.id"), nullable=False
    )
    setting_key: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(20), nullable=False)  # create, update, delete

    # Hash of values (not actual values) for verification
    old_value_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    new_value_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    changed_by_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("admin_users.id"), nullable=False
    )
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_platform_settings_audit_setting", "setting_id"),
        Index("ix_platform_settings_audit_changed_at", "changed_at"),
    )


# Well-known setting keys
class SettingKeys:
    """Well-known platform setting keys."""
    # Stripe
    STRIPE_SECRET_KEY = "stripe_secret_key"
    STRIPE_PUBLISHABLE_KEY = "stripe_publishable_key"
    STRIPE_WEBHOOK_SECRET = "stripe_webhook_secret"

    # OAuth (these supplement Cognito)
    GOOGLE_CLIENT_ID = "google_client_id"
    GOOGLE_CLIENT_SECRET = "google_client_secret"
    GITHUB_CLIENT_ID = "github_client_id"
    GITHUB_CLIENT_SECRET = "github_client_secret"
    MICROSOFT_CLIENT_ID = "microsoft_client_id"
    MICROSOFT_CLIENT_SECRET = "microsoft_client_secret"

    # Email
    SMTP_HOST = "smtp_host"
    SMTP_PORT = "smtp_port"
    SMTP_USERNAME = "smtp_username"
    SMTP_PASSWORD = "smtp_password"

    # Feature Flags
    FEATURE_CODE_ANALYSIS = "feature_code_analysis"
    FEATURE_SCHEDULED_SCANS = "feature_scheduled_scans"
    FEATURE_API_ACCESS = "feature_api_access"

    # Platform
    PLATFORM_MAINTENANCE_MODE = "platform_maintenance_mode"
    PLATFORM_SIGNUP_ENABLED = "platform_signup_enabled"


# Default settings to seed
DEFAULT_SETTINGS = [
    {
        "key": SettingKeys.STRIPE_SECRET_KEY,
        "is_secret": True,
        "category": SettingCategory.BILLING.value,
        "description": "Stripe Secret API Key (sk_live_... or sk_test_...)",
    },
    {
        "key": SettingKeys.STRIPE_PUBLISHABLE_KEY,
        "is_secret": False,
        "category": SettingCategory.BILLING.value,
        "description": "Stripe Publishable Key (pk_live_... or pk_test_...)",
    },
    {
        "key": SettingKeys.STRIPE_WEBHOOK_SECRET,
        "is_secret": True,
        "category": SettingCategory.BILLING.value,
        "description": "Stripe Webhook Signing Secret (whsec_...)",
    },
    {
        "key": SettingKeys.FEATURE_CODE_ANALYSIS,
        "is_secret": False,
        "category": SettingCategory.FEATURE.value,
        "description": "Enable code analysis feature",
        "value_text": "true",
    },
    {
        "key": SettingKeys.FEATURE_SCHEDULED_SCANS,
        "is_secret": False,
        "category": SettingCategory.FEATURE.value,
        "description": "Enable scheduled scans feature",
        "value_text": "true",
    },
    {
        "key": SettingKeys.PLATFORM_SIGNUP_ENABLED,
        "is_secret": False,
        "category": SettingCategory.GENERAL.value,
        "description": "Allow new user signups",
        "value_text": "true",
    },
    {
        "key": SettingKeys.PLATFORM_MAINTENANCE_MODE,
        "is_secret": False,
        "category": SettingCategory.GENERAL.value,
        "description": "Platform maintenance mode (disables access)",
        "value_text": "false",
    },
]
