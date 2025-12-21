"""Platform settings service for managing encrypted secrets."""

import hashlib
from datetime import datetime, timezone
from typing import Optional

from cryptography.fernet import Fernet
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.admin import AdminUser
from app.models.platform_settings import (
    PlatformSetting,
    PlatformSettingAudit,
    SettingCategory,
    DEFAULT_SETTINGS,
)

logger = structlog.get_logger()
settings = get_settings()


class PlatformSettingsService:
    """Service for managing platform-wide settings and encrypted secrets.

    Security Features:
    - Fernet encryption for secrets (symmetric, authenticated)
    - All changes are audit logged
    - Secrets are never returned in plaintext via API
    - Only super_admin can modify billing/auth secrets
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(service="PlatformSettingsService")
        self._fernet = self._get_fernet()

    def _get_fernet(self) -> Fernet:
        """Get Fernet instance for encryption/decryption.

        Uses the app's secret key to derive an encryption key.
        In production, this should use AWS KMS or similar.
        """
        # Derive a 32-byte key from the secret key
        key_material = settings.secret_key.get_secret_value().encode()
        # Use SHA256 to get consistent 32 bytes, then base64 encode for Fernet
        import base64

        derived_key = hashlib.sha256(key_material).digest()
        fernet_key = base64.urlsafe_b64encode(derived_key)
        return Fernet(fernet_key)

    def _encrypt(self, value: str) -> bytes:
        """Encrypt a value."""
        return self._fernet.encrypt(value.encode())

    def _decrypt(self, encrypted: bytes) -> str:
        """Decrypt a value."""
        return self._fernet.decrypt(encrypted).decode()

    def _hash_value(self, value: str) -> str:
        """Create a hash of a value for audit logging."""
        return hashlib.sha256(value.encode()).hexdigest()

    async def get_setting(self, key: str) -> Optional[PlatformSetting]:
        """Get a setting by key."""
        result = await self.db.execute(
            select(PlatformSetting).where(PlatformSetting.key == key)
        )
        return result.scalar_one_or_none()

    async def get_setting_value(self, key: str, decrypt: bool = True) -> Optional[str]:
        """Get the value of a setting.

        Args:
            key: The setting key
            decrypt: If True and setting is secret, decrypt the value

        Returns:
            The setting value (decrypted if secret and decrypt=True)
        """
        setting = await self.get_setting(key)
        if not setting:
            return None

        if setting.is_secret:
            if setting.value_encrypted and decrypt:
                try:
                    return self._decrypt(setting.value_encrypted)
                except Exception as e:
                    self.logger.error("decrypt_failed", key=key, error=str(e))
                    return None
            return None
        return setting.value_text

    async def get_settings_by_category(
        self, category: SettingCategory
    ) -> list[PlatformSetting]:
        """Get all settings in a category."""
        result = await self.db.execute(
            select(PlatformSetting).where(PlatformSetting.category == category.value)
        )
        return list(result.scalars().all())

    async def get_all_settings(self) -> list[PlatformSetting]:
        """Get all settings."""
        result = await self.db.execute(
            select(PlatformSetting).order_by(
                PlatformSetting.category, PlatformSetting.key
            )
        )
        return list(result.scalars().all())

    async def set_setting(
        self,
        key: str,
        value: str,
        admin: AdminUser,
        ip_address: Optional[str] = None,
        reason: Optional[str] = None,
        is_secret: bool = False,
        category: str = "general",
        description: Optional[str] = None,
    ) -> PlatformSetting:
        """Set a setting value.

        Creates the setting if it doesn't exist, updates if it does.
        All changes are audit logged.
        """
        setting = await self.get_setting(key)
        action = "update" if setting else "create"
        old_value_hash = None

        if setting:
            # Get old value hash for audit
            if setting.is_secret and setting.value_encrypted:
                try:
                    old_value = self._decrypt(setting.value_encrypted)
                    old_value_hash = self._hash_value(old_value)
                except Exception:
                    pass
            elif setting.value_text:
                old_value_hash = self._hash_value(setting.value_text)

            # Update existing setting
            if is_secret or setting.is_secret:
                setting.value_encrypted = self._encrypt(value)
                setting.value_text = None
            else:
                setting.value_text = value
                setting.value_encrypted = None

            setting.updated_at = datetime.now(timezone.utc)
            setting.updated_by_id = admin.id
            if description:
                setting.description = description
        else:
            # Create new setting
            setting = PlatformSetting(
                key=key,
                is_secret=is_secret,
                category=category,
                description=description,
                updated_by_id=admin.id,
            )
            if is_secret:
                setting.value_encrypted = self._encrypt(value)
            else:
                setting.value_text = value
            self.db.add(setting)

        await self.db.flush()

        # Create audit log
        new_value_hash = self._hash_value(value)
        audit = PlatformSettingAudit(
            setting_id=setting.id,
            setting_key=key,
            action=action,
            old_value_hash=old_value_hash,
            new_value_hash=new_value_hash,
            changed_by_id=admin.id,
            ip_address=ip_address,
            reason=reason,
        )
        self.db.add(audit)

        await self.db.commit()

        self.logger.info(
            "setting_updated",
            key=key,
            action=action,
            admin_id=str(admin.id),
            is_secret=is_secret,
        )

        return setting

    async def delete_setting(
        self,
        key: str,
        admin: AdminUser,
        ip_address: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """Delete a setting."""
        setting = await self.get_setting(key)
        if not setting:
            return False

        # Get old value hash for audit
        old_value_hash = None
        if setting.is_secret and setting.value_encrypted:
            try:
                old_value = self._decrypt(setting.value_encrypted)
                old_value_hash = self._hash_value(old_value)
            except Exception:
                pass
        elif setting.value_text:
            old_value_hash = self._hash_value(setting.value_text)

        # Create audit log before deletion
        audit = PlatformSettingAudit(
            setting_id=setting.id,
            setting_key=key,
            action="delete",
            old_value_hash=old_value_hash,
            new_value_hash=None,
            changed_by_id=admin.id,
            ip_address=ip_address,
            reason=reason,
        )
        self.db.add(audit)

        await self.db.delete(setting)
        await self.db.commit()

        self.logger.info("setting_deleted", key=key, admin_id=str(admin.id))
        return True

    async def get_audit_history(
        self, key: Optional[str] = None, limit: int = 100
    ) -> list[PlatformSettingAudit]:
        """Get audit history for settings."""
        query = select(PlatformSettingAudit).order_by(
            PlatformSettingAudit.changed_at.desc()
        )

        if key:
            query = query.where(PlatformSettingAudit.setting_key == key)

        query = query.limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def seed_default_settings(self, admin: AdminUser) -> int:
        """Seed default settings if they don't exist.

        Returns:
            Number of settings created
        """
        created = 0
        for default in DEFAULT_SETTINGS:
            existing = await self.get_setting(default["key"])
            if not existing:
                setting = PlatformSetting(
                    key=default["key"],
                    is_secret=default.get("is_secret", False),
                    category=default.get("category", "general"),
                    description=default.get("description"),
                    value_text=default.get("value_text"),
                    updated_by_id=admin.id,
                )
                self.db.add(setting)
                created += 1

        if created > 0:
            await self.db.commit()
            self.logger.info("default_settings_seeded", count=created)

        return created

    # Convenience methods for common settings
    async def get_stripe_secret_key(self) -> Optional[str]:
        """Get Stripe secret key (decrypted)."""
        from app.models.platform_settings import SettingKeys

        return await self.get_setting_value(SettingKeys.STRIPE_SECRET_KEY)

    async def get_stripe_publishable_key(self) -> Optional[str]:
        """Get Stripe publishable key."""
        from app.models.platform_settings import SettingKeys

        return await self.get_setting_value(SettingKeys.STRIPE_PUBLISHABLE_KEY)

    async def get_stripe_webhook_secret(self) -> Optional[str]:
        """Get Stripe webhook secret (decrypted)."""
        from app.models.platform_settings import SettingKeys

        return await self.get_setting_value(SettingKeys.STRIPE_WEBHOOK_SECRET)

    async def is_feature_enabled(self, feature_key: str) -> bool:
        """Check if a feature flag is enabled."""
        value = await self.get_setting_value(feature_key)
        return value is not None and value.lower() in ("true", "1", "yes", "enabled")

    async def is_maintenance_mode(self) -> bool:
        """Check if platform is in maintenance mode."""
        from app.models.platform_settings import SettingKeys

        return await self.is_feature_enabled(SettingKeys.PLATFORM_MAINTENANCE_MODE)


def get_platform_settings_service(db: AsyncSession) -> PlatformSettingsService:
    """Get platform settings service instance."""
    return PlatformSettingsService(db)
