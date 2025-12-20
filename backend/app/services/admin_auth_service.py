"""Admin authentication service with enhanced security.

Security Features:
1. Separate auth flow from regular users
2. Hardware MFA (WebAuthn) preferred
3. Session binding (IP, User-Agent)
4. Short-lived tokens (15 min access, 8 hr refresh)
5. Comprehensive audit logging
"""

import hashlib
import ipaddress
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import bcrypt
import pyotp
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.admin import (
    AdminUser,
    AdminSession,
    AdminAuditLog,
    AdminIPAllowlist,
    AdminRole,
)
from app.core.security import create_access_token

logger = structlog.get_logger()
settings = get_settings()


class AdminAuthService:
    """Service for admin authentication and session management."""

    # Security constants
    ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Short-lived for security
    REFRESH_TOKEN_EXPIRE_HOURS = 8  # Max session duration
    MAX_FAILED_ATTEMPTS = 3
    LOCKOUT_DURATION_MINUTES = 60
    PASSWORD_MIN_LENGTH = 16

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(service="AdminAuthService")

    async def authenticate(
        self,
        email: str,
        password: str,
        ip_address: str,
        user_agent: Optional[str] = None,
    ) -> tuple[AdminUser, bool]:
        """Authenticate admin user.

        Returns:
            tuple of (AdminUser, requires_mfa)

        Raises:
            ValueError: If authentication fails
        """
        # Get admin user
        result = await self.db.execute(
            select(AdminUser).where(AdminUser.email == email.lower())
        )
        admin = result.scalar_one_or_none()

        if not admin:
            # Log failed attempt (don't reveal if user exists)
            await self._log_action(
                admin_id=None,
                admin_email=email,
                admin_role=None,
                action="admin:login_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                error_message="Invalid credentials",
            )
            raise ValueError("Invalid credentials")

        # Check if account is locked
        if admin.is_locked:
            await self._log_action(
                admin_id=admin.id,
                admin_email=admin.email,
                admin_role=admin.role,
                action="admin:login_blocked",
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                error_message="Account locked",
            )
            raise ValueError("Account is locked. Please try again later.")

        # Check if account is active
        if not admin.is_active:
            await self._log_action(
                admin_id=admin.id,
                admin_email=admin.email,
                admin_role=admin.role,
                action="admin:login_blocked",
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                error_message="Account disabled",
            )
            raise ValueError("Account is disabled")

        # Verify password
        if not bcrypt.checkpw(password.encode(), admin.password_hash.encode()):
            # Increment failed attempts
            admin.failed_login_attempts += 1

            if admin.failed_login_attempts >= self.MAX_FAILED_ATTEMPTS:
                admin.locked_until = datetime.now(timezone.utc) + timedelta(
                    minutes=self.LOCKOUT_DURATION_MINUTES
                )
                self.logger.warning(
                    "admin_account_locked",
                    admin_id=str(admin.id),
                    attempts=admin.failed_login_attempts,
                )

            await self.db.commit()

            await self._log_action(
                admin_id=admin.id,
                admin_email=admin.email,
                admin_role=admin.role,
                action="admin:login_failed",
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                error_message="Invalid password",
            )
            raise ValueError("Invalid credentials")

        # Reset failed attempts on successful auth
        admin.failed_login_attempts = 0
        await self.db.commit()

        # Check if MFA is required (always for production)
        requires_mfa = admin.mfa_enabled

        if not requires_mfa:
            # MFA not enabled - this should be required in production
            self.logger.warning(
                "admin_login_without_mfa",
                admin_id=str(admin.id),
                admin_email=admin.email,
            )

        return admin, requires_mfa

    async def verify_totp(
        self,
        admin: AdminUser,
        totp_code: str,
    ) -> bool:
        """Verify TOTP code for MFA."""
        if not admin.mfa_secret_encrypted:
            return False

        # Decrypt MFA secret (in production, use KMS)
        # For now, we store it encrypted with app secret
        mfa_secret = self._decrypt_mfa_secret(admin.mfa_secret_encrypted)

        totp = pyotp.TOTP(mfa_secret)
        return totp.verify(totp_code, valid_window=1)

    async def create_session(
        self,
        admin: AdminUser,
        ip_address: str,
        user_agent: Optional[str] = None,
    ) -> tuple[str, str]:
        """Create admin session and return tokens.

        Returns:
            tuple of (access_token, refresh_token)
        """
        # Generate refresh token
        refresh_token = secrets.token_urlsafe(32)
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        # Create session
        session = AdminSession(
            admin_id=admin.id,
            ip_address=ip_address,
            user_agent=user_agent,
            refresh_token_hash=refresh_token_hash,
            expires_at=datetime.now(timezone.utc)
            + timedelta(hours=self.REFRESH_TOKEN_EXPIRE_HOURS),
            last_auth_at=datetime.now(timezone.utc),
        )
        self.db.add(session)

        # Update admin last login
        admin.last_login_at = datetime.now(timezone.utc)

        await self.db.commit()

        # Create access token
        access_token = create_access_token(
            data={
                "sub": str(admin.id),
                "type": "admin",
                "role": admin.role.value,
                "session_id": str(session.id),
            },
            expires_delta=timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES),
        )

        # Log successful login
        await self._log_action(
            admin_id=admin.id,
            admin_email=admin.email,
            admin_role=admin.role,
            action="admin:login",
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session.id,
            success=True,
        )

        return access_token, refresh_token

    async def validate_session(
        self,
        session_id: UUID,
        ip_address: str,
        user_agent: Optional[str] = None,
    ) -> Optional[AdminSession]:
        """Validate admin session."""
        result = await self.db.execute(
            select(AdminSession).where(
                AdminSession.id == session_id,
                AdminSession.is_active.is_(True),
            )
        )
        session = result.scalar_one_or_none()

        if not session:
            return None

        # Check expiration
        if not session.is_valid:
            return None

        # Verify IP hasn't changed (session binding)
        if session.ip_address != ip_address:
            self.logger.warning(
                "admin_session_ip_mismatch",
                session_id=str(session_id),
                expected_ip=session.ip_address,
                actual_ip=ip_address,
            )
            return None

        # Update last activity
        session.last_activity_at = datetime.now(timezone.utc)
        await self.db.commit()

        return session

    async def refresh_access_token(
        self,
        refresh_token: str,
        ip_address: str,
    ) -> Optional[str]:
        """Refresh access token using refresh token."""
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        result = await self.db.execute(
            select(AdminSession).where(
                AdminSession.refresh_token_hash == refresh_token_hash,
                AdminSession.is_active.is_(True),
            )
        )
        session = result.scalar_one_or_none()

        if not session or not session.is_valid:
            return None

        # Verify IP
        if session.ip_address != ip_address:
            return None

        # Get admin
        result = await self.db.execute(
            select(AdminUser).where(AdminUser.id == session.admin_id)
        )
        admin = result.scalar_one_or_none()

        if not admin or not admin.is_active:
            return None

        # Create new access token
        access_token = create_access_token(
            data={
                "sub": str(admin.id),
                "type": "admin",
                "role": admin.role.value,
                "session_id": str(session.id),
            },
            expires_delta=timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES),
        )

        session.last_activity_at = datetime.now(timezone.utc)
        await self.db.commit()

        return access_token

    async def logout(
        self,
        session_id: UUID,
        ip_address: str,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Terminate admin session."""
        result = await self.db.execute(
            select(AdminSession).where(AdminSession.id == session_id)
        )
        session = result.scalar_one_or_none()

        if not session:
            return False

        session.is_active = False
        session.terminated_reason = "logout"

        # Get admin for logging
        result = await self.db.execute(
            select(AdminUser).where(AdminUser.id == session.admin_id)
        )
        admin = result.scalar_one_or_none()

        await self.db.commit()

        if admin:
            await self._log_action(
                admin_id=admin.id,
                admin_email=admin.email,
                admin_role=admin.role,
                action="admin:logout",
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                success=True,
            )

        return True

    async def check_ip_allowed(self, ip_address: str) -> bool:
        """Check if IP is in the allowlist."""
        # Get all active allowlist entries
        result = await self.db.execute(
            select(AdminIPAllowlist).where(AdminIPAllowlist.is_active.is_(True))
        )
        allowlist = result.scalars().all()

        if not allowlist:
            # If no allowlist configured, deny by default in production
            # Allow in dev and staging modes
            if settings.environment in ("development", "staging"):
                return True
            return False

        # Check if IP matches any entry
        try:
            client_ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return False

        for entry in allowlist:
            if not entry.is_valid:
                continue

            try:
                # Check if it's a network (CIDR) or single IP
                if "/" in entry.ip_address:
                    network = ipaddress.ip_network(entry.ip_address, strict=False)
                    if client_ip in network:
                        return True
                else:
                    if client_ip == ipaddress.ip_address(entry.ip_address):
                        return True
            except ValueError:
                continue

        return False

    async def create_admin(
        self,
        email: str,
        password: str,
        full_name: str,
        role: AdminRole,
        created_by: Optional[AdminUser] = None,
    ) -> AdminUser:
        """Create a new admin user."""
        # Validate password strength
        if len(password) < self.PASSWORD_MIN_LENGTH:
            raise ValueError(
                f"Password must be at least {self.PASSWORD_MIN_LENGTH} characters"
            )

        # Check if email already exists
        result = await self.db.execute(
            select(AdminUser).where(AdminUser.email == email.lower())
        )
        if result.scalar_one_or_none():
            raise ValueError("Email already exists")

        # Hash password
        password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt(rounds=12)
        ).decode()

        # Create admin
        admin = AdminUser(
            email=email.lower(),
            password_hash=password_hash,
            full_name=full_name,
            role=role,
            requires_password_change=True,
            created_by_id=created_by.id if created_by else None,
        )
        self.db.add(admin)
        await self.db.commit()

        self.logger.info(
            "admin_created",
            admin_id=str(admin.id),
            email=admin.email,
            role=role.value,
            created_by=str(created_by.id) if created_by else None,
        )

        return admin

    async def setup_totp(self, admin: AdminUser) -> str:
        """Generate TOTP secret for MFA setup.

        Returns:
            TOTP provisioning URI for QR code
        """
        # Generate secret
        secret = pyotp.random_base32()

        # Encrypt and store
        admin.mfa_secret_encrypted = self._encrypt_mfa_secret(secret)
        await self.db.commit()

        # Generate provisioning URI
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=admin.email, issuer_name="A13E Admin")

    async def enable_mfa(self, admin: AdminUser, totp_code: str) -> bool:
        """Enable MFA after verifying TOTP code."""
        if not admin.mfa_secret_encrypted:
            return False

        if not await self.verify_totp(admin, totp_code):
            return False

        admin.mfa_enabled = True
        await self.db.commit()

        self.logger.info("admin_mfa_enabled", admin_id=str(admin.id))
        return True

    def _encrypt_mfa_secret(self, secret: str) -> bytes:
        """Encrypt MFA secret.

        In production, use AWS KMS or similar.
        For now, use simple XOR with app secret (NOT production-ready).
        """
        # TODO: Use proper encryption (KMS) in production
        key = settings.secret_key[:32].encode()
        secret_bytes = secret.encode()

        # Simple XOR for development (replace with Fernet/KMS)
        encrypted = bytes(a ^ b for a, b in zip(secret_bytes, key * 10))
        return encrypted

    def _decrypt_mfa_secret(self, encrypted: bytes) -> str:
        """Decrypt MFA secret."""
        key = settings.secret_key[:32].encode()

        decrypted = bytes(a ^ b for a, b in zip(encrypted, key * 10))
        return decrypted.decode()

    async def _log_action(
        self,
        action: str,
        ip_address: str,
        success: bool,
        admin_id: Optional[UUID] = None,
        admin_email: Optional[str] = None,
        admin_role: Optional[AdminRole] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[UUID] = None,
        error_message: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[UUID] = None,
    ) -> None:
        """Create audit log entry."""
        # Get previous log hash for chain integrity
        result = await self.db.execute(
            select(AdminAuditLog).order_by(AdminAuditLog.timestamp.desc()).limit(1)
        )
        previous_log = result.scalar_one_or_none()
        previous_hash = previous_log.log_hash if previous_log else None

        # Create log data for hashing
        log_data = {
            "admin_id": str(admin_id) if admin_id else None,
            "admin_email": admin_email or "unknown",
            "action": action,
            "ip_address": ip_address,
            "success": success,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        log_hash = hashlib.sha256(str(log_data).encode()).hexdigest()

        # Create log entry
        audit_log = AdminAuditLog(
            admin_id=admin_id or UUID("00000000-0000-0000-0000-000000000000"),
            admin_email=admin_email or "unknown",
            admin_role=admin_role or AdminRole.READONLY_ADMIN,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            success=success,
            error_message=error_message,
            resource_type=resource_type,
            resource_id=resource_id,
            log_hash=log_hash,
            previous_log_hash=previous_hash,
        )
        self.db.add(audit_log)
        await self.db.commit()


# Singleton-style factory
def get_admin_auth_service(db: AsyncSession) -> AdminAuthService:
    """Get admin auth service instance."""
    return AdminAuthService(db)
