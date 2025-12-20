"""Authentication service for user management and JWT handling."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from uuid import UUID

import bcrypt
import jwt
import pyotp
import structlog
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.user import (
    User,
    Organization,
    OrganizationMember,
    UserSession,
    UserRole,
    MembershipStatus,
    AuditLog,
    AuditLogAction,
)

logger = structlog.get_logger()
settings = get_settings()


class AuthService:
    """Service for authentication operations."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(service="AuthService")

    # Password hashing
    # BCrypt rounds: 12 provides good security (~250ms on modern hardware).
    # Consider increasing to 13 (500ms) if auth latency allows.
    # Make this configurable via settings if needed for tuning.
    BCRYPT_ROUNDS = 12

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt(rounds=AuthService.BCRYPT_ROUNDS)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify a password against a hash."""
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))

    # Token generation
    @staticmethod
    def hash_token(token: str) -> str:
        """Hash a token for storage.

        Security Note: Uses SHA-256 (fast hash) which is acceptable for API keys
        and refresh tokens because they are generated with secrets.token_urlsafe(48),
        providing ~288 bits of entropy. This makes brute force attacks computationally
        infeasible even with fast hashing. Slow hashes like bcrypt are reserved for
        user passwords which have lower entropy.
        """
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def generate_access_token(
        user_id: UUID,
        organization_id: Optional[UUID] = None,
        expires_minutes: Optional[int] = None,
    ) -> str:
        """Generate a JWT access token."""
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=expires_minutes or settings.access_token_expire_minutes
        )
        payload = {
            "sub": str(user_id),
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access",
        }
        if organization_id:
            payload["org"] = str(organization_id)

        return jwt.encode(payload, settings.secret_key, algorithm="HS256")

    @staticmethod
    def generate_refresh_token() -> str:
        """Generate a random refresh token."""
        return secrets.token_urlsafe(48)

    @staticmethod
    def decode_token(token: str) -> Optional[dict]:
        """Decode and validate a JWT token."""
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    # MFA
    @staticmethod
    def generate_mfa_secret() -> str:
        """Generate a new MFA secret."""
        return pyotp.random_base32()

    @staticmethod
    def get_mfa_provisioning_uri(secret: str, email: str) -> str:
        """Get the provisioning URI for MFA setup."""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=email, issuer_name="Detection Coverage Validator"
        )

    @staticmethod
    def verify_mfa_code(secret: str, code: str) -> bool:
        """Verify a TOTP MFA code."""
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    @staticmethod
    def generate_backup_codes(count: int = 10) -> tuple[list[str], list[str]]:
        """Generate MFA backup codes.

        Returns:
            Tuple of (display_codes, hashed_codes).
            display_codes: Show to user ONCE for saving.
            hashed_codes: Store in database (bcrypt hashed).
        """
        display_codes = []
        hashed_codes = []
        for _ in range(count):
            code = f"{secrets.token_hex(2)}-{secrets.token_hex(2)}"
            display_codes.append(code)
            # Hash backup codes like passwords for security
            hashed_codes.append(AuthService.hash_password(code))
        return display_codes, hashed_codes

    @staticmethod
    def verify_backup_code(code: str, hashed_codes: list[str]) -> tuple[bool, int]:
        """Verify a backup code against hashed codes.

        Returns:
            Tuple of (is_valid, index). Index is the position of the matched code,
            or -1 if not found.
        """
        for i, hashed in enumerate(hashed_codes):
            if AuthService.verify_password(code, hashed):
                return True, i
        return False, -1

    # User operations
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get a user by email address."""
        result = await self.db.execute(select(User).where(User.email == email.lower()))
        return result.scalar_one_or_none()

    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """Get a user by ID."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def create_user(
        self,
        email: str,
        password: str,
        full_name: str,
        email_verified: bool = False,
    ) -> User:
        """Create a new user."""
        user = User(
            email=email.lower(),
            full_name=full_name,
            password_hash=self.hash_password(password),
            email_verified=email_verified,
        )
        self.db.add(user)
        await self.db.flush()
        return user

    async def authenticate(
        self,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[Optional[User], Optional[str]]:
        """
        Authenticate a user with email and password.

        Returns:
            Tuple of (user, error_message). User is None if auth fails.
        """
        user = await self.get_user_by_email(email)

        if not user:
            await self._log_audit(
                action=AuditLogAction.USER_LOGIN_FAILED,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"email": email, "reason": "user_not_found"},
                success=False,
            )
            return None, "Invalid email or password"

        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            return None, "Account locked. Try again later."

        # Check if account is active
        if not user.is_active:
            return None, "Account is disabled"

        # Verify password
        if not user.password_hash or not self.verify_password(
            password, user.password_hash
        ):
            # Increment failed attempts
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.max_login_attempts:
                user.locked_until = datetime.now(timezone.utc) + timedelta(
                    minutes=settings.lockout_duration_minutes
                )

            await self._log_audit(
                action=AuditLogAction.USER_LOGIN_FAILED,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "reason": "invalid_password",
                    "attempts": user.failed_login_attempts,
                },
                success=False,
            )
            return None, "Invalid email or password"

        # Reset failed attempts on success
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.now(timezone.utc)

        return user, None

    async def create_session(
        self,
        user: User,
        organization_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Create a new session for a user.

        Returns:
            Tuple of (access_token, refresh_token)
        """
        refresh_token = self.generate_refresh_token()
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=settings.refresh_token_expire_days
        )

        session = UserSession(
            user_id=user.id,
            organization_id=organization_id,
            refresh_token_hash=self.hash_token(refresh_token),
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
        )
        self.db.add(session)

        access_token = self.generate_access_token(user.id, organization_id)

        await self._log_audit(
            action=AuditLogAction.USER_LOGIN,
            user_id=user.id,
            organization_id=organization_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return access_token, refresh_token

    async def refresh_session(
        self,
        refresh_token: str,
        ip_address: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Refresh an access token using a refresh token.

        Returns:
            Tuple of (new_access_token, new_refresh_token) or (None, None) if invalid.
        """
        token_hash = self.hash_token(refresh_token)
        result = await self.db.execute(
            select(UserSession).where(
                and_(
                    UserSession.refresh_token_hash == token_hash,
                    UserSession.is_active.is_(True),
                    UserSession.expires_at > datetime.now(timezone.utc),
                )
            )
        )
        session = result.scalar_one_or_none()

        if not session:
            return None, None

        # Get the user
        user = await self.get_user_by_id(session.user_id)
        if not user or not user.is_active:
            return None, None

        # Rotate refresh token
        new_refresh_token = self.generate_refresh_token()
        session.refresh_token_hash = self.hash_token(new_refresh_token)
        session.last_activity_at = datetime.now(timezone.utc)
        session.ip_address = ip_address

        # Generate new access token
        access_token = self.generate_access_token(user.id, session.organization_id)

        return access_token, new_refresh_token

    async def logout(
        self,
        refresh_token: str,
        user_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Invalidate a session by refresh token."""
        token_hash = self.hash_token(refresh_token)
        result = await self.db.execute(
            select(UserSession).where(UserSession.refresh_token_hash == token_hash)
        )
        session = result.scalar_one_or_none()

        if session:
            session.is_active = False
            await self._log_audit(
                action=AuditLogAction.USER_LOGOUT,
                user_id=user_id or session.user_id,
                organization_id=session.organization_id,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            return True
        return False

    async def logout_all_sessions(self, user_id: UUID) -> int:
        """Logout all sessions for a user."""
        result = await self.db.execute(
            select(UserSession).where(
                and_(
                    UserSession.user_id == user_id,
                    UserSession.is_active.is_(True),
                )
            )
        )
        sessions = result.scalars().all()
        count = 0
        for session in sessions:
            session.is_active = False
            count += 1
        return count

    # Organization operations
    async def get_user_organizations(self, user_id: UUID) -> list[Organization]:
        """Get all organizations a user belongs to."""
        result = await self.db.execute(
            select(Organization)
            .join(OrganizationMember)
            .where(
                and_(
                    OrganizationMember.user_id == user_id,
                    OrganizationMember.status == MembershipStatus.ACTIVE,
                    Organization.is_active.is_(True),
                )
            )
        )
        return list(result.scalars().all())

    async def get_user_membership(
        self, user_id: UUID, organization_id: UUID
    ) -> Optional[OrganizationMember]:
        """Get a user's membership in an organization."""
        result = await self.db.execute(
            select(OrganizationMember).where(
                and_(
                    OrganizationMember.user_id == user_id,
                    OrganizationMember.organization_id == organization_id,
                )
            )
        )
        return result.scalar_one_or_none()

    async def create_organization(
        self,
        name: str,
        slug: str,
        owner_user_id: UUID,
    ) -> Organization:
        """Create a new organization with an owner."""
        org = Organization(
            name=name,
            slug=slug.lower(),
        )
        self.db.add(org)
        await self.db.flush()

        # Add owner
        member = OrganizationMember(
            organization_id=org.id,
            user_id=owner_user_id,
            role=UserRole.OWNER,
            status=MembershipStatus.ACTIVE,
            joined_at=datetime.now(timezone.utc),
        )
        self.db.add(member)

        await self._log_audit(
            action=AuditLogAction.ORG_CREATED,
            user_id=owner_user_id,
            organization_id=org.id,
            details={"name": name, "slug": slug},
        )

        return org

    async def check_slug_available(self, slug: str) -> bool:
        """Check if an organization slug is available."""
        result = await self.db.execute(
            select(Organization).where(Organization.slug == slug.lower())
        )
        return result.scalar_one_or_none() is None

    # Password reset
    async def initiate_password_reset(self, email: str) -> Optional[str]:
        """
        Initiate password reset for a user.

        Returns the reset token if user exists, None otherwise.
        """
        user = await self.get_user_by_email(email)
        if not user:
            return None

        token = secrets.token_urlsafe(32)
        user.password_reset_token = self.hash_token(token)
        user.password_reset_expires_at = datetime.now(timezone.utc) + timedelta(
            hours=settings.password_reset_expire_hours
        )

        return token

    async def reset_password(
        self,
        token: str,
        new_password: str,
        ip_address: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Reset a user's password using a reset token.

        Returns:
            Tuple of (success, error_message)
        """
        token_hash = self.hash_token(token)
        result = await self.db.execute(
            select(User).where(
                and_(
                    User.password_reset_token == token_hash,
                    User.password_reset_expires_at > datetime.now(timezone.utc),
                )
            )
        )
        user = result.scalar_one_or_none()

        if not user:
            return False, "Invalid or expired reset token"

        user.password_hash = self.hash_password(new_password)
        user.password_reset_token = None
        user.password_reset_expires_at = None
        user.failed_login_attempts = 0
        user.locked_until = None

        await self._log_audit(
            action=AuditLogAction.USER_PASSWORD_RESET,
            user_id=user.id,
            ip_address=ip_address,
        )

        # Invalidate all existing sessions
        await self.logout_all_sessions(user.id)

        return True, None

    # Audit logging
    async def _log_audit(
        self,
        action: AuditLogAction,
        user_id: Optional[UUID] = None,
        organization_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[dict] = None,
        success: bool = True,
        error_message: Optional[str] = None,
    ):
        """Log an audit event."""
        log = AuditLog(
            action=action,
            user_id=user_id,
            organization_id=organization_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            success=success,
            error_message=error_message,
        )
        self.db.add(log)
