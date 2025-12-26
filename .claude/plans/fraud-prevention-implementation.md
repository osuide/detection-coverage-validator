# Fraud Prevention Implementation Plan

## Overview

This plan implements three fraud prevention measures to protect the free tier from abuse:

1. **Cloud Account Uniqueness** - Prevent same cloud account on multiple free-tier organisations
2. **Email Quality Validation** - Block disposable/temporary email addresses
3. **IP Blocking via AWS WAF** - Block VPN/proxy/Tor/datacentre IPs at signup (edge-level)

---

## ReAct Analysis

### Thought 1: Understanding the Attack Surface

**Observation**: The free tier allows 1 cloud account per organisation. The primary abuse vector is creating multiple free accounts to scan the same cloud environment repeatedly, or to scan unlimited different environments.

**Reasoning**:
- Current protection: Device fingerprinting limits 3 registrations/device/24h (will be tightened to 1/30 days)
- Gap: Same AWS/GCP account can be connected to N different free-tier organisations
- Gap: Disposable emails allow infinite account creation
- Gap: VPN/proxy usage indicates intent to evade detection

**Action**: Implement layered defences at registration, cloud account connection, and ongoing monitoring.

### Thought 2: Analysing Integration Points

**Observation**: Key integration points identified:
- Registration: `backend/app/api/routes/auth.py:signup()` (line 457)
- Cloud account creation: `backend/app/api/routes/accounts.py:create_account()` (line 86)
- Existing fingerprint service: `backend/app/services/fingerprint_service.py`
- Existing models: `backend/app/models/fingerprint.py`, `backend/app/models/cloud_account.py`

**Reasoning**:
- Email validation should happen in Pydantic schema (fail-fast)
- IP reputation should be checked during registration (before user creation)
- Cloud account uniqueness should be checked at connection time (after subscription tier check)

**Action**: Create new services and integrate at appropriate points.

### Thought 3: Database Schema Requirements

**Observation**: Need to track:
- Global cloud account hash → subscription tier mapping
- IP reputation cache (avoid repeated API calls)
- Disposable domain blocklist (static + dynamic)

**Reasoning**:
- Cloud account hash should be globally unique for free tier
- IP reputation has latency; cache results for 24h
- Domain blocklist should be updatable without deployment

---

## Phase 1: Cloud Account Uniqueness Enforcement

### 1.1 Database Migration

**File**: `backend/alembic/versions/030_add_cloud_account_fraud_prevention.py`

```python
"""Add cloud account fraud prevention fields.

Revision ID: 030_fraud_prevention
Revises: 029_add_service_awareness
Create Date: 2025-12-23
"""

from alembic import op
import sqlalchemy as sa

revision = "030_fraud_prevention"
down_revision = "029_add_service_awareness"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add global account hash for cross-org duplicate detection
    op.add_column(
        "cloud_accounts",
        sa.Column("global_account_hash", sa.String(64), nullable=True, index=True),
    )

    # Create global tracking table for free-tier cloud accounts
    op.create_table(
        "cloud_account_global_registry",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_hash", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("provider", sa.String(10), nullable=False),  # 'aws' or 'gcp'
        sa.Column("first_registered_org_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("first_registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("registration_count", sa.Integer, nullable=False, default=1),
        sa.Column("is_free_tier_locked", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # Create email-to-cloud-account binding table
    # Prevents cloud account cycling on free tier
    op.create_table(
        "free_email_cloud_account_bindings",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email_hash", sa.String(64), nullable=False, index=True),
        sa.Column("cloud_account_hash", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("email_hash", name="uq_email_cloud_binding"),
    )

    # Backfill existing cloud accounts with hashes
    op.execute("""
        UPDATE cloud_accounts
        SET global_account_hash = encode(
            sha256(concat(provider, ':', account_id)::bytea),
            'hex'
        )
        WHERE global_account_hash IS NULL
    """)

    # Make column non-nullable after backfill
    op.alter_column("cloud_accounts", "global_account_hash", nullable=False)

    # Backfill global registry for existing FREE tier cloud accounts
    # This prevents existing free accounts from being locked out
    op.execute("""
        INSERT INTO cloud_account_global_registry (
            id, account_hash, provider, first_registered_org_id,
            first_registered_at, registration_count, is_free_tier_locked
        )
        SELECT
            gen_random_uuid(),
            ca.global_account_hash,
            ca.provider,
            ca.organization_id,
            ca.created_at,
            1,
            true
        FROM cloud_accounts ca
        JOIN subscriptions s ON s.organization_id = ca.organization_id
        WHERE s.tier = 'free'
        ON CONFLICT (account_hash) DO NOTHING
    """)


def downgrade() -> None:
    op.drop_table("free_email_cloud_account_bindings")
    op.drop_table("cloud_account_global_registry")
    op.drop_column("cloud_accounts", "global_account_hash")
```

### 1.2 Model Updates

**File**: `backend/app/models/cloud_account.py` (additions)

```python
# Add to CloudAccount class:
global_account_hash: Mapped[str] = mapped_column(
    String(64), nullable=False, index=True
)

@staticmethod
def compute_account_hash(provider: CloudProvider, account_id: str) -> str:
    """Compute globally unique hash for a cloud account."""
    import hashlib
    return hashlib.sha256(f"{provider.value}:{account_id}".encode()).hexdigest()
```

**New File**: `backend/app/models/fraud_prevention.py`

```python
"""Fraud prevention models."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, ForeignKey
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
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
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

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )

    # SHA-256 hash of lowercase email
    email_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # The cloud account this email is bound to
    cloud_account_hash: Mapped[str] = mapped_column(
        String(64), nullable=False
    )

    provider: Mapped[str] = mapped_column(String(10), nullable=False)

    # When this binding was created
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Composite unique constraint: one email can only bind to one cloud account
    __table_args__ = (
        sa.UniqueConstraint('email_hash', name='uq_email_cloud_binding'),
    )

    @staticmethod
    def compute_email_hash(email: str) -> str:
        """Compute hash of email for comparison."""
        import hashlib
        return hashlib.sha256(email.lower().strip().encode()).hexdigest()


```

### 1.3 Service Implementation

**New File**: `backend/app/services/cloud_account_fraud_service.py`

```python
"""Cloud account fraud prevention service."""

from datetime import datetime, timezone
from typing import Optional, Tuple
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.billing import AccountTier, Subscription
from app.models.cloud_account import CloudAccount, CloudProvider
from app.models.fraud_prevention import CloudAccountGlobalRegistry, FreeEmailCloudAccountBinding
from app.models.user import User

logger = structlog.get_logger()

# Tiers that bypass the one-account-per-cloud-account restriction
PAID_TIERS = {AccountTier.INDIVIDUAL, AccountTier.PRO, AccountTier.ENTERPRISE, AccountTier.SUBSCRIBER}


class CloudAccountFraudService:
    """Service to prevent cloud account abuse on free tier."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def check_cloud_account_allowed(
        self,
        provider: CloudProvider,
        account_id: str,
        organization_id: UUID,
        user_email: str,  # Email of user making the request
    ) -> Tuple[bool, Optional[str]]:
        """Check if a cloud account can be connected by this organisation.

        Rules:
        - Paid tiers: Always allowed (consultants may scan client accounts)
        - Free tier:
          1. Email binding check: If this email has previously connected a different
             cloud account, block. One email = one cloud account forever on free tier.
          2. Global registry check: If this cloud account is already registered by
             another free-tier org, block.

        Returns:
            (allowed, reason) - True if allowed, False with explanation if blocked
        """
        # Get organisation's subscription tier
        sub_result = await self.db.execute(
            select(Subscription).where(Subscription.organization_id == organization_id)
        )
        subscription = sub_result.scalar_one_or_none()

        if not subscription:
            return False, "No active subscription found"

        # Paid tiers bypass all restrictions
        if subscription.tier in PAID_TIERS:
            logger.debug(
                "cloud_account_check_bypassed_paid_tier",
                tier=subscription.tier.value,
                organization_id=str(organization_id),
            )
            return True, None

        # --- FREE TIER CHECKS ---

        account_hash = CloudAccount.compute_account_hash(provider, account_id)
        email_hash = FreeEmailCloudAccountBinding.compute_email_hash(user_email)

        # Check 1: Has this email ever connected a cloud account on free tier?
        binding_result = await self.db.execute(
            select(FreeEmailCloudAccountBinding).where(
                FreeEmailCloudAccountBinding.email_hash == email_hash
            )
        )
        existing_binding = binding_result.scalar_one_or_none()

        if existing_binding:
            # This email has connected a cloud account before
            if existing_binding.cloud_account_hash != account_hash:
                # Trying to connect a DIFFERENT cloud account - BLOCK
                logger.warning(
                    "cloud_account_blocked_email_cycling",
                    email_hash=email_hash[:16] + "...",
                    requested_account_hash=account_hash[:16] + "...",
                    bound_account_hash=existing_binding.cloud_account_hash[:16] + "...",
                )
                return (
                    False,
                    "This email address has already been used with a different cloud account. "
                    "Free accounts are limited to one cloud account per email address. "
                    "Upgrade to a paid plan to connect additional cloud accounts."
                )
            # Same cloud account - allowed (re-registering same environment)

        # Check 2: Is this cloud account already registered by another free-tier org?
        registry_result = await self.db.execute(
            select(CloudAccountGlobalRegistry).where(
                CloudAccountGlobalRegistry.account_hash == account_hash
            )
        )
        registry_entry = registry_result.scalar_one_or_none()

        if registry_entry:
            # Account already registered
            if registry_entry.first_registered_org_id == organization_id:
                # Same org reconnecting - allowed
                return True, None

            if registry_entry.is_free_tier_locked:
                logger.warning(
                    "cloud_account_blocked_duplicate_free_tier",
                    account_hash=account_hash[:16] + "...",
                    provider=provider.value,
                    blocked_org_id=str(organization_id),
                    original_org_id=str(registry_entry.first_registered_org_id),
                )
                return (
                    False,
                    "This cloud account is already connected to another free account. "
                    "Upgrade to a paid plan to connect additional organisations."
                )

        return True, None

    async def register_cloud_account(
        self,
        provider: CloudProvider,
        account_id: str,
        organization_id: UUID,
        user_email: str,
        is_free_tier: bool,
    ) -> None:
        """Register a cloud account in the global registry and create email binding.

        Called after successful cloud account creation.
        Uses SELECT FOR UPDATE to prevent race conditions.
        """
        account_hash = CloudAccount.compute_account_hash(provider, account_id)
        email_hash = FreeEmailCloudAccountBinding.compute_email_hash(user_email)

        # Check if already registered (with row lock to prevent race condition)
        existing = await self.db.execute(
            select(CloudAccountGlobalRegistry)
            .where(CloudAccountGlobalRegistry.account_hash == account_hash)
            .with_for_update()
        )
        registry_entry = existing.scalar_one_or_none()

        if registry_entry:
            # Increment registration count
            registry_entry.registration_count += 1
            registry_entry.updated_at = datetime.now(timezone.utc)
        else:
            # Create new registry entry
            registry_entry = CloudAccountGlobalRegistry(
                account_hash=account_hash,
                provider=provider.value,
                first_registered_org_id=organization_id,
                first_registered_at=datetime.now(timezone.utc),
                is_free_tier_locked=True,  # Lock for free tier by default
            )
            self.db.add(registry_entry)

        await self.db.flush()

        logger.info(
            "cloud_account_registered_globally",
            account_hash=account_hash[:16] + "...",
            provider=provider.value,
            organization_id=str(organization_id),
            registration_count=registry_entry.registration_count,
        )

        # Create email-to-cloud-account binding for free tier
        # This is permanent and persists even after account deletion
        if is_free_tier:
            existing_binding = await self.db.execute(
                select(FreeEmailCloudAccountBinding).where(
                    FreeEmailCloudAccountBinding.email_hash == email_hash
                )
            )
            if not existing_binding.scalar_one_or_none():
                binding = FreeEmailCloudAccountBinding(
                    email_hash=email_hash,
                    cloud_account_hash=account_hash,
                    provider=provider.value,
                )
                self.db.add(binding)
                await self.db.flush()

                logger.info(
                    "email_cloud_account_binding_created",
                    email_hash=email_hash[:16] + "...",
                    cloud_account_hash=account_hash[:16] + "...",
                )

    async def release_cloud_account(
        self,
        provider: CloudProvider,
        account_id: str,
        organization_id: UUID,
    ) -> None:
        """Release a cloud account from the global registry when deleted.

        Only releases the free-tier lock if this was the original registering org.
        """
        account_hash = CloudAccount.compute_account_hash(provider, account_id)

        registry_result = await self.db.execute(
            select(CloudAccountGlobalRegistry).where(
                CloudAccountGlobalRegistry.account_hash == account_hash
            )
        )
        registry_entry = registry_result.scalar_one_or_none()

        if registry_entry:
            registry_entry.registration_count -= 1

            # Only release lock if original org is disconnecting and count reaches 0
            if (
                registry_entry.first_registered_org_id == organization_id
                and registry_entry.registration_count <= 0
            ):
                # Delete the registry entry entirely
                await self.db.delete(registry_entry)
                logger.info(
                    "cloud_account_released_globally",
                    account_hash=account_hash[:16] + "...",
                    organization_id=str(organization_id),
                )
```

### 1.4 Integration into Accounts API

**File**: `backend/app/api/routes/accounts.py` (modify `create_account`)

Add after subscription limit check (around line 120):

```python
# NEW: Check cloud account uniqueness and email binding for free tier
from app.services.cloud_account_fraud_service import CloudAccountFraudService

fraud_service = CloudAccountFraudService(db)
allowed, block_reason = await fraud_service.check_cloud_account_allowed(
    provider=account_in.provider,
    account_id=account_in.account_id,
    organization_id=auth.organization_id,
    user_email=auth.user_email,  # Pass user's email for binding check
)

if not allowed:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=block_reason,
    )

# After successful creation, register globally and create email binding
is_free_tier = subscription.tier not in PAID_TIERS
await fraud_service.register_cloud_account(
    provider=account.provider,
    account_id=account.account_id,
    organization_id=auth.organization_id,
    user_email=auth.user_email,
    is_free_tier=is_free_tier,
)
```

---

## Phase 2: Email Quality Validation

### 2.1 Create Email Validation Service

**Dependency**: Add `dnspython>=2.4.0` to `backend/requirements.txt` for MX record validation.

**New File**: `backend/app/services/email_quality_service.py`

```python
"""Email quality validation service for fraud prevention."""

import asyncio
import re
from typing import Optional, Tuple, Set
from functools import lru_cache

import structlog
from dns import resolver
from dns.exception import DNSException, Timeout

logger = structlog.get_logger()

# Comprehensive blocklist of disposable email domains
# Source: https://github.com/disposable-email-domains/disposable-email-domains
DISPOSABLE_DOMAINS: Set[str] = {
    # Top disposable domains (commonly used for abuse)
    "tempmail.com", "temp-mail.org", "guerrillamail.com", "guerrillamail.org",
    "mailinator.com", "maildrop.cc", "10minutemail.com", "10minutemail.net",
    "throwaway.email", "throwawaymail.com", "dispostable.com", "fakeinbox.com",
    "mailnesia.com", "sharklasers.com", "yopmail.com", "yopmail.fr",
    "trashmail.com", "trashmail.net", "getnada.com", "nada.email",
    "tempinbox.com", "tempr.email", "discard.email", "discardmail.com",
    "disposableemailaddresses.com", "emailondeck.com", "getairmail.com",
    "mohmal.com", "spambox.us", "spamgourmet.com", "burnermail.io",
    "mytemp.email", "tempail.com", "tmpmail.org", "tmpmail.net",
    "fakemailgenerator.com", "emailfake.com", "fakemail.net",
    "guerrillamailblock.com", "mintemail.com", "mt2015.com",
    "mailsac.com", "mailslurp.com", "emailna.co", "inboxkitten.com",
    "mailpoof.com", "tempmailaddress.com", "tempmailin.com", "dropmail.me",
    "crazymailing.com", "haltospam.com", "harakirimail.com",
    # Extended list - add more as discovered
    "1secmail.com", "1secmail.net", "1secmail.org",
    "5mail.cf", "5mail.ga", "5mail.gq", "5mail.ml",
    "byom.de", "chacuo.net", "cko.kr", "cool.fr.nf",
    "courriel.fr.nf", "disbox.net", "disbox.org", "einrot.com",
    "emkei.cz", "fleckens.hu", "generator.email", "getmails.eu",
    "gg.gg", "gishpuppy.com", "grr.la", "guerrillamail.biz",
    "guerrillamail.de", "guerrillamail.info", "guerrillamail.net",
    "hmamail.com", "imgof.com", "imgv.de", "jetable.fr.nf",
    "kasmail.com", "keemail.me", "mailcatch.com", "mailchop.com",
    "mailexpire.com", "mailfree.ga", "mailfree.gq", "mailfree.ml",
    "mailhub.pw", "mailimate.com", "mailsiphon.com", "mailtemp.info",
    "meltmail.com", "moakt.cc", "moakt.co", "moakt.ws",
    "mvrht.net", "notmailinator.com", "owlpic.com", "pokemail.net",
    "proxymail.eu", "rcpt.at", "rejectmail.com", "rtrtr.com",
    "s0ny.net", "sharklasers.com", "spamavert.com", "spambog.com",
    "spambog.de", "spambog.ru", "spamex.com", "spamherelots.com",
    "spamtroll.net", "superrito.com", "sute.jp", "techemail.com",
    "tempemail.biz", "tempemail.co.za", "tempemail.com", "tempemail.net",
    "temporaryemail.net", "temporaryforwarding.com", "temporaryinbox.com",
    "thankyou2010.com", "thisisnotmyrealemail.com", "throwawayemailaddress.com",
    "tmail.ws", "tmpjr.me", "trash-mail.at", "trash-mail.com",
    "trash-mail.de", "trash2009.com", "trashdevil.com", "trashemail.de",
    "trashymail.com", "trashymail.net", "wegwerfmail.de", "wegwerfmail.net",
    "wegwerfmail.org", "wetrash.com", "wh4f.org", "whopy.com",
    "willhackforfood.biz", "willselfdestruct.com", "wuzupmail.net",
    "xagloo.co", "xmaily.com", "yep.it", "yogamaven.com",
    "zetmail.com", "zoemail.net", "zoemail.org",
}

# Patterns for disposable domain detection
DISPOSABLE_PATTERNS = [
    r"^temp[.-]?mail",
    r"^throw[.-]?away",
    r"^trash[.-]?mail",
    r"^fake[.-]?mail",
    r"^spam[.-]?",
    r"^disposable",
    r"^guerrilla",
    r"^mailinator",
    r"10minute",
    r"burner",
]


class EmailQualityService:
    """Service for validating email quality and blocking disposable addresses."""

    def __init__(self):
        self._compiled_patterns = [re.compile(p, re.I) for p in DISPOSABLE_PATTERNS]

    def is_disposable_domain(self, domain: str) -> bool:
        """Check if domain is a known disposable email provider."""
        domain = domain.lower().strip()

        # Direct blocklist match
        if domain in DISPOSABLE_DOMAINS:
            return True

        # Pattern matching for variations
        for pattern in self._compiled_patterns:
            if pattern.search(domain):
                return True

        return False

    async def validate_mx_records(self, domain: str, timeout: float = 5.0) -> Tuple[bool, Optional[str]]:
        """Verify domain has valid MX records (can receive email)."""
        try:
            loop = asyncio.get_event_loop()
            # Run DNS lookup in executor with timeout to avoid blocking/hanging
            mx_records = await asyncio.wait_for(
                loop.run_in_executor(
                    None, lambda: resolver.resolve(domain, 'MX', lifetime=timeout)
                ),
                timeout=timeout + 1  # Extra second for executor overhead
            )
            if mx_records:
                return True, None
            return False, "Domain has no MX records"
        except resolver.NXDOMAIN:
            return False, "Domain does not exist"
        except resolver.NoAnswer:
            return False, "Domain has no MX records"
        except (asyncio.TimeoutError, Timeout):
            logger.warning("mx_lookup_timeout", domain=domain)
            # Don't block on timeout - may be slow DNS
            return True, None
        except DNSException as e:
            logger.warning("mx_lookup_failed", domain=domain, error=str(e))
            # Don't block on DNS failures - may be temporary
            return True, None

    async def validate_email_quality(
        self,
        email: str,
        check_mx: bool = True,
    ) -> Tuple[bool, Optional[str]]:
        """
        Comprehensive email quality validation.

        Checks:
        1. Disposable domain blocklist
        2. Disposable domain patterns
        3. Valid MX records (optional)

        Returns:
            (is_valid, error_message)
        """
        try:
            local, domain = email.lower().rsplit('@', 1)
        except ValueError:
            return False, "Invalid email format"

        # Check disposable domains
        if self.is_disposable_domain(domain):
            logger.warning(
                "disposable_email_blocked",
                domain=domain,
                email_hash=hash(email),  # Don't log full email
            )
            return False, "Please use a permanent email address. Disposable email addresses are not allowed."

        # Check MX records
        if check_mx:
            has_mx, mx_error = await self.validate_mx_records(domain)
            if not has_mx:
                logger.warning(
                    "email_mx_validation_failed",
                    domain=domain,
                    error=mx_error,
                )
                return False, f"Unable to verify email domain: {mx_error}"

        return True, None


# Singleton instance
_email_quality_service: Optional[EmailQualityService] = None


def get_email_quality_service() -> EmailQualityService:
    """Get singleton email quality service."""
    global _email_quality_service
    if _email_quality_service is None:
        _email_quality_service = EmailQualityService()
    return _email_quality_service
```

### 2.2 Create Custom Pydantic Validator

**New File**: `backend/app/schemas/validators.py`

```python
"""Custom Pydantic validators for fraud prevention."""

from typing import Annotated
from pydantic import AfterValidator, EmailStr
import asyncio

from app.services.email_quality_service import get_email_quality_service


def validate_email_quality_sync(email: str) -> str:
    """Synchronous wrapper for email quality validation.

    Note: Runs MX check in background, doesn't block on it.
    For full async validation, use the service directly.
    """
    service = get_email_quality_service()

    # Sync check - disposable domain only (fast)
    try:
        domain = email.lower().rsplit('@', 1)[1]
    except (ValueError, IndexError):
        raise ValueError("Invalid email format")

    if service.is_disposable_domain(domain):
        raise ValueError(
            "Please use a permanent email address. "
            "Disposable email addresses are not allowed."
        )

    return email


# Annotated type for validated email
ValidatedEmail = Annotated[EmailStr, AfterValidator(validate_email_quality_sync)]
```

### 2.3 Update Auth Schemas

**File**: `backend/app/schemas/auth.py` (modifications)

```python
# Add import at top:
from app.schemas.validators import ValidatedEmail

# Replace EmailStr with ValidatedEmail in:
# - SignupRequest.email
# - InviteMemberRequest.email

class SignupRequest(BaseModel):
    """Signup request."""

    email: ValidatedEmail  # Changed from EmailStr
    password: str = Field(..., min_length=12)
    # ... rest unchanged
```

### 2.4 Add Async Validation in Auth Route

**File**: `backend/app/api/routes/auth.py` (modify `signup`)

Add after fingerprint check, before email existence check:

```python
from app.services.email_quality_service import get_email_quality_service

# Validate email quality (async with MX check)
email_service = get_email_quality_service()
is_valid, email_error = await email_service.validate_email_quality(
    body.email,
    check_mx=True,
)
if not is_valid:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=email_error,
    )
```

---

## Phase 3: IP Blocking via AWS WAF

### 3.1 Design Rationale

**Use AWS WAF instead of application-level IP checking** because:

| Aspect | Application-Level | AWS WAF |
|--------|-------------------|---------|
| **Blocking point** | After request hits app | Edge, before app |
| **Latency impact** | +100ms per request | Zero |
| **VPN detection** | Poor (ip-api doesn't detect) | Excellent (AWS IP reputation) |
| **Maintenance** | We maintain code + blocklists | AWS maintains |
| **Reliability** | Third-party API dependency | AWS infrastructure |
| **Cost** | Free tier limits | Already paying for WAF |

**Where blocking applies**:
| Action | Block VPN/Proxy/Tor/DC? | Method |
|--------|------------------------|--------|
| `POST /api/v1/auth/signup` | **YES** | WAF |
| `POST /api/v1/auth/accept-invite` | No (org may be paid) | - |
| OAuth callback | No (can't distinguish login/register) | - |
| Login (any tier) | No | - |
| API access | No | - |

**Defence in Depth**: WAF is one layer. Even if someone bypasses it via OAuth, they still face:
1. Email quality check (blocks disposable emails)
2. Device fingerprinting (1 registration per device per 30 days)
3. Cloud account uniqueness (blocks duplicate free tier connections)

### 3.2 WAF Configuration Update

**File**: `infrastructure/terraform/modules/backend/main.tf`

Add the Anonymous IP List rule to the existing `aws_wafv2_web_acl.api` resource.

The existing WAF has these rules:
- Priority 0: IP Allowlist (when configured)
- Priority 1: AWS Managed Core Rule Set (OWASP)
- Priority 2: Known Bad Inputs
- Priority 3: SQL Injection Protection
- Priority 4: Rate Limiting

Add new rule at Priority 5:

```hcl
  # Rule 5: Block Anonymous IPs (VPN, Proxy, Tor, Hosting) for Signup Only
  # Uses AWS Managed Rules which maintain comprehensive IP reputation lists
  #
  # NOTE: Only applies to /auth/signup, NOT to:
  # - /auth/accept-invite (invitee may be joining paid org)
  # - OAuth callbacks (can't distinguish login from registration)
  rule {
    name     = "BlockAnonymousIPsForSignup"
    priority = 5

    override_action {
      none {}  # Use the rule group's block action
    }

    statement {
      # Scope: POST /api/v1/auth/signup from Anonymous IPs
      and_statement {
        statement {
          # Match signup endpoint exactly
          byte_match_statement {
            positional_constraint = "EXACTLY"
            search_string         = "/api/v1/auth/signup"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          # Only POST requests
          byte_match_statement {
            positional_constraint = "EXACTLY"
            search_string         = "POST"
            field_to_match {
              method {}
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
        statement {
          # Block if IP is in Anonymous IP List
          managed_rule_group_statement {
            name        = "AWSManagedRulesAnonymousIpList"
            vendor_name = "AWS"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "a13e-${var.environment}-anonymous-ip-signup-block"
      sampled_requests_enabled   = true
    }
  }
```

**Note**: The `AWSManagedRulesAnonymousIpList` includes:
- `AnonymousIPList` - IPs of VPNs, proxies, Tor nodes, and hosting providers
- `HostingProviderIPList` - IPs of hosting/cloud providers (datacentres)

### 3.3 Custom Block Response (Optional)

Add a custom response body for blocked registrations:

```hcl
  # Custom response for anonymous IP blocks
  custom_response_body {
    key          = "anonymous-ip-blocked"
    content_type = "APPLICATION_JSON"
    content      = jsonencode({
      error   = "registration_blocked"
      message = "Registration is not available from VPNs, proxies, or cloud infrastructure. Please disable your VPN and try again from your regular network."
      code    = "ANONYMOUS_IP_BLOCKED"
    })
  }
```

Then reference it in the rule:

```hcl
    action {
      block {
        custom_response {
          response_code            = 403
          custom_response_body_key = "anonymous-ip-blocked"
        }
      }
    }
```

### 3.4 CloudWatch Alarms for Monitoring

**File**: `infrastructure/terraform/modules/backend/cloudwatch.tf` (or add to main.tf)

```hcl
# Alarm for high volume of blocked anonymous IP registrations
resource "aws_cloudwatch_metric_alarm" "anonymous_ip_blocks" {
  alarm_name          = "a13e-${var.environment}-high-anonymous-ip-blocks"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300  # 5 minutes
  statistic           = "Sum"
  threshold           = 100  # Alert if >100 blocks in 5 minutes
  alarm_description   = "High volume of blocked anonymous IP registration attempts"

  dimensions = {
    WebACL = aws_wafv2_web_acl.api.name
    Rule   = "BlockAnonymousIPsForRegistration"
    Region = var.aws_region
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = {
    Name        = "a13e-${var.environment}-anonymous-ip-blocks"
    Environment = var.environment
  }
}
```

### 3.5 Frontend Error Handling

**File**: `frontend/src/services/authApi.ts` (or equivalent)

Handle the WAF block response gracefully:

```typescript
interface WafBlockResponse {
  error: string;
  message: string;
  code: string;
}

async function handleSignupError(response: Response): Promise<string> {
  if (response.status === 403) {
    try {
      const data: WafBlockResponse = await response.json();
      if (data.code === 'ANONYMOUS_IP_BLOCKED') {
        return data.message;  // User-friendly message from WAF
      }
    } catch {
      // Not a WAF response, use default
    }
    return 'Registration is temporarily unavailable. Please try again later.';
  }
  // Handle other errors...
}
```

### 3.6 No Application Code Changes Required

Unlike the previous plan, **no changes are needed to**:
- `backend/app/api/routes/auth.py`
- `backend/app/models/fraud_prevention.py` (no IPReputationCache model)
- `backend/app/services/` (no ip_reputation_service.py)

The WAF handles everything at the edge before requests reach the application.

---

## Phase 4: Configuration and Feature Flags

### 4.1 Add Settings

**File**: `backend/app/core/config.py` (additions)

```python
class Settings(BaseSettings):
    # ... existing settings ...

    # Fraud Prevention - application-level toggles
    # Note: IP blocking is handled by AWS WAF, not application code
    fraud_prevention_enabled: bool = True
    cloud_account_uniqueness_enabled: bool = True
    email_quality_check_enabled: bool = True
    email_mx_check_enabled: bool = True
```

---

## Phase 5: Admin Dashboard Integration

### 5.1 Add Admin Endpoints

**New File**: `backend/app/api/routes/admin/fraud.py`

```python
"""Admin fraud management endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_admin_role
from app.models.fraud_prevention import CloudAccountGlobalRegistry

router = APIRouter()


@router.get("/cloud-account-registry")
async def list_cloud_account_registry(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _admin = Depends(require_admin_role),
):
    """List all registered cloud accounts in global registry."""
    query = select(CloudAccountGlobalRegistry).order_by(
        CloudAccountGlobalRegistry.created_at.desc()
    ).offset(skip).limit(limit)

    result = await db.execute(query)
    entries = result.scalars().all()

    # Get total count
    count_result = await db.execute(
        select(func.count(CloudAccountGlobalRegistry.id))
    )
    total = count_result.scalar() or 0

    return {
        "items": [
            {
                "id": str(e.id),
                "account_hash": e.account_hash[:16] + "...",
                "provider": e.provider,
                "first_registered_org_id": str(e.first_registered_org_id),
                "first_registered_at": e.first_registered_at.isoformat(),
                "registration_count": e.registration_count,
                "is_free_tier_locked": e.is_free_tier_locked,
            }
            for e in entries
        ],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.delete("/cloud-account-registry/{entry_id}")
async def release_cloud_account_lock(
    entry_id: UUID,
    db: AsyncSession = Depends(get_db),
    _admin = Depends(require_admin_role),
):
    """Manually release a cloud account lock (admin override)."""
    result = await db.execute(
        select(CloudAccountGlobalRegistry).where(
            CloudAccountGlobalRegistry.id == entry_id
        )
    )
    entry = result.scalar_one_or_none()

    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    entry.is_free_tier_locked = False
    await db.commit()

    return {"message": "Lock released successfully"}


# Note: IP blocking metrics are available in AWS WAF console and CloudWatch
# No application-level IP tracking is needed
```

### 5.2 WAF Metrics Dashboard

IP blocking metrics are available via:
- **AWS WAF Console** → Web ACLs → `a13e-{env}-api-waf` → Sampled requests
- **CloudWatch** → Metrics → AWS/WAFV2 → `a13e-{env}-anonymous-ip-registration-block`

Consider creating a CloudWatch dashboard for fraud prevention:

```hcl
resource "aws_cloudwatch_dashboard" "fraud_prevention" {
  dashboard_name = "a13e-${var.environment}-fraud-prevention"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "WAF Blocked Registrations (Anonymous IPs)"
          region = var.aws_region
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.api.name,
             "Rule", "BlockAnonymousIPsForRegistration", "Region", var.aws_region]
          ]
          period = 300
          stat   = "Sum"
        }
      }
    ]
  })
}
```

---

## Testing Plan

### Unit Tests

1. **Cloud Account Uniqueness**
   - Test free tier blocked when account already registered
   - Test paid tier allowed even when account registered
   - Test same org can reconnect their own account
   - Test hash computation consistency
   - Test race condition handling (concurrent registrations)

2. **Email Quality**
   - Test blocklist domains rejected
   - Test pattern matching (tempmail*, throwaway*, etc.)
   - Test valid domains accepted
   - Test MX validation handling
   - Test DNS timeout handling

### Integration Tests

1. Full registration flow with all checks
2. Cloud account creation with uniqueness check
3. Admin override for locked accounts
4. OAuth registration flow (email quality check)

### WAF Testing

WAF rules should be tested in staging before production:

1. **VPN blocking**: Connect via VPN, attempt registration → expect 403
2. **Tor blocking**: Use Tor browser, attempt registration → expect 403
3. **Datacentre blocking**: From EC2/Lambda, attempt registration → expect 403
4. **Legitimate traffic**: From residential IP, attempt registration → expect success
5. **Login not blocked**: From VPN, attempt login → expect success

---

## Rollout Plan

### Week 1: Infrastructure
1. Deploy WAF rule in COUNT mode (monitor only, don't block)
2. Create and run database migration
3. Deploy email quality service (disabled via feature flag)
4. Analyse WAF logs to understand traffic patterns

### Week 2: Enable Blocking
1. Enable cloud account uniqueness (blocking)
2. Enable email quality check (blocking)
3. Switch WAF rule from COUNT to BLOCK mode

### Week 3: Monitoring & Polish
1. Monitor WAF blocked requests in CloudWatch
2. Deploy admin dashboard integration
3. Document support playbook for blocked users
4. Create CloudWatch dashboard for fraud metrics

---

## Metrics to Track

### Application-Level Metrics (PostgreSQL)

```sql
-- Cloud account duplicate blocks
SELECT
    DATE(created_at) as date,
    COUNT(*) as duplicate_blocks
FROM audit_logs
WHERE action = 'cloud_account_blocked'
  AND details->>'reason' = 'duplicate_free_tier'
  AND created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(created_at)
ORDER BY date DESC;

-- Email quality blocks (if logging added)
SELECT
    DATE(created_at) as date,
    COUNT(*) as email_blocks
FROM audit_logs
WHERE action = 'registration_blocked'
  AND details->>'reason' = 'disposable_email'
  AND created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(created_at)
ORDER BY date DESC;
```

### WAF Metrics (CloudWatch)

IP blocking metrics are available in CloudWatch under `AWS/WAFV2`:

```
Namespace: AWS/WAFV2
Dimensions:
  - WebACL: a13e-{env}-api-waf
  - Rule: BlockAnonymousIPsForRegistration
  - Region: {region}

Metrics:
  - BlockedRequests: Count of blocked registration attempts
  - AllowedRequests: Count of allowed registration attempts
```

**CloudWatch Insights Query** for WAF logs:

```
fields @timestamp, @message
| filter webaclId like /a13e.*api-waf/
| filter action = "BLOCK"
| filter ruleGroupId like /AnonymousIpList/
| stats count() by bin(1h)
```

---

## Phase 6: Tighten Device Fingerprint Limit

### 6.1 Current State

The existing fingerprint service allows **3 registrations per device per 24 hours**:

```python
# backend/app/services/fingerprint_service.py (current)
MAX_REGISTRATIONS_PER_FINGERPRINT_PER_DAY = 3
```

This is too generous - an abuser can create 3 free accounts per day from one device.

### 6.2 Recommended Change

Reduce to **1 registration per device per 30 days**:

```python
# backend/app/services/fingerprint_service.py (updated)
MAX_REGISTRATIONS_PER_FINGERPRINT = 1
REGISTRATION_WINDOW_DAYS = 30
```

**File**: `backend/app/services/fingerprint_service.py`

```python
# Change from:
MAX_REGISTRATIONS_PER_FINGERPRINT_PER_DAY = 3
REGISTRATION_WINDOW_HOURS = 24

# To:
MAX_REGISTRATIONS_PER_FINGERPRINT = 1
REGISTRATION_WINDOW_DAYS = 30

# Update check_registration_allowed():
async def check_registration_allowed(self, fingerprint_hash: str) -> Tuple[bool, Optional[str]]:
    """Check if registration is allowed from this device."""
    window_start = datetime.now(timezone.utc) - timedelta(days=REGISTRATION_WINDOW_DAYS)

    # Count registrations from this fingerprint in the window
    result = await self.db.execute(
        select(func.count(DeviceFingerprintAssociation.id))
        .join(DeviceFingerprint)
        .where(
            DeviceFingerprint.fingerprint_hash == fingerprint_hash,
            DeviceFingerprintAssociation.created_at >= window_start,
        )
    )
    recent_registrations = result.scalar() or 0

    if recent_registrations >= MAX_REGISTRATIONS_PER_FINGERPRINT:
        logger.warning(
            "registration_blocked_fingerprint_limit",
            fingerprint_hash=fingerprint_hash[:16] + "...",
            recent_registrations=recent_registrations,
        )
        return False, "Registration limit reached for this device. Please try again later."

    return True, None
```

---

## File Summary

### New Files (Backend)
- `backend/alembic/versions/030_add_cloud_account_fraud_prevention.py` - Database migration
- `backend/app/models/fraud_prevention.py` - CloudAccountGlobalRegistry model
- `backend/app/services/cloud_account_fraud_service.py` - Cloud account uniqueness service
- `backend/app/services/email_quality_service.py` - Disposable email blocking
- `backend/app/schemas/validators.py` - Pydantic ValidatedEmail type
- `backend/app/api/routes/admin/fraud.py` - Admin endpoints

### Modified Files (Backend)
- `backend/app/models/cloud_account.py` - Add `global_account_hash` field
- `backend/app/schemas/auth.py` - Use `ValidatedEmail` type
- `backend/app/api/routes/auth.py` - Add email quality check to signup
- `backend/app/api/routes/accounts.py` - Add cloud account uniqueness check
- `backend/app/core/config.py` - Add fraud prevention feature flags
- `backend/app/api/routes/admin/__init__.py` - Register fraud router
- `backend/app/services/fingerprint_service.py` - Reduce limit to 1 per 30 days

### Modified Files (Infrastructure)
- `infrastructure/terraform/modules/backend/main.tf` - Add WAF rule for anonymous IP blocking

### Frontend (Optional)
- `frontend/src/services/authApi.ts` - Handle WAF block response gracefully

---

## Summary: Defence in Depth

| Layer | Protection | Bypass Requirement |
|-------|------------|-------------------|
| **1. AWS WAF** | Blocks VPN/proxy/Tor/DC at `/auth/signup` | Residential IP |
| **2. Email Quality** | Blocks disposable emails | Permanent email address |
| **3. Device Fingerprint** | 1 registration per device per 30 days | Fresh device/browser |
| **4. Cloud Account Uniqueness** | One free org per AWS/GCP account | New cloud account |
| **5. Email-Cloud Binding** | One email = one cloud account forever (free tier) | New email address |

An attacker would need ALL of these for each free account:
1. A residential IP address
2. A permanent email address (not disposable)
3. A fresh browser/device (not used in last 30 days)
4. A unique cloud account (AWS or GCP)
5. A unique email per cloud account (cannot reuse email for different cloud accounts)

**The email-cloud binding closes the "cycling" loophole:**
- ❌ Register → scan AWS-A → delete → register same email → scan AWS-B (BLOCKED)
- ✅ Register → scan AWS-A → delete → register same email → scan AWS-A (ALLOWED)

This makes mass abuse economically unviable while keeping legitimate signups frictionless.

---

**END OF IMPLEMENTATION PLAN**
