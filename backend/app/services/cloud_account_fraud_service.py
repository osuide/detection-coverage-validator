"""Cloud account fraud prevention service.

Prevents abuse of the free tier by:
1. Blocking duplicate cloud account registrations across free-tier organisations
2. Binding emails to cloud accounts so users cannot cycle through different accounts
"""

from datetime import datetime, timezone
from typing import Optional, Tuple
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.billing import AccountTier, Subscription
from app.models.cloud_account import CloudAccount, CloudProvider
from app.models.fraud_prevention import (
    CloudAccountGlobalRegistry,
    FreeEmailCloudAccountBinding,
)

logger = structlog.get_logger()

# Tiers that bypass free-tier fraud prevention restrictions
PAID_TIERS = {
    AccountTier.INDIVIDUAL,
    AccountTier.PRO,
    AccountTier.ENTERPRISE,
    AccountTier.SUBSCRIBER,  # Legacy paid tier
}


class CloudAccountFraudService:
    """Service to prevent cloud account abuse on free tier."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def check_cloud_account_allowed(
        self,
        provider: CloudProvider,
        account_id: str,
        organization_id: UUID,
        user_email: str,
    ) -> Tuple[bool, Optional[str]]:
        """Check if a cloud account can be connected by this organisation.

        Rules:
        - Paid tiers: Always allowed (consultants may scan client accounts)
        - Free tier:
          1. Email binding check: If this email has previously connected a different
             cloud account, block. One email = one cloud account forever on free tier.
          2. Global registry check: If this cloud account is already registered by
             another free-tier org, block.

        Args:
            provider: Cloud provider (aws or gcp)
            account_id: Cloud account identifier
            organization_id: The organisation attempting to connect
            user_email: Email of the user making the request

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
                    "Upgrade to a paid plan to connect additional cloud accounts.",
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
                    "Upgrade to a paid plan to connect additional organisations.",
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

        Args:
            provider: Cloud provider (aws or gcp)
            account_id: Cloud account identifier
            organization_id: The organisation that connected the account
            user_email: Email of the user who connected the account
            is_free_tier: Whether the organisation is on free tier
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
                is_free_tier_locked=is_free_tier,
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

        Note: The email binding is NOT released - it persists permanently
        to prevent email cycling attacks.

        Only releases the free-tier lock if this was the original registering org.

        Args:
            provider: Cloud provider (aws or gcp)
            account_id: Cloud account identifier
            organization_id: The organisation deleting the account
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
            else:
                # Just decrement the count
                logger.info(
                    "cloud_account_registration_decremented",
                    account_hash=account_hash[:16] + "...",
                    organization_id=str(organization_id),
                    remaining_count=registry_entry.registration_count,
                )
