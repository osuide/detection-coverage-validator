"""Stripe billing service."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from uuid import UUID

import stripe
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.billing import (
    Subscription,
    Invoice,
    AccountTier,
    SubscriptionStatus,
    STRIPE_PRICES,
)
from app.models.user import Organization

logger = structlog.get_logger()
settings = get_settings()

# Initialize Stripe
stripe.api_key = settings.stripe_secret_key


class StripeService:
    """Service for Stripe billing operations."""

    @staticmethod
    async def get_or_create_customer(
        db: AsyncSession,
        organization: Organization,
        email: str,
        name: Optional[str] = None,
    ) -> str:
        """Get or create a Stripe customer for an organization."""
        # Check if organization already has a subscription with customer ID
        result = await db.execute(
            select(Subscription).where(Subscription.organization_id == organization.id)
        )
        subscription = result.scalar_one_or_none()

        if subscription and subscription.stripe_customer_id:
            return subscription.stripe_customer_id

        # Create a new Stripe customer
        try:
            customer = stripe.Customer.create(
                email=email,
                name=name or organization.name,
                metadata={
                    "organization_id": str(organization.id),
                    "organization_slug": organization.slug,
                },
            )
            logger.info(
                "stripe_customer_created",
                customer_id=customer.id,
                org_id=str(organization.id),
            )
            return customer.id
        except stripe.error.StripeError as e:
            logger.error(
                "stripe_customer_creation_failed",
                error=str(e),
                org_id=str(organization.id),
            )
            raise

    @staticmethod
    async def create_checkout_session(
        db: AsyncSession,
        organization_id: UUID,
        success_url: str,
        cancel_url: str,
        customer_email: str,
        additional_accounts: int = 0,
    ) -> Dict[str, Any]:
        """Create a Stripe Checkout session for subscription."""
        result = await db.execute(
            select(Organization).where(Organization.id == organization_id)
        )
        organization = result.scalar_one_or_none()
        if not organization:
            raise ValueError("Organization not found")

        # Get or create subscription record
        sub_result = await db.execute(
            select(Subscription).where(Subscription.organization_id == organization_id)
        )
        subscription = sub_result.scalar_one_or_none()

        customer_id = None
        if subscription and subscription.stripe_customer_id:
            customer_id = subscription.stripe_customer_id

        # Build line items
        line_items = []

        # Base subscription
        if settings.stripe_price_id_subscriber:
            line_items.append(
                {
                    "price": settings.stripe_price_id_subscriber,
                    "quantity": 1,
                }
            )
        else:
            # Fallback for development - create price inline
            line_items.append(
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {
                            "name": "Detection Coverage Validator - Subscriber",
                            "description": "Monthly subscription with unlimited scans, 3 cloud accounts, and full features",
                        },
                        "unit_amount": STRIPE_PRICES["subscriber_monthly"],
                        "recurring": {"interval": "month"},
                    },
                    "quantity": 1,
                }
            )

        # Additional accounts
        if additional_accounts > 0:
            if settings.stripe_price_id_additional_account:
                line_items.append(
                    {
                        "price": settings.stripe_price_id_additional_account,
                        "quantity": additional_accounts,
                    }
                )
            else:
                line_items.append(
                    {
                        "price_data": {
                            "currency": "usd",
                            "product_data": {
                                "name": "Additional Cloud Account",
                                "description": "Add more cloud accounts to your subscription",
                            },
                            "unit_amount": STRIPE_PRICES[
                                "additional_account_subscriber"
                            ],
                            "recurring": {"interval": "month"},
                        },
                        "quantity": additional_accounts,
                    }
                )

        try:
            checkout_params = {
                "mode": "subscription",
                "line_items": line_items,
                "success_url": success_url,
                "cancel_url": cancel_url,
                "metadata": {
                    "organization_id": str(organization_id),
                    "additional_accounts": str(additional_accounts),
                },
                "subscription_data": {
                    "metadata": {
                        "organization_id": str(organization_id),
                    }
                },
                "allow_promotion_codes": True,
            }

            if customer_id:
                checkout_params["customer"] = customer_id
            else:
                checkout_params["customer_email"] = customer_email

            session = stripe.checkout.Session.create(**checkout_params)

            logger.info(
                "stripe_checkout_created",
                session_id=session.id,
                org_id=str(organization_id),
            )

            return {
                "checkout_url": session.url,
                "session_id": session.id,
            }

        except stripe.error.StripeError as e:
            logger.error(
                "stripe_checkout_failed", error=str(e), org_id=str(organization_id)
            )
            raise

    @staticmethod
    async def create_portal_session(
        db: AsyncSession, organization_id: UUID, return_url: str
    ) -> Dict[str, Any]:
        """Create a Stripe Customer Portal session for managing subscription."""
        sub_result = await db.execute(
            select(Subscription).where(Subscription.organization_id == organization_id)
        )
        subscription = sub_result.scalar_one_or_none()

        if not subscription or not subscription.stripe_customer_id:
            raise ValueError("No Stripe customer found for this organization")

        try:
            session = stripe.billing_portal.Session.create(
                customer=subscription.stripe_customer_id,
                return_url=return_url,
            )

            return {
                "portal_url": session.url,
            }

        except stripe.error.StripeError as e:
            logger.error(
                "stripe_portal_failed", error=str(e), org_id=str(organization_id)
            )
            raise

    @staticmethod
    async def handle_checkout_completed(
        db: AsyncSession, session: Dict[str, Any]
    ) -> None:
        """Handle checkout.session.completed webhook event."""
        organization_id = UUID(session["metadata"]["organization_id"])
        additional_accounts = int(session["metadata"].get("additional_accounts", 0))
        customer_id = session["customer"]
        subscription_id = session["subscription"]

        # Get or create subscription record
        result = await db.execute(
            select(Subscription).where(Subscription.organization_id == organization_id)
        )
        subscription = result.scalar_one_or_none()

        if not subscription:
            subscription = Subscription(organization_id=organization_id)
            db.add(subscription)

        # Update subscription
        subscription.stripe_customer_id = customer_id
        subscription.stripe_subscription_id = subscription_id
        subscription.tier = AccountTier.SUBSCRIBER
        subscription.status = SubscriptionStatus.ACTIVE
        subscription.additional_accounts = additional_accounts
        subscription.included_accounts = 3  # Base plan includes 3

        # Fetch subscription details from Stripe
        try:
            stripe_sub = stripe.Subscription.retrieve(subscription_id)
            subscription.current_period_start = datetime.fromtimestamp(
                stripe_sub.current_period_start, tz=timezone.utc
            )
            subscription.current_period_end = datetime.fromtimestamp(
                stripe_sub.current_period_end, tz=timezone.utc
            )
        except stripe.error.StripeError as e:
            logger.warning("stripe_subscription_fetch_failed", error=str(e))

        await db.commit()
        logger.info(
            "subscription_activated", org_id=str(organization_id), tier="subscriber"
        )

    @staticmethod
    async def handle_subscription_updated(
        db: AsyncSession, stripe_subscription: Dict[str, Any]
    ) -> None:
        """Handle customer.subscription.updated webhook event."""
        subscription_id = stripe_subscription["id"]

        result = await db.execute(
            select(Subscription).where(
                Subscription.stripe_subscription_id == subscription_id
            )
        )
        subscription = result.scalar_one_or_none()

        if not subscription:
            logger.warning(
                "subscription_not_found", stripe_subscription_id=subscription_id
            )
            return

        # Update status
        status_map = {
            "active": SubscriptionStatus.ACTIVE,
            "past_due": SubscriptionStatus.PAST_DUE,
            "canceled": SubscriptionStatus.CANCELED,
            "unpaid": SubscriptionStatus.UNPAID,
        }
        subscription.status = status_map.get(
            stripe_subscription["status"], SubscriptionStatus.ACTIVE
        )

        # Update period
        subscription.current_period_start = datetime.fromtimestamp(
            stripe_subscription["current_period_start"], tz=timezone.utc
        )
        subscription.current_period_end = datetime.fromtimestamp(
            stripe_subscription["current_period_end"], tz=timezone.utc
        )

        subscription.cancel_at_period_end = stripe_subscription.get(
            "cancel_at_period_end", False
        )

        if stripe_subscription.get("canceled_at"):
            subscription.canceled_at = datetime.fromtimestamp(
                stripe_subscription["canceled_at"], tz=timezone.utc
            )

        await db.commit()
        logger.info(
            "subscription_updated",
            subscription_id=str(subscription.id),
            status=subscription.status.value,
        )

    @staticmethod
    async def handle_subscription_deleted(
        db: AsyncSession, stripe_subscription: Dict[str, Any]
    ) -> None:
        """Handle customer.subscription.deleted webhook event."""
        subscription_id = stripe_subscription["id"]

        result = await db.execute(
            select(Subscription).where(
                Subscription.stripe_subscription_id == subscription_id
            )
        )
        subscription = result.scalar_one_or_none()

        if not subscription:
            logger.warning(
                "subscription_not_found", stripe_subscription_id=subscription_id
            )
            return

        # Downgrade to free tier
        subscription.tier = AccountTier.FREE_SCAN
        subscription.status = SubscriptionStatus.CANCELED
        subscription.canceled_at = datetime.now(timezone.utc)

        await db.commit()
        logger.info("subscription_canceled", subscription_id=str(subscription.id))

    @staticmethod
    async def handle_invoice_paid(db: AsyncSession, invoice: Dict[str, Any]) -> None:
        """Handle invoice.paid webhook event."""
        stripe_customer_id = invoice["customer"]

        # Find subscription by customer ID
        result = await db.execute(
            select(Subscription).where(
                Subscription.stripe_customer_id == stripe_customer_id
            )
        )
        subscription = result.scalar_one_or_none()

        if not subscription:
            logger.warning(
                "subscription_not_found_for_invoice",
                stripe_customer_id=stripe_customer_id,
            )
            return

        # Create invoice record
        new_invoice = Invoice(
            organization_id=subscription.organization_id,
            stripe_invoice_id=invoice["id"],
            amount_cents=invoice["amount_paid"],
            currency=invoice["currency"],
            status=invoice["status"],
            invoice_pdf_url=invoice.get("invoice_pdf"),
            hosted_invoice_url=invoice.get("hosted_invoice_url"),
            period_start=(
                datetime.fromtimestamp(invoice["period_start"], tz=timezone.utc)
                if invoice.get("period_start")
                else None
            ),
            period_end=(
                datetime.fromtimestamp(invoice["period_end"], tz=timezone.utc)
                if invoice.get("period_end")
                else None
            ),
            paid_at=datetime.now(timezone.utc),
        )
        db.add(new_invoice)
        await db.commit()

        logger.info(
            "invoice_recorded",
            invoice_id=str(new_invoice.id),
            amount=invoice["amount_paid"],
        )

    @staticmethod
    async def handle_invoice_payment_failed(
        db: AsyncSession, invoice: Dict[str, Any]
    ) -> None:
        """Handle invoice.payment_failed webhook event."""
        stripe_customer_id = invoice["customer"]

        result = await db.execute(
            select(Subscription).where(
                Subscription.stripe_customer_id == stripe_customer_id
            )
        )
        subscription = result.scalar_one_or_none()

        if subscription:
            subscription.status = SubscriptionStatus.PAST_DUE
            await db.commit()
            logger.warning("payment_failed", org_id=str(subscription.organization_id))

    @staticmethod
    async def get_subscription_info(
        db: AsyncSession, organization_id: UUID
    ) -> Dict[str, Any]:
        """Get subscription info for an organization."""
        result = await db.execute(
            select(Subscription).where(Subscription.organization_id == organization_id)
        )
        subscription = result.scalar_one_or_none()

        if not subscription:
            # Return default free tier info
            return {
                "tier": AccountTier.FREE_SCAN.value,
                "status": SubscriptionStatus.ACTIVE.value,
                "free_scan_used": False,
                "free_scan_expires_at": None,
                "can_scan": True,
                "included_accounts": 1,
                "additional_accounts": 0,
                "total_accounts_allowed": 1,
                "current_period_end": None,
                "cancel_at_period_end": False,
            }

        return {
            "id": str(subscription.id),
            "tier": subscription.tier.value,
            "status": subscription.status.value,
            "free_scan_used": subscription.free_scan_used,
            "free_scan_at": (
                subscription.free_scan_at.isoformat()
                if subscription.free_scan_at
                else None
            ),
            "free_scan_expires_at": (
                subscription.free_scan_expires_at.isoformat()
                if subscription.free_scan_expires_at
                else None
            ),
            "can_scan": subscription.can_scan,
            "included_accounts": subscription.included_accounts,
            "additional_accounts": subscription.additional_accounts,
            "total_accounts_allowed": subscription.total_accounts_allowed,
            "current_period_start": (
                subscription.current_period_start.isoformat()
                if subscription.current_period_start
                else None
            ),
            "current_period_end": (
                subscription.current_period_end.isoformat()
                if subscription.current_period_end
                else None
            ),
            "cancel_at_period_end": subscription.cancel_at_period_end,
            "has_stripe": bool(subscription.stripe_subscription_id),
        }

    @staticmethod
    async def get_invoices(
        db: AsyncSession, organization_id: UUID, limit: int = 10
    ) -> list:
        """Get recent invoices for an organization."""
        result = await db.execute(
            select(Invoice)
            .where(Invoice.organization_id == organization_id)
            .order_by(Invoice.created_at.desc())
            .limit(limit)
        )
        invoices = result.scalars().all()

        return [
            {
                "id": str(inv.id),
                "stripe_invoice_id": inv.stripe_invoice_id,
                "amount_cents": inv.amount_cents,
                "amount_dollars": inv.amount_dollars,
                "currency": inv.currency,
                "status": inv.status,
                "invoice_pdf_url": inv.invoice_pdf_url,
                "hosted_invoice_url": inv.hosted_invoice_url,
                "period_start": (
                    inv.period_start.isoformat() if inv.period_start else None
                ),
                "period_end": inv.period_end.isoformat() if inv.period_end else None,
                "paid_at": inv.paid_at.isoformat() if inv.paid_at else None,
                "created_at": inv.created_at.isoformat(),
            }
            for inv in invoices
        ]


stripe_service = StripeService()
