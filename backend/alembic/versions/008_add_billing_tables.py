"""Add billing and subscription tables

Revision ID: 008
Revises: 007
Create Date: 2025-12-18

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create account_tier enum
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE account_tier AS ENUM ('free_scan', 'subscriber', 'enterprise');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )

    # Create subscription_status enum
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE subscription_status AS ENUM ('active', 'past_due', 'canceled', 'unpaid');
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )

    # Create subscriptions table using raw SQL to avoid SQLAlchemy trying to create enums again
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS subscriptions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            stripe_customer_id VARCHAR(255),
            stripe_subscription_id VARCHAR(255),
            tier account_tier NOT NULL DEFAULT 'free_scan',
            status subscription_status NOT NULL DEFAULT 'active',
            free_scan_used BOOLEAN NOT NULL DEFAULT FALSE,
            free_scan_at TIMESTAMP WITH TIME ZONE,
            free_scan_expires_at TIMESTAMP WITH TIME ZONE,
            included_accounts INTEGER NOT NULL DEFAULT 1,
            additional_accounts INTEGER NOT NULL DEFAULT 0,
            current_period_start TIMESTAMP WITH TIME ZONE,
            current_period_end TIMESTAMP WITH TIME ZONE,
            cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
            canceled_at TIMESTAMP WITH TIME ZONE,
            metadata JSONB,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_subscription_org UNIQUE (organization_id)
        )
    """
    )

    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_subscriptions_org ON subscriptions(organization_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe ON subscriptions(stripe_subscription_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_subscriptions_tier ON subscriptions(tier)"
    )

    # Create invoices table
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS invoices (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            stripe_invoice_id VARCHAR(255) NOT NULL,
            amount_cents INTEGER NOT NULL,
            currency VARCHAR(3) NOT NULL DEFAULT 'usd',
            status VARCHAR(50),
            invoice_pdf_url TEXT,
            hosted_invoice_url TEXT,
            period_start TIMESTAMP WITH TIME ZONE,
            period_end TIMESTAMP WITH TIME ZONE,
            paid_at TIMESTAMP WITH TIME ZONE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        )
    """
    )

    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_invoices_org ON invoices(organization_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_invoices_stripe ON invoices(stripe_invoice_id)"
    )

    # Add audit log actions for billing
    op.execute(
        """
        DO $$ BEGIN
            ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'subscription.created';
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )
    op.execute(
        """
        DO $$ BEGIN
            ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'subscription.upgraded';
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )
    op.execute(
        """
        DO $$ BEGIN
            ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'subscription.canceled';
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )
    op.execute(
        """
        DO $$ BEGIN
            ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'free_scan.used';
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_invoices_stripe")
    op.execute("DROP INDEX IF EXISTS idx_invoices_org")
    op.execute("DROP TABLE IF EXISTS invoices")

    op.execute("DROP INDEX IF EXISTS idx_subscriptions_tier")
    op.execute("DROP INDEX IF EXISTS idx_subscriptions_stripe")
    op.execute("DROP INDEX IF EXISTS idx_subscriptions_org")
    op.execute("DROP TABLE IF EXISTS subscriptions")

    # Note: enum types and values cannot be easily removed
    # They are left in place for safety
