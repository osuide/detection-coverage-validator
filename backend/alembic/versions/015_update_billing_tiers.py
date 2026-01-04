"""Update billing tiers for new simplified pricing model

Revision ID: 015
Revises: 014
Create Date: 2024-12-20

New billing model:
- FREE: 1 account, basic features ($0)
- INDIVIDUAL: Up to 6 accounts, full account-level features ($29/month)
- PRO: Up to 500 accounts, organisation features ($250/month)
- ENTERPRISE: Unlimited, SSO, dedicated support (custom pricing)

Legacy tiers (deprecated but supported):
- free_scan -> FREE
- subscriber -> INDIVIDUAL (or PRO if >6 accounts)

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "015"
down_revision: Union[str, None] = "014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create backup of existing subscription data for safety
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS subscriptions_backup_015 AS
        SELECT * FROM subscriptions;
    """
    )

    # Add new enum values to account_tier
    # Note: PostgreSQL requires a COMMIT after adding enum values before they can be used.
    # We must commit the current transaction, add the values outside a transaction,
    # then start a new transaction for the rest of the migration.
    op.execute("COMMIT")

    # Add enum values outside transaction (required for PostgreSQL enum safety)
    op.execute("ALTER TYPE account_tier ADD VALUE IF NOT EXISTS 'free'")
    op.execute("ALTER TYPE account_tier ADD VALUE IF NOT EXISTS 'individual'")
    op.execute("ALTER TYPE account_tier ADD VALUE IF NOT EXISTS 'pro'")

    # Start new transaction for the rest of the migration
    op.execute("BEGIN")

    # Add new columns to subscriptions table for the simplified tier model
    # max_accounts: NULL = unlimited (Enterprise), otherwise the limit
    op.execute(
        """
        ALTER TABLE subscriptions
        ADD COLUMN IF NOT EXISTS max_accounts INTEGER;
    """
    )

    # max_team_members: NULL = unlimited (Enterprise), otherwise the limit
    op.execute(
        """
        ALTER TABLE subscriptions
        ADD COLUMN IF NOT EXISTS max_team_members INTEGER;
    """
    )

    # org_features_enabled: Whether organisation features are available
    op.execute(
        """
        ALTER TABLE subscriptions
        ADD COLUMN IF NOT EXISTS org_features_enabled BOOLEAN NOT NULL DEFAULT FALSE;
    """
    )

    # history_retention_days: NULL = unlimited, otherwise days to retain
    op.execute(
        """
        ALTER TABLE subscriptions
        ADD COLUMN IF NOT EXISTS history_retention_days INTEGER;
    """
    )

    # tier_config: JSONB for storing tier-specific configuration overrides
    op.execute(
        """
        ALTER TABLE subscriptions
        ADD COLUMN IF NOT EXISTS tier_config JSONB;
    """
    )

    # Add audit log actions for tier changes
    # Note: These also need COMMIT/BEGIN pattern for PostgreSQL enum safety
    op.execute("COMMIT")
    op.execute(
        "ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'subscription.tier_changed'"
    )
    op.execute(
        "ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'subscription.tier_migrated'"
    )
    op.execute("BEGIN")

    # Data migration: Set defaults for existing subscriptions based on their current tier

    # free_scan -> max_accounts=1, max_team_members=1, history_retention_days=7
    op.execute(
        """
        UPDATE subscriptions
        SET
            max_accounts = 1,
            max_team_members = 1,
            org_features_enabled = FALSE,
            history_retention_days = 7
        WHERE tier = 'free_scan'
        AND max_accounts IS NULL;
    """
    )

    # subscriber -> Calculate max_accounts from included + additional, minimum of 3
    # Use GREATEST to handle edge case where included_accounts could be 0
    op.execute(
        """
        UPDATE subscriptions
        SET
            max_accounts = GREATEST(
                COALESCE(NULLIF(included_accounts, 0), 3) + COALESCE(additional_accounts, 0),
                3
            ),
            max_team_members = 3,
            org_features_enabled = TRUE,
            history_retention_days = NULL
        WHERE tier = 'subscriber'
        AND max_accounts IS NULL;
    """
    )

    # enterprise -> max_accounts=NULL (unlimited), max_team_members=NULL (unlimited)
    # Use a more robust WHERE clause that handles fresh columns
    op.execute(
        """
        UPDATE subscriptions
        SET
            max_accounts = NULL,
            max_team_members = NULL,
            org_features_enabled = TRUE,
            history_retention_days = NULL
        WHERE tier = 'enterprise';
    """
    )

    # Add index for org_features_enabled (useful for filtering)
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_subscriptions_org_features
        ON subscriptions(org_features_enabled)
        WHERE org_features_enabled = TRUE;
    """
    )

    # Validation: Ensure all non-enterprise subscriptions have max_accounts set
    op.execute(
        """
        DO $$
        DECLARE
            invalid_count INTEGER;
        BEGIN
            SELECT COUNT(*) INTO invalid_count
            FROM subscriptions
            WHERE max_accounts IS NULL
            AND tier NOT IN ('enterprise');

            IF invalid_count > 0 THEN
                RAISE WARNING 'Migration warning: % non-enterprise subscriptions have NULL max_accounts', invalid_count;
            END IF;
        END $$;
    """
    )


def downgrade() -> None:
    # Drop the index first
    op.execute("DROP INDEX IF EXISTS idx_subscriptions_org_features")

    # Remove new columns
    op.execute(
        """
        ALTER TABLE subscriptions DROP COLUMN IF EXISTS tier_config;
    """
    )
    op.execute(
        """
        ALTER TABLE subscriptions DROP COLUMN IF EXISTS history_retention_days;
    """
    )
    op.execute(
        """
        ALTER TABLE subscriptions DROP COLUMN IF EXISTS org_features_enabled;
    """
    )
    op.execute(
        """
        ALTER TABLE subscriptions DROP COLUMN IF EXISTS max_team_members;
    """
    )
    op.execute(
        """
        ALTER TABLE subscriptions DROP COLUMN IF EXISTS max_accounts;
    """
    )

    # Restore from backup if needed (manual step)
    # The backup table subscriptions_backup_015 is preserved

    # Note: enum values cannot be easily removed from PostgreSQL
    # The new tier values (free, individual, pro) will remain in the enum
    # This is safe as they won't be used after downgrade
