"""Add fraud prevention tables and fields.

Revision ID: 033_fraud_prevention
Revises: 032_add_mitre_threat_intelligence
Create Date: 2025-12-24

Adds fraud prevention infrastructure:
- global_account_hash on cloud_accounts: SHA-256 hash for duplicate detection
- cloud_account_global_registry: Tracks free-tier cloud account registrations globally
- free_email_cloud_account_bindings: Permanently binds emails to cloud accounts on free tier

This prevents:
1. Same cloud account being connected to multiple free-tier organisations
2. Email cycling through different cloud accounts on free tier
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PGUUID

# revision identifiers, used by Alembic.
revision = "033_fraud_prevention"
down_revision = "032_add_mitre_threat_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add global_account_hash to cloud_accounts for duplicate detection
    op.add_column(
        "cloud_accounts",
        sa.Column("global_account_hash", sa.String(64), nullable=True, index=True),
    )

    # Create global tracking table for free-tier cloud accounts
    op.create_table(
        "cloud_account_global_registry",
        sa.Column(
            "id",
            PGUUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "account_hash", sa.String(64), nullable=False, unique=True, index=True
        ),
        sa.Column("provider", sa.String(10), nullable=False),  # 'aws' or 'gcp'
        sa.Column("first_registered_org_id", PGUUID(as_uuid=True), nullable=False),
        sa.Column("first_registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("registration_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column(
            "is_free_tier_locked", sa.Boolean, nullable=False, server_default="true"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
    )

    # Create email-to-cloud-account binding table
    # Prevents cloud account cycling on free tier
    op.create_table(
        "free_email_cloud_account_bindings",
        sa.Column(
            "id",
            PGUUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("email_hash", sa.String(64), nullable=False, index=True),
        sa.Column("cloud_account_hash", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(10), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("email_hash", name="uq_email_cloud_binding"),
    )

    # Backfill existing cloud accounts with hashes
    op.execute(
        """
        UPDATE cloud_accounts
        SET global_account_hash = encode(
            sha256((provider || ':' || account_id)::bytea),
            'hex'
        )
        WHERE global_account_hash IS NULL
    """
    )

    # Make column non-nullable after backfill
    op.alter_column("cloud_accounts", "global_account_hash", nullable=False)

    # Backfill global registry for existing FREE tier cloud accounts
    # This prevents existing free accounts from being locked out
    op.execute(
        """
        INSERT INTO cloud_account_global_registry (
            id, account_hash, provider, first_registered_org_id,
            first_registered_at, registration_count, is_free_tier_locked,
            created_at, updated_at
        )
        SELECT
            gen_random_uuid(),
            ca.global_account_hash,
            ca.provider,
            ca.organization_id,
            ca.created_at,
            1,
            true,
            NOW(),
            NOW()
        FROM cloud_accounts ca
        JOIN subscriptions s ON s.organization_id = ca.organization_id
        WHERE s.tier = 'free'
        ON CONFLICT (account_hash) DO NOTHING
    """
    )


def downgrade() -> None:
    op.drop_table("free_email_cloud_account_bindings")
    op.drop_table("cloud_account_global_registry")
    op.drop_column("cloud_accounts", "global_account_hash")
