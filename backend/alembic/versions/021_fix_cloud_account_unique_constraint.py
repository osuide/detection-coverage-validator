"""Fix cloud_accounts unique constraint.

Changes account_id from globally unique to unique per organisation.
This allows multiple organisations to connect to the same AWS/GCP account.

Revision ID: 021_fix_cloud_account_unique
Revises: 020_add_compliance_frameworks
Create Date: 2024-12-21

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "021_fix_cloud_account_unique"
down_revision = "020_add_compliance_frameworks"
branch_labels = None
depends_on = None


def upgrade():
    # Drop the global unique constraint on account_id
    op.drop_constraint(
        "cloud_accounts_account_id_key", "cloud_accounts", type_="unique"
    )

    # Create composite unique constraint: organization_id + account_id
    # This allows the same cloud account to be connected by different organisations
    op.create_unique_constraint(
        "uq_cloud_accounts_org_account",
        "cloud_accounts",
        ["organization_id", "account_id"],
    )


def downgrade():
    # Drop the composite constraint
    op.drop_constraint(
        "uq_cloud_accounts_org_account", "cloud_accounts", type_="unique"
    )

    # Restore global unique constraint on account_id
    # Note: This will fail if duplicate account_ids exist across organisations
    op.create_unique_constraint(
        "cloud_accounts_account_id_key", "cloud_accounts", ["account_id"]
    )
