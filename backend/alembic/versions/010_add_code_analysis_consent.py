"""Add code analysis consent table.

Revision ID: 010
Revises: 009
Create Date: 2024-12-18

Adds the code_analysis_consents table for tracking user consent
for the enhanced code analysis feature (Lambda code parsing,
CloudFormation template analysis).
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade():
    # Create code analysis scope enum
    op.execute("CREATE TYPE code_analysis_scope AS ENUM ('lambda_functions', 'cloudformation', 'terraform', 'all')")

    # Create code_analysis_consents table
    op.execute("""
        CREATE TABLE code_analysis_consents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,

            -- Consent details
            consent_given BOOLEAN NOT NULL DEFAULT FALSE,
            consent_given_by UUID REFERENCES users(id),
            consent_given_at TIMESTAMP WITH TIME ZONE,

            -- Scope of consent
            scope code_analysis_scope NOT NULL DEFAULT 'all',

            -- What they acknowledged
            acknowledged_risks BOOLEAN NOT NULL DEFAULT FALSE,
            acknowledged_data_handling BOOLEAN NOT NULL DEFAULT FALSE,

            -- Revocation
            consent_revoked BOOLEAN NOT NULL DEFAULT FALSE,
            consent_revoked_by UUID REFERENCES users(id),
            consent_revoked_at TIMESTAMP WITH TIME ZONE,
            revocation_reason TEXT,

            -- Timestamps
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

            -- Unique constraint per account
            UNIQUE(cloud_account_id)
        )
    """)

    # Create indexes
    op.execute("CREATE INDEX ix_code_analysis_consents_org ON code_analysis_consents(organization_id)")
    op.execute("CREATE INDEX ix_code_analysis_consents_account ON code_analysis_consents(cloud_account_id)")
    op.execute("CREATE INDEX ix_code_analysis_consents_active ON code_analysis_consents(cloud_account_id) WHERE consent_given = TRUE AND consent_revoked = FALSE")


def downgrade():
    # Drop indexes
    op.execute("DROP INDEX IF EXISTS ix_code_analysis_consents_active")
    op.execute("DROP INDEX IF EXISTS ix_code_analysis_consents_account")
    op.execute("DROP INDEX IF EXISTS ix_code_analysis_consents_org")

    # Drop table
    op.execute("DROP TABLE IF EXISTS code_analysis_consents")

    # Drop enum
    op.execute("DROP TYPE IF EXISTS code_analysis_scope")
