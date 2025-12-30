"""Add cloud credentials table.

Revision ID: 011
Revises: 010
Create Date: 2024-12-18

Adds secure storage for cloud provider credentials:
- AWS IAM Role ARN and External ID (no secrets stored)
- GCP WIF configuration (no secrets stored - keyless auth)
- Permission tracking and validation status
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade():
    # Create credential type enum
    op.execute(
        """
        CREATE TYPE credential_type AS ENUM (
            'aws_iam_role',
            'gcp_workload_identity'
        )
    """
    )

    # Create credential status enum
    op.execute(
        """
        CREATE TYPE credential_status AS ENUM (
            'pending',
            'valid',
            'invalid',
            'expired',
            'permission_error'
        )
    """
    )

    # Create cloud_credentials table
    op.execute(
        """
        CREATE TABLE cloud_credentials (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            cloud_account_id UUID NOT NULL UNIQUE REFERENCES cloud_accounts(id) ON DELETE CASCADE,
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

            -- Credential type and status
            credential_type credential_type NOT NULL,
            status credential_status NOT NULL DEFAULT 'pending',
            status_message TEXT,
            last_validated_at TIMESTAMP WITH TIME ZONE,

            -- AWS IAM Role fields (not secrets)
            aws_role_arn VARCHAR(512),
            aws_external_id VARCHAR(64),

            -- GCP fields (not secrets)
            gcp_project_id VARCHAR(64),
            gcp_service_account_email VARCHAR(255),
            gcp_workload_identity_pool VARCHAR(512),

            -- Encrypted GCP service account key (only for SA key type)
            encrypted_key TEXT,

            -- Permission tracking
            granted_permissions JSONB,
            missing_permissions JSONB,

            -- Metadata
            created_by UUID REFERENCES users(id),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    """
    )

    # Create indexes
    op.execute(
        "CREATE INDEX ix_cloud_credentials_org ON cloud_credentials(organization_id)"
    )
    op.execute(
        "CREATE INDEX ix_cloud_credentials_account ON cloud_credentials(cloud_account_id)"
    )
    op.execute("CREATE INDEX ix_cloud_credentials_status ON cloud_credentials(status)")


def downgrade():
    # Drop indexes
    op.execute("DROP INDEX IF EXISTS ix_cloud_credentials_status")
    op.execute("DROP INDEX IF EXISTS ix_cloud_credentials_account")
    op.execute("DROP INDEX IF EXISTS ix_cloud_credentials_org")

    # Drop table
    op.execute("DROP TABLE IF EXISTS cloud_credentials")

    # Drop enums
    op.execute("DROP TYPE IF EXISTS credential_status")
    op.execute("DROP TYPE IF EXISTS credential_type")
