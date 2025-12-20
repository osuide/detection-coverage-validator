"""Add cloud organizations support

Revision ID: 016
Revises: 015
Create Date: 2024-12-20

Adds support for AWS Organisations and GCP Organisations:
- cloud_organizations table for tracking org connections
- cloud_organization_members table for tracking discovered accounts
- Updates cloud_accounts to link to cloud_organization
- Updates detections to support org-level scope

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "016"
down_revision: Union[str, None] = "015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create enums for cloud organization status
    cloud_organization_status = postgresql.ENUM(
        "discovered",
        "connecting",
        "connected",
        "partial",
        "error",
        "disconnected",
        name="cloud_organization_status",
        create_type=False,
    )
    cloud_organization_status.create(op.get_bind(), checkfirst=True)

    cloud_organization_member_status = postgresql.ENUM(
        "discovered",
        "pending",
        "connecting",
        "connected",
        "skipped",
        "error",
        "suspended",
        name="cloud_organization_member_status",
        create_type=False,
    )
    cloud_organization_member_status.create(op.get_bind(), checkfirst=True)

    detection_scope = postgresql.ENUM(
        "account",
        "organization",
        name="detection_scope",
        create_type=False,
    )
    detection_scope.create(op.get_bind(), checkfirst=True)

    # Create cloud_organizations table
    op.create_table(
        "cloud_organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "provider",
            sa.Enum("aws", "gcp", name="cloud_provider", create_type=False),
            nullable=False,
        ),
        sa.Column("cloud_org_id", sa.String(128), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("root_email", sa.String(255), nullable=True),
        sa.Column("master_account_id", sa.String(64), nullable=True),
        sa.Column(
            "status",
            cloud_organization_status,
            nullable=False,
            server_default="discovered",
        ),
        sa.Column("credentials_arn", sa.String(512), nullable=True),
        sa.Column("delegated_admins", postgresql.JSONB, nullable=True),
        sa.Column("org_metadata", postgresql.JSONB, nullable=True),
        sa.Column("total_accounts_discovered", sa.Integer, server_default="0"),
        sa.Column("total_accounts_connected", sa.Integer, server_default="0"),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("connected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )

    # Create unique constraint on organization_id + cloud_org_id
    op.create_unique_constraint(
        "uq_cloud_org_per_tenant",
        "cloud_organizations",
        ["organization_id", "cloud_org_id"],
    )

    # Create cloud_organization_members table
    op.create_table(
        "cloud_organization_members",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "cloud_organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cloud_organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "cloud_account_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cloud_accounts.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column("member_account_id", sa.String(64), nullable=False, index=True),
        sa.Column("member_name", sa.String(255), nullable=False),
        sa.Column("member_email", sa.String(255), nullable=True),
        sa.Column("hierarchy_path", sa.String(1024), nullable=True),
        sa.Column("parent_id", sa.String(128), nullable=True),
        sa.Column(
            "status",
            cloud_organization_member_status,
            nullable=False,
            server_default="discovered",
        ),
        sa.Column("join_method", sa.String(64), nullable=True),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lifecycle_state", sa.String(64), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("member_metadata", postgresql.JSONB, nullable=True),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("connected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )

    # Create unique constraint on cloud_organization_id + member_account_id
    op.create_unique_constraint(
        "uq_member_per_cloud_org",
        "cloud_organization_members",
        ["cloud_organization_id", "member_account_id"],
    )

    # Add cloud_organization_id to cloud_accounts
    op.add_column(
        "cloud_accounts",
        sa.Column(
            "cloud_organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cloud_organizations.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_cloud_accounts_cloud_organization_id",
        "cloud_accounts",
        ["cloud_organization_id"],
    )

    # Add org-level detection fields to detections table
    op.add_column(
        "detections",
        sa.Column(
            "cloud_organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cloud_organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.add_column(
        "detections",
        sa.Column(
            "detection_scope",
            detection_scope,
            nullable=False,
            server_default="account",
        ),
    )
    op.add_column(
        "detections",
        sa.Column(
            "applies_to_all_accounts",
            sa.Boolean,
            nullable=False,
            server_default="true",
        ),
    )
    op.add_column(
        "detections",
        sa.Column(
            "applies_to_account_ids",
            postgresql.JSONB,
            nullable=True,
        ),
    )

    # Create indexes for detection org fields
    op.create_index(
        "ix_detections_cloud_organization_id",
        "detections",
        ["cloud_organization_id"],
    )
    op.create_index(
        "ix_detections_detection_scope",
        "detections",
        ["detection_scope"],
    )

    # Make cloud_account_id nullable (for org-level detections)
    op.alter_column(
        "detections",
        "cloud_account_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
    )

    # Add check constraint for detection scope consistency
    op.execute(
        """
        ALTER TABLE detections
        ADD CONSTRAINT ck_detection_scope_consistency
        CHECK (
            (detection_scope = 'account' AND cloud_account_id IS NOT NULL) OR
            (detection_scope = 'organization' AND cloud_organization_id IS NOT NULL)
        )
    """
    )


def downgrade() -> None:
    # Remove check constraint
    op.execute(
        "ALTER TABLE detections DROP CONSTRAINT IF EXISTS ck_detection_scope_consistency"
    )

    # Make cloud_account_id non-nullable again (will fail if org-level detections exist)
    op.alter_column(
        "detections",
        "cloud_account_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
    )

    # Drop detection org fields
    op.drop_index("ix_detections_detection_scope", table_name="detections")
    op.drop_index("ix_detections_cloud_organization_id", table_name="detections")
    op.drop_column("detections", "applies_to_account_ids")
    op.drop_column("detections", "applies_to_all_accounts")
    op.drop_column("detections", "detection_scope")
    op.drop_column("detections", "cloud_organization_id")

    # Drop cloud_organization_id from cloud_accounts
    op.drop_index(
        "ix_cloud_accounts_cloud_organization_id", table_name="cloud_accounts"
    )
    op.drop_column("cloud_accounts", "cloud_organization_id")

    # Drop cloud_organization_members table
    op.drop_constraint(
        "uq_member_per_cloud_org", "cloud_organization_members", type_="unique"
    )
    op.drop_table("cloud_organization_members")

    # Drop cloud_organizations table
    op.drop_constraint("uq_cloud_org_per_tenant", "cloud_organizations", type_="unique")
    op.drop_table("cloud_organizations")

    # Drop enums
    op.execute("DROP TYPE IF EXISTS detection_scope")
    op.execute("DROP TYPE IF EXISTS cloud_organization_member_status")
    op.execute("DROP TYPE IF EXISTS cloud_organization_status")
