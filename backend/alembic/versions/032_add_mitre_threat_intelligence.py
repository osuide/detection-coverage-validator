"""Add MITRE threat intelligence tables.

Revision ID: 032_add_mitre_threat_intelligence
Revises: 031_add_security_function
Create Date: 2025-12-23
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "032_add_mitre_threat_intelligence"
down_revision: Union[str, None] = "031_add_security_function"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create mitre_threat_groups table
    op.create_table(
        "mitre_threat_groups",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("stix_id", sa.String(255), unique=True, nullable=False),
        sa.Column("external_id", sa.String(32), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False, index=True),
        sa.Column("aliases", postgresql.JSONB, server_default="[]"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_revoked", sa.Boolean, server_default="false"),
        sa.Column("is_deprecated", sa.Boolean, server_default="false"),
        sa.Column("external_references", postgresql.JSONB, server_default="[]"),
        sa.Column("mitre_version", sa.String(16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    # GIN index for alias searching
    op.create_index(
        "ix_threat_groups_aliases_gin",
        "mitre_threat_groups",
        ["aliases"],
        postgresql_using="gin",
    )

    # Create mitre_campaigns table
    op.create_table(
        "mitre_campaigns",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("stix_id", sa.String(255), unique=True, nullable=False),
        sa.Column("external_id", sa.String(32), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False, index=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_revoked", sa.Boolean, server_default="false"),
        sa.Column("is_deprecated", sa.Boolean, server_default="false"),
        sa.Column("external_references", postgresql.JSONB, server_default="[]"),
        sa.Column("mitre_version", sa.String(16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # Create mitre_software table
    op.create_table(
        "mitre_software",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("stix_id", sa.String(255), unique=True, nullable=False),
        sa.Column("external_id", sa.String(32), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False, index=True),
        sa.Column("software_type", sa.String(32), nullable=False),  # malware or tool
        sa.Column("aliases", postgresql.JSONB, server_default="[]"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("platforms", postgresql.JSONB, server_default="[]"),
        sa.Column("is_revoked", sa.Boolean, server_default="false"),
        sa.Column("is_deprecated", sa.Boolean, server_default="false"),
        sa.Column("external_references", postgresql.JSONB, server_default="[]"),
        sa.Column("mitre_version", sa.String(16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_software_type",
        "mitre_software",
        ["software_type"],
    )

    # Create mitre_technique_relationships table
    op.create_table(
        "mitre_technique_relationships",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "technique_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("techniques.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "related_type", sa.String(32), nullable=False
        ),  # group, campaign, software
        sa.Column(
            "related_id", postgresql.UUID(as_uuid=True), nullable=False
        ),  # FK to respective table
        sa.Column("relationship_type", sa.String(64), nullable=True),  # uses, etc.
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("external_references", postgresql.JSONB, server_default="[]"),
        sa.Column("mitre_version", sa.String(16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_technique_relationships_technique",
        "mitre_technique_relationships",
        ["technique_id"],
    )
    op.create_index(
        "ix_technique_relationships_related",
        "mitre_technique_relationships",
        ["related_type", "related_id"],
    )
    op.create_unique_constraint(
        "uq_technique_relationship",
        "mitre_technique_relationships",
        ["technique_id", "related_type", "related_id"],
    )

    # Create mitre_sync_history table
    op.create_table(
        "mitre_sync_history",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status", sa.String(32), nullable=False
        ),  # pending, running, completed, failed
        sa.Column("mitre_version", sa.String(16), nullable=True),
        sa.Column("stix_version", sa.String(16), nullable=True),
        sa.Column(
            "triggered_by_admin_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("admin_users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("trigger_type", sa.String(32), nullable=False),  # manual, scheduled
        sa.Column("stats", postgresql.JSONB, server_default="{}"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_sync_history_status",
        "mitre_sync_history",
        ["status"],
    )
    op.create_index(
        "ix_sync_history_started",
        "mitre_sync_history",
        [sa.text("started_at DESC")],
    )

    # Create mitre_data_version table (single row)
    op.create_table(
        "mitre_data_version",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("mitre_version", sa.String(16), nullable=False),
        sa.Column("stix_version", sa.String(16), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "last_sync_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("mitre_sync_history.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("total_groups", sa.Integer, server_default="0"),
        sa.Column("total_campaigns", sa.Integer, server_default="0"),
        sa.Column("total_software", sa.Integer, server_default="0"),
        sa.Column("total_relationships", sa.Integer, server_default="0"),
        sa.Column("source_url", sa.String(512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("mitre_data_version")
    op.drop_table("mitre_sync_history")
    op.drop_table("mitre_technique_relationships")
    op.drop_table("mitre_software")
    op.drop_table("mitre_campaigns")
    op.drop_table("mitre_threat_groups")
