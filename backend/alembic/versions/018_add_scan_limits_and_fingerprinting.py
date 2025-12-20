"""Add scan limits and device fingerprinting for abuse prevention.

Revision ID: 018
Revises: 017
Create Date: 2024-12-20

Adds:
- device_fingerprints table for storing fingerprint hashes
- device_fingerprint_associations table linking fingerprints to users/orgs
- organisation_scan_tracking table for weekly scan limits
- weekly_scans_allowed column to subscriptions table
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create device_fingerprints table
    op.create_table(
        "device_fingerprints",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "fingerprint_hash",
            sa.String(64),
            nullable=False,
            unique=True,
            index=True,
        ),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "associated_user_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "associated_org_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "abuse_score",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "is_flagged",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
        sa.Column("flag_reason", sa.String(255), nullable=True),
        sa.Column("admin_notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Create indexes for device_fingerprints
    op.create_index(
        "idx_fingerprints_flagged",
        "device_fingerprints",
        ["is_flagged"],
    )
    op.create_index(
        "idx_fingerprints_abuse_score",
        "device_fingerprints",
        ["abuse_score"],
    )

    # Create device_fingerprint_associations table
    op.create_table(
        "device_fingerprint_associations",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "fingerprint_id",
            UUID(as_uuid=True),
            sa.ForeignKey("device_fingerprints.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column("ip_address", sa.String(45), nullable=True),  # IPv6 compatible
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("seen_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("fingerprint_id", "user_id", name="uq_fingerprint_user"),
    )

    # Create organisation_scan_tracking table
    op.create_table(
        "organisation_scan_tracking",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
            index=True,
        ),
        sa.Column(
            "weekly_scan_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "week_start_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "last_scan_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "total_scans",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Add weekly_scans_allowed to subscriptions table
    # NULL = unlimited (paid tiers), positive integer = limit (free tier)
    op.add_column(
        "subscriptions",
        sa.Column("weekly_scans_allowed", sa.Integer(), nullable=True),
    )

    # Add scan_reset_interval_days to subscriptions table
    op.add_column(
        "subscriptions",
        sa.Column(
            "scan_reset_interval_days",
            sa.Integer(),
            nullable=False,
            server_default="7",
        ),
    )


def downgrade() -> None:
    # Remove columns from subscriptions
    op.drop_column("subscriptions", "scan_reset_interval_days")
    op.drop_column("subscriptions", "weekly_scans_allowed")

    # Drop tables
    op.drop_table("organisation_scan_tracking")
    op.drop_table("device_fingerprint_associations")

    # Drop indexes first
    op.drop_index("idx_fingerprints_abuse_score", table_name="device_fingerprints")
    op.drop_index("idx_fingerprints_flagged", table_name="device_fingerprints")

    op.drop_table("device_fingerprints")
