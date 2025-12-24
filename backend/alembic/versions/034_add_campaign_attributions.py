"""Add campaign attribution relationships.

Revision ID: 034_campaign_attributions
Revises: 033_fraud_prevention
Create Date: 2025-12-24

Adds campaign-to-group attribution table to store MITRE's
'attributed-to' relationships: which threat groups conducted
which campaigns.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB

# revision identifiers, used by Alembic.
revision = "034_campaign_attributions"
down_revision = "033_fraud_prevention"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create campaign attributions table
    op.create_table(
        "mitre_campaign_attributions",
        sa.Column("id", PGUUID(as_uuid=True), primary_key=True),
        sa.Column(
            "campaign_id",
            PGUUID(as_uuid=True),
            sa.ForeignKey("mitre_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "group_id",
            PGUUID(as_uuid=True),
            sa.ForeignKey("mitre_threat_groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("external_references", JSONB(), server_default="[]"),
        sa.Column("mitre_version", sa.String(16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # Create indexes for efficient lookups
    op.create_index(
        "ix_mitre_campaign_attributions_campaign_id",
        "mitre_campaign_attributions",
        ["campaign_id"],
    )
    op.create_index(
        "ix_mitre_campaign_attributions_group_id",
        "mitre_campaign_attributions",
        ["group_id"],
    )

    # Unique constraint to prevent duplicate attributions
    op.create_unique_constraint(
        "uq_campaign_group_attribution",
        "mitre_campaign_attributions",
        ["campaign_id", "group_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_campaign_group_attribution", "mitre_campaign_attributions", type_="unique"
    )
    op.drop_index(
        "ix_mitre_campaign_attributions_group_id",
        table_name="mitre_campaign_attributions",
    )
    op.drop_index(
        "ix_mitre_campaign_attributions_campaign_id",
        table_name="mitre_campaign_attributions",
    )
    op.drop_table("mitre_campaign_attributions")
