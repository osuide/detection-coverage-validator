"""Add processed_webhook_events table.

H11: Adds idempotency tracking for Stripe webhook events to prevent replay attacks.

Revision ID: 022_add_processed_webhook
Revises: 021_fix_cloud_account_unique
Create Date: 2024-12-21

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision = "022_add_processed_webhook"
down_revision = "021_fix_cloud_account_unique"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "processed_webhook_events",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("event_id", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column(
            "processed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade():
    op.drop_table("processed_webhook_events")
