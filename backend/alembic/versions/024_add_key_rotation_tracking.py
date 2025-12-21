"""Add key rotation tracking to cloud_credentials.

M14: Adds key_rotated_at and key_rotation_count for GCP key rotation audit trail.

Revision ID: 024_add_key_rotation
Revises: 023_add_previous_token
Create Date: 2024-12-21

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "024_add_key_rotation"
down_revision = "023_add_previous_token"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "cloud_credentials",
        sa.Column("key_rotated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "cloud_credentials",
        sa.Column(
            "key_rotation_count", sa.Integer(), nullable=False, server_default="0"
        ),
    )


def downgrade():
    op.drop_column("cloud_credentials", "key_rotation_count")
    op.drop_column("cloud_credentials", "key_rotated_at")
