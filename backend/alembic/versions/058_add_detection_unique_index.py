"""Add unique index on Detection(cloud_account_id, source_arn).

Revision ID: 058_detection_unique
Revises: 057_detection_cascade
Create Date: 2026-01-15
"""

from alembic import op
from sqlalchemy import text

revision = "058_detection_unique"
down_revision = "057_detection_cascade"
branch_labels = None
depends_on = None

INDEX_NAME = "ix_detections_account_arn_unique"


def upgrade() -> None:
    # First, clean up any existing duplicates (keep oldest by discovered_at, then by id for determinism)
    op.execute(text("""
        WITH duplicates AS (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY cloud_account_id, source_arn
                       ORDER BY discovered_at ASC, id ASC
                   ) as rn
            FROM detections
            WHERE cloud_account_id IS NOT NULL
              AND source_arn IS NOT NULL
        )
        DELETE FROM detections
        WHERE id IN (SELECT id FROM duplicates WHERE rn > 1)
    """))

    # Create partial unique INDEX (not constraint - PostgreSQL requires INDEX for WHERE clause)
    op.execute(text(f"""
        CREATE UNIQUE INDEX {INDEX_NAME}
        ON detections (cloud_account_id, source_arn)
        WHERE cloud_account_id IS NOT NULL AND source_arn IS NOT NULL
    """))


def downgrade() -> None:
    op.execute(text(f"DROP INDEX IF EXISTS {INDEX_NAME}"))
