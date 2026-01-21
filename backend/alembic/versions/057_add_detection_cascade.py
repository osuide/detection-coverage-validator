"""Add CASCADE on Detection.cloud_account_id foreign key.

Revision ID: 057_detection_cascade
Revises: 056_api_key_updated
Create Date: 2026-01-15
"""

from alembic import op
from sqlalchemy import text

revision = "057_detection_cascade"
down_revision = "056_api_key_updated"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    # Step 1: Handle detection_mappings FK first (depends on detections.id)
    # Query actual constraint name from pg_catalog
    mapping_fk_result = conn.execute(text("""
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'detection_mappings'::regclass
        AND confrelid = 'detections'::regclass
        AND contype = 'f'
    """))
    mapping_fk_row = mapping_fk_result.fetchone()

    if mapping_fk_row:
        mapping_fk_name = mapping_fk_row[0]
        # Drop and recreate with CASCADE
        op.drop_constraint(mapping_fk_name, "detection_mappings", type_="foreignkey")
        op.create_foreign_key(
            mapping_fk_name,
            "detection_mappings",
            "detections",
            ["detection_id"],
            ["id"],
            ondelete="CASCADE",
        )

    # Step 2: Handle detections.cloud_account_id FK
    # Query actual constraint name from pg_catalog
    det_fk_result = conn.execute(text("""
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'detections'::regclass
        AND confrelid = 'cloud_accounts'::regclass
        AND contype = 'f'
    """))
    det_fk_row = det_fk_result.fetchone()

    if det_fk_row:
        det_fk_name = det_fk_row[0]
        op.drop_constraint(det_fk_name, "detections", type_="foreignkey")
        op.create_foreign_key(
            det_fk_name,
            "detections",
            "cloud_accounts",
            ["cloud_account_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    conn = op.get_bind()

    # Revert detection_mappings FK
    mapping_fk_result = conn.execute(text("""
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'detection_mappings'::regclass
        AND confrelid = 'detections'::regclass
        AND contype = 'f'
    """))
    mapping_fk_row = mapping_fk_result.fetchone()

    if mapping_fk_row:
        mapping_fk_name = mapping_fk_row[0]
        op.drop_constraint(mapping_fk_name, "detection_mappings", type_="foreignkey")
        op.create_foreign_key(
            mapping_fk_name,
            "detection_mappings",
            "detections",
            ["detection_id"],
            ["id"],
        )

    # Revert detections FK
    det_fk_result = conn.execute(text("""
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'detections'::regclass
        AND confrelid = 'cloud_accounts'::regclass
        AND contype = 'f'
    """))
    det_fk_row = det_fk_result.fetchone()

    if det_fk_row:
        det_fk_name = det_fk_row[0]
        op.drop_constraint(det_fk_name, "detections", type_="foreignkey")
        op.create_foreign_key(
            det_fk_name, "detections", "cloud_accounts", ["cloud_account_id"], ["id"]
        )
