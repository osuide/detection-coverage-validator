"""Add azure_services to cloud_context JSONB.

Revision ID: 060_add_azure_svc
Revises: 059_add_azure_support
Create Date: 2026-01-25

Data migration to update cloud_context column with azure_services
from the updated compliance JSON files.
"""

import json
from pathlib import Path

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "060_add_azure_svc"
down_revision = "059_azure_support"
branch_labels = None
depends_on = None

# Data directory relative to this migration file
DATA_DIR = Path(__file__).parent.parent.parent / "app" / "data" / "compliance_mappings"


def upgrade() -> None:
    """Update cloud_context with azure_services for compliance controls."""
    conn = op.get_bind()

    # Map framework_id to JSON file
    framework_files = {
        "nist-800-53-r5": "nist_800_53_r5.json",
        "cis-controls-v8": "cis_controls_v8.json",
    }

    for framework_id, filename in framework_files.items():
        file_path = DATA_DIR / filename
        if not file_path.exists():
            print(f"Warning: {file_path} not found, skipping")
            continue

        # Load JSON data
        with open(file_path) as f:
            data = json.load(f)

        # Get framework ID from database
        result = conn.execute(
            sa.text("SELECT id FROM compliance_frameworks WHERE framework_id = :fid"),
            {"fid": framework_id},
        )
        row = result.fetchone()
        if not row:
            print(f"Warning: Framework {framework_id} not found in database")
            continue

        framework_uuid = row[0]
        updated_count = 0

        # Update each control's cloud_context
        for control_data in data["controls"]:
            control_id = control_data["control_id"]
            cloud_context = control_data.get("cloud_context")

            if cloud_context and "azure_services" in cloud_context:
                # Update the cloud_context JSONB column
                conn.execute(
                    sa.text("""
                        UPDATE compliance_controls
                        SET cloud_context = :ctx
                        WHERE framework_id = :fid AND control_id = :cid
                        """),
                    {
                        "ctx": json.dumps(cloud_context),
                        "fid": framework_uuid,
                        "cid": control_id,
                    },
                )
                updated_count += 1

        print(f"Updated {updated_count} controls for {framework_id}")


def downgrade() -> None:
    """Remove azure_services from cloud_context.

    Note: This is a data migration. Downgrade removes azure_services
    but preserves other cloud_context fields.
    """
    conn = op.get_bind()

    # Remove azure_services key from all cloud_context JSONB
    conn.execute(sa.text("""
            UPDATE compliance_controls
            SET cloud_context = cloud_context - 'azure_services'
            WHERE cloud_context ? 'azure_services'
            """))
