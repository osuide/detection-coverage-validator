"""Add security_function field to detections.

Revision ID: 031_add_security_function
Revises: 030_fix_pre_technique_platforms
Create Date: 2025-12-23

Adds NIST CSF security function classification to detections.
This explains what security purpose each detection serves:
- detect: Threat detection - maps to MITRE ATT&CK techniques
- protect: Preventive controls - access controls, encryption, MFA
- identify: Visibility controls - logging, monitoring, posture
- recover: Recovery controls - backup, DR, versioning
- operational: Non-security controls - tagging, cost, performance
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "031_add_security_function"
down_revision = "030_fix_pre_technique_platforms"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create the enum type
    security_function_enum = sa.Enum(
        "detect",
        "protect",
        "identify",
        "recover",
        "operational",
        name="security_function",
    )
    security_function_enum.create(op.get_bind(), checkfirst=True)

    # Add security_function column with default 'operational'
    # We use 'operational' as default because existing unmapped detections
    # will be reclassified by the classifier on next scan
    op.add_column(
        "detections",
        sa.Column(
            "security_function",
            sa.Enum(
                "detect",
                "protect",
                "identify",
                "recover",
                "operational",
                name="security_function",
            ),
            nullable=False,
            server_default="operational",
        ),
    )

    # Add index for filtering by security function
    op.create_index(
        "ix_detections_security_function",
        "detections",
        ["security_function"],
    )

    # Update existing detections that have MITRE mappings to 'detect'
    # This ensures MITRE-mapped detections are correctly classified
    op.execute(
        """
        UPDATE detections d
        SET security_function = 'detect'
        WHERE EXISTS (
            SELECT 1 FROM detection_mappings dm
            WHERE dm.detection_id = d.id
        )
        """
    )


def downgrade() -> None:
    op.drop_index("ix_detections_security_function", table_name="detections")
    op.drop_column("detections", "security_function")

    # Drop the enum type
    sa.Enum(name="security_function").drop(op.get_bind(), checkfirst=True)
