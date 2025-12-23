"""Fix PRE technique platforms.

Update Reconnaissance (TA0043) and Resource Development (TA0042) techniques
to have platform ["PRE"] instead of cloud platforms, as they are pre-compromise
tactics not part of the MITRE ATT&CK Cloud Matrix.

Revision ID: 030_fix_pre_technique_platforms
Revises: 029_add_service_awareness
Create Date: 2024-12-23
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "030_fix_pre_technique_platforms"
down_revision = "029_add_service_awareness"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Update PRE techniques to have correct platform."""
    # Update techniques in Reconnaissance (TA0043) and Resource Development (TA0042)
    # to have platform ["PRE"] instead of cloud platforms
    op.execute(
        """
        UPDATE techniques
        SET platforms = '["PRE"]'::jsonb
        WHERE tactic_id IN (
            SELECT id FROM tactics WHERE tactic_id IN ('TA0043', 'TA0042')
        )
        """
    )


def downgrade() -> None:
    """Revert PRE techniques to cloud platforms."""
    op.execute(
        """
        UPDATE techniques
        SET platforms = '["AWS", "Azure", "GCP", "IaaS"]'::jsonb
        WHERE tactic_id IN (
            SELECT id FROM tactics WHERE tactic_id IN ('TA0043', 'TA0042')
        )
        """
    )
