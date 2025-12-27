"""Fix empty technique_name in coverage_gaps.

Revision ID: 039_fix_gap_names
Revises: 038_add_eval_history
Create Date: 2025-12-27

This data migration fixes gaps that were created with empty technique_name
before the fix that looks up technique info from the database.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "039_fix_gap_names"
down_revision = "038_add_eval_history"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Update gaps with empty technique_name from techniques table."""
    conn = op.get_bind()

    # Update gaps that have empty technique_name
    conn.execute(
        sa.text(
            """
        UPDATE coverage_gaps g
        SET
            technique_name = t.name,
            tactic_id = COALESCE(tac.tactic_id, ''),
            tactic_name = COALESCE(tac.name, 'Unknown')
        FROM techniques t
        LEFT JOIN tactics tac ON t.tactic_id = tac.id
        WHERE g.technique_id = t.technique_id
        AND (g.technique_name = '' OR g.technique_name IS NULL)
    """
        )
    )


def downgrade() -> None:
    """No downgrade - data migration only."""
    pass
