"""Add Inspector and Macie detection types.

Revision ID: 051
Revises: 050
Create Date: 2025-12-31

Adds inspector_finding and macie_finding to the detectiontype enum
to support AWS Inspector vulnerability scanning and AWS Macie
sensitive data discovery.
"""

from typing import Sequence, Union

from alembic import op


revision: str = "051"
down_revision: Union[str, None] = "050"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add inspector_finding and macie_finding to detectiontype enum."""
    # Add Inspector detection type
    op.execute("ALTER TYPE detectiontype ADD VALUE IF NOT EXISTS 'inspector_finding'")
    # Add Macie detection type
    op.execute("ALTER TYPE detectiontype ADD VALUE IF NOT EXISTS 'macie_finding'")


def downgrade() -> None:
    """Remove inspector_finding and macie_finding from detectiontype enum.

    Note: PostgreSQL doesn't support removing enum values directly.
    This would require recreating the enum type, which is complex and
    potentially dangerous in production. For simplicity, we leave the
    values in place as they are harmless if unused.
    """
    pass
