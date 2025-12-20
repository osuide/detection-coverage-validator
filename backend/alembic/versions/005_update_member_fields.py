"""Update organization member fields for invites

Revision ID: 005
Revises: 004
Create Date: 2025-12-18

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add new enum value 'removed' to membershipstatus
    op.execute(
        """
        DO $$ BEGIN
            ALTER TYPE membershipstatus ADD VALUE IF NOT EXISTS 'removed';
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )

    # Add new audit log action values
    op.execute(
        """
        DO $$ BEGIN
            ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'member.invited';
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )
    op.execute(
        """
        DO $$ BEGIN
            ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'member.joined';
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )
    op.execute(
        """
        DO $$ BEGIN
            ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'member.role_changed';
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )
    op.execute(
        """
        DO $$ BEGIN
            ALTER TYPE auditlogaction ADD VALUE IF NOT EXISTS 'member.removed';
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
    """
    )

    # Rename columns if needed
    # Check if invite_email exists and rename to invited_email
    op.execute(
        """
        DO $$ BEGIN
            ALTER TABLE organization_members RENAME COLUMN invite_email TO invited_email;
        EXCEPTION WHEN undefined_column THEN NULL;
        END $$;
    """
    )

    # Rename invited_by_id to invited_by
    op.execute(
        """
        DO $$ BEGIN
            ALTER TABLE organization_members RENAME COLUMN invited_by_id TO invited_by;
        EXCEPTION WHEN undefined_column THEN NULL;
        END $$;
    """
    )

    # Add invited_at column if not exists
    op.execute(
        """
        DO $$ BEGIN
            ALTER TABLE organization_members ADD COLUMN IF NOT EXISTS invited_at TIMESTAMP WITH TIME ZONE;
        EXCEPTION WHEN duplicate_column THEN NULL;
        END $$;
    """
    )

    # Remove unique constraint on invite_token if it exists (we hash tokens now)
    op.execute(
        """
        DO $$ BEGIN
            ALTER TABLE organization_members DROP CONSTRAINT IF EXISTS organization_members_invite_token_key;
        EXCEPTION WHEN undefined_object THEN NULL;
        END $$;
    """
    )


def downgrade() -> None:
    # Note: PostgreSQL enum values cannot be removed easily
    # These operations are non-reversible for enums
    pass
