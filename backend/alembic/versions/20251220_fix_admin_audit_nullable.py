"""Make admin_id and admin_role nullable in admin_audit_logs

Revision ID: fix_audit_nullable
Revises: None
Create Date: 2025-12-20

This fixes the foreign key constraint issue when logging failed login
attempts for non-existent admin users.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "fix_audit_nullable"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Make admin_id and admin_role nullable."""
    # Drop the foreign key constraint first
    op.drop_constraint(
        "admin_audit_logs_admin_id_fkey", "admin_audit_logs", type_="foreignkey"
    )

    # Make admin_id nullable
    op.alter_column(
        "admin_audit_logs",
        "admin_id",
        existing_type=sa.dialects.postgresql.UUID(),
        nullable=True,
    )

    # Make admin_role nullable
    op.alter_column(
        "admin_audit_logs",
        "admin_role",
        existing_type=sa.Enum(
            "super_admin",
            "platform_admin",
            "support_admin",
            "readonly_admin",
            name="admin_role",
        ),
        nullable=True,
    )

    # Re-add the foreign key constraint with ON DELETE SET NULL
    op.create_foreign_key(
        "admin_audit_logs_admin_id_fkey",
        "admin_audit_logs",
        "admin_users",
        ["admin_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    """Revert changes - make columns non-nullable again."""
    # This is potentially destructive if there are NULL values
    # First delete any rows with NULL admin_id
    op.execute("DELETE FROM admin_audit_logs WHERE admin_id IS NULL")

    # Drop the foreign key
    op.drop_constraint(
        "admin_audit_logs_admin_id_fkey", "admin_audit_logs", type_="foreignkey"
    )

    # Make admin_id non-nullable
    op.alter_column(
        "admin_audit_logs",
        "admin_id",
        existing_type=sa.dialects.postgresql.UUID(),
        nullable=False,
    )

    # Make admin_role non-nullable (default to readonly_admin)
    op.execute(
        "UPDATE admin_audit_logs SET admin_role = 'readonly_admin' WHERE admin_role IS NULL"
    )
    op.alter_column(
        "admin_audit_logs",
        "admin_role",
        existing_type=sa.Enum(
            "super_admin",
            "platform_admin",
            "support_admin",
            "readonly_admin",
            name="admin_role",
        ),
        nullable=False,
    )

    # Re-add the original foreign key constraint
    op.create_foreign_key(
        "admin_audit_logs_admin_id_fkey",
        "admin_audit_logs",
        "admin_users",
        ["admin_id"],
        ["id"],
    )
