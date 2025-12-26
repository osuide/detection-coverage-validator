"""Fix allowed_auth_methods default to include SSO providers.

Revision ID: 035_fix_allowed_auth_methods
Revises: 034_campaign_attributions
Create Date: 2025-12-26

Updates existing organization_security_settings records that only have
["password"] in allowed_auth_methods to include all common SSO providers.
This fixes an issue where SSO logins were blocked because the default
only included password authentication.
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "035_fix_allowed_auth_methods"
down_revision = "034_campaign_attributions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Update existing records that only have ["password"] to include all SSO providers
    # This ensures existing users aren't locked out of SSO
    op.execute(
        """
        UPDATE organization_security_settings
        SET allowed_auth_methods = '["password", "google", "github", "cognito"]'::jsonb
        WHERE allowed_auth_methods = '["password"]'::jsonb
    """
    )


def downgrade() -> None:
    # Don't revert - this would lock users out of SSO again
    pass
