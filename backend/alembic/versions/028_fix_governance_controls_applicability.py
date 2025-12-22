"""Fix cloud applicability for governance/process controls.

Revision ID: 028
Revises: 027
Create Date: 2025-12-22

Mark 43 CIS Controls and 19 NIST 800-53 controls as 'informational'
that cannot be assessed via cloud log scanning (governance, process,
documentation, training, assessment controls).
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "028_fix_governance_controls"
down_revision = "027_add_cloud_metrics"
branch_labels = None
depends_on = None

# CIS Controls that should be 'informational'
CIS_INFORMATIONAL_CONTROLS = [
    # Service Provider Management - all governance/vendor management
    "15",
    "15.1",
    "15.2",
    "15.3",
    "15.4",
    "15.5",
    "15.6",
    "15.7",
    # Application Software Security - process/governance subcontrols
    "16.1",
    "16.2",
    "16.3",
    "16.6",
    "16.9",
    "16.10",
    "16.13",
    "16.14",
    # Incident Response Management - all governance/process
    "17",
    "17.1",
    "17.2",
    "17.3",
    "17.4",
    "17.5",
    "17.6",
    "17.7",
    "17.8",
    "17.9",
    # Penetration Testing - all assessment/process
    "18",
    "18.1",
    "18.2",
    "18.3",
    "18.4",
    "18.5",
    # Earlier process/governance controls
    "3.1",
    "3.7",
    "3.8",
    "4.1",
    "4.2",
    "6.1",
    "6.2",
    "7.1",
    "7.2",
    "8.1",
    "8.11",
]

# NIST 800-53 Controls that should be 'informational'
NIST_INFORMATIONAL_CONTROLS = [
    # Policy and Procedures controls
    "AC-1",
    "AU-1",
    # Assessment/audit process controls
    "CA-2",
    "CA-8",
    "AU-6",
    # Contingency planning (documentation)
    "CP-2",
    # System Development Lifecycle controls (process/governance)
    "SA-3",
    "SA-4",
    "SA-8",
    "SA-9",
    "SA-10",
    "SA-11",
    "SA-15",
    "SA-16",
    "SA-17",
    # Supply chain controls (vendor management)
    "SR-4",
    "SR-5",
    "SR-6",
    # Other governance/analysis
    "RA-9",
]


def upgrade() -> None:
    # Update CIS Controls v8
    cis_controls_str = ", ".join(f"'{c}'" for c in CIS_INFORMATIONAL_CONTROLS)
    op.execute(
        f"""
        UPDATE compliance_controls
        SET cloud_applicability = 'informational'
        WHERE control_id IN ({cis_controls_str})
        AND framework_id IN (
            SELECT id FROM compliance_frameworks
            WHERE framework_id = 'cis-controls-v8'
        )
        AND cloud_applicability != 'informational'
    """
    )

    # Update NIST 800-53 R5
    nist_controls_str = ", ".join(f"'{c}'" for c in NIST_INFORMATIONAL_CONTROLS)
    op.execute(
        f"""
        UPDATE compliance_controls
        SET cloud_applicability = 'informational'
        WHERE control_id IN ({nist_controls_str})
        AND framework_id IN (
            SELECT id FROM compliance_frameworks
            WHERE framework_id = 'nist-800-53-r5'
        )
        AND cloud_applicability != 'informational'
    """
    )


def downgrade() -> None:
    # Revert CIS Controls to moderately_relevant (default for these categories)
    cis_controls_str = ", ".join(f"'{c}'" for c in CIS_INFORMATIONAL_CONTROLS)
    op.execute(
        f"""
        UPDATE compliance_controls
        SET cloud_applicability = 'moderately_relevant'
        WHERE control_id IN ({cis_controls_str})
        AND framework_id IN (
            SELECT id FROM compliance_frameworks
            WHERE framework_id = 'cis-controls-v8'
        )
    """
    )

    # Revert NIST Controls
    nist_controls_str = ", ".join(f"'{c}'" for c in NIST_INFORMATIONAL_CONTROLS)
    op.execute(
        f"""
        UPDATE compliance_controls
        SET cloud_applicability = 'moderately_relevant'
        WHERE control_id IN ({nist_controls_str})
        AND framework_id IN (
            SELECT id FROM compliance_frameworks
            WHERE framework_id = 'nist-800-53-r5'
        )
    """
    )
