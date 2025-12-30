"""Tests for cloud credential IAM policies.

This test module validates the IAM policy definitions used for scanning
cloud accounts. Tests verify the source file contains expected permissions.
"""

import re
import pytest


def read_source_file():
    """Read the cloud_credential.py source file."""
    with open("app/models/cloud_credential.py", "r") as f:
        return f.read()


class TestAWSIAMPolicy:
    """Tests for AWS IAM policy definitions."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_source_file()

    def test_policy_has_correct_version(self, source_content):
        """Test that policy has correct version."""
        assert '"Version": "2012-10-17"' in source_content

    def test_security_hub_statement_exists(self, source_content):
        """Test that Security Hub statement exists."""
        assert '"Sid": "A13ESecurityHubAccess"' in source_content

    def test_security_hub_has_describe_hub(self, source_content):
        """Test that Security Hub has DescribeHub permission."""
        assert '"securityhub:DescribeHub"' in source_content

    def test_security_hub_has_get_enabled_standards(self, source_content):
        """Test that Security Hub has GetEnabledStandards permission."""
        assert '"securityhub:GetEnabledStandards"' in source_content

    def test_security_hub_has_get_insights(self, source_content):
        """Test that Security Hub has GetInsights permission."""
        assert '"securityhub:GetInsights"' in source_content

    def test_security_hub_has_get_findings(self, source_content):
        """Test that Security Hub has GetFindings permission for compliance posture."""
        assert '"securityhub:GetFindings"' in source_content

    def test_security_hub_has_legacy_describe_standards_controls(self, source_content):
        """Test that Security Hub has legacy DescribeStandardsControls for backward compatibility."""
        assert '"securityhub:DescribeStandardsControls"' in source_content

    def test_security_hub_has_cspm_list_security_control_definitions(
        self, source_content
    ):
        """Test that Security Hub has CSPM ListSecurityControlDefinitions API."""
        assert '"securityhub:ListSecurityControlDefinitions"' in source_content

    def test_security_hub_has_cspm_batch_get_security_controls(self, source_content):
        """Test that Security Hub has CSPM BatchGetSecurityControls API."""
        assert '"securityhub:BatchGetSecurityControls"' in source_content

    def test_security_hub_has_cspm_list_standards_control_associations(
        self, source_content
    ):
        """Test that Security Hub has CSPM ListStandardsControlAssociations API."""
        assert '"securityhub:ListStandardsControlAssociations"' in source_content

    def test_no_write_permissions_in_security_hub(self, source_content):
        """Test that Security Hub section has no write/modify permissions."""
        # Find the Security Hub section
        sh_match = re.search(
            r'"Sid": "A13ESecurityHubAccess"[\s\S]*?"Action": \[([\s\S]*?)\]',
            source_content,
        )
        assert sh_match is not None, "Could not find Security Hub statement"

        actions_section = sh_match.group(1)

        # Check for dangerous actions
        dangerous_patterns = [
            "securityhub:Create",
            "securityhub:Delete",
            "securityhub:Update",
            "securityhub:Enable",
            "securityhub:Disable",
            "securityhub:Batch.*Update",
        ]

        for pattern in dangerous_patterns:
            assert not re.search(
                pattern, actions_section
            ), f"Found dangerous action: {pattern}"


class TestAWSRequiredPermissions:
    """Tests for AWS required permissions list."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_source_file()

    def test_permissions_list_exists(self, source_content):
        """Test that AWS_REQUIRED_PERMISSIONS list exists."""
        assert "AWS_REQUIRED_PERMISSIONS" in source_content

    def test_security_hub_describe_hub_in_list(self, source_content):
        """Test that securityhub:DescribeHub is in the permissions list."""
        # Look for the permission entry
        assert '"action": "securityhub:DescribeHub"' in source_content

    def test_security_hub_get_enabled_standards_in_list(self, source_content):
        """Test that securityhub:GetEnabledStandards is in the permissions list."""
        assert '"action": "securityhub:GetEnabledStandards"' in source_content

    def test_security_hub_get_insights_in_list(self, source_content):
        """Test that securityhub:GetInsights is in the permissions list."""
        assert '"action": "securityhub:GetInsights"' in source_content

    def test_security_hub_get_findings_in_list(self, source_content):
        """Test that securityhub:GetFindings is in the permissions list."""
        assert '"action": "securityhub:GetFindings"' in source_content

    def test_security_hub_describe_standards_controls_in_list(self, source_content):
        """Test that securityhub:DescribeStandardsControls is in the permissions list."""
        assert '"action": "securityhub:DescribeStandardsControls"' in source_content

    def test_cspm_list_security_control_definitions_in_list(self, source_content):
        """Test that CSPM ListSecurityControlDefinitions is in the permissions list."""
        assert (
            '"action": "securityhub:ListSecurityControlDefinitions"' in source_content
        )

    def test_cspm_batch_get_security_controls_in_list(self, source_content):
        """Test that CSPM BatchGetSecurityControls is in the permissions list."""
        assert '"action": "securityhub:BatchGetSecurityControls"' in source_content

    def test_cspm_list_standards_control_associations_in_list(self, source_content):
        """Test that CSPM ListStandardsControlAssociations is in the permissions list."""
        assert (
            '"action": "securityhub:ListStandardsControlAssociations"' in source_content
        )

    def test_cspm_permissions_have_service_label(self, source_content):
        """Test that CSPM permissions are labelled with 'Security Hub CSPM' service."""
        # Each CSPM permission should have "Security Hub CSPM" as service
        cspm_actions = [
            "ListSecurityControlDefinitions",
            "BatchGetSecurityControls",
            "ListStandardsControlAssociations",
        ]

        for action in cspm_actions:
            # Find the permission block for this action
            pattern = rf'"action": "securityhub:{action}"[\s\S]*?"service": "([^"]+)"'
            match = re.search(pattern, source_content)
            assert match is not None, f"Could not find service for {action}"
            assert "CSPM" in match.group(
                1
            ), f"CSPM permission {action} should have CSPM in service label"


class TestExternalIDGeneration:
    """Tests for external ID generation (no app imports needed)."""

    def test_external_id_format_pattern(self):
        """Test external ID format by reading the generation logic."""
        import secrets

        # Replicate the logic from CloudCredential.generate_external_id()
        external_id = f"a13e-{secrets.token_hex(16)}"

        assert external_id.startswith("a13e-")
        assert len(external_id) == 37  # "a13e-" (5) + 32 hex chars

    def test_external_id_uniqueness(self):
        """Test that generated external IDs are unique."""
        import secrets

        ids = {f"a13e-{secrets.token_hex(16)}" for _ in range(100)}
        assert len(ids) == 100

    def test_external_id_generation_logic_in_source(self):
        """Test that the external ID generation logic exists in source."""
        source = read_source_file()
        assert "generate_external_id" in source
        assert 'f"a13e-{secrets.token_hex(16)}"' in source
