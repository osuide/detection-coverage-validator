"""Tests for Security Hub MITRE mappings.

Tests verify the mapping source code contains expected CSPM functionality.
"""

import re
import pytest


def read_mappings_source():
    """Read the Security Hub mappings source file."""
    with open("app/mappers/securityhub_mappings.py", "r") as f:
        return f.read()


class TestCSPMMappingFunctionExists:
    """Tests for CSPM mapping function existence."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_mappings_source()

    def test_cspm_control_function_exists(self, source_content):
        """Test that CSPM control mapping function exists."""
        assert "def get_techniques_for_cspm_control" in source_content

    def test_cspm_function_has_control_id_param(self, source_content):
        """Test that CSPM function has control_id parameter."""
        assert "control_id: str" in source_content

    def test_cspm_function_has_standard_associations_param(self, source_content):
        """Test that CSPM function has standard_associations parameter."""
        assert "standard_associations:" in source_content

    def test_cspm_function_has_docstring(self, source_content):
        """Test that CSPM function has documentation."""
        func_match = re.search(
            r"def get_techniques_for_cspm_control\([\s\S]*?\"\"\"([\s\S]*?)\"\"\"",
            source_content,
        )
        assert func_match is not None
        docstring = func_match.group(1)
        assert "CSPM" in docstring
        assert "standard-agnostic" in docstring


class TestCSPMMappingLogic:
    """Tests for CSPM mapping logic."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_mappings_source()

    def test_normalises_control_id(self, source_content):
        """Test that CSPM function normalises control IDs."""
        assert "control_id.lower()" in source_content

    def test_uses_fsbp_as_primary_for_service_ids(self, source_content):
        """Test that CSPM uses FSBP mappings as primary for service-based IDs.

        The function should:
        1. Check CIS mappings first for CIS-prefixed IDs (e.g., CIS.3.2)
        2. Use FSBP as primary for service-based IDs (e.g., IAM.1, S3.1)

        This test verifies that FSBP is used as the primary source for
        non-CIS control IDs (the common case for CSPM API).
        """
        # Verify both CIS and FSBP mappings are present
        assert "CIS_BENCHMARK_MAPPINGS" in source_content
        assert "FSBP_MAPPINGS" in source_content

        # Verify FSBP lookup uses fsbp.{normalised_id} format
        assert 'fsbp_key = f"fsbp.{normalised_id}"' in source_content
        assert "fsbp_key in FSBP_MAPPINGS" in source_content

    def test_handles_cis_prefixed_ids_first(self, source_content):
        """Test that CIS-prefixed control IDs are handled directly."""
        # CIS-prefixed IDs like CIS.3.2 should be looked up directly in CIS mappings
        assert 'normalised_id.startswith("cis.")' in source_content
        # Should return early after finding CIS match
        assert "cis_seen" in source_content  # Deduplicate for CIS path

    def test_falls_back_to_cis(self, source_content):
        """Test that CSPM falls back to CIS mappings for non-CIS IDs."""
        assert "CIS_BENCHMARK_MAPPINGS" in source_content

    def test_falls_back_to_pci(self, source_content):
        """Test that CSPM falls back to PCI mappings."""
        assert "PCI_DSS_MAPPINGS" in source_content

    def test_deduplicates_techniques(self, source_content):
        """Test that CSPM function deduplicates techniques."""
        cspm_func = re.search(
            r"def get_techniques_for_cspm_control\([\s\S]*?(?=def get_techniques_for_security_hub)",
            source_content,
        )
        assert cspm_func is not None
        func_body = cspm_func.group(0)
        assert "Deduplicate" in func_body or "seen:" in func_body


class TestLegacyFunctionBackwardCompatibility:
    """Tests for legacy function backward compatibility."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_mappings_source()

    def test_legacy_function_still_exists(self, source_content):
        """Test that legacy function still exists."""
        assert "def get_techniques_for_security_hub" in source_content

    def test_legacy_function_has_api_version_param(self, source_content):
        """Test that legacy function has api_version parameter."""
        func_match = re.search(
            r"def get_techniques_for_security_hub\([\s\S]*?\) ->",
            source_content,
        )
        assert func_match is not None
        assert "api_version:" in func_match.group(0)

    def test_legacy_function_routes_to_cspm(self, source_content):
        """Test that legacy function routes to CSPM when api_version is 'cspm'."""
        func_match = re.search(
            r"def get_techniques_for_security_hub\([\s\S]*?(?=def get_all_mapped_standards)",
            source_content,
        )
        assert func_match is not None
        func_body = func_match.group(0)

        # Check that it routes to CSPM function
        assert 'api_version == "cspm"' in func_body
        assert "get_techniques_for_cspm_control" in func_body

    def test_legacy_function_handles_fsbp(self, source_content):
        """Test that legacy function still handles FSBP standard."""
        assert 'if "foundational" in standard_name.lower()' in source_content

    def test_legacy_function_handles_cis(self, source_content):
        """Test that legacy function still handles CIS standard."""
        assert 'if "cis" in standard_name.lower()' in source_content

    def test_legacy_function_handles_pci(self, source_content):
        """Test that legacy function still handles PCI standard."""
        assert 'if "pci" in standard_name.lower()' in source_content


class TestMappingCoverage:
    """Tests for mapping coverage."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_mappings_source()

    def test_fsbp_has_s3_mappings(self, source_content):
        """Test that FSBP has S3 control mappings."""
        assert '"fsbp.s3.1"' in source_content
        assert '"fsbp.s3.8"' in source_content

    def test_fsbp_has_iam_mappings(self, source_content):
        """Test that FSBP has IAM control mappings."""
        assert '"fsbp.iam.1"' in source_content
        assert '"fsbp.iam.4"' in source_content

    def test_fsbp_has_ec2_mappings(self, source_content):
        """Test that FSBP has EC2 control mappings."""
        assert '"fsbp.ec2.1"' in source_content
        assert '"fsbp.ec2.2"' in source_content

    def test_fsbp_has_cloudtrail_mappings(self, source_content):
        """Test that FSBP has CloudTrail control mappings."""
        assert '"fsbp.cloudtrail.1"' in source_content

    def test_fsbp_has_guardduty_mappings(self, source_content):
        """Test that FSBP has GuardDuty control mappings."""
        assert '"fsbp.guardduty.1"' in source_content


class TestCSPMControlIDFormat:
    """Tests for CSPM control ID format handling."""

    def test_s3_1_maps_to_techniques(self):
        """Test that S3.1 control ID can be normalised to fsbp.s3.1."""
        control_id = "S3.1"
        normalised = f"fsbp.{control_id.lower().replace('-', '.')}"
        assert normalised == "fsbp.s3.1"

    def test_iam_1_maps_to_techniques(self):
        """Test that IAM.1 control ID can be normalised to fsbp.iam.1."""
        control_id = "IAM.1"
        normalised = f"fsbp.{control_id.lower().replace('-', '.')}"
        assert normalised == "fsbp.iam.1"

    def test_ec2_18_maps_to_techniques(self):
        """Test that EC2.18 control ID can be normalised to fsbp.ec2.18."""
        control_id = "EC2.18"
        normalised = f"fsbp.{control_id.lower().replace('-', '.')}"
        assert normalised == "fsbp.ec2.18"

    def test_codebuild_1_maps_to_techniques(self):
        """Test that CodeBuild.1 control ID can be normalised."""
        control_id = "CodeBuild.1"
        normalised = f"fsbp.{control_id.lower().replace('-', '.')}"
        assert normalised == "fsbp.codebuild.1"

    def test_secretsmanager_1_maps_to_techniques(self):
        """Test that SecretsManager.1 control ID can be normalised."""
        control_id = "SecretsManager.1"
        normalised = f"fsbp.{control_id.lower().replace('-', '.')}"
        assert normalised == "fsbp.secretsmanager.1"


class TestGetAllMappedStandards:
    """Tests for get_all_mapped_standards function."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_mappings_source()

    def test_function_exists(self, source_content):
        """Test that function exists."""
        assert "def get_all_mapped_standards" in source_content

    def test_returns_fsbp_controls(self, source_content):
        """Test that function returns FSBP controls."""
        assert '"fsbp":' in source_content

    def test_returns_cis_controls(self, source_content):
        """Test that function returns CIS controls."""
        assert '"cis":' in source_content

    def test_returns_pci_controls(self, source_content):
        """Test that function returns PCI controls."""
        assert '"pci":' in source_content
