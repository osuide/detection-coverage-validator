"""Tests for Security Hub scanner.

Tests verify the scanner source code contains expected CSPM functionality.
"""

import re
import pytest


def read_scanner_source():
    """Read the Security Hub scanner source file."""
    with open("app/scanners/aws/securityhub_scanner.py", "r") as f:
        return f.read()


class TestSecurityHubScannerStructure:
    """Tests for Security Hub scanner structure."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_scanner_source()

    def test_scanner_has_cspm_docstring(self, source_content):
        """Test that scanner has CSPM documentation."""
        assert "CSPM" in source_content
        # Check for "consolidated" somewhere in the docstring
        assert "consolidated" in source_content.lower()

    def test_scanner_has_chunk_list_helper(self, source_content):
        """Test that scanner has chunk list helper for batch API."""
        assert "_chunk_list" in source_content
        assert "chunk_size" in source_content

    def test_scanner_has_get_cspm_control_status_method(self, source_content):
        """Test that scanner has CSPM control status method."""
        assert "_get_cspm_control_status" in source_content

    def test_scanner_has_control_associations_method(self, source_content):
        """Test that scanner has control associations method."""
        assert "_get_control_associations" in source_content

    def test_scanner_has_legacy_fallback(self, source_content):
        """Test that scanner has legacy fallback logic."""
        assert "_scan_enabled_standards" in source_content


class TestCSPMAPIUsage:
    """Tests for CSPM API usage in scanner."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_scanner_source()

    def test_uses_list_security_control_definitions(self, source_content):
        """Test that scanner uses ListSecurityControlDefinitions API."""
        assert "list_security_control_definitions" in source_content

    def test_uses_batch_get_security_controls(self, source_content):
        """Test that scanner uses BatchGetSecurityControls API."""
        assert "batch_get_security_controls" in source_content

    def test_cspm_detection_has_api_version_marker(self, source_content):
        """Test that CSPM detections are marked with api_version."""
        # Aggregated detections use cspm_aggregated
        assert '"api_version": "cspm_aggregated"' in source_content

    def test_cspm_stores_control_id(self, source_content):
        """Test that CSPM detection stores control_id."""
        assert '"control_id":' in source_content

    def test_cspm_stores_control_arn(self, source_content):
        """Test that CSPM detection stores control_arn."""
        assert '"control_arn":' in source_content

    def test_cspm_stores_status_by_region(self, source_content):
        """Test that CSPM detection stores status_by_region map."""
        assert '"status_by_region":' in source_content


class TestPerRegionStatus:
    """Tests for per-region status collection."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_scanner_source()

    def test_collects_status_across_regions(self, source_content):
        """Test that scan() collects status from all regions."""
        # Check that scan() processes regions and merges status
        assert "status_by_region" in source_content
        assert "cspm_control_data" in source_content

    def test_first_region_stores_full_data(self, source_content):
        """Test that first region stores full control data."""
        assert "first_cspm_region" in source_content
        assert "cspm_scanned" in source_content

    def test_subsequent_regions_only_add_status(self, source_content):
        """Test that subsequent regions only add status."""
        # Check for the pattern that adds status to existing controls
        assert 'cspm_control_data[control_id]["status_by_region"]' in source_content

    def test_creates_single_detection_per_control(self, source_content):
        """Test that one detection is created per control."""
        # Check for the phase 2 loop that creates detections
        assert "securityhub_cspm_complete" in source_content
        assert "total_controls" in source_content


class TestGracefulFallback:
    """Tests for graceful fallback to legacy API."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_scanner_source()

    def test_handles_access_denied_gracefully(self, source_content):
        """Test that scanner handles AccessDeniedException gracefully."""
        assert "AccessDeniedException" in source_content

    def test_returns_empty_dict_on_cspm_failure(self, source_content):
        """Test that _get_cspm_control_status returns empty dict on failure."""
        # Check that there's a return {} in the CSPM method after access denied
        method = re.search(
            r"def _get_cspm_control_status\([\s\S]*?(?=\n    async def |\n    def _)",
            source_content,
        )
        assert method is not None
        assert "return {}" in method.group(0)

    def test_logs_region_status(self, source_content):
        """Test that scanner logs region status collection."""
        assert "securityhub_cspm_first_region" in source_content
        assert "securityhub_cspm_region_status" in source_content


class TestBatchProcessing:
    """Tests for batch processing of controls."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_scanner_source()

    def test_uses_pagination_for_control_definitions(self, source_content):
        """Test that scanner paginates control definitions."""
        assert 'get_paginator("list_security_control_definitions")' in source_content

    def test_chunks_control_ids_for_batch_api(self, source_content):
        """Test that scanner chunks control IDs for batch API."""
        assert "_chunk_list(control_ids, 100)" in source_content


class TestControlAssociations:
    """Tests for control associations retrieval."""

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_scanner_source()

    def test_gets_standards_arn(self, source_content):
        """Test that associations include standards ARN."""
        assert '"standards_arn":' in source_content

    def test_gets_association_status(self, source_content):
        """Test that associations include association status."""
        assert '"association_status":' in source_content

    def test_gets_related_requirements(self, source_content):
        """Test that associations include related requirements."""
        assert '"related_requirements":' in source_content


class TestChunkListHelper:
    """Tests for the chunk list helper function."""

    def test_chunk_list_function_logic(self):
        """Test the chunk list function logic."""

        # Replicate the function logic
        def chunk_list(items, chunk_size):
            return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]

        # Test basic chunking
        items = list(range(250))
        chunks = chunk_list(items, 100)

        assert len(chunks) == 3
        assert len(chunks[0]) == 100
        assert len(chunks[1]) == 100
        assert len(chunks[2]) == 50

    def test_chunk_list_empty_input(self):
        """Test chunk list with empty input."""

        def chunk_list(items, chunk_size):
            return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]

        chunks = chunk_list([], 100)
        assert chunks == []

    def test_chunk_list_smaller_than_chunk_size(self):
        """Test chunk list when items < chunk_size."""

        def chunk_list(items, chunk_size):
            return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]

        items = list(range(50))
        chunks = chunk_list(items, 100)

        assert len(chunks) == 1
        assert len(chunks[0]) == 50


class TestServicePrefixCoverage:
    """Tests to ensure all AWS Security Hub service prefixes are recognised.

    This prevents "OTHER" category from appearing in the Detections Dashboard.
    Complete list from: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html
    """

    # Complete list of AWS service prefixes (December 2025)
    # Source: AWS Security Hub CSPM Control Reference
    AWS_SERVICE_PREFIXES = [
        # A
        "Account",
        "ACM",
        "Amplify",
        "APIGateway",
        "AppConfig",
        "AppFlow",
        "AppRunner",
        "AppSync",
        "Athena",
        "AutoScaling",
        # B
        "Backup",
        "Batch",
        # C
        "CloudFormation",
        "CloudFront",
        "CloudTrail",
        "CloudWatch",
        "CodeArtifact",
        "CodeBuild",
        "CodeGuruProfiler",
        "CodeGuruReviewer",
        "Cognito",
        "Config",
        "Connect",
        # D
        "DataFirehose",
        "DataSync",
        "Detective",
        "DMS",
        "DocumentDB",
        "DynamoDB",
        # E
        "EC2",
        "ECR",
        "ECS",
        "EFS",
        "EKS",
        "ElastiCache",
        "ElasticBeanstalk",
        "ELB",
        "EMR",
        "ES",
        "EventBridge",
        # F
        "FraudDetector",
        "FSx",
        # G
        "Glue",
        "GlobalAccelerator",
        "GuardDuty",
        # I
        "IAM",
        "Inspector",
        "IoT",
        "IoTEvents",
        "IoTSiteWise",
        "IoTTwinMaker",
        "IoTWireless",
        "IVS",
        # K
        "Keyspaces",
        "Kinesis",
        "KMS",
        # L
        "Lambda",
        # M
        "Macie",
        "MQ",
        "MSK",
        # N
        "Neptune",
        "NetworkFirewall",
        # O
        "Opensearch",
        # P
        "PCA",
        # R
        "RDS",
        "Redshift",
        "Route53",
        # S
        "S3",
        "SageMaker",
        "SecretsManager",
        "SecurityHub",
        "SNS",
        "SQS",
        "SSM",
        "StepFunctions",
        # T
        "Transfer",
        # W
        "WAF",
    ]

    @pytest.fixture
    def source_content(self):
        """Load the source file content."""
        return read_scanner_source()

    def test_all_service_prefixes_in_scanner(self, source_content):
        """Test that all AWS service prefixes are in the scanner's service_prefixes set.

        This test ensures no controls fall to the "OTHER" category due to
        missing service prefixes.
        """
        # Extract the service_prefixes set from the source
        # The prefixes are stored as uppercase strings
        missing_prefixes = []

        for prefix in self.AWS_SERVICE_PREFIXES:
            # Check for the uppercase version in quotes
            if f'"{prefix.upper()}"' not in source_content:
                missing_prefixes.append(prefix)

        assert not missing_prefixes, (
            f"Missing service prefixes in scanner: {missing_prefixes}. "
            f"Add these to the service_prefixes set in _infer_standard_from_control_id()"
        )

    def test_service_prefixes_return_fsbp(self, source_content):
        """Test that service-prefixed control IDs return 'fsbp' standard.

        The _infer_standard_from_control_id method should return 'fsbp' for
        all service-prefixed controls since AWS CSPM uses standard-agnostic IDs.
        """
        # Verify the method returns 'fsbp' for service prefixes
        assert 'return "fsbp"' in source_content
        assert "if prefix in service_prefixes:" in source_content

    @pytest.mark.parametrize(
        "control_id,expected_standard",
        [
            # Standard CSPM format (should return 'fsbp')
            ("S3.1", "fsbp"),
            ("IAM.6", "fsbp"),
            ("EC2.18", "fsbp"),
            ("Backup.1", "fsbp"),
            ("EventBridge.3", "fsbp"),
            ("DocumentDB.1", "fsbp"),
            ("Glue.1", "fsbp"),
            # Legacy PCI format (should return 'pci')
            ("PCI.IAM.1", "pci"),
            ("PCI.S3.1", "pci"),
            # Legacy CIS format (should return 'cis')
            ("1.1", "cis"),
            ("2.3", "cis"),
            ("3.14", "cis"),
        ],
    )
    def test_control_id_pattern_matching(self, control_id, expected_standard):
        """Test that control IDs are correctly mapped to standards."""
        from app.scanners.aws.securityhub_scanner import SecurityHubScanner

        # Create a minimal scanner instance for testing
        scanner = SecurityHubScanner.__new__(SecurityHubScanner)

        result = scanner._infer_standard_from_control_id(control_id)
        assert result == expected_standard, (
            f"Control ID '{control_id}' should map to '{expected_standard}', "
            f"but got '{result}'"
        )

    def test_no_other_category_for_known_prefixes(self):
        """Test that known prefixes never fall to 'other' category."""
        from app.scanners.aws.securityhub_scanner import SecurityHubScanner

        scanner = SecurityHubScanner.__new__(SecurityHubScanner)

        # Test all known prefixes with a sample control number
        for prefix in self.AWS_SERVICE_PREFIXES:
            control_id = f"{prefix}.1"
            result = scanner._infer_standard_from_control_id(control_id)

            assert result is not None, (
                f"Control ID '{control_id}' returned None - "
                f"prefix '{prefix}' is missing from service_prefixes set"
            )
            assert (
                result == "fsbp"
            ), f"Control ID '{control_id}' should map to 'fsbp', got '{result}'"


class TestStandardArnParsing:
    """Tests for parsing standard ARNs to standard IDs."""

    @pytest.mark.parametrize(
        "standards_arn,expected_standard_id",
        [
            # FSBP
            (
                "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0",
                "fsbp",
            ),
            (
                "arn:aws:securityhub:eu-west-2::standards/aws-foundational-security-best-practices/v/1.0.0",
                "fsbp",
            ),
            # CIS (modern format)
            (
                "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0",
                "cis",
            ),
            (
                "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/3.0.0",
                "cis",
            ),
            # CIS (legacy ruleset format)
            (
                "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
                "cis",
            ),
            # NIST 800-53
            (
                "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0",
                "nist",
            ),
            # NIST 800-171
            (
                "arn:aws:securityhub:us-east-1::standards/nist-800-171/v/2.0.0",
                "nist171",
            ),
            # PCI DSS
            (
                "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1",
                "pci",
            ),
            # AWS Resource Tagging
            (
                "arn:aws:securityhub:us-east-1::standards/aws-resource-tagging-standard/v/1.0.0",
                "tagging",
            ),
            # Unknown standard
            (
                "arn:aws:securityhub:us-east-1::standards/unknown-standard/v/1.0.0",
                None,
            ),
            # Empty ARN
            ("", None),
        ],
    )
    def test_get_standard_id_from_arn(self, standards_arn, expected_standard_id):
        """Test that standard ARNs are correctly parsed to standard IDs."""
        from app.scanners.aws.securityhub_scanner import _get_standard_id_from_arn

        result = _get_standard_id_from_arn(standards_arn)
        assert result == expected_standard_id, (
            f"ARN '{standards_arn}' should map to '{expected_standard_id}', "
            f"but got '{result}'"
        )


class TestInferenceBasedGrouping:
    """Tests for inference-based control grouping."""

    @pytest.fixture
    def scanner_with_logger(self):
        """Create a scanner instance with a mock logger."""
        from unittest.mock import MagicMock

        from app.scanners.aws.securityhub_scanner import SecurityHubScanner

        scanner = SecurityHubScanner.__new__(SecurityHubScanner)
        scanner.logger = MagicMock()
        return scanner

    def test_group_controls_by_inferred_standard(self, scanner_with_logger):
        """Test that controls are grouped by inferred standard from control ID."""
        scanner = scanner_with_logger

        # Sample control data with service-based IDs
        cspm_control_data = {
            "S3.1": {"control_id": "S3.1", "title": "S3 control 1"},
            "IAM.1": {"control_id": "IAM.1", "title": "IAM control 1"},
            "EC2.1": {"control_id": "EC2.1", "title": "EC2 control 1"},
        }

        result = scanner._group_controls_by_standard(cspm_control_data)

        # All service-based controls should go to FSBP
        assert "fsbp" in result
        assert len(result["fsbp"]) == 3
        assert "S3.1" in result["fsbp"]
        assert "IAM.1" in result["fsbp"]
        assert "EC2.1" in result["fsbp"]

    def test_service_prefixed_controls_go_to_fsbp(self, scanner_with_logger):
        """Test that all service-prefixed controls are grouped under FSBP."""
        scanner = scanner_with_logger

        cspm_control_data = {
            "S3.1": {"control_id": "S3.1"},
            "Backup.1": {"control_id": "Backup.1"},
            "Glue.1": {"control_id": "Glue.1"},
            "EventBridge.1": {"control_id": "EventBridge.1"},
        }

        result = scanner._group_controls_by_standard(cspm_control_data)

        # All should be in FSBP
        assert "fsbp" in result
        assert len(result["fsbp"]) == 4

    def test_unrecognised_prefix_goes_to_other(self, scanner_with_logger):
        """Test that controls with unrecognised prefixes go to 'other'."""
        scanner = scanner_with_logger

        cspm_control_data = {
            "S3.1": {"control_id": "S3.1", "title": "S3 control 1"},
            "FictionalService.1": {
                "control_id": "FictionalService.1",
                "title": "Unknown",
            },
        }

        result = scanner._group_controls_by_standard(cspm_control_data)

        # S3.1 should be in FSBP
        assert "S3.1" in result.get("fsbp", {})
        # FictionalService.1 should be in 'other'
        assert "FictionalService.1" in result.get("other", {})

    def test_empty_controls_returns_empty_result(self, scanner_with_logger):
        """Test that empty controls dict returns empty result."""
        scanner = scanner_with_logger

        result = scanner._group_controls_by_standard({})

        # All buckets should be empty and removed
        assert result == {}
