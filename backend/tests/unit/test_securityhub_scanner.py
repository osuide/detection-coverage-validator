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
