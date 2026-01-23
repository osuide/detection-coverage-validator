"""Unit tests for DefenderScanner regulatory compliance scanning.

Tests the _scan_regulatory_compliance method added to DefenderScanner
for CIS Azure v2.1.0 and NIST SP 800-53 Rev. 5 compliance standards.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from azure.core.exceptions import (
    AzureError,
    HttpResponseError,
    ResourceNotFoundError,
)

from app.scanners.azure.defender_scanner import (
    DefenderScanner,
    AZURE_COMPLIANCE_STANDARDS,
)


@pytest.fixture
def mock_credential():
    """Mock Azure credential for testing."""
    return AsyncMock()


class AsyncIteratorMock:
    """Helper to create async iterables for Azure SDK mocks."""

    def __init__(self, items):
        self.items = items

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self.items:
            raise StopAsyncIteration
        return self.items.pop(0)


@pytest.fixture
def mock_security_center():
    """Mock SecurityCenter client with realistic responses."""
    mock = MagicMock()

    # Mock standard response (CIS Azure v2.1.0)
    # Note: counts must be consistent with number of controls yielded
    # We yield 1 control, so counts should reflect that
    mock_standard = MagicMock()
    mock_standard.name = "CIS-Azure-v2.1.0"
    mock_standard.properties = MagicMock()
    mock_standard.properties.state = "Passed"
    mock_standard.properties.passed_controls = 1
    mock_standard.properties.failed_controls = 0
    mock_standard.properties.skipped_controls = 0

    # Mock control response
    mock_control = MagicMock()
    mock_control.name = "1.1"
    mock_control.properties = MagicMock()

    # Use side_effect to create fresh iterators each call
    mock.regulatory_compliance_standards.list.return_value = AsyncIteratorMock(
        [mock_standard]
    )
    mock.regulatory_compliance_controls.list.return_value = AsyncIteratorMock(
        [mock_control]
    )
    mock.assessments.list.return_value = AsyncIteratorMock([])

    return mock


class TestDefenderRegulatoryCompliance:
    """Tests for DefenderScanner regulatory compliance scanning."""

    @pytest.mark.asyncio
    async def test_scan_returns_detection_for_cis_standard(
        self, mock_credential, mock_security_center
    ):
        """Scanner should create one detection for CIS v2.1.0."""
        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
        ) as mock_client_class:
            # Configure the async context manager
            mock_client_class.return_value.__aenter__.return_value = (
                mock_security_center
            )
            mock_client_class.return_value.__aexit__.return_value = None

            scanner = DefenderScanner(session=mock_credential)
            detections = await scanner.scan(
                regions=[],  # Ignored but required for interface
                options={"subscription_id": "test-sub-id"},
            )

        compliance_detections = [
            d for d in detections if "Regulatory Compliance" in d.name
        ]
        assert len(compliance_detections) == 1
        assert compliance_detections[0].raw_config["standard_id"] == "azure_cis_v2"

    @pytest.mark.asyncio
    async def test_scan_includes_compliance_metrics(
        self, mock_credential, mock_security_center
    ):
        """Detection should include compliance metrics."""
        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
        ) as mock_client_class:
            mock_client_class.return_value.__aenter__.return_value = (
                mock_security_center
            )
            mock_client_class.return_value.__aexit__.return_value = None

            scanner = DefenderScanner(session=mock_credential)
            detections = await scanner.scan(
                regions=[],
                options={"subscription_id": "test-sub-id"},
            )

        compliance = [d for d in detections if "Regulatory Compliance" in d.name][0]
        effectiveness = compliance.raw_config["detection_effectiveness"]
        assert effectiveness["passed_count"] == 1
        assert effectiveness["failed_count"] == 0
        assert effectiveness["compliance_percent"] == 100

    @pytest.mark.asyncio
    async def test_scan_requires_subscription_id(self, mock_credential):
        """Scanner should raise error if subscription_id not provided."""
        scanner = DefenderScanner(session=mock_credential)

        with pytest.raises(ValueError, match="subscription_id"):
            await scanner.scan(regions=[], options={})

    @pytest.mark.asyncio
    async def test_scan_handles_resource_not_found(self, mock_credential):
        """Scanner should return empty list when Defender not enabled."""
        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
        ) as mock_client_class:
            mock_client_class.return_value.__aenter__.side_effect = (
                ResourceNotFoundError("Defender not enabled")
            )

            scanner = DefenderScanner(session=mock_credential)
            detections = await scanner.scan(
                regions=[],
                options={"subscription_id": "test-sub-id"},
            )

            # Should return empty list, not raise exception
            assert detections == []

    @pytest.mark.asyncio
    async def test_scan_handles_http_error(self, mock_credential):
        """Scanner should re-raise HttpResponseError after logging."""
        mock_response = MagicMock()
        mock_response.headers = {"Retry-After": "60"}
        error = HttpResponseError(response=mock_response, message="Rate limited")
        error.status_code = 429

        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
        ) as mock_client_class:
            mock_client_class.return_value.__aenter__.side_effect = error

            scanner = DefenderScanner(session=mock_credential)
            with pytest.raises(HttpResponseError):
                await scanner.scan(
                    regions=[],
                    options={"subscription_id": "test-sub-id"},
                )

    @pytest.mark.asyncio
    async def test_scan_handles_azure_error(self, mock_credential):
        """Scanner should re-raise AzureError after logging."""
        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
        ) as mock_client_class:
            mock_client_class.return_value.__aenter__.side_effect = AzureError(
                "Connection refused"
            )

            scanner = DefenderScanner(session=mock_credential)
            with pytest.raises(AzureError):
                await scanner.scan(
                    regions=[],
                    options={"subscription_id": "test-sub-id"},
                )

    @pytest.mark.asyncio
    async def test_scan_handles_empty_standards_list(
        self, mock_credential, mock_security_center
    ):
        """Scanner should return empty compliance list when no standards configured."""

        async def empty_standards():
            return
            yield  # Empty generator

        mock_security_center.regulatory_compliance_standards.list.return_value = (
            empty_standards()
        )

        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
        ) as mock_client_class:
            mock_client_class.return_value.__aenter__.return_value = (
                mock_security_center
            )
            mock_client_class.return_value.__aexit__.return_value = None

            scanner = DefenderScanner(session=mock_credential)
            detections = await scanner.scan(
                regions=[],
                options={"subscription_id": "test-sub-id"},
            )

        compliance = [d for d in detections if "Regulatory Compliance" in d.name]
        assert len(compliance) == 0

    @pytest.mark.asyncio
    async def test_scan_handles_control_without_properties(
        self, mock_credential, mock_security_center
    ):
        """Scanner should skip controls with None properties (hasattr check)."""
        mock_control_no_props = MagicMock()
        mock_control_no_props.name = "1.2"
        mock_control_no_props.properties = None  # Missing properties

        mock_control_with_props = MagicMock()
        mock_control_with_props.name = "1.1"
        mock_control_with_props.properties = MagicMock()

        async def controls_with_missing():
            yield mock_control_no_props
            yield mock_control_with_props

        mock_security_center.regulatory_compliance_controls.list.return_value = (
            controls_with_missing()
        )

        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
        ) as mock_client_class:
            mock_client_class.return_value.__aenter__.return_value = (
                mock_security_center
            )
            mock_client_class.return_value.__aexit__.return_value = None

            scanner = DefenderScanner(session=mock_credential)
            detections = await scanner.scan(
                regions=[],
                options={"subscription_id": "test-sub-id"},
            )

        # Should still return detection, skipping the bad control
        compliance = [d for d in detections if "Regulatory Compliance" in d.name]
        assert len(compliance) == 1


class TestAzureComplianceStandardsMapping:
    """Tests for the AZURE_COMPLIANCE_STANDARDS constant."""

    def test_cis_azure_mapping_exists(self):
        """CIS Azure v2.1.0 mapping should exist."""
        assert "CIS-Azure-v2.1.0" in AZURE_COMPLIANCE_STANDARDS
        mapping = AZURE_COMPLIANCE_STANDARDS["CIS-Azure-v2.1.0"]
        assert mapping["standard_id"] == "azure_cis_v2"
        assert mapping["framework"] == "CIS"

    def test_nist_mapping_exists(self):
        """NIST SP 800-53 R5 mapping should exist."""
        assert "NIST-SP-800-53-R5" in AZURE_COMPLIANCE_STANDARDS
        mapping = AZURE_COMPLIANCE_STANDARDS["NIST-SP-800-53-R5"]
        assert mapping["standard_id"] == "azure_nist_800_53_r5"
        assert mapping["framework"] == "NIST"
