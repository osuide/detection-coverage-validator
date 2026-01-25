"""Unit tests for Azure services in compliance schemas and data.

Tests that azure_services field is properly defined in schemas and
correctly populated in compliance mapping JSON files.
"""

import json
from pathlib import Path

import pytest

from app.schemas.compliance import CloudContextResponse


class TestCloudContextResponseSchema:
    """Test CloudContextResponse schema includes azure_services."""

    def test_azure_services_field_exists(self) -> None:
        """azure_services field should exist in the schema."""
        assert "azure_services" in CloudContextResponse.model_fields

    def test_azure_services_empty_default(self) -> None:
        """azure_services should default to empty list."""
        response = CloudContextResponse()
        assert response.azure_services == []

    def test_azure_services_accepts_list(self) -> None:
        """azure_services should accept a list of strings."""
        response = CloudContextResponse(
            azure_services=["Entra ID", "Azure Monitor", "Azure Key Vault"]
        )
        assert len(response.azure_services) == 3
        assert "Entra ID" in response.azure_services

    def test_all_cloud_services_present(self) -> None:
        """Schema should support AWS, GCP, and Azure services."""
        response = CloudContextResponse(
            aws_services=["IAM", "CloudTrail"],
            gcp_services=["Cloud IAM", "Cloud Audit Logs"],
            azure_services=["Entra ID", "Azure Activity Log"],
        )
        assert len(response.aws_services) == 2
        assert len(response.gcp_services) == 2
        assert len(response.azure_services) == 2


class TestComplianceMappingsAzureServices:
    """Test compliance mapping JSON files have azure_services."""

    @pytest.fixture
    def mappings_dir(self) -> Path:
        """Get the compliance mappings directory."""
        return (
            Path(__file__).parent.parent.parent / "app" / "data" / "compliance_mappings"
        )

    @pytest.fixture
    def nist_data(self, mappings_dir: Path) -> dict:
        """Load NIST 800-53 R5 compliance data."""
        with open(mappings_dir / "nist_800_53_r5.json") as f:
            return json.load(f)

    @pytest.fixture
    def cis_data(self, mappings_dir: Path) -> dict:
        """Load CIS Controls v8 compliance data."""
        with open(mappings_dir / "cis_controls_v8.json") as f:
            return json.load(f)

    def test_nist_highly_relevant_p1_have_azure_services(self, nist_data: dict) -> None:
        """P1 highly_relevant NIST controls should have azure_services."""
        controls_with_azure = 0
        controls_missing_azure = []

        for control in nist_data["controls"]:
            if (
                control.get("priority") == "P1"
                and control.get("cloud_applicability") == "highly_relevant"
            ):
                cloud_context = control.get("cloud_context", {})
                if cloud_context.get("azure_services"):
                    controls_with_azure += 1
                else:
                    controls_missing_azure.append(control["control_id"])

        assert (
            controls_with_azure > 0
        ), "No P1 highly_relevant controls have azure_services"
        # Allow some flexibility - not all controls may need Azure services
        assert (
            len(controls_missing_azure) == 0
        ), f"P1 highly_relevant controls missing azure_services: {controls_missing_azure}"

    def test_cis_highly_relevant_p1_have_azure_services(self, cis_data: dict) -> None:
        """P1 highly_relevant CIS controls should have azure_services."""
        controls_with_azure = 0
        controls_missing_azure = []

        for control in cis_data["controls"]:
            if (
                control.get("priority") == "P1"
                and control.get("cloud_applicability") == "highly_relevant"
            ):
                cloud_context = control.get("cloud_context", {})
                if cloud_context.get("azure_services"):
                    controls_with_azure += 1
                else:
                    controls_missing_azure.append(control["control_id"])

        assert (
            controls_with_azure > 0
        ), "No P1 highly_relevant controls have azure_services"
        assert (
            len(controls_missing_azure) == 0
        ), f"P1 highly_relevant controls missing azure_services: {controls_missing_azure}"

    def test_azure_services_are_valid_strings(self, nist_data: dict) -> None:
        """azure_services should contain valid non-empty strings."""
        for control in nist_data["controls"]:
            cloud_context = control.get("cloud_context", {})
            azure_services = cloud_context.get("azure_services", [])

            for svc in azure_services:
                assert isinstance(svc, str), f"azure_services should be strings: {svc}"
                assert len(svc) > 0, "azure_services should not contain empty strings"

    def test_azure_services_mapping_consistency(
        self, nist_data: dict, cis_data: dict
    ) -> None:
        """Azure services should be consistent across frameworks."""
        # Collect all unique Azure service names
        all_azure_services = set()

        for data in [nist_data, cis_data]:
            for control in data["controls"]:
                cloud_context = control.get("cloud_context", {})
                azure_services = cloud_context.get("azure_services", [])
                all_azure_services.update(azure_services)

        # Check for expected common Azure services
        expected_services = {
            "Entra ID",
            "Azure Monitor",
            "Microsoft Defender for Cloud",
        }
        assert expected_services.issubset(
            all_azure_services
        ), f"Missing expected Azure services. Found: {all_azure_services}"
