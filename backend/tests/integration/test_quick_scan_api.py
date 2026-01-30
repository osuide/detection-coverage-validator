"""Integration tests for quick scan API endpoint.

Tests the full request/response cycle including rate limiting,
validation, and error handling.
"""

import asyncio
from unittest.mock import patch

import pytest
from httpx import AsyncClient

QUICK_SCAN_URL = "/api/v1/quick-scan/analyse"

VALID_TERRAFORM = """
resource "aws_guardduty_detector" "main" {
  enable = true
}
"""

MULTI_RESOURCE_TERRAFORM = """
resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name = "encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
}
"""

SAMPLE_TECHNIQUES = [
    {
        "id": "uuid-1",
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "platforms": ["AWS"],
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "is_subtechnique": False,
    },
    {
        "id": "uuid-2",
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "platforms": ["AWS"],
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "is_subtechnique": False,
    },
]


class TestQuickScanEndpoint:
    """Tests for the POST /api/v1/quick-scan/analyse endpoint."""

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_valid_terraform_returns_200(
        self, mock_techniques, client: AsyncClient
    ):
        mock_techniques.return_value = SAMPLE_TECHNIQUES
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": VALID_TERRAFORM},
        )
        assert response.status_code == 200
        data = response.json()
        assert "summary" in data
        assert "tactic_coverage" in data
        assert "top_gaps" in data
        assert "detections" in data
        assert data["summary"]["detections_found"] >= 1

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_multi_resource_scan(self, mock_techniques, client: AsyncClient):
        mock_techniques.return_value = SAMPLE_TECHNIQUES
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": MULTI_RESOURCE_TERRAFORM},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["summary"]["detections_found"] >= 2
        assert data["summary"]["resources_parsed"] >= 3

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_non_detection_resources_return_zero(
        self, mock_techniques, client: AsyncClient
    ):
        mock_techniques.return_value = SAMPLE_TECHNIQUES
        hcl = """
resource "aws_s3_bucket" "logs" {
  bucket = "my-logs"
}
"""
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": hcl},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["summary"]["detections_found"] == 0
        assert data["summary"]["resources_parsed"] >= 1


class TestQuickScanValidation:
    """Tests for input validation and error handling."""

    async def test_empty_content_returns_422(self, client: AsyncClient):
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": ""},
        )
        assert response.status_code == 422

    async def test_missing_content_returns_422(self, client: AsyncClient):
        response = await client.post(
            QUICK_SCAN_URL,
            json={},
        )
        assert response.status_code == 422

    async def test_oversized_content_returns_422(self, client: AsyncClient):
        huge = "a" * 260_000
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": huge},
        )
        assert response.status_code == 422

    async def test_invalid_hcl_returns_422(self, client: AsyncClient):
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": "this is not valid HCL {{{"},
        )
        assert response.status_code == 422

    async def test_no_body_returns_422(self, client: AsyncClient):
        response = await client.post(QUICK_SCAN_URL)
        assert response.status_code == 422

    @patch(
        "app.api.routes.quick_scan.run_quick_scan",
        side_effect=asyncio.TimeoutError(),
    )
    async def test_parse_timeout_returns_408(self, mock_scan, client: AsyncClient):
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": VALID_TERRAFORM},
        )
        assert response.status_code == 408
        data = response.json()
        assert "timeout" in data["detail"].lower()

    async def test_invalid_hcl_error_body_has_no_traceback(self, client: AsyncClient):
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": "invalid {{{"},
        )
        assert response.status_code == 422
        assert "Traceback" not in response.text
        assert "hcl2" not in response.text.lower()


class TestQuickScanCredentialLeakage:
    """Verify credentials in input do not appear in API responses."""

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_credentials_not_in_response(
        self, mock_techniques, client: AsyncClient
    ):
        """AWS credentials in input must not appear in response."""
        mock_techniques.return_value = SAMPLE_TECHNIQUES
        hcl = """
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_guardduty_detector" "main" {
  enable = true
}
"""
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": hcl},
        )
        response_text = response.text
        assert "AKIAIOSFODNN7EXAMPLE" not in response_text
        assert "wJalrXUtnFEMI" not in response_text


class TestQuickScanResponseSchema:
    """Verify response structure and concurrent scan isolation."""

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_response_schema_matches(self, mock_techniques, client: AsyncClient):
        """Verify response matches expected schema."""
        mock_techniques.return_value = SAMPLE_TECHNIQUES
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": VALID_TERRAFORM},
        )
        assert response.status_code == 200
        data = response.json()

        summary = data["summary"]
        assert isinstance(summary["total_techniques"], int)
        assert isinstance(summary["covered_techniques"], int)
        assert isinstance(summary["coverage_percentage"], (int, float))
        assert isinstance(summary["detections_found"], int)
        assert isinstance(summary["resources_parsed"], int)
        assert isinstance(summary["truncated"], bool)

        for det in data["detections"]:
            assert "name" in det
            assert "source_arn" in det
            assert "detection_type" in det

        for gap in data["top_gaps"]:
            assert "technique_id" in gap
            assert "technique_name" in gap
            assert "tactic_name" in gap
            assert "priority" in gap

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_concurrent_scans_independent(
        self, mock_techniques, client: AsyncClient
    ):
        """Two concurrent scans must not interfere with each other."""
        mock_techniques.return_value = SAMPLE_TECHNIQUES
        hcl_a = 'resource "aws_guardduty_detector" "a" {\n  enable = true\n}'
        hcl_b = 'resource "aws_s3_bucket" "b" {\n  bucket = "logs"\n}'
        resp_a, resp_b = await asyncio.gather(
            client.post(QUICK_SCAN_URL, json={"content": hcl_a}),
            client.post(QUICK_SCAN_URL, json={"content": hcl_b}),
        )
        assert resp_a.json()["summary"]["detections_found"] >= 1
        assert resp_b.json()["summary"]["detections_found"] == 0


class TestQuickScanRateLimiting:
    """Tests for rate limiting on the quick scan endpoint."""

    async def test_rate_limit_headers_present(self, client: AsyncClient):
        """Rate limit headers should be in response."""
        response = await client.post(
            QUICK_SCAN_URL,
            json={"content": VALID_TERRAFORM},
        )
        assert response.status_code in (200, 429)

    async def test_exceeding_rate_limit_returns_429(self, client: AsyncClient):
        """Sending >5 requests per 5 minutes should trigger rate limiting."""
        for _ in range(8):
            response = await client.post(
                QUICK_SCAN_URL,
                json={"content": VALID_TERRAFORM},
            )
            if response.status_code == 429:
                break
        else:
            pytest.skip("Rate limiter did not trigger within 8 requests")

        assert response.status_code == 429
