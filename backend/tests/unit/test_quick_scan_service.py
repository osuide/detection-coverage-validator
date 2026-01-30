"""Unit tests for quick scan service and coverage functions."""

from unittest.mock import patch

import pytest

from app.analyzers.coverage_calculator import TechniqueCoverageInfo
from app.mappers.pattern_mapper import MappingResult
from app.models.detection import DetectionType
from app.parsers.terraform_hcl_parser import ParseResult
from app.scanners.base import RawDetection
from app.services.quick_scan_service import (
    _empty_result,
    build_technique_coverage_from_mappings,
    calculate_tactic_summary,
    run_quick_scan,
)

# ---------------------------------------------------------------------------
# Sample technique data — keys match cache.py get_cached_techniques() output
# Uses "name" (NOT "technique_name")
# ---------------------------------------------------------------------------

SAMPLE_TECHNIQUES = [
    {
        "id": "uuid-1",
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "platforms": ["AWS", "Azure", "GCP"],
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "is_subtechnique": False,
    },
    {
        "id": "uuid-2",
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "platforms": ["AWS", "Azure", "GCP"],
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "is_subtechnique": False,
    },
    {
        "id": "uuid-3",
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "platforms": ["AWS", "Azure", "GCP"],
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "is_subtechnique": False,
    },
]


# ---------------------------------------------------------------------------
# Coverage function tests
# ---------------------------------------------------------------------------


class TestBuildTechniqueCoverage:
    """Tests for building technique coverage from mappings."""

    def test_all_uncovered(self):
        coverage = build_technique_coverage_from_mappings(SAMPLE_TECHNIQUES, [])
        assert len(coverage) == 3
        assert all(tc.status == "uncovered" for tc in coverage)
        assert all(tc.detection_count == 0 for tc in coverage)

    def test_one_covered(self):
        mapping = MappingResult(
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic_id="TA0001",
            tactic_name="Initial Access",
            confidence=0.8,
            matched_indicators=["guardduty"],
            rationale="GuardDuty detects credential misuse",
        )
        coverage = build_technique_coverage_from_mappings(SAMPLE_TECHNIQUES, [mapping])

        covered = [tc for tc in coverage if tc.status == "covered"]
        uncovered = [tc for tc in coverage if tc.status == "uncovered"]

        assert len(covered) == 1
        assert covered[0].technique_id == "T1078"
        assert covered[0].technique_name == "Valid Accounts"
        assert covered[0].detection_count == 1
        assert covered[0].max_confidence == 0.8
        assert len(uncovered) == 2

    def test_multiple_mappings_same_technique(self):
        mappings = [
            MappingResult(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic_id="TA0001",
                tactic_name="Initial Access",
                confidence=0.7,
                matched_indicators=["detector_a"],
                rationale="First detection",
            ),
            MappingResult(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic_id="TA0001",
                tactic_name="Initial Access",
                confidence=0.9,
                matched_indicators=["detector_b"],
                rationale="Second detection",
            ),
        ]
        coverage = build_technique_coverage_from_mappings(SAMPLE_TECHNIQUES, mappings)

        t1078 = next(tc for tc in coverage if tc.technique_id == "T1078")
        assert t1078.detection_count == 2
        assert t1078.max_confidence == 0.9
        assert t1078.avg_confidence == 0.8

    def test_empty_techniques_list(self):
        coverage = build_technique_coverage_from_mappings([], [])
        assert coverage == []


class TestCalculateTacticSummary:
    """Tests for tactic-level summary calculation."""

    def test_single_tactic(self):
        coverage = [
            TechniqueCoverageInfo(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic_id="TA0001",
                tactic_name="Initial Access",
                status="covered",
                detection_count=1,
                max_confidence=0.8,
                avg_confidence=0.8,
            ),
            TechniqueCoverageInfo(
                technique_id="T1190",
                technique_name="Exploit Public-Facing App",
                tactic_id="TA0001",
                tactic_name="Initial Access",
                status="uncovered",
                detection_count=0,
                max_confidence=0.0,
                avg_confidence=0.0,
            ),
        ]
        summary = calculate_tactic_summary(coverage)
        assert "Initial Access" in summary
        assert summary["Initial Access"]["total"] == 2
        assert summary["Initial Access"]["covered"] == 1
        assert summary["Initial Access"]["percentage"] == 50.0

    def test_multiple_tactics(self):
        coverage = [
            TechniqueCoverageInfo(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic_id="TA0001",
                tactic_name="Initial Access",
                status="covered",
                detection_count=1,
                max_confidence=0.8,
                avg_confidence=0.8,
            ),
            TechniqueCoverageInfo(
                technique_id="T1059",
                technique_name="Command Interpreter",
                tactic_id="TA0002",
                tactic_name="Execution",
                status="uncovered",
                detection_count=0,
                max_confidence=0.0,
                avg_confidence=0.0,
            ),
        ]
        summary = calculate_tactic_summary(coverage)
        assert len(summary) == 2
        assert summary["Initial Access"]["percentage"] == 100.0
        assert summary["Execution"]["percentage"] == 0.0

    def test_empty_coverage(self):
        summary = calculate_tactic_summary([])
        assert summary == {}


# ---------------------------------------------------------------------------
# Empty result tests
# ---------------------------------------------------------------------------


class TestEmptyResult:
    """Tests for empty result builder."""

    def test_empty_result_no_error(self):
        parse_result = ParseResult(detections=[], resource_count=5)
        result = _empty_result(parse_result)
        assert result["summary"]["detections_found"] == 0
        assert result["summary"]["resources_parsed"] == 5
        assert "error" not in result

    def test_empty_result_with_error(self):
        parse_result = ParseResult(detections=[], resource_count=0)
        result = _empty_result(parse_result, error="Cache miss")
        assert result["error"] == "Cache miss"


# ---------------------------------------------------------------------------
# Cache key construction tests
# ---------------------------------------------------------------------------


class TestGetAllTechniques:
    """Tests for MITRE technique cache retrieval."""

    @patch("app.services.quick_scan_service.get_cached")
    @patch("app.services.quick_scan_service.mitre_techniques_key")
    async def test_cache_key_matches_expected_format(
        self, mock_key_fn, mock_get_cached
    ):
        """Verify cache key construction matches get_cached_techniques() format."""
        mock_key_fn.return_value = "mitre:techniques"
        mock_get_cached.return_value = SAMPLE_TECHNIQUES

        from app.services.quick_scan_service import _get_all_techniques

        result = await _get_all_techniques()

        mock_get_cached.assert_called_once_with("mitre:techniques:cloud=True")
        assert result == SAMPLE_TECHNIQUES

    @patch("app.services.quick_scan_service.get_cached")
    async def test_cache_miss_returns_empty_list(self, mock_get_cached):
        mock_get_cached.return_value = None

        from app.services.quick_scan_service import _get_all_techniques

        result = await _get_all_techniques()

        assert result == []


# ---------------------------------------------------------------------------
# PatternMapper seam tests
# ---------------------------------------------------------------------------


class TestPatternMapperSeam:
    """Verify RawDetection objects from quick scan work with PatternMapper."""

    def test_raw_detection_accepted_by_pattern_mapper(self):
        """PatternMapper must accept RawDetection with DetectionType enum and synthetic source_arn."""
        from app.mappers.pattern_mapper import PatternMapper

        rd = RawDetection(
            name="aws_guardduty_detector.main",
            detection_type=DetectionType.GUARDDUTY_FINDING,
            source_arn="iac://terraform/aws_guardduty_detector/main",
            region="iac-static",
            raw_config={},
        )
        mapper = PatternMapper()
        # Should not raise — may return empty list if no indicators match
        results = mapper.map_detection(rd)
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# Service orchestration tests
# ---------------------------------------------------------------------------


class TestRunQuickScan:
    """Tests for the main quick scan orchestration."""

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_full_scan_with_guardduty(self, mock_techniques):
        mock_techniques.return_value = SAMPLE_TECHNIQUES

        hcl = """
resource "aws_guardduty_detector" "main" {
  enable = true
}
"""
        result = await run_quick_scan(hcl)

        assert result["summary"]["detections_found"] == 1
        assert result["summary"]["resources_parsed"] == 1
        assert result["summary"]["total_techniques"] == 3
        assert "tactic_coverage" in result
        assert "top_gaps" in result
        assert "detections" in result

    async def test_scan_empty_content_raises(self):
        with pytest.raises(ValueError, match="Empty content"):
            await run_quick_scan("")

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_scan_no_detection_resources(self, mock_techniques):
        mock_techniques.return_value = []
        hcl = """
resource "aws_s3_bucket" "logs" {
  bucket = "my-logs"
}
"""
        result = await run_quick_scan(hcl)
        assert result["summary"]["detections_found"] == 0
        assert result["summary"]["resources_parsed"] == 1

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_scan_mitre_cache_miss(self, mock_techniques):
        mock_techniques.return_value = []
        hcl = """
resource "aws_guardduty_detector" "main" {
  enable = true
}
"""
        result = await run_quick_scan(hcl)
        assert "error" in result
        assert result["error"] == "MITRE technique data unavailable"

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_detections_response_capped_at_50(self, mock_techniques):
        mock_techniques.return_value = SAMPLE_TECHNIQUES
        # Generate 80 detection resources
        lines = [
            f'resource "aws_guardduty_detector" "d{i}" {{\n  enable = true\n}}'
            for i in range(80)
        ]
        result = await run_quick_scan("\n\n".join(lines))
        assert result["summary"]["detections_found"] == 80
        assert len(result["detections"]) == 50

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_multi_provider_scan(self, mock_techniques):
        """AWS + GCP + Azure resources in one configuration."""
        mock_techniques.return_value = SAMPLE_TECHNIQUES
        hcl = """
resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "google_logging_metric" "audit" {
  name   = "audit-log-metric"
  filter = "protoPayload.methodName=\\"SetIamPolicy\\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "azurerm_security_center_subscription_pricing" "defender" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}
"""
        result = await run_quick_scan(hcl)
        assert result["summary"]["detections_found"] == 3
        detection_arns = {d["source_arn"] for d in result["detections"]}
        assert "iac://terraform/aws_guardduty_detector/main" in detection_arns
        assert "iac://terraform/google_logging_metric/audit" in detection_arns
        assert (
            "iac://terraform/azurerm_security_center_subscription_pricing/defender"
            in detection_arns
        )

    @patch("app.services.quick_scan_service._get_all_techniques")
    async def test_gaps_populated_for_uncovered_techniques(self, mock_techniques):
        """Mock 2 techniques, scan HCL that covers 1. Assert top_gaps contains the uncovered one."""
        mock_techniques.return_value = [
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
        hcl = """
resource "aws_guardduty_detector" "main" {
  enable = true
}
"""
        result = await run_quick_scan(hcl)
        # T1190 should be uncovered since GuardDuty does not detect
        # Exploit Public-Facing Application
        assert len(result["top_gaps"]) > 0
        # The total techniques should be 2
        assert result["summary"]["total_techniques"] == 2
