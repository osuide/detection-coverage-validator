"""Tests for the pattern mapper."""

import pytest
from app.mappers.pattern_mapper import PatternMapper
from app.mappers.indicator_library import TECHNIQUE_INDICATORS
from app.scanners.base import RawDetection
from app.models.detection import DetectionType


class TestPatternMapper:
    """Tests for PatternMapper class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mapper = PatternMapper()

    def test_map_eventbridge_rule_with_iam_events(self):
        """Test mapping an EventBridge rule monitoring IAM events."""
        detection = RawDetection(
            name="Monitor-IAM-CreateAccessKey",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            source_arn="arn:aws:events:us-east-1:123456789012:rule/test",
            region="us-east-1",
            raw_config={},
            event_pattern={
                "source": ["aws.iam"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["iam.amazonaws.com"],
                    "eventName": ["CreateAccessKey", "CreateLoginProfile"]
                }
            },
            description="Monitor for new IAM credentials being created",
        )

        mappings = self.mapper.map_detection(detection, min_confidence=0.4)

        # Should map to T1098.001 (Additional Cloud Credentials)
        technique_ids = [m.technique_id for m in mappings]
        assert "T1098.001" in technique_ids

    def test_map_cloudwatch_query_with_login_pattern(self):
        """Test mapping a CloudWatch query for console logins."""
        detection = RawDetection(
            name="Console-Login-Monitor",
            detection_type=DetectionType.CLOUDWATCH_LOGS_INSIGHTS,
            source_arn="arn:aws:logs:us-east-1:123456789012:query:abc123",
            region="us-east-1",
            raw_config={},
            query_pattern="fields @timestamp, @message | filter eventName = 'ConsoleLogin' | filter errorMessage like /Failed/",
            log_groups=["/aws/cloudtrail/logs"],
            description="Monitor for failed console login attempts",
        )

        mappings = self.mapper.map_detection(detection, min_confidence=0.4)

        # Should map to T1078.004 (Valid Accounts: Cloud Accounts)
        technique_ids = [m.technique_id for m in mappings]
        assert any("T1078" in tid for tid in technique_ids)

    def test_map_detection_with_no_matches(self):
        """Test mapping a detection that doesn't match any techniques."""
        detection = RawDetection(
            name="Random-Metric",
            detection_type=DetectionType.CLOUDWATCH_LOGS_INSIGHTS,
            source_arn="arn:aws:logs:us-east-1:123456789012:query:xyz",
            region="us-east-1",
            raw_config={},
            query_pattern="fields @timestamp | stats count(*)",
            description="Just counting things",
        )

        mappings = self.mapper.map_detection(detection, min_confidence=0.6)

        # Should have no high-confidence mappings
        assert len(mappings) == 0

    def test_confidence_scoring(self):
        """Test that confidence scores are within valid range."""
        detection = RawDetection(
            name="Security-Detection",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            source_arn="arn:aws:events:us-east-1:123456789012:rule/test",
            region="us-east-1",
            raw_config={},
            event_pattern={
                "source": ["aws.cloudtrail"],
                "detail": {
                    "eventName": ["StopLogging", "DeleteTrail"]
                }
            },
            description="Detect CloudTrail tampering",
        )

        mappings = self.mapper.map_detection(detection, min_confidence=0.0)

        for mapping in mappings:
            assert 0.0 <= mapping.confidence <= 1.0
            assert mapping.technique_id
            assert mapping.technique_name
            # rationale may be empty for some low-confidence mappings
            assert isinstance(mapping.rationale, str)

    def test_get_all_techniques(self):
        """Test getting all technique indicators."""
        techniques = self.mapper.get_all_techniques()
        assert len(techniques) > 0
        assert all(hasattr(t, 'technique_id') for t in techniques)

    def test_get_technique_by_id(self):
        """Test getting a specific technique."""
        technique = self.mapper.get_technique("T1078.004")
        assert technique is not None
        assert technique.technique_name == "Valid Accounts: Cloud Accounts"

    def test_get_techniques_for_event(self):
        """Test getting techniques for a CloudTrail event."""
        techniques = self.mapper.get_techniques_for_event("CreateAccessKey")
        assert "T1098.001" in techniques
