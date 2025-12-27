"""Tests for the pattern mapper."""

from app.mappers.pattern_mapper import PatternMapper
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
                    "eventName": ["CreateAccessKey", "CreateLoginProfile"],
                },
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
                "detail": {"eventName": ["StopLogging", "DeleteTrail"]},
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
        assert all(hasattr(t, "technique_id") for t in techniques)

    def test_get_technique_by_id(self):
        """Test getting a specific technique."""
        technique = self.mapper.get_technique("T1078.004")
        assert technique is not None
        assert technique.technique_name == "Valid Accounts: Cloud Accounts"

    def test_get_techniques_for_event(self):
        """Test getting techniques for a CloudTrail event."""
        techniques = self.mapper.get_techniques_for_event("CreateAccessKey")
        assert "T1098.001" in techniques

    def test_map_aggregated_securityhub_detection(self):
        """Test mapping an aggregated Security Hub CSPM detection."""
        detection = RawDetection(
            name="SecurityHub-All-Controls",
            detection_type=DetectionType.SECURITY_HUB,
            source_arn="arn:aws:securityhub:us-east-1:123456789012:hub/default",
            region="us-east-1",
            raw_config={
                "api_version": "cspm_aggregated",
                "controls": [
                    {
                        "control_id": "S3.1",
                        "status_by_region": {
                            "us-east-1": "ENABLED",
                            "eu-west-1": "ENABLED",
                        },
                    },
                    {
                        "control_id": "S3.2",
                        "status_by_region": {
                            "us-east-1": "ENABLED",
                            "eu-west-1": "DISABLED",
                        },
                    },
                    {
                        "control_id": "S3.8",
                        "status_by_region": {
                            "us-east-1": "ENABLED",
                        },
                    },
                    {
                        "control_id": "IAM.1",
                        "status_by_region": {
                            "us-east-1": "DISABLED",
                            "eu-west-1": "DISABLED",
                        },
                    },
                ],
            },
            description="Aggregated Security Hub controls",
            is_managed=True,
        )

        mappings = self.mapper.map_detection(detection)

        # Should have mappings from the enabled S3 controls
        technique_ids = [m.technique_id for m in mappings]
        assert "T1530" in technique_ids  # S3.1, S3.2, S3.8 all map to T1530

        # Find the T1530 mapping and check it consolidates controls
        t1530_mapping = next(m for m in mappings if m.technique_id == "T1530")
        assert "S3.1" in t1530_mapping.rationale
        assert "S3.2" in t1530_mapping.rationale
        assert "S3.8" in t1530_mapping.rationale

        # IAM.1 should NOT be in any rationale (it's disabled)
        for mapping in mappings:
            assert "IAM.1" not in mapping.rationale

    def test_map_aggregated_securityhub_disabled_controls_excluded(self):
        """Test that disabled controls are excluded from aggregated mapping."""
        detection = RawDetection(
            name="SecurityHub-All-Controls",
            detection_type=DetectionType.SECURITY_HUB,
            source_arn="arn:aws:securityhub:us-east-1:123456789012:hub/default",
            region="us-east-1",
            raw_config={
                "api_version": "cspm_aggregated",
                "controls": [
                    {
                        "control_id": "EC2.1",
                        "status_by_region": {
                            "us-east-1": "DISABLED",
                        },
                    },
                    {
                        "control_id": "EC2.2",
                        "status_by_region": {},  # No regions, effectively disabled
                    },
                ],
            },
            description="Aggregated Security Hub controls - all disabled",
            is_managed=True,
        )

        mappings = self.mapper.map_detection(detection)

        # Should have no mappings since all controls are disabled
        assert len(mappings) == 0

    def test_map_aggregated_securityhub_highest_confidence_kept(self):
        """Test that highest confidence is kept when multiple controls map to same technique."""
        detection = RawDetection(
            name="SecurityHub-IAM-Controls",
            detection_type=DetectionType.SECURITY_HUB,
            source_arn="arn:aws:securityhub:us-east-1:123456789012:hub/default",
            region="us-east-1",
            raw_config={
                "api_version": "cspm_aggregated",
                "controls": [
                    {
                        "control_id": "IAM.4",  # Maps to T1078 with 0.9 confidence
                        "status_by_region": {"us-east-1": "ENABLED"},
                    },
                    {
                        "control_id": "IAM.3",  # Maps to T1078 with 0.85 confidence
                        "status_by_region": {"us-east-1": "ENABLED"},
                    },
                ],
            },
            description="Aggregated Security Hub IAM controls",
            is_managed=True,
        )

        mappings = self.mapper.map_detection(detection)

        # Find T1078 mapping
        t1078_mappings = [m for m in mappings if m.technique_id == "T1078"]

        # Should have exactly one T1078 mapping (deduplicated)
        assert len(t1078_mappings) == 1

        # Confidence should be the highest (0.9 from IAM.4)
        assert t1078_mappings[0].confidence == 0.9

        # Both controls should be in rationale
        assert "IAM.3" in t1078_mappings[0].rationale
        assert "IAM.4" in t1078_mappings[0].rationale
