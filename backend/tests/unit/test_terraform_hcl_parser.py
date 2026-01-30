"""Unit tests for Terraform HCL quick scan parser."""

import pytest

from app.parsers.terraform_hcl_parser import (
    MAX_CONTENT_BYTES,
    MAX_DETECTIONS,
    ParseResult,
    _extract_detections,
    _unwrap_hcl_value,
    _validate_content,
    _sanitise_config,
    parse_terraform_content,
)
from app.models.detection import DetectionType


class TestValidateContent:
    """Tests for content validation before parsing."""

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Empty content"):
            _validate_content("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="Empty content"):
            _validate_content("   \n\t  ")

    def test_exceeds_size_limit_raises(self):
        huge = "a" * (MAX_CONTENT_BYTES + 1)
        with pytest.raises(ValueError, match="exceeds maximum size"):
            _validate_content(huge)

    def test_valid_content_passes(self):
        result = _validate_content('resource "aws_guardduty_detector" "main" {}')
        assert result == 'resource "aws_guardduty_detector" "main" {}'

    def test_exactly_at_limit_passes(self):
        content = "a" * MAX_CONTENT_BYTES
        result = _validate_content(content)
        assert len(result) == MAX_CONTENT_BYTES

    def test_multibyte_characters_count_bytes(self):
        """Ensure UTF-8 byte length is used, not character count."""
        # Each emoji is 4 bytes in UTF-8
        emoji_content = "\U0001f512" * (MAX_CONTENT_BYTES // 4 + 1)
        with pytest.raises(ValueError, match="exceeds maximum size"):
            _validate_content(emoji_content)


class TestUnwrapHclValue:
    """Tests for python-hcl2 value unwrapping."""

    def test_unwrap_single_element_list(self):
        assert _unwrap_hcl_value(["my-alarm"]) == "my-alarm"

    def test_no_unwrap_multi_element_list(self):
        assert _unwrap_hcl_value(["a", "b"]) == ["a", "b"]

    def test_no_unwrap_non_list(self):
        assert _unwrap_hcl_value("plain") == "plain"

    def test_no_unwrap_empty_list(self):
        assert _unwrap_hcl_value([]) == []

    def test_unwrap_none(self):
        assert _unwrap_hcl_value(None) is None

    def test_unwrap_nested_dict_in_list(self):
        val = [{"key": "value"}]
        assert _unwrap_hcl_value(val) == {"key": "value"}


class TestSanitiseConfig:
    """Tests for recursive substring-based secret stripping."""

    def test_strips_access_key(self):
        config = {"access_key": "AKIAIOSFODNN7EXAMPLE", "enable": True}
        result = _sanitise_config(config)
        assert "access_key" not in result
        assert result["enable"] is True

    def test_strips_secret_key(self):
        config = {"secret_key": "wJalrXUtnFEMI/K7MDENG", "name": "test"}
        result = _sanitise_config(config)
        assert "secret_key" not in result
        assert result["name"] == "test"

    def test_strips_password_substring(self):
        """db_password should be stripped because it contains 'password'."""
        config = {"db_password": "hunter2", "tier": "Standard"}
        result = _sanitise_config(config)
        assert "db_password" not in result
        assert result["tier"] == "Standard"

    def test_strips_token(self):
        config = {"token": "abc123", "enabled": True}
        result = _sanitise_config(config)
        assert "token" not in result

    def test_strips_private_key(self):
        config = {"private_key": "-----BEGIN RSA PRIVATE KEY-----", "name": "x"}
        result = _sanitise_config(config)
        assert "private_key" not in result

    def test_strips_connection_string(self):
        config = {"connection_string": "Server=myServer;Database=myDB;", "type": "sql"}
        result = _sanitise_config(config)
        assert "connection_string" not in result

    def test_strips_api_key(self):
        config = {"api_key": "sk-12345", "region": "eu-west-1"}
        result = _sanitise_config(config)
        assert "api_key" not in result

    def test_strips_secret_substring(self):
        """master_secret should be stripped because it contains 'secret'."""
        config = {"master_secret": "s3cr3t", "name": "test"}
        result = _sanitise_config(config)
        assert "master_secret" not in result
        assert result["name"] == "test"

    def test_strips_credential_substring(self):
        config = {"db_credential": "cred123", "port": 5432}
        result = _sanitise_config(config)
        assert "db_credential" not in result
        assert result["port"] == 5432

    def test_strips_auth_substring(self):
        config = {"auth_header": "Bearer xxx", "timeout": 30}
        result = _sanitise_config(config)
        assert "auth_header" not in result
        assert result["timeout"] == 30

    def test_nested_dict_sanitisation(self):
        """Secrets inside nested dicts should be recursively stripped."""
        config = {
            "settings": {
                "db_password": "hunter2",
                "port": 5432,
            },
            "name": "test",
        }
        result = _sanitise_config(config)
        assert "db_password" not in result["settings"]
        assert result["settings"]["port"] == 5432
        assert result["name"] == "test"

    def test_list_of_dicts_sanitisation(self):
        """Secrets inside dicts within lists should be recursively stripped."""
        config = {
            "providers": [
                {"access_key": "AKIA...", "region": "eu-west-1"},
                {"name": "secondary", "secret": "abc"},
            ],
            "enabled": True,
        }
        result = _sanitise_config(config)
        assert "access_key" not in result["providers"][0]
        assert result["providers"][0]["region"] == "eu-west-1"
        assert "secret" not in result["providers"][1]
        assert result["providers"][1]["name"] == "secondary"
        assert result["enabled"] is True

    def test_preserves_safe_keys(self):
        config = {
            "alarm_name": "high-cpu",
            "threshold": 80,
            "namespace": "AWS/EC2",
        }
        result = _sanitise_config(config)
        assert result == config


class TestExtractDetections:
    """Tests for detection extraction from parsed HCL dict."""

    def test_extract_guardduty(self):
        parsed = {
            "resource": [{"aws_guardduty_detector": {"main": {"enable": [True]}}}]
        }
        detections = _extract_detections(parsed).detections
        assert len(detections) == 1
        assert detections[0].detection_type == DetectionType.GUARDDUTY_FINDING
        assert detections[0].name == "aws_guardduty_detector.main"
        assert detections[0].source_arn == "iac://terraform/aws_guardduty_detector/main"
        assert detections[0].region == "iac-static"

    def test_extract_cloudwatch_alarm(self):
        parsed = {
            "resource": [
                {
                    "aws_cloudwatch_metric_alarm": {
                        "high_cpu": {
                            "alarm_name": ["high-cpu"],
                            "description": ["CPU alarm"],
                        }
                    }
                }
            ]
        }
        detections = _extract_detections(parsed).detections
        assert len(detections) == 1
        assert detections[0].detection_type == DetectionType.CLOUDWATCH_ALARM
        assert detections[0].raw_config is not None

    def test_extract_eventbridge_rule(self):
        parsed = {
            "resource": [
                {
                    "aws_cloudwatch_event_rule": {
                        "login_rule": {
                            "name": ["capture-login"],
                            "event_pattern": ['{"source":["aws.signin"]}'],
                        }
                    }
                }
            ]
        }
        detections = _extract_detections(parsed).detections
        assert len(detections) == 1
        assert detections[0].detection_type == DetectionType.EVENTBRIDGE_RULE
        assert detections[0].raw_config is not None

    def test_extract_gcp_resources(self):
        parsed = {
            "resource": [
                {
                    "google_logging_metric": {
                        "audit_log": {"filter": ["protoPayload.methodName"]}
                    }
                },
                {
                    "google_monitoring_alert_policy": {
                        "cpu_alert": {"display_name": ["High CPU"]}
                    }
                },
            ]
        }
        detections = _extract_detections(parsed).detections
        assert len(detections) == 2
        types = {d.detection_type for d in detections}
        assert DetectionType.GCP_CLOUD_LOGGING in types
        assert DetectionType.GCP_CLOUD_MONITORING in types

    def test_extract_azure_resources(self):
        parsed = {
            "resource": [
                {
                    "azurerm_security_center_subscription_pricing": {
                        "defender": {"tier": ["Standard"]}
                    }
                },
                {"azurerm_policy_assignment": {"audit_vms": {"name": ["audit-vms"]}}},
            ]
        }
        detections = _extract_detections(parsed).detections
        assert len(detections) == 2
        types = {d.detection_type for d in detections}
        assert DetectionType.AZURE_DEFENDER in types
        assert DetectionType.AZURE_POLICY in types

    def test_skip_non_detection_resources(self):
        parsed = {
            "resource": [
                {"aws_s3_bucket": {"logs": {"bucket": ["my-logs"]}}},
                {"aws_vpc": {"main": {"cidr_block": ["10.0.0.0/16"]}}},
            ]
        }
        detections = _extract_detections(parsed).detections
        assert len(detections) == 0

    def test_truncate_at_max_detections(self):
        """Ensure we stop at MAX_DETECTIONS to prevent memory exhaustion."""
        resources = []
        for i in range(MAX_DETECTIONS + 50):
            resources.append(
                {"aws_guardduty_detector": {f"detector_{i}": {"enable": [True]}}}
            )
        parsed = {"resource": resources}
        detections = _extract_detections(parsed).detections
        assert len(detections) == MAX_DETECTIONS

    def test_no_resources_key(self):
        parsed = {"variable": [{"region": {"default": ["us-east-1"]}}]}
        detections = _extract_detections(parsed).detections
        assert len(detections) == 0

    def test_malformed_resource_block_skipped(self):
        parsed = {
            "resource": [
                "not a dict",
                42,
                {"aws_guardduty_detector": "not a dict either"},
                {"aws_guardduty_detector": {"valid": {"enable": [True]}}},
            ]
        }
        detections = _extract_detections(parsed).detections
        assert len(detections) == 1

    def test_mixed_detection_and_infra_resources(self):
        parsed = {
            "resource": [
                {"aws_s3_bucket": {"logs": {"bucket": ["logs"]}}},
                {"aws_guardduty_detector": {"main": {"enable": [True]}}},
                {"aws_vpc": {"main": {"cidr_block": ["10.0.0.0/16"]}}},
                {
                    "aws_config_config_rule": {
                        "encryption": {"name": ["check-encryption"]}
                    }
                },
            ]
        }
        detections = _extract_detections(parsed).detections
        assert len(detections) == 2
        types = {d.detection_type for d in detections}
        assert DetectionType.GUARDDUTY_FINDING in types
        assert DetectionType.CONFIG_RULE in types

    def test_secret_keys_stripped_from_config(self):
        """Config passed to detection should not contain secret keys."""
        parsed = {
            "resource": [
                {
                    "aws_cloudwatch_metric_alarm": {
                        "test": {
                            "alarm_name": ["test"],
                            "access_key": ["AKIAIOSFODNN7EXAMPLE"],
                        }
                    }
                }
            ]
        }
        detections = _extract_detections(parsed).detections
        assert len(detections) == 1
        assert "access_key" not in detections[0].raw_config


class TestParametrisedResourceTypeMappings:
    """Parametrised test covering all 18 resource type -> DetectionType mappings."""

    @pytest.mark.parametrize(
        "resource_type,expected_type",
        [
            ("aws_cloudwatch_metric_alarm", DetectionType.CLOUDWATCH_ALARM),
            (
                "aws_cloudwatch_log_metric_filter",
                DetectionType.CLOUDWATCH_LOGS_INSIGHTS,
            ),
            ("aws_cloudwatch_event_rule", DetectionType.EVENTBRIDGE_RULE),
            ("aws_config_config_rule", DetectionType.CONFIG_RULE),
            ("aws_guardduty_detector", DetectionType.GUARDDUTY_FINDING),
            ("aws_securityhub_account", DetectionType.SECURITY_HUB),
            ("aws_inspector2_enabler", DetectionType.INSPECTOR_FINDING),
            ("aws_lambda_function", DetectionType.CUSTOM_LAMBDA),
            ("aws_macie2_account", DetectionType.MACIE_FINDING),
            ("google_logging_metric", DetectionType.GCP_CLOUD_LOGGING),
            ("google_monitoring_alert_policy", DetectionType.GCP_CLOUD_MONITORING),
            (
                "google_scc_notification_config",
                DetectionType.GCP_SECURITY_COMMAND_CENTER,
            ),
            ("google_eventarc_trigger", DetectionType.GCP_EVENTARC),
            ("google_cloudfunctions_function", DetectionType.GCP_CLOUD_FUNCTION),
            ("google_cloudfunctions2_function", DetectionType.GCP_CLOUD_FUNCTION),
            (
                "azurerm_security_center_subscription_pricing",
                DetectionType.AZURE_DEFENDER,
            ),
            ("azurerm_policy_assignment", DetectionType.AZURE_POLICY),
            ("azurerm_policy_definition", DetectionType.AZURE_POLICY),
        ],
    )
    def test_all_resource_type_mappings(self, resource_type, expected_type):
        parsed = {"resource": [{resource_type: {"test": {"enabled": [True]}}}]}
        detections = _extract_detections(parsed).detections
        assert len(detections) == 1
        assert detections[0].detection_type == expected_type


class TestParseTerraformContent:
    """Async integration tests for the main entry point."""

    async def test_parse_valid_terraform(self):
        hcl = """
resource "aws_guardduty_detector" "main" {
  enable = true
}
"""
        result = await parse_terraform_content(hcl)
        assert isinstance(result, ParseResult)
        assert len(result.detections) == 1
        assert result.resource_count == 1
        assert result.truncated is False

    async def test_parse_empty_content_raises(self):
        with pytest.raises(ValueError, match="Empty content"):
            await parse_terraform_content("")

    async def test_parse_oversized_content_raises(self):
        huge = (
            'resource "aws_s3_bucket" "x" { bucket = "'
            + "a" * MAX_CONTENT_BYTES
            + '" }'
        )
        with pytest.raises(ValueError, match="exceeds maximum size"):
            await parse_terraform_content(huge)

    async def test_parse_invalid_hcl_raises(self):
        with pytest.raises(Exception):
            await parse_terraform_content("not valid HCL content {{{")

    async def test_parse_no_detection_resources(self):
        hcl = """
resource "aws_s3_bucket" "logs" {
  bucket = "my-logs"
}
"""
        result = await parse_terraform_content(hcl)
        assert len(result.detections) == 0
        assert result.resource_count == 1
