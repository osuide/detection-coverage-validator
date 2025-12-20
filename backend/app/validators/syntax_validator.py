"""Syntax validator for detection queries and patterns."""

import json
from typing import Any, Optional

from app.models.detection import DetectionType
from app.validators.base_validator import (
    BaseValidator,
    ValidationResult,
    ValidationSeverity,
    ValidationIssue,
)


class SyntaxValidator(BaseValidator):
    """Validates detection query and pattern syntax.

    Checks:
    - CloudWatch Logs Insights query syntax
    - EventBridge event pattern JSON validity
    - GCP Cloud Logging filter syntax
    - Basic regex pattern validity
    """

    @property
    def name(self) -> str:
        return "syntax"

    async def validate(
        self,
        detection: Any,
        session: Optional[Any] = None,
    ) -> ValidationResult:
        """Validate detection syntax based on type.

        Args:
            detection: Detection model instance
            session: Not used for syntax validation

        Returns:
            ValidationResult with syntax assessment
        """
        detection_type = detection.detection_type
        issues = []
        score = 1.0

        # Route to type-specific validator
        if detection_type == DetectionType.CLOUDWATCH_LOGS_INSIGHTS:
            type_score, type_issues = self._validate_cloudwatch_query(detection)
        elif detection_type == DetectionType.EVENTBRIDGE_RULE:
            type_score, type_issues = self._validate_event_pattern(detection)
        elif detection_type == DetectionType.GCP_CLOUD_LOGGING:
            type_score, type_issues = self._validate_gcp_logging_filter(detection)
        elif detection_type == DetectionType.GCP_EVENTARC:
            type_score, type_issues = self._validate_eventarc_pattern(detection)
        elif detection_type in [
            DetectionType.GUARDDUTY_FINDING,
            DetectionType.GCP_SECURITY_COMMAND_CENTER,
        ]:
            # Managed detections - skip syntax validation
            type_score, type_issues = 1.0, []
        else:
            # Generic validation
            type_score, type_issues = self._validate_generic(detection)

        issues.extend(type_issues)
        score = min(score, type_score)

        result = self._create_result(
            is_valid=score > 0.5,
            score=score,
        )
        result.issues = issues
        result.metadata = {
            "detection_type": (
                detection_type.value
                if hasattr(detection_type, "value")
                else str(detection_type)
            ),
            "has_query_pattern": bool(detection.query_pattern),
            "has_event_pattern": bool(detection.event_pattern),
        }

        return result

    def _validate_cloudwatch_query(
        self,
        detection: Any,
    ) -> tuple[float, list[ValidationIssue]]:
        """Validate CloudWatch Logs Insights query syntax."""
        issues = []
        score = 1.0

        query = detection.query_pattern
        if not query:
            issues.append(
                ValidationIssue(
                    message="CloudWatch Logs Insights detection missing query pattern",
                    severity=ValidationSeverity.CRITICAL,
                    code="MISSING_QUERY",
                )
            )
            return 0.0, issues

        # Basic syntax checks for CloudWatch Logs Insights
        # Common commands: fields, filter, stats, sort, limit, parse

        # Check for basic structure
        query_lower = query.lower().strip()

        # Check for common syntax patterns
        valid_commands = [
            "fields",
            "filter",
            "stats",
            "sort",
            "limit",
            "parse",
            "display",
        ]
        has_valid_command = any(cmd in query_lower for cmd in valid_commands)

        if not has_valid_command:
            issues.append(
                ValidationIssue(
                    message="Query doesn't contain recognized CloudWatch Logs Insights commands",
                    severity=ValidationSeverity.WARNING,
                    code="UNRECOGNIZED_SYNTAX",
                    details={"query_preview": query[:100]},
                )
            )
            score = 0.7

        # Check for unbalanced brackets
        if not self._check_balanced_brackets(query):
            issues.append(
                ValidationIssue(
                    message="Query has unbalanced brackets or parentheses",
                    severity=ValidationSeverity.CRITICAL,
                    code="UNBALANCED_BRACKETS",
                )
            )
            score = min(score, 0.3)

        # Check for common mistakes
        if "| |" in query:
            issues.append(
                ValidationIssue(
                    message="Query contains empty pipe operation '| |'",
                    severity=ValidationSeverity.WARNING,
                    code="EMPTY_PIPE",
                )
            )
            score = min(score, 0.6)

        return score, issues

    def _validate_event_pattern(
        self,
        detection: Any,
    ) -> tuple[float, list[ValidationIssue]]:
        """Validate EventBridge event pattern JSON."""
        issues = []
        score = 1.0

        event_pattern = detection.event_pattern
        if not event_pattern:
            # Check raw_config for event pattern
            raw_config = detection.raw_config or {}
            event_pattern = raw_config.get("eventPattern") or raw_config.get(
                "event_pattern"
            )

        if not event_pattern:
            issues.append(
                ValidationIssue(
                    message="EventBridge rule missing event pattern",
                    severity=ValidationSeverity.CRITICAL,
                    code="MISSING_EVENT_PATTERN",
                )
            )
            return 0.0, issues

        # If it's a string, try to parse as JSON
        if isinstance(event_pattern, str):
            try:
                event_pattern = json.loads(event_pattern)
            except json.JSONDecodeError as e:
                issues.append(
                    ValidationIssue(
                        message=f"Event pattern is not valid JSON: {str(e)}",
                        severity=ValidationSeverity.CRITICAL,
                        code="INVALID_JSON",
                        details={"error": str(e)},
                    )
                )
                return 0.0, issues

        # Check for empty pattern
        if not event_pattern:
            issues.append(
                ValidationIssue(
                    message="Event pattern is empty",
                    severity=ValidationSeverity.CRITICAL,
                    code="EMPTY_PATTERN",
                )
            )
            return 0.0, issues

        # Validate pattern structure
        if not isinstance(event_pattern, dict):
            issues.append(
                ValidationIssue(
                    message="Event pattern must be a JSON object",
                    severity=ValidationSeverity.CRITICAL,
                    code="INVALID_PATTERN_TYPE",
                )
            )
            return 0.0, issues

        # Check for valid EventBridge pattern keys
        valid_keys = {
            "source",
            "detail-type",
            "detail",
            "account",
            "region",
            "resources",
            "time",
            "id",
            "version",
        }
        unknown_keys = set(event_pattern.keys()) - valid_keys
        if unknown_keys:
            issues.append(
                ValidationIssue(
                    message=f"Event pattern contains unrecognized keys: {unknown_keys}",
                    severity=ValidationSeverity.WARNING,
                    code="UNKNOWN_PATTERN_KEYS",
                    details={"unknown_keys": list(unknown_keys)},
                )
            )
            score = 0.8

        return score, issues

    def _validate_gcp_logging_filter(
        self,
        detection: Any,
    ) -> tuple[float, list[ValidationIssue]]:
        """Validate GCP Cloud Logging filter syntax."""
        issues = []
        score = 1.0

        query = detection.query_pattern
        raw_config = detection.raw_config or {}
        filter_string = query or raw_config.get("filter", "")

        if not filter_string:
            issues.append(
                ValidationIssue(
                    message="GCP Cloud Logging detection missing filter",
                    severity=ValidationSeverity.CRITICAL,
                    code="MISSING_FILTER",
                )
            )
            return 0.0, issues

        # Basic GCP logging filter syntax checks
        # Check for balanced quotes
        if filter_string.count('"') % 2 != 0:
            issues.append(
                ValidationIssue(
                    message="Filter has unbalanced double quotes",
                    severity=ValidationSeverity.CRITICAL,
                    code="UNBALANCED_QUOTES",
                )
            )
            score = min(score, 0.3)

        # Check for balanced parentheses
        if not self._check_balanced_brackets(filter_string):
            issues.append(
                ValidationIssue(
                    message="Filter has unbalanced brackets or parentheses",
                    severity=ValidationSeverity.CRITICAL,
                    code="UNBALANCED_BRACKETS",
                )
            )
            score = min(score, 0.3)

        # Check for common GCP logging patterns
        common_patterns = [
            "resource.type",
            "protoPayload",
            "jsonPayload",
            "textPayload",
            "logName",
            "severity",
            "timestamp",
        ]
        has_common_pattern = any(p in filter_string for p in common_patterns)

        if not has_common_pattern and len(filter_string) > 10:
            issues.append(
                ValidationIssue(
                    message="Filter doesn't contain common GCP logging field patterns",
                    severity=ValidationSeverity.INFO,
                    code="UNUSUAL_FILTER_PATTERN",
                )
            )
            score = min(score, 0.9)

        return score, issues

    def _validate_eventarc_pattern(
        self,
        detection: Any,
    ) -> tuple[float, list[ValidationIssue]]:
        """Validate GCP Eventarc trigger pattern."""
        issues = []
        score = 1.0

        event_pattern = detection.event_pattern
        raw_config = detection.raw_config or {}

        if not event_pattern:
            event_pattern = raw_config.get("eventFilters", [])

        # Eventarc uses event filters list
        if isinstance(event_pattern, dict):
            event_filters = event_pattern.get("eventFilters", [])
        elif isinstance(event_pattern, list):
            event_filters = event_pattern
        else:
            event_filters = []

        if not event_filters:
            # Check raw_config
            event_filters = raw_config.get("eventFilters", [])

        if not event_filters:
            issues.append(
                ValidationIssue(
                    message="Eventarc trigger missing event filters",
                    severity=ValidationSeverity.WARNING,
                    code="MISSING_EVENT_FILTERS",
                )
            )
            score = 0.7

        # Validate filter structure
        for i, filter_item in enumerate(event_filters):
            if not isinstance(filter_item, dict):
                issues.append(
                    ValidationIssue(
                        message=f"Event filter {i} is not a valid object",
                        severity=ValidationSeverity.CRITICAL,
                        code="INVALID_FILTER_TYPE",
                    )
                )
                score = min(score, 0.3)
                continue

            if "attribute" not in filter_item:
                issues.append(
                    ValidationIssue(
                        message=f"Event filter {i} missing 'attribute' field",
                        severity=ValidationSeverity.WARNING,
                        code="MISSING_FILTER_ATTRIBUTE",
                    )
                )
                score = min(score, 0.7)

            if "value" not in filter_item:
                issues.append(
                    ValidationIssue(
                        message=f"Event filter {i} missing 'value' field",
                        severity=ValidationSeverity.WARNING,
                        code="MISSING_FILTER_VALUE",
                    )
                )
                score = min(score, 0.7)

        return score, issues

    def _validate_generic(
        self,
        detection: Any,
    ) -> tuple[float, list[ValidationIssue]]:
        """Generic validation for unknown detection types."""
        issues = []
        score = 1.0

        # Check if detection has some configuration
        raw_config = detection.raw_config or {}
        query = detection.query_pattern

        if not raw_config and not query:
            issues.append(
                ValidationIssue(
                    message="Detection has no configuration data",
                    severity=ValidationSeverity.WARNING,
                    code="NO_CONFIG",
                )
            )
            score = 0.5

        return score, issues

    def _check_balanced_brackets(self, text: str) -> bool:
        """Check if brackets and parentheses are balanced."""
        stack = []
        brackets = {
            "(": ")",
            "[": "]",
            "{": "}",
        }

        for char in text:
            if char in brackets:
                stack.append(brackets[char])
            elif char in brackets.values():
                if not stack or stack.pop() != char:
                    return False

        return len(stack) == 0
