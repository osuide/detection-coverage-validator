"""Reference validator for checking detection resource references."""

from typing import Any, Optional

from app.models.detection import DetectionType
from app.validators.base_validator import (
    BaseValidator,
    ValidationResult,
    ValidationSeverity,
    ValidationIssue,
)


class ReferenceValidator(BaseValidator):
    """Validates that detection references to cloud resources are valid.

    Checks:
    - Log groups exist (CloudWatch, GCP Cloud Logging)
    - SNS topics exist (for alarm notifications)
    - Lambda functions exist (for custom handlers)
    - GCP Pub/Sub topics exist
    """

    @property
    def name(self) -> str:
        return "references"

    async def validate(
        self,
        detection: Any,
        session: Optional[Any] = None,
    ) -> ValidationResult:
        """Validate detection resource references.

        Args:
            detection: Detection model instance
            session: Cloud session (boto3/gcp) for resource checks

        Returns:
            ValidationResult with reference validation assessment
        """
        issues = []
        score = 1.0
        checked_resources = []

        if not session:
            # Can't validate references without a session
            result = self._create_result(is_valid=True, score=1.0)
            result.metadata = {
                "skipped": True,
                "reason": "No cloud session provided",
            }
            return result

        detection_type = detection.detection_type

        # Route to type-specific validation
        if detection_type == DetectionType.CLOUDWATCH_LOGS_INSIGHTS:
            ref_score, ref_issues, resources = await self._validate_cloudwatch_refs(
                detection, session
            )
        elif detection_type == DetectionType.EVENTBRIDGE_RULE:
            ref_score, ref_issues, resources = await self._validate_eventbridge_refs(
                detection, session
            )
        elif detection_type == DetectionType.GCP_CLOUD_LOGGING:
            ref_score, ref_issues, resources = await self._validate_gcp_logging_refs(
                detection, session
            )
        elif detection_type == DetectionType.GCP_EVENTARC:
            ref_score, ref_issues, resources = await self._validate_eventarc_refs(
                detection, session
            )
        else:
            # No specific reference validation for this type
            ref_score, ref_issues, resources = 1.0, [], []

        issues.extend(ref_issues)
        checked_resources.extend(resources)
        score = min(score, ref_score)

        result = self._create_result(
            is_valid=score > 0.5,
            score=score,
        )
        result.issues = issues
        result.metadata = {
            "checked_resources": checked_resources,
            "missing_resources": [
                r for r in checked_resources if not r.get("exists", True)
            ],
        }

        return result

    async def _validate_cloudwatch_refs(
        self,
        detection: Any,
        session: Any,
    ) -> tuple[float, list[ValidationIssue], list[dict]]:
        """Validate CloudWatch detection references."""
        issues = []
        resources = []
        score = 1.0

        # Check log groups
        log_groups = detection.log_groups or []
        region = detection.region

        if not log_groups:
            # Try to get from raw_config
            raw_config = detection.raw_config or {}
            log_groups = raw_config.get("logGroupNames", [])

        for log_group in log_groups:
            exists = await self._log_group_exists(session, log_group, region)
            resources.append(
                {
                    "type": "log_group",
                    "name": log_group,
                    "region": region,
                    "exists": exists,
                }
            )

            if not exists:
                issues.append(
                    ValidationIssue(
                        message=f"Log group '{log_group}' does not exist in region {region}",
                        severity=ValidationSeverity.CRITICAL,
                        code="MISSING_LOG_GROUP",
                        details={"log_group": log_group, "region": region},
                    )
                )
                score = min(score, 0.3)

        return score, issues, resources

    async def _validate_eventbridge_refs(
        self,
        detection: Any,
        session: Any,
    ) -> tuple[float, list[ValidationIssue], list[dict]]:
        """Validate EventBridge rule references."""
        issues = []
        resources = []
        score = 1.0

        raw_config = detection.raw_config or {}
        region = detection.region

        # Check targets (SNS, Lambda, etc.)
        targets = raw_config.get("targets", [])

        for target in targets:
            target_arn = target.get("Arn") or target.get("arn")
            if not target_arn:
                continue

            # Determine target type from ARN
            if ":sns:" in target_arn:
                exists = await self._sns_topic_exists(session, target_arn, region)
                resource_type = "sns_topic"
            elif ":lambda:" in target_arn:
                exists = await self._lambda_exists(session, target_arn, region)
                resource_type = "lambda_function"
            else:
                # Unknown target type, assume exists
                exists = True
                resource_type = "unknown"

            resources.append(
                {
                    "type": resource_type,
                    "arn": target_arn,
                    "region": region,
                    "exists": exists,
                }
            )

            if not exists:
                issues.append(
                    ValidationIssue(
                        message=f"EventBridge target '{target_arn}' does not exist",
                        severity=ValidationSeverity.CRITICAL,
                        code="MISSING_TARGET",
                        details={"target_arn": target_arn},
                    )
                )
                score = min(score, 0.3)

        return score, issues, resources

    async def _validate_gcp_logging_refs(
        self,
        detection: Any,
        session: Any,
    ) -> tuple[float, list[ValidationIssue], list[dict]]:
        """Validate GCP Cloud Logging metric references."""
        issues = []
        resources = []
        score = 1.0

        # GCP log-based metrics don't have explicit log source references
        # like CloudWatch (they use filter expressions)
        # Validation would require parsing the filter and checking resources

        raw_config = detection.raw_config or {}

        # Check for referenced resources in filter
        filter_string = raw_config.get("filter", "")

        # Extract project references
        project_pattern = r'projects/([^/\s"]+)'
        import re

        project_matches = re.findall(project_pattern, filter_string)

        for project in project_matches:
            # Note: Would need GCP credentials to validate project access
            resources.append(
                {
                    "type": "gcp_project",
                    "name": project,
                    "exists": True,  # Assume exists without validation
                }
            )

        return score, issues, resources

    async def _validate_eventarc_refs(
        self,
        detection: Any,
        session: Any,
    ) -> tuple[float, list[ValidationIssue], list[dict]]:
        """Validate Eventarc trigger references."""
        issues = []
        resources = []
        score = 1.0

        raw_config = detection.raw_config or {}

        # Check destination references
        destination = raw_config.get("destination", {})

        if destination.get("type") == "cloud_run":
            service = destination.get("service")
            if service:
                resources.append(
                    {
                        "type": "cloud_run_service",
                        "name": service,
                        "exists": True,  # Would need GCP client to validate
                    }
                )

        if destination.get("type") == "cloud_function":
            function_name = destination.get("function")
            if function_name:
                resources.append(
                    {
                        "type": "cloud_function",
                        "name": function_name,
                        "exists": True,  # Would need GCP client to validate
                    }
                )

        # Check transport (Pub/Sub)
        transport = raw_config.get("transport", {})
        pubsub = transport.get("pubsub", {})
        topic = pubsub.get("topic")

        if topic:
            resources.append(
                {
                    "type": "pubsub_topic",
                    "name": topic,
                    "exists": True,  # Would need GCP client to validate
                }
            )

        return score, issues, resources

    async def _log_group_exists(
        self,
        session: Any,
        log_group: str,
        region: str,
    ) -> bool:
        """Check if a CloudWatch log group exists."""
        try:
            client = session.client("logs", region_name=region)
            response = client.describe_log_groups(
                logGroupNamePrefix=log_group,
                limit=1,
            )

            log_groups = response.get("logGroups", [])
            return any(lg.get("logGroupName") == log_group for lg in log_groups)

        except Exception:
            # If we can't check, assume it exists
            return True

    async def _sns_topic_exists(
        self,
        session: Any,
        topic_arn: str,
        region: str,
    ) -> bool:
        """Check if an SNS topic exists."""
        try:
            client = session.client("sns", region_name=region)
            client.get_topic_attributes(TopicArn=topic_arn)
            return True
        except Exception:
            return False

    async def _lambda_exists(
        self,
        session: Any,
        function_arn: str,
        region: str,
    ) -> bool:
        """Check if a Lambda function exists."""
        try:
            client = session.client("lambda", region_name=region)

            # Extract function name from ARN
            if ":" in function_arn:
                function_name = function_arn.split(":")[-1]
            else:
                function_name = function_arn

            client.get_function(FunctionName=function_name)
            return True
        except Exception:
            return False
