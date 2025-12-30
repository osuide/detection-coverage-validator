"""CloudWatch Logs Insights query scanner following 04-PARSER-AGENT.md design."""

from datetime import datetime
from typing import Any, Optional

from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection
from app.scanners.aws.service_mappings import extract_services_from_log_groups


def _serialize_for_json(obj: Any) -> Any:
    """Recursively convert datetime objects to ISO format strings for JSON serialization."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: _serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_serialize_for_json(item) for item in obj]
    return obj


class CloudWatchLogsInsightsScanner(BaseScanner):
    """Scanner for CloudWatch Logs Insights saved queries.

    Discovers saved queries that can be used as detections for security monitoring.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.CLOUDWATCH_LOGS_INSIGHTS

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan all regions for CloudWatch Logs Insights queries."""
        all_detections = []

        for region in regions:
            self.logger.info("scanning_region", region=region)
            try:
                detections = await self.scan_region(region, options)
                all_detections.extend(detections)
                self.logger.info(
                    "region_scan_complete",
                    region=region,
                    count=len(detections),
                )
            except ClientError as e:
                self.logger.error(
                    "region_scan_error",
                    region=region,
                    error=str(e),
                )

        return all_detections

    async def scan_region(
        self,
        region: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan a single region for saved queries."""
        detections = []

        # Create regional client
        client = self.session.client("logs", region_name=region)

        try:
            # describe_query_definitions doesn't support pagination
            # Use nextToken manually if needed
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs["nextToken"] = next_token

                response = client.describe_query_definitions(**kwargs)

                for query_def in response.get("queryDefinitions", []):
                    detection = self._parse_query_definition(query_def, region)
                    if detection:
                        detections.append(detection)

                next_token = response.get("nextToken")
                if not next_token:
                    break

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                self.logger.warning("access_denied", region=region)
            else:
                raise

        return detections

    def _parse_query_definition(
        self,
        query_def: dict[str, Any],
        region: str,
    ) -> Optional[RawDetection]:
        """Parse a CloudWatch Logs Insights query definition."""
        query_id = query_def.get("queryDefinitionId", "")
        name = query_def.get("name", f"query-{query_id[:8]}")
        query_string = query_def.get("queryString", "")
        log_groups = query_def.get("logGroupNames", [])

        # Extract target services from log group names
        target_services = (
            extract_services_from_log_groups(log_groups) if log_groups else None
        )

        # Build ARN
        account_id = self._get_account_id()
        arn = f"arn:aws:logs:{region}:{account_id}:query-definition:{query_id}"

        return RawDetection(
            name=name,
            detection_type=DetectionType.CLOUDWATCH_LOGS_INSIGHTS,
            source_arn=arn,
            region=region,
            raw_config={
                "queryDefinitionId": query_id,
                "name": name,
                "queryString": query_string,
                "logGroupNames": log_groups,
            },
            query_pattern=query_string,
            log_groups=log_groups if log_groups else None,
            description=f"CloudWatch Logs Insights query: {name}",
            target_services=target_services or None,
        )

    def _get_account_id(self) -> str:
        """Get the current AWS account ID."""
        try:
            sts = self.session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception:
            return "unknown"


class CloudWatchMetricAlarmScanner(BaseScanner):
    """Scanner for CloudWatch Metric Alarms.

    Discovers CloudWatch alarms that could indicate security-relevant metrics.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.CLOUDWATCH_ALARM

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan all regions for CloudWatch alarms."""
        all_detections = []

        for region in regions:
            self.logger.info("scanning_alarms", region=region)
            try:
                detections = await self._scan_alarms(region)
                all_detections.extend(detections)
            except ClientError as e:
                self.logger.error("alarm_scan_error", region=region, error=str(e))

        return all_detections

    async def _scan_alarms(self, region: str) -> list[RawDetection]:
        """Scan for metric alarms in a region."""
        detections = []
        skipped = 0
        client = self.session.client("cloudwatch", region_name=region)

        paginator = client.get_paginator("describe_alarms")

        for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
            for alarm in page.get("MetricAlarms", []):
                # Filter out AWS-managed operational alarms
                if self._is_aws_managed_operational(alarm):
                    skipped += 1
                    continue

                # Only include security-relevant alarms
                if not self._is_security_relevant(alarm):
                    skipped += 1
                    continue

                detection = self._parse_alarm(alarm, region)
                if detection:
                    detections.append(detection)

        if skipped > 0:
            self.logger.info(
                "filtered_operational_alarms",
                region=region,
                skipped=skipped,
                included=len(detections),
            )

        return detections

    def _is_aws_managed_operational(self, alarm: dict) -> bool:
        """Check if alarm is an AWS-managed operational alarm (not security).

        These are automatically created by AWS services like Auto Scaling,
        and are not security detections.
        """
        description = alarm.get("AlarmDescription") or ""
        name = alarm.get("AlarmName", "")
        namespace = alarm.get("Namespace", "")

        # Auto-scaling alarms created by DynamoDB, ECS, Application Auto Scaling
        if "DO NOT EDIT OR DELETE" in description:
            return True
        if "TargetTrackingScaling" in description or "TargetTrackingScaling" in name:
            return True

        # AWS-managed operational namespaces (not security)
        operational_namespaces = [
            "AWS/Billing",  # Billing alarms
            "AWS/AutoScaling",  # EC2 Auto Scaling operational
            "AWS/ApplicationAutoScaling",  # App Auto Scaling
            "AWS/ECS",  # ECS service scaling (unless security keyword)
            "AWS/RDS",  # RDS operational metrics (unless security keyword)
            "AWS/ElastiCache",  # Cache operational metrics
            "AWS/Kinesis",  # Kinesis throughput
            "AWS/SQS",  # Queue depth (operational)
            "AWS/SNS",  # Topic metrics (operational)
        ]

        # Check if it's a purely operational namespace
        # (will be overridden if security keywords present)
        if namespace in operational_namespaces:
            # But still include if it has security keywords in the name
            name_lower = name.lower()
            description_lower = (alarm.get("AlarmDescription") or "").lower()
            text_to_check = f"{name_lower} {description_lower}"
            security_keywords = [
                "unauthorized",
                "security",
                "threat",
                "anomaly",
                "suspicious",
                "failed",
                "denied",
                "breach",
                "intrusion",
                "attack",
                "malicious",
                "error",  # Application errors
                "dlq",  # Dead letter queues
                "dead-letter",
                "injection",
                "alert",
            ]
            if not any(kw in text_to_check for kw in security_keywords):
                return True

        return False

    def _is_security_relevant(self, alarm: dict) -> bool:
        """Check if alarm is security-relevant based on namespace/metric."""
        # Security-focused namespaces - always include
        security_namespaces = [
            "AWS/GuardDuty",
            "AWS/SecurityHub",
            "AWS/CloudTrail",
            "AWS/IAM",
            "AWS/Config",
            "AWS/Inspector",
            "AWS/Macie",
            "AWS/WAF",
            "AWS/WAFv2",
            "AWS/Shield",
            "AWS/NetworkFirewall",
            "AWS/Detective",
        ]

        # Security-related keywords in alarm names/descriptions/namespaces
        security_keywords = [
            "unauthorized",
            "security",
            "threat",
            "anomaly",
            "suspicious",
            "failed",
            "denied",
            "breach",
            "intrusion",
            "attack",
            "malicious",
            "root",
            "console",
            "login",
            "authentication",
            "credential",
            "privilege",
            "escalation",
            "exfiltration",
            "encryption",
            "kms",
            "secret",
            "password",
            "api",
            "cloudtrail",
            "guardduty",
            "securityhub",
            "config",
            "compliance",
            "violation",
            "policy",
            "permission",
            "access",
            "iam",
            "role",
            "user",
            "mfa",
            "vpc",
            "firewall",
            "network",
            "egress",
            "ingress",
            # Additional keywords for common security-relevant alarms
            "error",  # Lambda/application errors can indicate attacks
            "injection",  # SQL injection, prompt injection, etc.
            "dlq",  # Dead letter queues indicate processing failures
            "dead-letter",  # Alternative DLQ naming
            "lambda",  # Lambda function monitoring
            "waf",  # Web Application Firewall
            "bot",  # Bot detection
            "rate-limit",  # Rate limiting alerts
            "throttl",  # Throttling (partial match for throttle/throttled)
            "block",  # Blocked requests/IPs
            "forbidden",  # 403 errors
            "alert",  # Generic security alerts
        ]

        namespace = alarm.get("Namespace", "")
        name = alarm.get("AlarmName", "").lower()
        description = (alarm.get("AlarmDescription") or "").lower()

        # Always include alarms from security namespaces
        if namespace in security_namespaces:
            return True

        # Include if namespace, name, or description contains security keywords
        # Include namespace to catch custom security namespaces like "MyApp/Security"
        text_to_check = f"{namespace.lower()} {name} {description}"
        if any(kw in text_to_check for kw in security_keywords):
            return True

        return False

    def _parse_alarm(self, alarm: dict, region: str) -> Optional[RawDetection]:
        """Parse a CloudWatch alarm."""
        # Extract evaluation summary from alarm state
        # StateValue can be: OK, ALARM, INSUFFICIENT_DATA
        state_value = alarm.get("StateValue", "INSUFFICIENT_DATA")
        state_reason = alarm.get("StateReason")
        state_updated = alarm.get("StateUpdatedTimestamp")

        evaluation_summary = {
            "type": "alarm_state",
            "state": state_value,
            "state_reason": state_reason,
            "state_updated_at": (
                state_updated.isoformat()
                if hasattr(state_updated, "isoformat")
                else state_updated
            ),
        }

        # Serialize datetime objects in raw_config for JSON storage
        serialized_alarm = _serialize_for_json(alarm)
        return RawDetection(
            name=alarm.get("AlarmName", ""),
            detection_type=DetectionType.CLOUDWATCH_ALARM,
            source_arn=alarm.get("AlarmArn", ""),
            region=region,
            raw_config=serialized_alarm,
            description=alarm.get("AlarmDescription"),
            evaluation_summary=evaluation_summary,
        )
