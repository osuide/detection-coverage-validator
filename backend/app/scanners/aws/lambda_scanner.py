"""AWS Lambda function scanner for custom detection discovery.

Discovers Lambda functions that appear to be security detections based on:
- Function name/description containing security keywords
- Event source mappings from security-relevant services
- Triggers from EventBridge, CloudWatch Events, GuardDuty, etc.
"""

from typing import Any, Optional

from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


class LambdaScanner(BaseScanner):
    """Scanner for AWS Lambda functions used as custom security detections.

    Discovers Lambda functions that are potentially security-related based on:
    - Function name containing security keywords
    - Description containing security keywords
    - Event source mappings from security services
    - EventBridge triggers for security events
    """

    # Security keywords in function names/descriptions
    SECURITY_KEYWORDS = {
        "security",
        "alert",
        "detect",
        "monitor",
        "guard",
        "audit",
        "threat",
        "anomaly",
        "suspicious",
        "unauthorized",
        "incident",
        "compliance",
        "remediation",
        "response",
        "siem",
        "soc",
        "cloudtrail",
        "guardduty",
        "securityhub",
        "config",
        "iam",
    }

    # Event source patterns that indicate security functions
    SECURITY_EVENT_SOURCES = {
        "events.amazonaws.com",  # EventBridge
        "guardduty.amazonaws.com",
        "securityhub.amazonaws.com",
        "config.amazonaws.com",
        "sns.amazonaws.com",  # Often used for security alerts
        "sqs.amazonaws.com",  # Security event queues
        "s3.amazonaws.com",  # CloudTrail log processing
        "kinesis.amazonaws.com",  # Log streaming
        "cloudtrail.amazonaws.com",
    }

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.CUSTOM_LAMBDA

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan all regions for Lambda functions used as detections in parallel."""
        return await self.scan_regions_parallel(regions, options)

    async def scan_region(
        self,
        region: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan a single region for security Lambda functions."""
        detections = []

        client = self.session.client("lambda", region_name=region)

        try:
            paginator = client.get_paginator("list_functions")

            # Non-blocking paginate
            pages = await self.run_sync(lambda: list(paginator.paginate()))

            for page in pages:
                for function in page.get("Functions", []):
                    # Get detailed function info
                    function_info = await self._get_function_info(client, function)

                    # Check if security-related
                    if self._is_security_detection(function_info):
                        detection = self._build_detection(function_info, region)
                        if detection:
                            detections.append(detection)

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                self.logger.warning("lambda_access_denied", region=region)
            else:
                raise

        return detections

    async def _get_function_info(
        self,
        client: Any,
        function: dict,
    ) -> dict:
        """Get detailed function information including triggers."""
        function_name = function.get("FunctionName", "")
        function_arn = function.get("FunctionArn", "")

        info = {
            "function_name": function_name,
            "function_arn": function_arn,
            "runtime": function.get("Runtime"),
            "description": function.get("Description", ""),
            "timeout": function.get("Timeout"),
            "memory_size": function.get("MemorySize"),
            "last_modified": function.get("LastModified"),
            "handler": function.get("Handler"),
            "role": function.get("Role"),
            "environment": {},
            "triggers": [],
            "event_source_mappings": [],
            "tags": {},
        }

        # Get environment variables (sanitized - no secrets)
        try:
            config = await self.run_sync(
                client.get_function_configuration, FunctionName=function_name
            )
            env_vars = config.get("Environment", {}).get("Variables", {})
            # Sanitize environment variables (remove potential secrets)
            info["environment"] = self._sanitize_env_vars(env_vars)
        except ClientError:
            pass

        # Get event source mappings (triggers)
        try:
            esm_paginator = client.get_paginator("list_event_source_mappings")
            pages = await self.run_sync(
                lambda: list(esm_paginator.paginate(FunctionName=function_name))
            )
            for page in pages:
                for mapping in page.get("EventSourceMappings", []):
                    info["event_source_mappings"].append(
                        {
                            "event_source_arn": mapping.get("EventSourceArn"),
                            "state": mapping.get("State"),
                            "batch_size": mapping.get("BatchSize"),
                            "starting_position": mapping.get("StartingPosition"),
                        }
                    )
        except ClientError:
            pass

        # Get function tags
        try:
            tags_response = await self.run_sync(client.list_tags, Resource=function_arn)
            info["tags"] = tags_response.get("Tags", {})
        except ClientError:
            pass

        # Get function policy (to identify triggers)
        try:
            policy_response = await self.run_sync(
                client.get_policy, FunctionName=function_name
            )
            policy = policy_response.get("Policy", "{}")
            triggers = self._extract_triggers_from_policy(policy)
            info["triggers"] = triggers
        except ClientError:
            # No policy = no resource-based triggers
            pass

        return info

    def _sanitize_env_vars(self, env_vars: dict) -> dict:
        """Remove sensitive environment variables."""
        sensitive_patterns = {
            "key",
            "secret",
            "password",
            "token",
            "auth",
            "credential",
            "api_key",
            "apikey",
            "private",
        }

        sanitized = {}
        for key, value in env_vars.items():
            key_lower = key.lower()
            is_sensitive = any(pattern in key_lower for pattern in sensitive_patterns)

            if is_sensitive:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value

        return sanitized

    def _extract_triggers_from_policy(self, policy: str) -> list[dict]:
        """Extract trigger information from function policy."""
        import json

        triggers = []

        try:
            policy_doc = json.loads(policy)
            statements = policy_doc.get("Statement", [])

            for stmt in statements:
                principal = stmt.get("Principal", {})
                condition = stmt.get("Condition", {})

                # Extract service principal
                if isinstance(principal, dict):
                    service = principal.get("Service", "")
                elif isinstance(principal, str):
                    service = principal
                else:
                    service = ""

                # Extract source ARN from conditions
                source_arn = None
                arn_like = condition.get("ArnLike", {})
                if arn_like:
                    source_arn = arn_like.get("AWS:SourceArn")

                if service:
                    triggers.append(
                        {
                            "service": service,
                            "source_arn": source_arn,
                            "action": stmt.get("Action"),
                        }
                    )

        except (json.JSONDecodeError, KeyError):
            pass

        return triggers

    def _is_security_detection(self, function_info: dict) -> bool:
        """Determine if a Lambda function is a security detection."""
        function_name = function_info.get("function_name", "").lower()
        description = function_info.get("description", "").lower()
        tags = function_info.get("tags", {})
        triggers = function_info.get("triggers", [])
        event_sources = function_info.get("event_source_mappings", [])

        # Check function name for security keywords
        if any(keyword in function_name for keyword in self.SECURITY_KEYWORDS):
            return True

        # Check description for security keywords
        if any(keyword in description for keyword in self.SECURITY_KEYWORDS):
            return True

        # Check tags
        for key, value in tags.items():
            combined = f"{key} {value}".lower()
            if any(keyword in combined for keyword in self.SECURITY_KEYWORDS):
                return True

        # Check triggers for security event sources
        for trigger in triggers:
            service = trigger.get("service", "").lower()
            source_arn = trigger.get("source_arn", "") or ""

            if any(src in service for src in self.SECURITY_EVENT_SOURCES):
                return True

            # Check for specific ARN patterns
            security_arn_patterns = ["guardduty", "securityhub", "cloudtrail", "config"]
            if any(pattern in source_arn.lower() for pattern in security_arn_patterns):
                return True

        # Check event source mappings
        for esm in event_sources:
            source_arn = esm.get("event_source_arn", "") or ""

            # Kinesis streams for log processing
            if ":kinesis:" in source_arn and any(
                kw in source_arn.lower()
                for kw in ["security", "audit", "cloudtrail", "log"]
            ):
                return True

            # SQS queues for security events
            if ":sqs:" in source_arn and any(
                kw in source_arn.lower() for kw in ["security", "alert", "event"]
            ):
                return True

        return False

    def _build_detection(
        self,
        function_info: dict,
        region: str,
    ) -> Optional[RawDetection]:
        """Build a RawDetection from function info."""
        function_name = function_info.get("function_name", "")
        function_arn = function_info.get("function_arn", "")
        description = function_info.get("description", "")

        # Extract security indicators for mapping
        security_indicators = self._extract_security_indicators(function_info)

        # Build description
        trigger_summary = self._summarize_triggers(function_info)
        if trigger_summary:
            full_description = (
                f"{description} | Triggers: {trigger_summary}"
                if description
                else f"Triggers: {trigger_summary}"
            )
        else:
            full_description = (
                description or f"Custom Lambda detection: {function_name}"
            )

        return RawDetection(
            name=function_name,
            detection_type=DetectionType.CUSTOM_LAMBDA,
            source_arn=function_arn,
            region=region,
            raw_config={
                "functionName": function_name,
                "functionArn": function_arn,
                "runtime": function_info.get("runtime"),
                "handler": function_info.get("handler"),
                "timeout": function_info.get("timeout"),
                "memorySize": function_info.get("memory_size"),
                "lastModified": function_info.get("last_modified"),
                "role": function_info.get("role"),
                "environment": function_info.get("environment", {}),
                "triggers": function_info.get("triggers", []),
                "eventSourceMappings": function_info.get("event_source_mappings", []),
                "tags": function_info.get("tags", {}),
                "securityIndicators": security_indicators,
            },
            description=full_description,
            is_managed=False,
        )

    def _extract_security_indicators(self, function_info: dict) -> dict:
        """Extract security-relevant indicators for mapping."""
        indicators = {
            "monitored_services": set(),
            "event_types": [],
            "security_keywords_found": [],
            "inferred_purpose": "",
        }

        function_name = function_info.get("function_name", "").lower()
        description = function_info.get("description", "").lower()

        # Find keywords
        for keyword in self.SECURITY_KEYWORDS:
            if keyword in function_name or keyword in description:
                indicators["security_keywords_found"].append(keyword)

        # Analyze triggers
        for trigger in function_info.get("triggers", []):
            service = trigger.get("service", "")
            source_arn = trigger.get("source_arn", "") or ""

            if "events.amazonaws.com" in service:
                indicators["monitored_services"].add("eventbridge")
                # Try to extract event pattern from source ARN
                if "rule" in source_arn:
                    indicators["event_types"].append("EventBridge rule trigger")

            if "guardduty.amazonaws.com" in service:
                indicators["monitored_services"].add("guardduty")
                indicators["event_types"].append("GuardDuty finding")

            if "securityhub.amazonaws.com" in service:
                indicators["monitored_services"].add("securityhub")
                indicators["event_types"].append("Security Hub finding")

            if "config.amazonaws.com" in service:
                indicators["monitored_services"].add("config")
                indicators["event_types"].append("AWS Config event")

            if "sns.amazonaws.com" in service:
                indicators["monitored_services"].add("sns")
                indicators["event_types"].append("SNS notification")

        # Analyze event source mappings
        for esm in function_info.get("event_source_mappings", []):
            source_arn = esm.get("event_source_arn", "") or ""

            if ":kinesis:" in source_arn:
                indicators["monitored_services"].add("kinesis")
                if "cloudtrail" in source_arn.lower():
                    indicators["event_types"].append("CloudTrail logs via Kinesis")
                else:
                    indicators["event_types"].append("Kinesis stream processing")

            if ":sqs:" in source_arn:
                indicators["monitored_services"].add("sqs")
                indicators["event_types"].append("SQS queue processing")

            if ":dynamodb:" in source_arn:
                indicators["monitored_services"].add("dynamodb")
                indicators["event_types"].append("DynamoDB stream processing")

        # Infer purpose based on indicators
        indicators["inferred_purpose"] = self._infer_purpose(indicators)

        # Convert set to list for JSON serialization
        indicators["monitored_services"] = list(indicators["monitored_services"])

        return indicators

    def _infer_purpose(self, indicators: dict) -> str:
        """Infer the detection purpose from indicators."""
        services = indicators.get("monitored_services", set())
        keywords = indicators.get("security_keywords_found", [])

        if "guardduty" in services:
            return "GuardDuty finding processor/enricher"
        if "securityhub" in services:
            return "Security Hub finding handler"
        if "config" in services:
            return "AWS Config compliance/remediation"

        if "alert" in keywords or "incident" in keywords:
            return "Security alert/incident handler"
        if "audit" in keywords or "compliance" in keywords:
            return "Audit/compliance automation"
        if "monitor" in keywords or "detect" in keywords:
            return "Security monitoring/detection"
        if "remediation" in keywords or "response" in keywords:
            return "Security remediation/response"

        if "eventbridge" in services:
            return "EventBridge security event processor"
        if "kinesis" in services:
            return "Log/event stream processor"

        return "Custom security automation"

    def _summarize_triggers(self, function_info: dict) -> str:
        """Create a summary of function triggers."""
        trigger_parts = []

        for trigger in function_info.get("triggers", []):
            service = trigger.get("service", "")
            if service:
                # Clean up service name
                service_name = service.replace(".amazonaws.com", "")
                trigger_parts.append(service_name)

        for esm in function_info.get("event_source_mappings", []):
            source_arn = esm.get("event_source_arn", "") or ""
            if ":kinesis:" in source_arn:
                trigger_parts.append("Kinesis")
            elif ":sqs:" in source_arn:
                trigger_parts.append("SQS")
            elif ":dynamodb:" in source_arn:
                trigger_parts.append("DynamoDB")

        return ", ".join(set(trigger_parts)) if trigger_parts else ""
