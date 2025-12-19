"""CloudFormation and Terraform template parser for detection discovery.

Parses Infrastructure as Code templates to discover security detections:
- EventBridge rules
- CloudWatch alarms
- Config rules
- SNS topics for security alerts
- Step Functions for incident response

IMPORTANT: This parser only runs when:
1. User has an active paying subscription
2. User has explicitly consented to code analysis
3. Required IAM permissions are available
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional

import structlog
import yaml
from botocore.exceptions import ClientError

logger = structlog.get_logger()


@dataclass
class IaCDetection:
    """A detection discovered from IaC templates."""

    name: str
    resource_type: str  # e.g., "AWS::Events::Rule", "aws_cloudwatch_event_rule"
    detection_type: str  # e.g., "eventbridge_rule", "cloudwatch_alarm"

    # Source template info
    template_type: str  # "cloudformation" or "terraform"
    stack_name: Optional[str] = None
    file_path: Optional[str] = None
    logical_id: Optional[str] = None  # CFN logical resource ID

    # Detection config
    event_pattern: Optional[dict] = None
    alarm_config: Optional[dict] = None
    rule_config: Optional[dict] = None

    # Analysis hints
    description: str = ""
    security_indicators: list[str] = field(default_factory=list)
    suggested_techniques: list[str] = field(default_factory=list)


@dataclass
class IaCAnalysisResult:
    """Result of analyzing IaC templates."""

    source_type: str  # "cloudformation" or "terraform"
    source_name: str  # Stack name or file path

    # Discovered detections
    detections: list[IaCDetection] = field(default_factory=list)

    # Analysis metadata
    resources_analyzed: int = 0
    security_resources_found: int = 0

    # Errors and warnings
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    permission_errors: list[str] = field(default_factory=list)
    missing_permissions: list[str] = field(default_factory=list)


@dataclass
class PermissionCheckResult:
    """Result of IAM permission check for IaC analysis."""

    has_required_permissions: bool
    missing_permissions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class CloudFormationParser:
    """Parses CloudFormation stacks and templates for security detections.

    Discovers:
    - EventBridge rules for security events
    - CloudWatch alarms with security thresholds
    - Config rules for compliance
    - SNS topics used for security alerts
    - Step Functions for incident response
    """

    # Required IAM permissions
    REQUIRED_PERMISSIONS = [
        "cloudformation:GetTemplate",
        "cloudformation:ListStacks",
        "cloudformation:DescribeStacks",
    ]

    # Resource types that indicate security detections
    SECURITY_RESOURCE_TYPES = {
        # CloudFormation
        "AWS::Events::Rule",
        "AWS::CloudWatch::Alarm",
        "AWS::Config::ConfigRule",
        "AWS::SNS::Topic",
        "AWS::StepFunctions::StateMachine",
        "AWS::Lambda::Function",
        "AWS::GuardDuty::Detector",
        "AWS::SecurityHub::Hub",
        # Terraform (for reference)
        "aws_cloudwatch_event_rule",
        "aws_cloudwatch_metric_alarm",
        "aws_config_config_rule",
        "aws_sns_topic",
        "aws_sfn_state_machine",
        "aws_lambda_function",
    }

    # Keywords indicating security purpose
    SECURITY_KEYWORDS = {
        "security", "alert", "detect", "monitor", "guard", "audit",
        "threat", "anomaly", "suspicious", "unauthorized", "incident",
        "compliance", "remediation", "response", "siem", "soc",
        "cloudtrail", "guardduty", "securityhub", "config",
        "breach", "attack", "intrusion", "malicious", "violation",
    }

    def __init__(self, session=None):
        """Initialize parser with AWS session."""
        self.session = session
        self.logger = logger.bind(component="CloudFormationParser")

    async def check_permissions(self, region: str = "us-east-1") -> PermissionCheckResult:
        """Check if required IAM permissions are available."""
        result = PermissionCheckResult(has_required_permissions=True)

        if not self.session:
            result.has_required_permissions = False
            result.missing_permissions = self.REQUIRED_PERMISSIONS.copy()
            result.warnings.append("No AWS session configured")
            return result

        client = self.session.client("cloudformation", region_name=region)

        # Test cloudformation:ListStacks
        try:
            client.list_stacks(StackStatusFilter=["CREATE_COMPLETE"])
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDeniedException":
                result.has_required_permissions = False
                result.missing_permissions.append("cloudformation:ListStacks")
                result.warnings.append(
                    "Missing cloudformation:ListStacks permission. "
                    "This is needed to discover CloudFormation stacks containing security detections."
                )

        # Test cloudformation:GetTemplate with a dummy stack
        try:
            client.get_template(StackName="__permission_check_dummy__")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDeniedException":
                result.has_required_permissions = False
                result.missing_permissions.append("cloudformation:GetTemplate")
                result.warnings.append(
                    "Missing cloudformation:GetTemplate permission. "
                    "This is needed to analyze CloudFormation templates for security resources."
                )
            # ValidationError is expected for non-existent stack

        if not result.has_required_permissions:
            result.warnings.append(
                f"To enable IaC analysis, add these permissions to your IAM policy: "
                f"{', '.join(result.missing_permissions)}"
            )

        return result

    async def analyze_stack(
        self,
        stack_name: str,
        region: str,
        consent_verified: bool = False,
    ) -> IaCAnalysisResult:
        """Analyze a CloudFormation stack for security detections.

        Args:
            stack_name: CloudFormation stack name
            region: AWS region
            consent_verified: MUST be True - confirms user has consented

        Returns:
            IaCAnalysisResult with discovered detections
        """
        result = IaCAnalysisResult(
            source_type="cloudformation",
            source_name=stack_name,
        )

        # CRITICAL: Require explicit consent
        if not consent_verified:
            result.errors.append(
                "IaC analysis requires explicit user consent. "
                "Please enable code analysis in your account settings."
            )
            return result

        if not self.session:
            result.errors.append("AWS session not configured")
            return result

        client = self.session.client("cloudformation", region_name=region)

        # Get template
        try:
            response = client.get_template(
                StackName=stack_name,
                TemplateStage="Original",
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")

            if error_code == "AccessDeniedException":
                result.permission_errors.append(
                    "Access denied when retrieving CloudFormation template. "
                    "Ensure your IAM role has cloudformation:GetTemplate permission."
                )
                result.missing_permissions.append("cloudformation:GetTemplate")
            elif error_code == "ValidationError":
                result.errors.append(f"Stack not found: {stack_name}")
            else:
                result.errors.append(f"Error retrieving template: {str(e)}")

            return result

        # Parse template
        template_body = response.get("TemplateBody", "")

        if isinstance(template_body, str):
            # Try to parse as YAML first, then JSON
            try:
                template = yaml.safe_load(template_body)
            except yaml.YAMLError:
                try:
                    template = json.loads(template_body)
                except json.JSONDecodeError:
                    result.errors.append("Could not parse template as YAML or JSON")
                    return result
        else:
            template = template_body

        # Analyze resources
        resources = template.get("Resources", {})
        result.resources_analyzed = len(resources)

        for logical_id, resource in resources.items():
            resource_type = resource.get("Type", "")

            if resource_type in self.SECURITY_RESOURCE_TYPES:
                detection = self._analyze_resource(
                    logical_id=logical_id,
                    resource_type=resource_type,
                    resource_config=resource,
                    stack_name=stack_name,
                )

                if detection:
                    result.detections.append(detection)
                    result.security_resources_found += 1

        self.logger.info(
            "stack_analysis_complete",
            stack=stack_name,
            resources=result.resources_analyzed,
            detections=len(result.detections),
        )

        return result

    async def analyze_all_stacks(
        self,
        region: str,
        consent_verified: bool = False,
    ) -> list[IaCAnalysisResult]:
        """Analyze all CloudFormation stacks in a region."""
        results = []

        if not consent_verified:
            return [IaCAnalysisResult(
                source_type="cloudformation",
                source_name="all",
                errors=["IaC analysis requires explicit user consent."],
            )]

        if not self.session:
            return [IaCAnalysisResult(
                source_type="cloudformation",
                source_name="all",
                errors=["AWS session not configured"],
            )]

        client = self.session.client("cloudformation", region_name=region)

        try:
            paginator = client.get_paginator("list_stacks")

            for page in paginator.paginate(
                StackStatusFilter=[
                    "CREATE_COMPLETE",
                    "UPDATE_COMPLETE",
                    "UPDATE_ROLLBACK_COMPLETE",
                ]
            ):
                for stack in page.get("StackSummaries", []):
                    stack_name = stack.get("StackName")

                    result = await self.analyze_stack(
                        stack_name=stack_name,
                        region=region,
                        consent_verified=True,
                    )
                    results.append(result)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDeniedException":
                return [IaCAnalysisResult(
                    source_type="cloudformation",
                    source_name="all",
                    permission_errors=["Missing cloudformation:ListStacks permission"],
                    missing_permissions=["cloudformation:ListStacks"],
                )]

        return results

    def _analyze_resource(
        self,
        logical_id: str,
        resource_type: str,
        resource_config: dict,
        stack_name: str,
    ) -> Optional[IaCDetection]:
        """Analyze a single CloudFormation resource."""
        properties = resource_config.get("Properties", {})

        if resource_type == "AWS::Events::Rule":
            return self._analyze_eventbridge_rule(logical_id, properties, stack_name)
        elif resource_type == "AWS::CloudWatch::Alarm":
            return self._analyze_cloudwatch_alarm(logical_id, properties, stack_name)
        elif resource_type == "AWS::Config::ConfigRule":
            return self._analyze_config_rule(logical_id, properties, stack_name)
        elif resource_type == "AWS::Lambda::Function":
            return self._analyze_lambda_function(logical_id, properties, stack_name)

        return None

    def _analyze_eventbridge_rule(
        self,
        logical_id: str,
        properties: dict,
        stack_name: str,
    ) -> Optional[IaCDetection]:
        """Analyze EventBridge rule for security patterns."""
        name = properties.get("Name", logical_id)
        description = properties.get("Description", "")
        event_pattern = properties.get("EventPattern", {})

        # Check if security-related
        security_indicators = self._find_security_indicators(
            name=name,
            description=description,
            config=event_pattern,
        )

        if not security_indicators:
            return None

        # Suggest MITRE techniques based on event pattern
        suggested_techniques = self._suggest_techniques_from_event_pattern(event_pattern)

        return IaCDetection(
            name=name,
            resource_type="AWS::Events::Rule",
            detection_type="eventbridge_rule",
            template_type="cloudformation",
            stack_name=stack_name,
            logical_id=logical_id,
            event_pattern=event_pattern,
            description=description,
            security_indicators=security_indicators,
            suggested_techniques=suggested_techniques,
        )

    def _analyze_cloudwatch_alarm(
        self,
        logical_id: str,
        properties: dict,
        stack_name: str,
    ) -> Optional[IaCDetection]:
        """Analyze CloudWatch alarm for security patterns."""
        name = properties.get("AlarmName", logical_id)
        description = properties.get("AlarmDescription", "")
        metric_name = properties.get("MetricName", "")
        namespace = properties.get("Namespace", "")

        # Security-related namespaces
        security_namespaces = {
            "AWS/GuardDuty",
            "AWS/SecurityHub",
            "AWS/CloudTrail",
            "AWS/Config",
            "CWAgent",  # Often used for security metrics
        }

        security_indicators = []

        if namespace in security_namespaces:
            security_indicators.append(f"namespace:{namespace}")

        security_indicators.extend(self._find_security_indicators(
            name=name,
            description=description,
            config={"metric": metric_name, "namespace": namespace},
        ))

        if not security_indicators:
            return None

        return IaCDetection(
            name=name,
            resource_type="AWS::CloudWatch::Alarm",
            detection_type="cloudwatch_alarm",
            template_type="cloudformation",
            stack_name=stack_name,
            logical_id=logical_id,
            alarm_config={
                "metricName": metric_name,
                "namespace": namespace,
                "threshold": properties.get("Threshold"),
                "comparisonOperator": properties.get("ComparisonOperator"),
            },
            description=description,
            security_indicators=security_indicators,
        )

    def _analyze_config_rule(
        self,
        logical_id: str,
        properties: dict,
        stack_name: str,
    ) -> Optional[IaCDetection]:
        """Analyze AWS Config rule."""
        name = properties.get("ConfigRuleName", logical_id)
        description = properties.get("Description", "")
        source = properties.get("Source", {})

        # Config rules are inherently security-related
        return IaCDetection(
            name=name,
            resource_type="AWS::Config::ConfigRule",
            detection_type="config_rule",
            template_type="cloudformation",
            stack_name=stack_name,
            logical_id=logical_id,
            rule_config={
                "sourceIdentifier": source.get("SourceIdentifier"),
                "owner": source.get("Owner"),
            },
            description=description,
            security_indicators=["config_rule"],
            suggested_techniques=["T1562.008"],  # Impair Defenses
        )

    def _analyze_lambda_function(
        self,
        logical_id: str,
        properties: dict,
        stack_name: str,
    ) -> Optional[IaCDetection]:
        """Analyze Lambda function for security indicators."""
        name = properties.get("FunctionName", logical_id)
        description = properties.get("Description", "")

        security_indicators = self._find_security_indicators(
            name=name,
            description=description,
        )

        if not security_indicators:
            return None

        return IaCDetection(
            name=name,
            resource_type="AWS::Lambda::Function",
            detection_type="custom_lambda",
            template_type="cloudformation",
            stack_name=stack_name,
            logical_id=logical_id,
            description=description,
            security_indicators=security_indicators,
        )

    def _find_security_indicators(
        self,
        name: str = "",
        description: str = "",
        config: dict = None,
    ) -> list[str]:
        """Find security keywords in resource configuration."""
        indicators = []
        config = config or {}

        # Check name and description
        text = f"{name} {description}".lower()

        for keyword in self.SECURITY_KEYWORDS:
            if keyword in text:
                indicators.append(f"keyword:{keyword}")

        # Check config structure
        config_str = json.dumps(config).lower()
        for keyword in self.SECURITY_KEYWORDS:
            if keyword in config_str and f"keyword:{keyword}" not in indicators:
                indicators.append(f"config:{keyword}")

        return indicators

    def _suggest_techniques_from_event_pattern(self, event_pattern: dict) -> list[str]:
        """Suggest MITRE techniques based on EventBridge event pattern."""
        techniques = []

        source = event_pattern.get("source", [])
        detail = event_pattern.get("detail", {})

        # Map event sources to techniques
        source_to_technique = {
            "aws.cloudtrail": ["T1562.008"],  # Impair Defenses
            "aws.iam": ["T1098", "T1087.004"],  # Account Manipulation, Account Discovery
            "aws.ec2": ["T1562.007", "T1580"],  # Disable Firewall, Infrastructure Discovery
            "aws.s3": ["T1530"],  # Data from Cloud Storage
            "aws.guardduty": ["T1562.008"],  # Impair Defenses
            "aws.securityhub": ["T1562.008"],
            "aws.signin": ["T1078.004"],  # Valid Accounts: Cloud Accounts
        }

        for src in source if isinstance(source, list) else [source]:
            if src in source_to_technique:
                techniques.extend(source_to_technique[src])

        # Check for specific event names in detail
        event_names = detail.get("eventName", [])
        event_name_to_technique = {
            "CreateAccessKey": "T1098.001",
            "CreateUser": "T1136.003",
            "StopLogging": "T1562.008",
            "DeleteTrail": "T1562.008",
            "AuthorizeSecurityGroupIngress": "T1562.007",
        }

        for event_name in event_names if isinstance(event_names, list) else [event_names]:
            if event_name in event_name_to_technique:
                techniques.append(event_name_to_technique[event_name])

        return list(set(techniques))

    def get_permission_requirements(self) -> dict:
        """Get IAM permission requirements for IaC analysis."""
        return {
            "required_permissions": self.REQUIRED_PERMISSIONS,
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "CloudFormationAnalysis",
                        "Effect": "Allow",
                        "Action": self.REQUIRED_PERMISSIONS,
                        "Resource": "*",
                    }
                ]
            },
            "description": (
                "These permissions allow the Detection Coverage Validator to discover "
                "security detections defined in your CloudFormation stacks."
            ),
            "risks": [
                "CloudFormation templates will be downloaded and analyzed",
                "Template analysis may reveal infrastructure patterns",
            ],
            "mitigations": [
                "Templates are analyzed in-memory and not stored",
                "Only security-relevant resources are extracted",
                "You can revoke consent at any time",
            ],
        }


def parse_terraform_file(content: str, file_path: str) -> list[IaCDetection]:
    """Parse a Terraform file for security detections.

    This is a simple HCL parser for common patterns.
    For full HCL parsing, consider using python-hcl2.
    """
    detections = []

    # Simple regex patterns for Terraform resources
    resource_pattern = re.compile(
        r'resource\s+"(aws_\w+)"\s+"(\w+)"\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
        re.MULTILINE | re.DOTALL
    )

    security_resource_types = {
        "aws_cloudwatch_event_rule",
        "aws_cloudwatch_metric_alarm",
        "aws_config_config_rule",
        "aws_lambda_function",
        "aws_sns_topic",
    }

    for match in resource_pattern.finditer(content):
        resource_type = match.group(1)
        resource_name = match.group(2)
        resource_body = match.group(3)

        if resource_type not in security_resource_types:
            continue

        # Check for security keywords
        security_keywords = {
            "security", "alert", "detect", "monitor", "guard", "audit",
            "cloudtrail", "guardduty", "securityhub",
        }

        body_lower = resource_body.lower()
        indicators = [kw for kw in security_keywords if kw in body_lower]

        if not indicators:
            continue

        detection_type_map = {
            "aws_cloudwatch_event_rule": "eventbridge_rule",
            "aws_cloudwatch_metric_alarm": "cloudwatch_alarm",
            "aws_config_config_rule": "config_rule",
            "aws_lambda_function": "custom_lambda",
            "aws_sns_topic": "sns_topic",
        }

        detections.append(IaCDetection(
            name=resource_name,
            resource_type=resource_type,
            detection_type=detection_type_map.get(resource_type, "unknown"),
            template_type="terraform",
            file_path=file_path,
            security_indicators=[f"keyword:{ind}" for ind in indicators],
        ))

    return detections
