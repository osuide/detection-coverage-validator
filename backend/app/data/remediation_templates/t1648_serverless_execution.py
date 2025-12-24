"""
T1648 - Serverless Execution

Adversaries use serverless functions (Lambda, Cloud Functions) to execute
arbitrary code. Can be used for cryptomining, privilege escalation, or backdoors.
Pacu can create malicious Lambda functions.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
    CloudProvider,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1648",
    technique_name="Serverless Execution",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1648/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit serverless computing services (Lambda, Cloud Functions) "
            "to execute arbitrary code. Used for cryptomining, privilege escalation "
            "through IAM roles, or persistent backdoors triggered by events."
        ),
        attacker_goal="Execute malicious code via serverless functions",
        why_technique=[
            "Serverless has IAM roles with permissions",
            "Event-triggered execution for persistence",
            "Can add credentials to new users",
            "Abuse automation for lateral movement",
            "Hard to detect among legitimate functions",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Serverless functions can have powerful IAM roles. "
            "Event-triggered functions provide persistence. "
            "Difficult to detect among many legitimate functions."
        ),
        business_impact=[
            "Arbitrary code execution",
            "Privilege escalation via function roles",
            "Persistent backdoors",
            "Resource abuse",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1098.001", "T1530"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1648-aws-lambda",
            name="AWS Lambda Function Creation Detection",
            description="Detect creation of new Lambda functions.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.lambda"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["CreateFunction20150331", "CreateFunction"]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda function creation

Parameters:
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  LambdaCreateRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.lambda]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateFunction20150331
            - CreateFunction
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect Lambda function creation

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "lambda-creation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "lambda_create" {
  name = "lambda-function-creation"
  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["CreateFunction20150331", "CreateFunction"] }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.lambda_create.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Lambda Function Created",
                alert_description_template="New Lambda function {functionName} created by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify function creation was authorised",
                    "Review function code for malicious content",
                    "Check IAM role attached to function",
                    "Review event triggers",
                ],
                containment_actions=[
                    "Delete unauthorised functions",
                    "Review Lambda deployment permissions",
                    "Audit function IAM roles",
                    "Check for event triggers",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD deployment pipelines",
            detection_coverage="95% - catches all function creation",
            evasion_considerations="Cannot evade creation detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1648-gcp-functions",
            name="GCP Cloud Functions Creation Detection",
            description="Detect creation of new Cloud Functions.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CreateFunction"
OR protoPayload.methodName="google.cloud.functions.v2.FunctionService.CreateFunction"''',
                gcp_terraform_template="""# GCP: Detect Cloud Functions creation

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "function_create" {
  name   = "cloud-functions-creation"
  filter = <<-EOT
    protoPayload.methodName=~"CloudFunctionsService.CreateFunction|FunctionService.CreateFunction"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "function_create" {
  display_name = "Cloud Function Created"
  combiner     = "OR"
  conditions {
    display_name = "Function creation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_create.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Function Created",
                alert_description_template="New Cloud Function was created.",
                investigation_steps=[
                    "Verify function was authorised",
                    "Review function code",
                    "Check service account permissions",
                    "Review triggers",
                ],
                containment_actions=[
                    "Delete unauthorised functions",
                    "Review deployment permissions",
                    "Audit service accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD pipelines",
            detection_coverage="95% - catches all creation",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1648-aws-lambda", "t1648-gcp-functions"],
    total_effort_hours=1.5,
    coverage_improvement="+15% improvement for Execution tactic",
)
