"""
T1651 - Cloud Administration Command

Adversaries use cloud management services (SSM, Azure RunCommand) to
execute commands on VMs. Used by APT29 and Pacu.
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
    technique_id="T1651",
    technique_name="Cloud Administration Command",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1651/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use cloud management services (AWS Systems Manager, Azure RunCommand) "
            "to execute commands on virtual machines through installed VM agents."
        ),
        attacker_goal="Execute commands on VMs via cloud management services",
        why_technique=[
            "Legitimate admin tool often allowed",
            "No need for SSH/RDP access",
            "Commands executed as SYSTEM/root",
            "May bypass network security controls",
            "Logs may be overlooked",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Enables command execution with high privileges. "
            "Legitimate tool makes detection difficult. "
            "Bypasses traditional network security."
        ),
        business_impact=[
            "Arbitrary command execution",
            "Malware deployment",
            "Data exfiltration",
            "Lateral movement",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1530", "T1485"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1651-aws-ssm",
            name="AWS SSM Command Execution Detection",
            description="Detect commands executed via AWS Systems Manager.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["SendCommand", "StartSession"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect SSM command execution

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

  SSMCommandRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ssm]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [SendCommand, StartSession]
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
                terraform_template="""# Detect SSM command execution

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ssm-command-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "ssm_command" {
  name = "ssm-command-execution"
  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["SendCommand", "StartSession"] }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.ssm_command.name
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
                alert_severity="high",
                alert_title="SSM Command Executed",
                alert_description_template="SSM command sent to {instanceIds} by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify command execution was authorised",
                    "Review the command content",
                    "Check target instances",
                    "Review command output",
                ],
                containment_actions=[
                    "Review SSM permissions",
                    "Check instance for compromise",
                    "Audit SSM usage patterns",
                    "Consider SSM Session Manager logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist automation and patching systems",
            detection_coverage="95% - catches all SSM commands",
            evasion_considerations="Cannot evade SSM logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1651-gcp-osconfig",
            name="GCP OS Config Command Detection",
            description="Detect commands via GCP OS Config Agent.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"osconfig.*Execute|osconfig.*Run"''',
                gcp_terraform_template="""# GCP: Detect OS Config command execution

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "osconfig_cmd" {
  name   = "osconfig-command-execution"
  filter = <<-EOT
    protoPayload.methodName=~"osconfig.*Execute|osconfig.*Run"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "osconfig_cmd" {
  display_name = "OS Config Command Execution"
  combiner     = "OR"
  conditions {
    display_name = "Command executed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.osconfig_cmd.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: OS Config Command Executed",
                alert_description_template="Command executed via OS Config Agent.",
                investigation_steps=[
                    "Verify execution was authorised",
                    "Review command content",
                    "Check target VMs",
                    "Review execution logs",
                ],
                containment_actions=[
                    "Review OS Config permissions",
                    "Check VM for compromise",
                    "Audit command history",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist patching and automation",
            detection_coverage="90% - catches logged commands",
            evasion_considerations="Direct SSH may bypass",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1651-aws-ssm", "t1651-gcp-osconfig"],
    total_effort_hours=1.5,
    coverage_improvement="+15% improvement for Execution tactic",
)
