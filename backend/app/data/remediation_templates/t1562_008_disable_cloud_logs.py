"""
T1562.008 - Impair Defences: Disable or Modify Cloud Logs

Adversaries disable or modify cloud logging to evade detection.
Common targets: CloudTrail, Cloud Audit Logs, VPC Flow Logs.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    Campaign,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
    CloudProvider,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1562.008",
    technique_name="Impair Defences: Disable or Modify Cloud Logs",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1562/008/",
    threat_context=ThreatContext(
        description=(
            "Adversaries disable or modify cloud logging services to evade detection. "
            "Targets include CloudTrail, VPC Flow Logs, Cloud Audit Logs, and "
            "application-level logging."
        ),
        attacker_goal="Disable cloud logging to hide malicious activity",
        why_technique=[
            "Eliminates audit trail of attacker actions",
            "Makes incident response difficult",
            "Often done early in attack chain",
            "Single API call can disable logging",
            "May go unnoticed without monitoring",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="CloudTrail Deletion Attacks",
                year=2024,
                description="Multiple threat actors observed deleting CloudTrail trails as first action after compromise",
                reference_url="https://www.datadoghq.com/state-of-cloud-security/",
            ),
            Campaign(
                name="TeamTNT Log Evasion",
                year=2024,
                description="Cryptomining group disabling CloudWatch agent and audit logging on compromised instances",
                reference_url="https://www.cadosecurity.com/blog/teamtnt-reemerges-with-new-aggressive-cloud-campaign",
            ),
        ],
        prevalence="common",
        trend="stable",
        severity_score=9,
        severity_reasoning=(
            "Disabling logging blinds defenders and enables follow-on attacks. "
            "Often indicates active compromise requiring immediate response. "
            "Without logs, incident investigation becomes extremely difficult."
        ),
        business_impact=[
            "Loss of audit trail for compliance",
            "Inability to investigate incidents",
            "Potential regulatory violations",
            "Extended dwell time for attackers",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1530", "T1537", "T1078.004"],
        often_follows=["T1078.004", "T1528"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - CloudTrail Modification
        DetectionStrategy(
            strategy_id="t1562008-aws-cloudtrail",
            name="CloudTrail Modification Detection",
            description="Detect when CloudTrail is stopped, deleted, or modified.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Stealth:IAMUser/CloudTrailLoggingDisabled",
                    "Stealth:IAMUser/LoggingConfigurationModified",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect CloudTrail modifications

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge for CloudTrail modifications
  CloudTrailModRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.cloudtrail]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - StopLogging
            - DeleteTrail
            - UpdateTrail
            - PutEventSelectors
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
                terraform_template="""# Detect CloudTrail modifications

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "cloudtrail-modification-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "cloudtrail_mod" {
  name = "cloudtrail-modifications"
  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.cloudtrail_mod.name
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
                alert_severity="critical",
                alert_title="CloudTrail Logging Modified",
                alert_description_template="CloudTrail trail {trailName} was modified or disabled.",
                investigation_steps=[
                    "Identify who made the change",
                    "Check if trail is currently logging",
                    "Review recent API calls before logging stopped",
                    "Check for other concurrent suspicious activity",
                ],
                containment_actions=[
                    "Immediately re-enable CloudTrail logging",
                    "Lock down the IAM user/role that made the change",
                    "Review and rotate compromised credentials",
                    "Enable CloudTrail log file validation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised infrastructure automation",
            detection_coverage="95% - catches all CloudTrail API calls",
            evasion_considerations="Cannot evade if trail logs to separate account",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["GuardDuty or CloudTrail enabled"],
        ),
        # Strategy 2: AWS - VPC Flow Logs Deletion
        DetectionStrategy(
            strategy_id="t1562008-aws-flowlogs",
            name="VPC Flow Logs Modification Detection",
            description="Detect when VPC Flow Logs are deleted or disabled.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["DeleteFlowLogs"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect VPC Flow Logs deletion

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge for Flow Logs deletion
  FlowLogsDelRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [DeleteFlowLogs]
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
                terraform_template="""# Detect VPC Flow Logs deletion

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "flowlogs-deletion-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "flowlogs_del" {
  name = "flowlogs-deletion"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["DeleteFlowLogs"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.flowlogs_del.name
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
                alert_title="VPC Flow Logs Deleted",
                alert_description_template="VPC Flow Logs were deleted from {vpcId}.",
                investigation_steps=[
                    "Identify who deleted the flow logs",
                    "Check which VPCs are now unmonitored",
                    "Review recent network activity",
                    "Look for concurrent suspicious activity",
                ],
                containment_actions=[
                    "Re-enable VPC Flow Logs immediately",
                    "Review IAM permissions for flow logs management",
                    "Check for data exfiltration attempts",
                    "Enable flow logs to a protected S3 bucket",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist VPC cleanup automation",
            detection_coverage="95% - catches deletion events",
            evasion_considerations="Attacker may avoid triggering by not deleting",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: GCP - Cloud Audit Logs Modification
        DetectionStrategy(
            strategy_id="t1562008-gcp-auditlogs",
            name="GCP Audit Logs Modification Detection",
            description="Detect when Cloud Audit Logs configuration is modified.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"SetIamPolicy|UpdateSink|DeleteSink"
protoPayload.serviceName="logging.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect audit log modifications

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "audit_log_mod" {
  name   = "audit-log-modifications"
  filter = <<-EOT
    protoPayload.serviceName="logging.googleapis.com"
    protoPayload.methodName=~"(UpdateSink|DeleteSink|SetIamPolicy)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "audit_mod" {
  display_name = "Audit Log Configuration Changed"
  combiner     = "OR"

  conditions {
    display_name = "Logging configuration modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.audit_log_mod.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="critical",
                alert_title="GCP: Audit Log Configuration Modified",
                alert_description_template="Cloud Audit Logs configuration was modified.",
                investigation_steps=[
                    "Review what logging configuration changed",
                    "Identify the principal making the change",
                    "Check if log sinks were deleted",
                    "Verify current logging coverage",
                ],
                containment_actions=[
                    "Restore deleted log sinks",
                    "Lock down logging configuration permissions",
                    "Enable organisation policy for logging",
                    "Review service account permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised log management automation",
            detection_coverage="90% - catches API calls to logging service",
            evasion_considerations="Attacker may use compromised admin account",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - Data Access Logs Disabled
        DetectionStrategy(
            strategy_id="t1562008-gcp-dataaccess",
            name="GCP Data Access Logs Monitoring",
            description="Detect when Data Access audit logs are disabled.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="SetIamPolicy"
protoPayload.request.policy.auditConfigs:*""",
                gcp_terraform_template="""# GCP: Monitor Data Access audit log configuration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "data_access_mod" {
  name   = "data-access-log-changes"
  filter = <<-EOT
    protoPayload.methodName="SetIamPolicy"
    protoPayload.request.policy.auditConfigs:*
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "data_access" {
  display_name = "Data Access Logs Configuration Changed"
  combiner     = "OR"

  conditions {
    display_name = "Audit config modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.data_access_mod.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Data Access Logs Configuration Changed",
                alert_description_template="Data Access audit log configuration was modified.",
                investigation_steps=[
                    "Review the audit config changes",
                    "Check which services had logging disabled",
                    "Verify the principal making changes",
                    "Review recent data access patterns",
                ],
                containment_actions=[
                    "Re-enable Data Access logs",
                    "Set organisation-level audit config",
                    "Review IAM permissions for audit config",
                    "Enable log sinks to external destination",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Baseline normal audit config changes",
            detection_coverage="85% - catches IAM policy changes with audit config",
            evasion_considerations="Requires specific query for audit config",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1562008-aws-cloudtrail",
        "t1562008-gcp-auditlogs",
        "t1562008-aws-flowlogs",
        "t1562008-gcp-dataaccess",
    ],
    total_effort_hours=2.5,
    coverage_improvement="+25% improvement for Defence Evasion tactic",
)
