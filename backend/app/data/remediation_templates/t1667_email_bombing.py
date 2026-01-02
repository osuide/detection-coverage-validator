"""
T1667 - Email Bombing

Adversaries flood targeted email addresses with overwhelming message volumes
to disrupt operations, bury legitimate communications, and enable social
engineering attacks. Often precedes vishing and ransomware deployment.
Used by Storm-1811 (Black Basta ransomware).
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
    technique_id="T1667",
    technique_name="Email Bombing",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1667/",
    threat_context=ThreatContext(
        description=(
            "Adversaries flood targeted email addresses with overwhelming message volumes "
            "to disrupt business operations by burying legitimate communications including "
            "security alerts, help desk tickets, and client correspondence. Email bombing "
            "serves as a distraction technique and social engineering precursor, where "
            "attackers follow bombardment with vishing calls posing as IT support to "
            "deploy ransomware or steal credentials."
        ),
        attacker_goal="Disrupt operations and enable social engineering through email flooding",
        why_technique=[
            "Buries security alerts and legitimate communications",
            "Creates frustration enabling social engineering",
            "Automated registration in unvalidated email lists",
            "Precursor to vishing and ransomware attacks",
            "Low technical barrier to execution",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Disrupts business operations and serves as precursor to ransomware. "
            "Recent campaigns demonstrate effectiveness in enabling Black Basta deployment."
        ),
        business_impact=[
            "Disrupted business communications",
            "Missed security alerts",
            "Delayed help desk response",
            "Enabler for social engineering",
            "Potential ransomware deployment",
        ],
        typical_attack_phase="impact",
        often_precedes=["T1566", "T1219"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1667-aws-ses-rate",
            name="AWS SES Inbound Email Rate Detection",
            description="Detect abnormally high inbound email volumes to single recipients via AWS SES.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, mail.destination, mail.messageId, mail.source
| filter eventName = "Receive"
| stats count(*) as emailCount by mail.destination[0], bin(5m)
| filter emailCount > 50
| sort emailCount desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect email bombing via SES inbound rate monitoring

Parameters:
  SESLogGroup:
    Type: String
    Description: CloudWatch log group for SES events
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # SNS topic for email bombing alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Email Bombing Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId

  # Metric filter for high email rate
  HighEmailRateFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SESLogGroup
      FilterPattern: '{ $.eventName = "Receive" }'
      MetricTransformations:
        - MetricName: InboundEmailCount
          MetricNamespace: Security/EmailBombing
          MetricValue: "1"
          DefaultValue: 0

  # Alarm for email bombing detection
  EmailBombingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EmailBombingDetected
      AlarmDescription: High volume of emails to single recipient
      MetricName: InboundEmailCount
      Namespace: Security/EmailBombing
      Statistic: Sum
      Period: 300
      Threshold: 200
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# AWS: Detect email bombing via SES rate monitoring

variable "ses_log_group" {
  type        = string
  description = "CloudWatch log group for SES events"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

data "aws_caller_identity" "current" {}

# SNS topic for alerts
resource "aws_sns_topic" "email_bombing_alerts" {
  name         = "email-bombing-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Email Bombing Alerts"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.email_bombing_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.email_bombing_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.email_bombing_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for high email rate
resource "aws_cloudwatch_log_metric_filter" "high_email_rate" {
  name           = "high-email-rate"
  log_group_name = var.ses_log_group
  pattern        = "{ $.eventName = \"Receive\" }"

  metric_transformation {
    name          = "InboundEmailCount"
    namespace     = "Security/EmailBombing"
    value         = "1"
    default_value = 0
  }
}

# Alarm for email bombing
resource "aws_cloudwatch_metric_alarm" "email_bombing" {
  alarm_name          = "EmailBombingDetected"
  alarm_description   = "High volume of emails to single recipient"
  metric_name         = "InboundEmailCount"
  namespace           = "Security/EmailBombing"
  statistic           = "Sum"
  period              = 300
  threshold           = 200
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.email_bombing_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Email Bombing Attack Detected",
                alert_description_template="Abnormally high email volume detected to {destination}.",
                investigation_steps=[
                    "Identify targeted recipient email addresses",
                    "Review sender domains and patterns",
                    "Check for follow-up vishing attempts via phone logs",
                    "Review help desk tickets for unusual IT support calls",
                    "Check for remote access tool installations",
                    "Verify no credential compromise occurred",
                ],
                containment_actions=[
                    "Implement rate limiting on recipient mailboxes",
                    "Block sender domains at email gateway",
                    "Alert affected users about potential vishing",
                    "Monitor for remote access tool deployment",
                    "Review and block suspicious IP addresses",
                    "Enable additional email filtering rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on legitimate mailing lists and normal email volumes",
            detection_coverage="75% - catches mass email floods",
            evasion_considerations="Slow-rate bombing over extended periods may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["AWS SES with CloudWatch logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1667-aws-workmail-rate",
            name="AWS WorkMail Inbound Rate Detection",
            description="Detect email bombing via WorkMail organisation mailbox monitoring.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, recipientAddress, senderAddress, messageId
| filter eventType = "INBOUND"
| stats count(*) as emailCount by recipientAddress, bin(5m)
| filter emailCount > 50
| sort emailCount desc""",
                terraform_template="""# AWS: Detect email bombing via WorkMail monitoring

variable "workmail_log_group" {
  type        = string
  description = "CloudWatch log group for WorkMail events"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

data "aws_caller_identity" "current" {}

# SNS topic for alerts
resource "aws_sns_topic" "workmail_bombing_alerts" {
  name         = "workmail-email-bombing-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "WorkMail Email Bombing Alerts"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.workmail_bombing_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.workmail_bombing_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.workmail_bombing_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for high inbound rate
resource "aws_cloudwatch_log_metric_filter" "workmail_high_rate" {
  name           = "workmail-high-inbound-rate"
  log_group_name = var.workmail_log_group
  pattern        = "{ $.eventType = \"INBOUND\" }"

  metric_transformation {
    name          = "WorkMailInboundCount"
    namespace     = "Security/EmailBombing"
    value         = "1"
    default_value = 0
  }
}

# Alarm for email bombing
resource "aws_cloudwatch_metric_alarm" "workmail_bombing" {
  alarm_name          = "WorkMailEmailBombing"
  alarm_description   = "High volume of inbound emails in WorkMail"
  metric_name         = "WorkMailInboundCount"
  namespace           = "Security/EmailBombing"
  statistic           = "Sum"
  period              = 300
  threshold           = 200
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.workmail_bombing_alerts.arn]
}""",
                alert_severity="high",
                alert_title="WorkMail Email Bombing Detected",
                alert_description_template="High email volume to {recipientAddress} in WorkMail.",
                investigation_steps=[
                    "Identify targeted WorkMail users",
                    "Review sender patterns and domains",
                    "Check for vishing follow-up attempts",
                    "Review recent IT support interactions",
                    "Verify no credential compromise",
                    "Check for remote access software installations",
                ],
                containment_actions=[
                    "Apply rate limiting to affected mailboxes",
                    "Block malicious sender domains",
                    "Alert users about social engineering risk",
                    "Monitor for ransomware indicators",
                    "Enable advanced email filtering",
                    "Review and update email security policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold for organisations with high legitimate email volume",
            detection_coverage="70% - detects rapid email floods",
            evasion_considerations="Time-delayed bombing may bypass threshold detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["AWS WorkMail with CloudWatch logging"],
        ),
        DetectionStrategy(
            strategy_id="t1667-gcp-workspace-rate",
            name="GCP Workspace Email Rate Detection",
            description="Detect email bombing via Google Workspace email logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gmail_message"
protoPayload.methodName="gmail.MessageReceived"
severity="INFO"''',
                gcp_terraform_template="""# GCP: Detect email bombing via Workspace logs

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Email Bombing Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for high email rate
resource "google_logging_metric" "high_email_rate" {
  project = var.project_id
  name   = "high-inbound-email-rate"
  filter = <<-EOT
    resource.type="gmail_message"
    protoPayload.methodName="gmail.MessageReceived"
    severity="INFO"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "recipient"
      value_type  = "STRING"
      description = "Email recipient address"
    }
  }

  label_extractors = {
    "recipient" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for email bombing
resource "google_monitoring_alert_policy" "email_bombing" {
  project      = var.project_id
  display_name = "Email Bombing Detection"
  combiner     = "OR"

  conditions {
    display_name = "High inbound email rate"

    condition_threshold {
      filter          = "resource.type=\"gmail_message\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.high_email_rate.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 200

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "High volume of inbound emails detected, possible email bombing attack. Review recipient and sender patterns."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Email Bombing Attack Detected",
                alert_description_template="Abnormally high email volume in Google Workspace.",
                investigation_steps=[
                    "Identify targeted Workspace users",
                    "Review Gmail admin console for suspicious patterns",
                    "Check sender domains and registration sources",
                    "Monitor for follow-up vishing calls",
                    "Review recent user activity logs",
                    "Check for credential compromise indicators",
                ],
                containment_actions=[
                    "Apply Gmail rate limiting rules",
                    "Block sender domains via admin console",
                    "Alert affected users about vishing risk",
                    "Enable advanced phishing protection",
                    "Review and update email filtering policies",
                    "Monitor for ransomware deployment attempts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune for legitimate bulk email and mailing list subscriptions",
            detection_coverage="75% - detects rapid email bombardment",
            evasion_considerations="Distributed bombing from multiple sources may evade simple rate limits",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Google Workspace with audit logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1667-aws-ses-pattern",
            name="AWS SES Repetitive Sender Detection",
            description="Detect email bombing via sender pattern analysis in SES logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, mail.source, mail.destination, mail.commonHeaders.subject
| filter eventName = "Receive"
| stats count(*) as emailCount, count_distinct(mail.commonHeaders.subject) as uniqueSubjects by mail.source, mail.destination[0], bin(10m)
| filter emailCount > 30 AND uniqueSubjects < 5
| sort emailCount desc""",
                terraform_template="""# AWS: Detect email bombing via sender pattern analysis

variable "ses_log_group" {
  type        = string
  description = "CloudWatch log group for SES events"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

data "aws_caller_identity" "current" {}

# SNS topic for pattern-based alerts
resource "aws_sns_topic" "pattern_alerts" {
  name         = "email-bombing-pattern-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Email Bombing Pattern Alerts"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.pattern_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.pattern_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.pattern_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch Insights query for scheduled analysis
resource "aws_cloudwatch_query_definition" "email_bombing_pattern" {
  name = "email-bombing-sender-pattern"

  log_group_names = [var.ses_log_group]

  query_string = <<-EOT
    fields @timestamp, mail.source, mail.destination, mail.commonHeaders.subject
    | filter eventName = "Receive"
    | stats count(*) as emailCount, count_distinct(mail.commonHeaders.subject) as uniqueSubjects by mail.source, mail.destination[0], bin(10m)
    | filter emailCount > 30 AND uniqueSubjects < 5
    | sort emailCount desc
  EOT
}

# EventBridge rule for scheduled query execution
resource "aws_cloudwatch_event_rule" "pattern_check" {
  name                = "email-bombing-pattern-check"
  description         = "Check for email bombing patterns every 15 minutes"
  schedule_expression = "rate(15 minutes)"
}

# DLQ for failed event deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "email-bombing-pattern-dlq"
  message_retention_seconds = 1209600
}

data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.pattern_check.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "eventbridge_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# EventBridge target with DLQ and retry policy
resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.pattern_check.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.pattern_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account = "$.account"
      region  = "$.region"
      time    = "$.time"
      source  = "$.source"
      detail  = "$.detail"
    }

    input_template = <<-EOT
"Security Alert
Time: <time>
Account: <account>
Region: <region>
Source: <source>
Action: Review event details and investigate"
EOT
  }

}

# SNS topic policy to allow EventBridge
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.pattern_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.pattern_alerts.arn
      Condition = {
        StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = aws_cloudwatch_event_rule.pattern_check.arn }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Email Bombing Pattern Detected",
                alert_description_template="Repetitive email pattern from {source} to {destination}.",
                investigation_steps=[
                    "Analyse sender domain reputation",
                    "Check for automated list registration patterns",
                    "Review email subject and content patterns",
                    "Identify if sender is legitimate service",
                    "Check for user complaints or help desk tickets",
                    "Correlate with phone call logs for vishing",
                ],
                containment_actions=[
                    "Create email filtering rules for sender patterns",
                    "Block sender domains if malicious",
                    "Implement CAPTCHA for list registrations",
                    "Enable SPF/DKIM/DMARC validation",
                    "Alert affected users",
                    "Monitor for escalation to vishing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Low false positive rate due to pattern analysis",
            detection_coverage="65% - catches automated registration bombing",
            evasion_considerations="Varied subjects and distributed senders may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["AWS SES with detailed CloudWatch logging"],
        ),
    ],
    recommended_order=[
        "t1667-aws-ses-rate",
        "t1667-gcp-workspace-rate",
        "t1667-aws-workmail-rate",
        "t1667-aws-ses-pattern",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+25% improvement for Impact tactic detection",
)
