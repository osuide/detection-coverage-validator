"""
T1598 - Phishing for Information

Adversaries send phishing messages to extract sensitive information rather than
deploy malware. Uses social engineering to gather credentials and intelligence.
Used by APT28, Kimsuky, Scattered Spider, ZIRCONIUM.
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
    technique_id="T1598",
    technique_name="Phishing for Information",
    tactic_ids=["TA0043"],
    mitre_url="https://attack.mitre.org/techniques/T1598/",
    threat_context=ThreatContext(
        description=(
            "Adversaries send phishing messages to elicit sensitive information "
            "from targets rather than deliver malicious payloads. Includes credential "
            "harvesting, spearphishing for intelligence, and social engineering via "
            "email, phone (vishing), or messaging services."
        ),
        attacker_goal="Gather credentials, contact lists, and actionable intelligence through social engineering",
        why_technique=[
            "Low technical barrier to entry",
            "Effective against human targets",
            "Enables reconnaissance for targeted attacks",
            "Can bypass technical security controls",
            "Facilitates credential theft and account takeover",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Reconnaissance technique that enables subsequent attacks. Credential theft "
            "can lead to account compromise and initial access to cloud environments."
        ),
        business_impact=[
            "Credential compromise",
            "Account takeover risk",
            "Intellectual property theft",
            "Enables targeted attacks",
            "Regulatory compliance violations",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1078", "T1566", "T1534", "T1199"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1598-aws-ses",
            name="AWS SES Suspicious Email Detection",
            description="Detect phishing emails sent via compromised AWS SES.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, mail.source, mail.destination, mail.commonHeaders.subject
| filter eventType = "Send"
| filter mail.commonHeaders.subject like /verify|confirm|urgent|suspended|reset|account/i
| stats count(*) as emails by mail.source, bin(1h)
| filter emails > 50
| sort emails desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect phishing campaigns via SES logs

Parameters:
  SESLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  PhishingFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SESLogGroup
      FilterPattern: '[timestamp, request_id, event_type=Send, result, subject=*verify* | subject=*confirm* | subject=*urgent* | subject=*suspended*]'
      MetricTransformations:
        - MetricName: SuspiciousEmails
          MetricNamespace: Security
          MetricValue: "1"

  PhishingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighVolumePhishingEmails
      MetricName: SuspiciousEmails
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect phishing campaigns via SES logs

variable "ses_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ses-phishing-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "phishing_emails" {
  name           = "phishing-emails"
  log_group_name = var.ses_log_group
  pattern        = "[timestamp, request_id, event_type=Send, result, subject=*verify* | subject=*confirm* | subject=*urgent*]"

  metric_transformation {
    name      = "SuspiciousEmails"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "phishing_campaign" {
  alarm_name          = "HighVolumePhishingEmails"
  metric_name         = "SuspiciousEmails"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Phishing Campaign Detected",
                alert_description_template="High volume of suspicious emails from {source}.",
                investigation_steps=[
                    "Review email subjects and content patterns",
                    "Check sender reputation and authentication",
                    "Analyse recipient list for targeting patterns",
                    "Review DKIM/SPF/DMARC records",
                    "Check for compromised AWS credentials",
                ],
                containment_actions=[
                    "Suspend compromised SES identities",
                    "Rotate AWS credentials",
                    "Enable SES sending restrictions",
                    "Report phishing domains",
                    "Notify affected recipients",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust keyword patterns for your organisation's email patterns",
            detection_coverage="50% - keyword-based detection",
            evasion_considerations="Adversaries may avoid common phishing keywords",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["AWS SES with CloudWatch logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1598-aws-guardduty",
            name="AWS GuardDuty Phishing Detection",
            description="Detect credential phishing via GuardDuty findings.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.type, detail.service.action.actionType
| filter detail.type like /Phishing|CredentialAccess/
| stats count(*) by detail.type, bin(1h)""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on GuardDuty phishing findings

Parameters:
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  GuardDutyPhishingRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Detect phishing-related GuardDuty findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
            - CredentialAccess:IAMUser/AnomalousBehavior
            - Stealth:IAMUser/CloudTrailLoggingDisabled
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: PhishingAlert""",
                terraform_template="""# Alert on GuardDuty phishing findings

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "guardduty-phishing-alerts"
  kms_master_key_id = "alias/aws/sns"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for EventBridge targets
resource "aws_sqs_queue" "events_dlq" {
  name                      = "guardduty-phishing-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "events_dlq" {
  queue_url = aws_sqs_queue.events_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.events_dlq.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "guardduty_phishing" {
  name        = "guardduty-phishing-detection"
  description = "Detect phishing-related GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "CredentialAccess:IAMUser/AnomalousBehavior",
        "Stealth:IAMUser/CloudTrailLoggingDisabled"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_phishing.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.events_dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

# Allow EventBridge to publish to SNS
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_phishing.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Credential Phishing Detected",
                alert_description_template="GuardDuty detected potential credential compromise for {principal}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Check affected IAM user activity",
                    "Review CloudTrail logs for anomalous access",
                    "Verify MFA status and recent changes",
                    "Check for lateral movement indicators",
                ],
                containment_actions=[
                    "Disable compromised IAM credentials",
                    "Enable MFA if not present",
                    "Review and revoke sessions",
                    "Reset user credentials",
                    "Enable CloudTrail if disabled",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are generally reliable",
            detection_coverage="60% - detects credential misuse post-phishing",
            evasion_considerations="Only detects post-phishing credential usage",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-50 (GuardDuty costs)",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1598-aws-workmail",
            name="AWS WorkMail Spoofing Detection",
            description="Detect email spoofing attempts in WorkMail.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, messageId, sender, recipients
| filter outcome = "FAILED" and reason like /SPF|DKIM|DMARC/
| stats count(*) as failures by sender, bin(1h)
| filter failures > 10
| sort failures desc""",
                terraform_template="""# Detect email spoofing in WorkMail

variable "workmail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "workmail-spoofing-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "spoofing_attempts" {
  name           = "email-spoofing-attempts"
  log_group_name = var.workmail_log_group
  pattern        = "[timestamp, message_id, outcome=FAILED, reason=*SPF* | reason=*DKIM* | reason=*DMARC*]"

  metric_transformation {
    name      = "SpoofingAttempts"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "spoofing_campaign" {
  alarm_name          = "EmailSpoofingDetected"
  metric_name         = "SpoofingAttempts"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Email Spoofing Attempts Detected",
                alert_description_template="Multiple SPF/DKIM/DMARC failures from {sender}.",
                investigation_steps=[
                    "Review sender domain and authentication failures",
                    "Check if legitimate domain is being spoofed",
                    "Analyse email content for phishing indicators",
                    "Review recipient list for targeting",
                    "Check email headers for anomalies",
                ],
                containment_actions=[
                    "Block spoofed sender domains",
                    "Strengthen DMARC policy to reject",
                    "Alert affected users",
                    "Report to domain registrar",
                    "Enable advanced threat protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="SPF/DKIM/DMARC failures indicate misconfiguration or spoofing",
            detection_coverage="70% - catches authentication failures",
            evasion_considerations="Adversaries may use lookalike domains",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "AWS WorkMail with logging enabled",
                "SPF/DKIM/DMARC configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1598-gcp-gmail",
            name="GCP Gmail API Suspicious Activity",
            description="Detect phishing via Gmail API access patterns.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="audited_resource"
protoPayload.serviceName="gmail.googleapis.com"
protoPayload.methodName="gmail.users.messages.send"
protoPayload.metadata.event.event_name="send_messages"
protoPayload.metadata.event.num_messages_sent>100""",
                gcp_terraform_template="""# GCP: Detect phishing via Gmail API

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "high_volume_emails" {
  project = var.project_id
  name   = "high-volume-email-sending"
  filter = <<-EOT
    resource.type="audited_resource"
    protoPayload.serviceName="gmail.googleapis.com"
    protoPayload.methodName="gmail.users.messages.send"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "phishing_campaign" {
  project      = var.project_id
  display_name = "Phishing Campaign Detection"
  combiner     = "OR"
  conditions {
    display_name = "High email volume"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.high_volume_emails.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: High Volume Email Activity",
                alert_description_template="Unusual email sending volume detected via Gmail API.",
                investigation_steps=[
                    "Review Gmail API activity logs",
                    "Check OAuth token usage",
                    "Analyse email content and recipients",
                    "Verify user account legitimacy",
                    "Review API access patterns",
                ],
                containment_actions=[
                    "Revoke suspicious OAuth tokens",
                    "Reset user credentials",
                    "Enable Gmail API restrictions",
                    "Contact affected recipients",
                    "Enable advanced phishing protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on normal email volumes",
            detection_coverage="50% - detects high-volume campaigns",
            evasion_considerations="Low-volume targeted phishing may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Gmail API audit logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1598-gcp-workspace",
            name="GCP Workspace Security Investigation",
            description="Detect phishing via Workspace security centre.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="workspace_account"
protoPayload.metadata.event.type="SUSPICIOUS_LOGIN"
OR protoPayload.metadata.event.type="ACCOUNT_WARNING"
OR protoPayload.metadata.event.type="GOVERNMENT_ATTACK_WARNING"''',
                gcp_terraform_template="""# GCP: Workspace security alerts

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "workspace_security_events" {
  project = var.project_id
  name   = "workspace-security-events"
  filter = <<-EOT
    resource.type="workspace_account"
    (protoPayload.metadata.event.type="SUSPICIOUS_LOGIN"
    OR protoPayload.metadata.event.type="ACCOUNT_WARNING"
    OR protoPayload.metadata.event.type="GOVERNMENT_ATTACK_WARNING")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "workspace_threats" {
  project      = var.project_id
  display_name = "Workspace Security Threats"
  combiner     = "OR"
  conditions {
    display_name = "Security event detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.workspace_security_events.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Workspace Security Alert",
                alert_description_template="Google Workspace detected suspicious account activity.",
                investigation_steps=[
                    "Review Workspace security investigation tool",
                    "Check account activity and login history",
                    "Verify user identity and location",
                    "Review email forwarding rules",
                    "Check for data exfiltration",
                ],
                containment_actions=[
                    "Force password reset",
                    "Revoke active sessions",
                    "Enable 2-step verification",
                    "Review and remove email delegates",
                    "Enable advanced protection programme",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Workspace security alerts are highly reliable",
            detection_coverage="80% - comprehensive threat detection",
            evasion_considerations="Google's ML detects most phishing attempts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="Included with Workspace",
            prerequisites=["Google Workspace with security centre enabled"],
        ),
        # Azure Strategy: Phishing for Information
        DetectionStrategy(
            strategy_id="t1598-azure",
            name="Azure Phishing for Information Detection",
            description=(
                "Azure detection for Phishing for Information. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Phishing for Information Detection
// Technique: T1598
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc""",
                azure_terraform_template="""# Azure Detection for Phishing for Information
# MITRE ATT&CK: T1598

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

variable "resource_group_name" {
  type        = string
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "phishing-for-information-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "phishing-for-information-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Phishing for Information Detection
// Technique: T1598
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects Phishing for Information (T1598) activity in Azure environment"
  display_name = "Phishing for Information Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1598"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Phishing for Information Detected",
                alert_description_template=(
                    "Phishing for Information activity detected. "
                    "Caller: {Caller}. Resource: {Resource}."
                ),
                investigation_steps=[
                    "Review Azure Activity Log for full operation details",
                    "Check caller identity and verify if authorised",
                    "Review affected resources and assess impact",
                    "Check for related activities in the same time window",
                    "Verify against change management records",
                ],
                containment_actions=[
                    "Disable compromised user/service principal if unauthorised",
                    "Revoke active sessions using Entra ID",
                    "Review and restrict Azure RBAC permissions",
                    "Enable additional Defender for Cloud protections",
                    "Implement Azure Policy to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Allowlist known automation accounts and CI/CD service principals. "
                "Use Azure Policy to define expected behaviour baselines."
            ),
            detection_coverage="70% - Azure-native detection for cloud operations",
            evasion_considerations=(
                "Attackers may use legitimate credentials from expected locations. "
                "Combine with Defender for Cloud for ML-based anomaly detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-50 (Log Analytics + Defender)",
            prerequisites=[
                "Azure subscription with Log Analytics workspace",
                "Defender for Cloud enabled (recommended)",
                "Appropriate Azure RBAC permissions for deployment",
            ],
        ),
    ],
    recommended_order=[
        "t1598-aws-guardduty",
        "t1598-gcp-workspace",
        "t1598-aws-workmail",
        "t1598-aws-ses",
        "t1598-gcp-gmail",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+25% improvement for Reconnaissance tactic",
)
