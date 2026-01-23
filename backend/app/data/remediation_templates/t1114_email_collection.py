"""
T1114 - Email Collection

Adversaries target user email to extract sensitive information including trade secrets,
personal data, and details about incident response operations. Used by Ember Bear,
Magic Hound, Scattered Spider, and Silent Librarian.
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
    technique_id="T1114",
    technique_name="Email Collection",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1114/",
    threat_context=ThreatContext(
        description=(
            "Adversaries target user email to extract sensitive information including trade secrets, "
            "personal data, and details about incident response operations. This intelligence helps "
            "attackers maintain persistence, evade defences, and gather information for further attacks. "
            "Email collection can occur through local file access, remote email protocols, or automated "
            "forwarding rules."
        ),
        attacker_goal="Extract sensitive email data for intelligence gathering and maintaining persistent access",
        why_technique=[
            "Email contains high-value intelligence and credentials",
            "Can reveal incident response details and security posture",
            "Access to trade secrets and confidential business data",
            "May contain MFA codes and authentication tokens",
            "Provides reconnaissance for lateral movement",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Email collection provides attackers with high-value intelligence including credentials, "
            "trade secrets, and incident response capabilities. Can lead to data breaches, compliance "
            "violations, and further compromise. Difficult to detect when done gradually."
        ),
        business_impact=[
            "Intellectual property and trade secret theft",
            "Exposure of sensitive business communications",
            "Credential and authentication token compromise",
            "Regulatory compliance violations (GDPR, HIPAA)",
            "Disclosure of incident response capabilities to attackers",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1567", "T1537", "T1048"],
        often_follows=["T1078.004", "T1110", "T1621", "T1528"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1114-aws-workmail",
            name="AWS WorkMail Access Monitoring",
            description="Detect unusual email access patterns in AWS WorkMail including bulk downloads and mailbox exports.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters.organizationId, requestParameters.entityId
| filter eventSource = "workmail.amazonaws.com"
| filter eventName in ["GetMailboxDetails", "ExportMailbox", "GetRawMessageContent", "SearchMailboxes"]
| stats count(*) as access_count by userIdentity.arn, sourceIPAddress, bin(1h) as hour_window
| filter access_count >= 50
| sort access_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious WorkMail email collection attempts

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: WorkMail Email Collection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for email access
  EmailAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "workmail.amazonaws.com" && ($.eventName = "GetRawMessageContent" || $.eventName = "ExportMailbox") }'
      MetricTransformations:
        - MetricName: WorkMailEmailAccess
          MetricNamespace: Security/EmailCollection
          MetricValue: "1"

  # Step 3: Create alarm for bulk email collection
  BulkEmailAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1114-WorkMail-BulkAccess
      AlarmDescription: High volume of WorkMail email access detected
      MetricName: WorkMailEmailAccess
      Namespace: Security/EmailCollection
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect WorkMail email collection attempts

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "workmail_alerts" {
  name         = "workmail-email-collection-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "WorkMail Email Collection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.workmail_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for email access
resource "aws_cloudwatch_log_metric_filter" "email_access" {
  name           = "workmail-email-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"workmail.amazonaws.com\" && ($.eventName = \"GetRawMessageContent\" || $.eventName = \"ExportMailbox\") }"

  metric_transformation {
    name      = "WorkMailEmailAccess"
    namespace = "Security/EmailCollection"
    value     = "1"
  }
}

# Step 3: Create alarm for bulk email collection
resource "aws_cloudwatch_metric_alarm" "bulk_email_access" {
  alarm_name          = "T1114-WorkMail-BulkAccess"
  alarm_description   = "High volume of WorkMail email access detected"
  metric_name         = "WorkMailEmailAccess"
  namespace           = "Security/EmailCollection"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.workmail_alerts.arn]
}

# Step 4: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.workmail_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.workmail_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="AWS WorkMail Bulk Email Access Detected",
                alert_description_template="User {userIdentity.arn} accessed {access_count} emails from IP {sourceIPAddress}. This may indicate email collection activity.",
                investigation_steps=[
                    "Identify which mailboxes were accessed",
                    "Verify the user's business need for bulk email access",
                    "Check source IP geolocation and reputation",
                    "Review email content accessed for sensitivity",
                    "Check for concurrent suspicious activities from this user",
                ],
                containment_actions=[
                    "Suspend the compromised user account",
                    "Reset user credentials and revoke active sessions",
                    "Block source IP if external and malicious",
                    "Review and restrict WorkMail API access",
                    "Enable MFA if not already enforced",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised backup and archival operations; adjust threshold based on organisation size",
            detection_coverage="75% - catches API-based email collection",
            evasion_considerations="Slow collection over extended periods; use of legitimate backup tools",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudTrail enabled for WorkMail events",
                "CloudTrail logs in CloudWatch",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1114-aws-ses",
            name="AWS SES Email Export Detection",
            description="Monitor AWS SES for unusual email retrieval and export activities.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters.messageId
| filter eventSource = "ses.amazonaws.com"
| filter eventName in ["GetMessage", "GetRawMessageContent", "ListMessages"]
| stats count(*) as message_count by userIdentity.arn, sourceIPAddress, bin(1h) as hour_window
| filter message_count >= 100
| sort message_count desc""",
                terraform_template="""# AWS: Detect SES email collection

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "ses_alerts" {
  name = "ses-email-collection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ses_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for SES message retrieval
resource "aws_cloudwatch_log_metric_filter" "ses_message_access" {
  name           = "ses-message-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ses.amazonaws.com\" && $.eventName = \"GetRawMessageContent\" }"

  metric_transformation {
    name      = "SESMessageAccess"
    namespace = "Security/EmailCollection"
    value     = "1"
  }
}

# Step 3: Alarm for bulk message retrieval
resource "aws_cloudwatch_metric_alarm" "ses_bulk_access" {
  alarm_name          = "T1114-SES-BulkAccess"
  alarm_description   = "High volume of SES message retrieval detected"
  metric_name         = "SESMessageAccess"
  namespace           = "Security/EmailCollection"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ses_alerts.arn]
}

# Step 4: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.ses_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ses_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="AWS SES Bulk Message Retrieval",
                alert_description_template="User {userIdentity.arn} retrieved {message_count} messages via SES from {sourceIPAddress}.",
                investigation_steps=[
                    "Verify the user's role requires SES message access",
                    "Check which messages were retrieved",
                    "Review source IP for legitimacy",
                    "Determine if this is automated processing or manual access",
                    "Check for data exfiltration indicators",
                ],
                containment_actions=[
                    "Revoke SES access from compromised credentials",
                    "Review SES access policies",
                    "Enable additional logging if not present",
                    "Implement rate limiting on SES API access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate email processing services and automation roles",
            detection_coverage="70% - catches API-based retrieval",
            evasion_considerations="Legitimate-appearing automation; slow retrieval rates",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled for SES API events"],
        ),
        DetectionStrategy(
            strategy_id="t1114-gcp-gmail",
            name="Google Workspace Gmail API Access",
            description="Detect bulk Gmail message access via Gmail API which may indicate email collection.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="gmail.googleapis.com"
AND protoPayload.methodName=~"gmail.users.messages.(get|list)"
AND severity!="INFO"''',
                gcp_terraform_template="""# GCP: Detect Gmail API bulk email access

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  display_name = "Email Collection Alerts"
  type         = "email"
  project      = var.project_id
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for Gmail API access
resource "google_logging_metric" "gmail_bulk_access" {
  name   = "gmail-bulk-message-access"
  project = var.project_id
  filter = <<-EOT
    protoPayload.serviceName="gmail.googleapis.com"
    AND protoPayload.methodName=~"gmail.users.messages.(get|list)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert for bulk access
resource "google_monitoring_alert_policy" "gmail_bulk_access" {
  project      = var.project_id
  display_name = "T1114-Gmail-BulkAccess"
  combiner     = "OR"

  conditions {
    display_name = "High volume Gmail API access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gmail_bulk_access.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_SUM"
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
}""",
                alert_severity="high",
                alert_title="GCP: Gmail Bulk Message Access",
                alert_description_template="High volume of Gmail API message access detected. This may indicate email collection activity.",
                investigation_steps=[
                    "Identify the service account or user accessing Gmail API",
                    "Review OAuth scopes granted to the application",
                    "Check which mailboxes were accessed",
                    "Verify the application is authorised",
                    "Review message access patterns and volume",
                ],
                containment_actions=[
                    "Revoke OAuth token for suspicious application",
                    "Disable compromised service account",
                    "Review and restrict Gmail API access organisation-wide",
                    "Enable advanced Gmail security features",
                    "Implement Gmail API rate limiting",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised email management and backup applications",
            detection_coverage="80% - catches API-based collection",
            evasion_considerations="Use of legitimate-appearing applications; gradual collection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=[
                "Google Workspace with Gmail API enabled",
                "Cloud Logging configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1114-gcp-export",
            name="Google Workspace Mailbox Export Detection",
            description="Monitor for mailbox exports and data takeout requests which can indicate email collection.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="admin.googleapis.com"
AND protoPayload.methodName=~"(EXPORT_MAILBOX|TAKEOUT_INITIATED|DOWNLOAD_USER_DATA)"''',
                gcp_terraform_template="""# GCP: Detect Workspace mailbox exports

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  display_name = "Mailbox Export Alerts"
  type         = "email"
  project      = var.project_id
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log metric for mailbox exports
resource "google_logging_metric" "mailbox_export" {
  name    = "workspace-mailbox-export"
  project = var.project_id
  filter  = <<-EOT
    protoPayload.serviceName="admin.googleapis.com"
    AND protoPayload.methodName=~"EXPORT_MAILBOX|TAKEOUT"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert on any export activity
resource "google_monitoring_alert_policy" "mailbox_export" {
  project      = var.project_id
  display_name = "T1114-Mailbox-Export"
  combiner     = "OR"

  conditions {
    display_name = "Mailbox export detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.mailbox_export.name}\""
      duration        = "0s"
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
                alert_title="GCP: Workspace Mailbox Export",
                alert_description_template="A mailbox export or data takeout was initiated in Google Workspace.",
                investigation_steps=[
                    "Identify who initiated the export request",
                    "Verify the business justification for the export",
                    "Check which mailbox(es) were exported",
                    "Review the user's recent activity for anomalies",
                    "Determine where the exported data was sent",
                ],
                containment_actions=[
                    "Cancel unauthorised export requests",
                    "Reset credentials for affected accounts",
                    "Review and restrict data export permissions",
                    "Enable additional approval workflows for exports",
                    "Investigate for data exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exports are relatively rare; validate with IT team processes",
            detection_coverage="90% - catches all export requests",
            evasion_considerations="Legitimate administrative exports; gradual API-based collection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Google Workspace admin audit logs enabled"],
        ),
        # Azure Strategy: Email Collection
        DetectionStrategy(
            strategy_id="t1114-azure",
            name="Azure Email Collection Detection",
            description=(
                "Azure detection for Email Collection. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Email Collection Detection
// Technique: T1114
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
                azure_terraform_template="""# Azure Detection for Email Collection
# MITRE ATT&CK: T1114

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
  name                = "email-collection-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "email-collection-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Email Collection Detection
// Technique: T1114
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

  description = "Detects Email Collection (T1114) activity in Azure environment"
  display_name = "Email Collection Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1114"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Email Collection Detected",
                alert_description_template=(
                    "Email Collection activity detected. "
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
        "t1114-aws-workmail",
        "t1114-gcp-gmail",
        "t1114-gcp-export",
        "t1114-aws-ses",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+20% improvement for Collection tactic",
)
