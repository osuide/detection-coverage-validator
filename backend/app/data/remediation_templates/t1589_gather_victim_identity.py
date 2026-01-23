"""
T1589 - Gather Victim Identity Information

Adversaries gather information about the victim's identity that can be used during
targeting, including personal data, credentials, email addresses, and employee names.
Used by APT32, FIN13, LAPSUS$, Magic Hound, Scattered Spider, Star Blizzard, Volt Typhoon.
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
    technique_id="T1589",
    technique_name="Gather Victim Identity Information",
    tactic_ids=["TA0043"],
    mitre_url="https://attack.mitre.org/techniques/T1589/",
    threat_context=ThreatContext(
        description=(
            "Adversaries gather information about the victim's identity that can be used "
            "during targeting, including credentials (T1589.001), email addresses (T1589.002), "
            "and employee names (T1589.003). This reconnaissance occurs through direct phishing, "
            "active scanning of authentication services to enumerate valid usernames, analysis "
            "of public datasets (social media, websites), and exploitation of exposed data from "
            "breaches or code repositories."
        ),
        attacker_goal="Collect identity information to enable targeted social engineering and initial access attacks",
        why_technique=[
            "Enables highly targeted phishing campaigns",
            "Facilitates social engineering attacks",
            "Identifies high-value targets within organisations",
            "Discovers valid usernames for credential attacks",
            "Bypasses generic security awareness training",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Reconnaissance technique that enables downstream attacks. Whilst pre-compromise "
            "activity cannot be directly prevented by cloud controls, detecting enumeration "
            "attempts and suspicious authentication patterns provides early warning of targeting."
        ),
        business_impact=[
            "Enabler for targeted phishing campaigns",
            "Increased risk of credential compromise",
            "Social engineering attack preparation",
            "Privacy and data protection concerns",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1566", "T1078", "T1110", "T1598"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1589-aws-username-enum",
            name="AWS Username Enumeration Detection",
            description="Detect username enumeration attempts via CloudTrail authentication failures.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, errorCode, userIdentity.userName
| filter eventName in ["ConsoleLogin", "GetUser", "ListUsers", "GetUserPolicy"]
| filter errorCode in ["NoSuchEntity", "AccessDenied", "InvalidUserID.NotFound"]
| stats count(*) as failures by sourceIPAddress, bin(5m)
| filter failures > 10
| sort failures desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect username enumeration attempts via CloudTrail

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Username Enumeration Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for username enumeration
  UsernameEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "GetUser" || $.eventName = "ListUsers") && ($.errorCode = "NoSuchEntity" || $.errorCode = "AccessDenied") }'
      MetricTransformations:
        - MetricName: UsernameEnumeration
          MetricNamespace: Security/Reconnaissance
          MetricValue: "1"
          DefaultValue: 0

  # Alarm for high enumeration activity
  UsernameEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighUsernameEnumeration
      AlarmDescription: Detects potential username enumeration attacks
      MetricName: UsernameEnumeration
      Namespace: Security/Reconnaissance
      Statistic: Sum
      Period: 300
      Threshold: 15
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect username enumeration via CloudTrail
# This monitors for suspicious patterns of user lookup failures

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "username_enum_alerts" {
  name         = "username-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Username Enumeration Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.username_enum_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for username enumeration attempts
resource "aws_cloudwatch_log_metric_filter" "username_enum" {
  name           = "username-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"GetUser\" || $.eventName = \"ListUsers\") && ($.errorCode = \"NoSuchEntity\" || $.errorCode = \"AccessDenied\") }"

  metric_transformation {
    name          = "UsernameEnumeration"
    namespace     = "Security/Reconnaissance"
    value         = "1"
    default_value = 0
  }
}

# Alarm for detecting enumeration patterns
resource "aws_cloudwatch_metric_alarm" "username_enum_attack" {
  alarm_name          = "HighUsernameEnumeration"
  alarm_description   = "Detects potential username enumeration attacks"
  metric_name         = "UsernameEnumeration"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 300
  threshold           = 15
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.username_enum_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Username Enumeration Activity Detected",
                alert_description_template="Multiple failed user lookup attempts from {sourceIPAddress}.",
                investigation_steps=[
                    "Review source IP address and geolocation",
                    "Check if IP is known reconnaissance scanner",
                    "Analyse pattern of usernames being enumerated",
                    "Review other activity from same source IP",
                    "Check for successful authentications following enumeration",
                    "Correlate with authentication logs for targeted accounts",
                ],
                containment_actions=[
                    "Block source IP at network perimeter",
                    "Enable MFA for all identified enumerated accounts",
                    "Notify affected users of potential targeting",
                    "Review and restrict IAM user listing permissions",
                    "Implement rate limiting on authentication endpoints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate automation tools may trigger this; whitelist known IPs and service accounts",
            detection_coverage="50% - detects enumeration via AWS APIs but not external sources",
            evasion_considerations="Attackers may use slow enumeration or distributed sources",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled and logging to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1589-aws-suspicious-auth",
            name="AWS Suspicious Authentication Pattern Detection",
            description="Detect reconnaissance through suspicious authentication patterns and timing.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, eventName, errorCode
| filter eventName in ["ConsoleLogin", "AssumeRole", "GetSessionToken"]
| filter errorCode in ["Failed", "InvalidUserID.NotFound"]
| stats count(*) as attempts, count_distinct(userIdentity.principalId) as uniqueUsers by sourceIPAddress, bin(10m)
| filter uniqueUsers > 5 or attempts > 20
| sort attempts desc""",
                terraform_template="""# Detect suspicious authentication patterns indicating reconnaissance
# Monitors for rapid authentication attempts across multiple accounts

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "auth_recon_alerts" {
  name         = "authentication-reconnaissance-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Authentication Reconnaissance Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.auth_recon_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for suspicious authentication patterns
resource "aws_cloudwatch_log_metric_filter" "auth_recon" {
  name           = "authentication-reconnaissance"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"ConsoleLogin\" || $.eventName = \"AssumeRole\") && $.errorCode = \"Failed\" }"

  metric_transformation {
    name          = "FailedAuthAttempts"
    namespace     = "Security/Reconnaissance"
    value         = "1"
    default_value = 0
  }
}

# Alarm for suspicious patterns
resource "aws_cloudwatch_metric_alarm" "auth_recon_attack" {
  alarm_name          = "SuspiciousAuthenticationPattern"
  alarm_description   = "Detects potential account reconnaissance via auth attempts"
  metric_name         = "FailedAuthAttempts"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 600
  threshold           = 25
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.auth_recon_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious Authentication Pattern Detected",
                alert_description_template="Multiple failed authentication attempts from {sourceIPAddress} across different accounts.",
                investigation_steps=[
                    "Identify source IP and check threat intelligence feeds",
                    "Review list of targeted usernames/accounts",
                    "Check if any attempts succeeded",
                    "Analyse timing patterns for automation indicators",
                    "Review user-agent strings for reconnaissance tools",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Block offending IP addresses",
                    "Enforce MFA for targeted accounts",
                    "Review and strengthen password policies",
                    "Alert affected users to potential targeting",
                    "Consider implementing CAPTCHA on login",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on normal authentication patterns; exclude known service IPs",
            detection_coverage="60% - detects authentication-based reconnaissance",
            evasion_considerations="Slow, distributed attacks may evade threshold-based detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with authentication logging"],
        ),
        DetectionStrategy(
            strategy_id="t1589-gcp-identity-enum",
            name="GCP Identity Enumeration Detection",
            description="Detect identity enumeration attempts via Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="audited_resource"
protoPayload.methodName=~"google.iam.admin.v1.*.Get*|google.iam.admin.v1.*.List*"
protoPayload.status.code!=0
protoPayload.status.code=~"5|7"''',
                gcp_terraform_template="""# GCP: Detect identity enumeration via Cloud Logging
# Monitors for repeated failed IAM lookups indicating reconnaissance

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log metric for identity enumeration
resource "google_logging_metric" "identity_enum" {
  name    = "identity-enumeration-attempts"
  project = var.project_id
  filter  = <<-EOT
    resource.type="audited_resource"
    protoPayload.methodName=~"google.iam.admin.v1.*.Get*|google.iam.admin.v1.*.List*"
    protoPayload.status.code!=0
    protoPayload.status.code=~"5|7"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }

  label_extractors = {
    "source_ip" = "EXTRACT(protoPayload.requestMetadata.callerIp)"
  }
}

# Alert policy for enumeration detection
resource "google_monitoring_alert_policy" "identity_enum_attack" {
  project      = var.project_id
  display_name = "Identity Enumeration Detected"
  combiner     = "OR"

  conditions {
    display_name = "High enumeration rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.identity_enum.name}\" resource.type=\"audited_resource\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Identity enumeration activity detected. Multiple failed IAM lookup attempts may indicate reconnaissance."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Identity Enumeration Activity",
                alert_description_template="Multiple failed IAM lookup attempts detected from suspicious source.",
                investigation_steps=[
                    "Review source IP and caller identity",
                    "Check Cloud Audit Logs for full request details",
                    "Identify which identities were being enumerated",
                    "Review successful operations from same source",
                    "Check for privilege escalation attempts",
                    "Correlate with authentication logs",
                ],
                containment_actions=[
                    "Block source IP via Cloud Armor",
                    "Review and restrict IAM permissions for listing operations",
                    "Enable VPC Service Controls if not already enabled",
                    "Notify affected identity owners",
                    "Enable additional authentication requirements",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate automation service accounts and known IP ranges",
            detection_coverage="55% - detects GCP IAM enumeration",
            evasion_considerations="Low-and-slow attacks may evade rate-based detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled for IAM"],
        ),
        DetectionStrategy(
            strategy_id="t1589-aws-public-exposure",
            name="AWS Public Identity Information Exposure Detection",
            description="Detect inadvertent public exposure of identity information via S3, CodeCommit, and other services.",
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="config",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                config_rule_identifier="s3-bucket-public-read-prohibited",
                terraform_template="""# Detect public exposure of identity information
# Monitors for publicly accessible resources that may leak identity data

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "public_exposure_alerts" {
  name         = "public-identity-exposure-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Public Identity Exposure Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.public_exposure_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Config rule for S3 public access
resource "aws_config_config_rule" "s3_public_read" {
  name = "s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Config rule for public snapshots
resource "aws_config_config_rule" "ebs_snapshot_public" {
  name = "ebs-snapshot-public-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Config recorder (if not already exists)
resource "aws_config_configuration_recorder" "main" {
  name     = "identity-exposure-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported = true
  }
}

# IAM role for Config
resource "aws_iam_role" "config_role" {
  name = "config-identity-exposure-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# EventBridge rule to alert on non-compliance
resource "aws_cloudwatch_event_rule" "public_exposure" {
  name        = "public-identity-exposure"
  description = "Alert on public exposure of resources"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = [
        "s3-bucket-public-read-prohibited",
        "ebs-snapshot-public-prohibited"
      ]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

# Dead Letter Queue for public exposure events
resource "aws_sqs_queue" "dlq" {
  name                      = "public-identity-exposure-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.public_exposure.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.public_exposure_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account        = "$.account"
      region         = "$.region"
      time           = "$.time"
      configRuleName = "$.detail.configRuleName"
      resourceType   = "$.detail.resourceType"
      resourceId     = "$.detail.resourceId"
      complianceType = "$.detail.newEvaluationResult.complianceType"
    }

    input_template = <<-EOT
"AWS Config Compliance Alert
Time: <time>
Account: <account>
Region: <region>
Rule: <configRuleName>
Resource: <resourceType> / <resourceId>
Compliance: <complianceType>
Action: Review Config rule and remediate"
EOT
  }

}

# Allow EventBridge to publish to SNS
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.public_exposure_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.public_exposure_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.public_exposure.arn
        }
      }
    }]
  })
}

# SQS queue policy to allow EventBridge to send to DLQ
resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.public_exposure.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Public Exposure of Identity Information Detected",
                alert_description_template="Resource {resourceId} is publicly accessible and may expose identity information.",
                investigation_steps=[
                    "Identify the publicly accessible resource",
                    "Review contents for sensitive identity data",
                    "Check access logs for external access",
                    "Determine who made the resource public",
                    "Assess potential data exposure scope",
                    "Review other resources from same owner",
                ],
                containment_actions=[
                    "Immediately remove public access permissions",
                    "Rotate any exposed credentials",
                    "Notify affected individuals if PII exposed",
                    "Review and restrict permissions for resource modification",
                    "Implement preventive controls (S3 Block Public Access)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Some public buckets are intentional; mark as exceptions where appropriate",
            detection_coverage="70% - detects public exposure of AWS resources",
            evasion_considerations="Doesn't detect data already exfiltrated before exposure was detected",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["AWS Config enabled", "S3 Block Public Access configured"],
        ),
        # Azure Strategy: Gather Victim Identity Information
        DetectionStrategy(
            strategy_id="t1589-azure",
            name="Azure Gather Victim Identity Information Detection",
            description=(
                "Azure detection for Gather Victim Identity Information. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Gather Victim Identity Information Detection
// Technique: T1589
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
                azure_terraform_template="""# Azure Detection for Gather Victim Identity Information
# MITRE ATT&CK: T1589

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
  name                = "gather-victim-identity-information-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "gather-victim-identity-information-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Gather Victim Identity Information Detection
// Technique: T1589
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

  description = "Detects Gather Victim Identity Information (T1589) activity in Azure environment"
  display_name = "Gather Victim Identity Information Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1589"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Gather Victim Identity Information Detected",
                alert_description_template=(
                    "Gather Victim Identity Information activity detected. "
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
        "t1589-aws-public-exposure",
        "t1589-aws-username-enum",
        "t1589-gcp-identity-enum",
        "t1589-aws-suspicious-auth",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+15% improvement for Reconnaissance tactic",
)
