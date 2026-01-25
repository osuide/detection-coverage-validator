"""
T1586 - Compromise Accounts

Adversaries compromise existing accounts rather than creating new ones to leverage
established trust. Includes social media, email, and cloud accounts.
Resource Development tactic - occurs during pre-compromise phase.
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
    technique_id="T1586",
    technique_name="Compromise Accounts",
    tactic_ids=["TA0042"],
    mitre_url="https://attack.mitre.org/techniques/T1586/",
    threat_context=ThreatContext(
        description=(
            "Adversaries compromise existing accounts on social media, email, or cloud "
            "platforms to support operations. Methods include phishing, purchasing "
            "credentials from breach databases, brute-forcing, or insider access. "
            "Compromised accounts provide established trust for social engineering."
        ),
        attacker_goal="Compromise existing accounts to leverage established trust and facilitate subsequent attacks",
        why_technique=[
            "Established trust and credibility",
            "Bypass new account scrutiny",
            "Access to existing social networks",
            "Facilitate credential phishing",
            "Cloud account access for infrastructure",
            "Evade detection through legitimate appearance",
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Resource Development technique occurring before Initial Access. Compromised "
            "accounts enable social engineering, phishing campaigns, and cloud infrastructure "
            "abuse. Detection is challenging as activity occurs outside organisational control."
        ),
        business_impact=[
            "Credential phishing enabler",
            "Social engineering campaigns",
            "Cloud infrastructure abuse",
            "Reputational damage",
            "Supply chain attack vector",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1566.001", "T1566.002", "T1598", "T1078.004"],
        often_follows=["T1589", "T1594"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1586-aws-cloudtrail-anomalous",
            name="AWS CloudTrail Anomalous Account Activity",
            description="Detect compromised AWS accounts via anomalous authentication patterns and activity.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, eventName, userAgent
| filter eventName in ["ConsoleLogin", "AssumeRole", "GetSessionToken"]
| filter errorCode != "AccessDenied"
| stats count(*) as logins, count_distinct(sourceIPAddress) as ip_count,
        count_distinct(userAgent) as agent_count by userIdentity.principalId, bin(1h)
| filter ip_count > 3 or agent_count > 2
| sort logins desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect compromised AWS accounts via anomalous authentication

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS topic for security alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: compromised-account-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for multiple IPs
  MultipleIPFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "ConsoleLogin" || $.eventName = "AssumeRole") && $.errorCode != "AccessDenied" }'
      MetricTransformations:
        - MetricName: AccountLogins
          MetricNamespace: Security/AccountCompromise
          MetricValue: "1"
          DefaultValue: 0

  # Alarm for suspicious login patterns
  SuspiciousLoginAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CompromisedAccountDetection
      AlarmDescription: Multiple IPs or user agents for single account
      MetricName: AccountLogins
      Namespace: Security/AccountCompromise
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect compromised accounts via anomalous authentication

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# SNS topic for alerts
resource "aws_sns_topic" "compromised_account_alerts" {
  name = "compromised-account-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.compromised_account_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for authentication events
resource "aws_cloudwatch_log_metric_filter" "account_logins" {
  name           = "account-logins"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"ConsoleLogin\" || $.eventName = \"AssumeRole\") && $.errorCode != \"AccessDenied\" }"

  metric_transformation {
    name      = "AccountLogins"
    namespace = "Security/AccountCompromise"
    value     = "1"
    default_value = 0
  }
}

# Alarm for suspicious login patterns
resource "aws_cloudwatch_metric_alarm" "compromised_account" {
  alarm_name          = "CompromisedAccountDetection"
  alarm_description   = "Multiple IPs or user agents for single account"
  metric_name         = "AccountLogins"
  namespace           = "Security/AccountCompromise"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.compromised_account_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Potential Compromised AWS Account Detected",
                alert_description_template="Anomalous authentication patterns detected for {principalId} with multiple source IPs or user agents.",
                investigation_steps=[
                    "Review authentication timeline for the account",
                    "Check source IP addresses and geolocations",
                    "Verify user agent strings against known devices",
                    "Review recent API calls and resource changes",
                    "Check for MFA usage on suspicious logins",
                    "Contact account owner to verify activity",
                ],
                containment_actions=[
                    "Reset account credentials immediately",
                    "Revoke active sessions and tokens",
                    "Enable MFA if not already active",
                    "Review and revoke suspicious IAM permissions",
                    "Check for unauthorised resource creation",
                    "Enable CloudTrail across all regions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds for travelling users or VPN usage. Whitelist known automation patterns.",
            detection_coverage="50% - detects post-compromise cloud account usage",
            evasion_considerations="Attackers may mimic legitimate access patterns or use compromised infrastructure",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with logging to CloudWatch Logs"],
        ),
        DetectionStrategy(
            strategy_id="t1586-aws-guardduty",
            name="AWS GuardDuty Compromised Credentials",
            description="Leverage GuardDuty findings to detect compromised AWS credentials.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.type, detail.severity, detail.resource.accessKeyDetails.userName
| filter detail.type like /UnauthorizedAccess|PenTest|CredentialAccess/
| filter detail.severity >= 7
| sort @timestamp desc""",
                terraform_template="""# AWS: GuardDuty findings for compromised credentials

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Enable GuardDuty (if not already enabled)
resource "aws_guardduty_detector" "main" {
  enable = true

  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# SNS topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-compromised-credentials"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for high-severity credential findings
resource "aws_cloudwatch_event_rule" "compromised_credentials" {
  name        = "guardduty-compromised-credentials"
  description = "Detect compromised credential findings from GuardDuty"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
      type = [
        { prefix = "UnauthorizedAccess" },
        { prefix = "PenTest" },
        { prefix = "CredentialAccess" }
      ]
    }
  })
}

# Dead Letter Queue for GuardDuty findings
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-compromised-credentials-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.compromised_credentials.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
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

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.compromised_credentials.arn
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.compromised_credentials.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Compromised Credentials Detected",
                alert_description_template="GuardDuty detected compromised credential activity: {finding_type}",
                investigation_steps=[
                    "Review GuardDuty finding details and evidence",
                    "Identify affected IAM user or role",
                    "Check CloudTrail for unauthorised API calls",
                    "Review resource changes and data access",
                    "Determine compromise timeline and scope",
                    "Check for lateral movement indicators",
                ],
                containment_actions=[
                    "Rotate compromised credentials immediately",
                    "Revoke all active sessions",
                    "Attach deny-all policy to affected principal",
                    "Review and remove unauthorised resources",
                    "Enable MFA for all accounts",
                    "Implement IP-based access restrictions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are pre-tuned; review severity 7+ findings carefully",
            detection_coverage="70% - comprehensive credential compromise detection",
            evasion_considerations="May miss subtle compromises that appear as normal activity",
            implementation_effort=EffortLevel.LOW,
            implementation_time="15-30 minutes",
            estimated_monthly_cost="$30-100+ depending on CloudTrail volume",
            prerequisites=["GuardDuty enabled", "EventBridge configured"],
        ),
        DetectionStrategy(
            strategy_id="t1586-gcp-login-anomaly",
            name="GCP Anomalous Login Detection",
            description="Detect compromised GCP accounts via unusual authentication patterns.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="login.googleapis.com"
protoPayload.methodName="google.login.LoginService.loginSuccess"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect compromised accounts via anomalous authentication

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "security_email" {
  display_name = "Security Team Email"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for successful logins
resource "google_logging_metric" "successful_logins" {
  name    = "successful-account-logins"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="login.googleapis.com"
    protoPayload.methodName="google.login.LoginService.loginSuccess"
    severity="NOTICE"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "user_email"
      value_type  = "STRING"
      description = "User email address"
    }
  }

  label_extractors = {
    "user_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Alert policy for unusual login frequency
resource "google_monitoring_alert_policy" "anomalous_logins" {
  project      = var.project_id
  display_name = "Anomalous Account Login Activity"
  combiner     = "OR"

  conditions {
    display_name = "High login frequency"

    condition_threshold {
      filter          = "resource.type=\"global\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.successful_logins.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_email.id]

  alert_strategy {
    notification_rate_limit {
      period = "3600s"
    }
  }
}

# Log-based metric for failed logins
resource "google_logging_metric" "failed_logins" {
  name    = "failed-account-logins"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="login.googleapis.com"
    protoPayload.methodName="google.login.LoginService.loginFailure"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Alert for credential stuffing attacks
resource "google_monitoring_alert_policy" "credential_stuffing" {
  project      = var.project_id
  display_name = "Potential Credential Stuffing Attack"
  combiner     = "OR"

  conditions {
    display_name = "High failed login rate"

    condition_threshold {
      filter          = "resource.type=\"global\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.failed_logins.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Anomalous Account Activity Detected",
                alert_description_template="Unusual authentication patterns detected for GCP account.",
                investigation_steps=[
                    "Review login audit logs for affected account",
                    "Check source IP addresses and geolocations",
                    "Verify device and browser fingerprints",
                    "Review API activity after suspicious logins",
                    "Check for new service account key creation",
                    "Verify workspace admin activity",
                ],
                containment_actions=[
                    "Reset account password immediately",
                    "Revoke active sessions and tokens",
                    "Enforce 2-Step Verification",
                    "Review and revoke suspicious OAuth grants",
                    "Check for unauthorised GCP resources",
                    "Enable advanced security features in Workspace",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds for organisations with mobile workforce. Consider implementing context-aware access policies.",
            detection_coverage="50% - detects post-compromise cloud account usage",
            evasion_considerations="Attackers may use compromised devices or mimic legitimate patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Login audit logging configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1586-aws-iam-access-analyzer",
            name="AWS IAM Access Analyzer External Access",
            description="Detect external access to AWS resources that may indicate compromised accounts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="access_analyzer",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.resourceType, detail.principal.AWS, detail.findingType
| filter detail.findingType = "ExternalAccess"
| filter detail.isPublic = false
| sort @timestamp desc""",
                terraform_template="""# AWS: IAM Access Analyzer for external access detection

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Enable IAM Access Analyzer
resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "account-analyzer"
  type          = "ACCOUNT"

  tags = {
    Purpose = "CompromisedAccountDetection"
  }
}

# SNS topic for Access Analyzer alerts
resource "aws_sns_topic" "access_analyzer_alerts" {
  name = "access-analyzer-external-access"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.access_analyzer_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for external access findings
resource "aws_cloudwatch_event_rule" "external_access" {
  name        = "access-analyzer-external-access"
  description = "Detect external access to AWS resources"

  event_pattern = jsonencode({
    source      = ["aws.access-analyzer"]
    detail-type = ["Access Analyzer Finding"]
    detail = {
      status      = ["ACTIVE"]
      findingType = ["ExternalAccess"]
      isPublic    = [false]
    }
  })
}

# Dead Letter Queue for Access Analyzer findings
resource "aws_sqs_queue" "analyzer_dlq" {
  name                      = "access-analyzer-external-access-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.external_access.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.access_analyzer_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.analyzer_dlq.arn
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

resource "aws_sns_topic_policy" "eventbridge_publish" {
  arn = aws_sns_topic.access_analyzer_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.access_analyzer_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.external_access.arn
        }
      }
    }]
  })
}

# SQS queue policy for Access Analyzer DLQ
resource "aws_sqs_queue_policy" "analyzer_dlq_policy" {
  queue_url = aws_sqs_queue.analyzer_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.analyzer_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.external_access.arn
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="External Access to AWS Resource Detected",
                alert_description_template="IAM Access Analyzer detected external access to {resourceType}.",
                investigation_steps=[
                    "Review Access Analyzer finding details",
                    "Identify the external principal with access",
                    "Check resource policy and sharing configuration",
                    "Review CloudTrail for resource modification events",
                    "Verify if external access is authorised",
                    "Check for other resources with similar access",
                ],
                containment_actions=[
                    "Remove unauthorised external access",
                    "Update resource policies to restrict access",
                    "Review and rotate potentially compromised credentials",
                    "Enable SCPs to prevent cross-account sharing",
                    "Implement resource sharing approval workflows",
                    "Archive Access Analyzer findings once resolved",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Review legitimate cross-account access patterns and archive expected findings",
            detection_coverage="60% - detects unauthorised resource sharing",
            evasion_considerations="Only detects resource-level access, not credential compromise directly",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["IAM Access Analyzer enabled"],
        ),
        # Azure Strategy: Compromise Accounts
        DetectionStrategy(
            strategy_id="t1586-azure",
            name="Azure Compromise Accounts Detection",
            description=(
                "Azure detection for Compromise Accounts. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "Leaked credentials",
                    "Suspected Brute Force attack (Kerberos, NTLM)",
                    "Unfamiliar sign-in properties",
                ],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Compromise Accounts (T1586)
# Microsoft Defender detects Compromise Accounts activity

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
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1586-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1586"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (

                    "Leaked credentials",
                    "Suspected Brute Force attack (Kerberos, NTLM)",
                    "Unfamiliar sign-in properties"
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Compromise Accounts activity"
  display_name = "Defender: Compromise Accounts"
  enabled      = true

  tags = {
    "mitre-technique" = "T1586"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Compromise Accounts Detected",
                alert_description_template=(
                    "Compromise Accounts activity detected. "
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
        "t1586-aws-guardduty",
        "t1586-aws-cloudtrail-anomalous",
        "t1586-gcp-login-anomaly",
        "t1586-aws-iam-access-analyzer",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+15% improvement for Resource Development tactic detection",
)
