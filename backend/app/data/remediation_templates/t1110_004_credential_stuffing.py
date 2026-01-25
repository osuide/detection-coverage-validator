"""
T1110.004 - Brute Force: Credential Stuffing

Adversaries use credentials obtained from breach dumps of unrelated accounts to
gain access to target accounts through credential overlap.
Used by Chimera, TrickBot.
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
    technique_id="T1110.004",
    technique_name="Brute Force: Credential Stuffing",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1110/004/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use credentials obtained from breach dumps of unrelated accounts "
            "to gain access through credential overlap. This technique exploits password reuse "
            "patterns across services including SSH, RDP, cloud services, and web applications. "
            "Attackers systematically test compromised username-password pairs against target systems."
        ),
        attacker_goal="Gain access to accounts by exploiting password reuse with breached credentials",
        why_technique=[
            "Exploits widespread password reuse",
            "Breached credential databases readily available",
            "Bypasses weak password policies",
            "Difficult to distinguish from legitimate logins",
            "Effective against cloud and SaaS platforms",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Credential stuffing exploits legitimate credentials, making detection challenging. "
            "Successful attacks grant initial access to accounts, enabling lateral movement and "
            "data exfiltration across cloud and on-premises environments."
        ),
        business_impact=[
            "Account compromise",
            "Unauthorised data access",
            "Compliance violations",
            "Lateral movement enabler",
            "Cloud service compromise",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1078.002", "T1110.003"],
        often_follows=["T1589.001", "T1589.002"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1110-004-aws-cloudtrail",
            name="AWS CloudTrail Failed Authentication Detection",
            description="Detect credential stuffing via failed AWS console and API authentication attempts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, errorCode, userIdentity.userName
| filter errorCode = "Failed authentication"
| stats count(*) as failed_attempts by sourceIPAddress, bin(5m)
| filter failed_attempts > 10
| sort failed_attempts desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect credential stuffing via CloudTrail failed authentications

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Credential Stuffing Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter to count failed authentications
  FailedAuthFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.errorCode = "Failed authentication" }'
      MetricTransformations:
        - MetricName: FailedAuthentications
          MetricNamespace: Security/CredentialStuffing
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alarm for high failed authentication rate
  CredentialStuffingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CredentialStuffingDetection
      AlarmDescription: Detects potential credential stuffing attacks
      MetricName: FailedAuthentications
      Namespace: Security/CredentialStuffing
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

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
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# AWS: Detect credential stuffing via CloudTrail failed authentications

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

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "credential_stuffing_alerts" {
  name         = "credential-stuffing-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Credential Stuffing Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.credential_stuffing_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter to count failed authentications
resource "aws_cloudwatch_log_metric_filter" "failed_auth" {
  name           = "failed-authentications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.errorCode = \"Failed authentication\" }"

  metric_transformation {
    name          = "FailedAuthentications"
    namespace     = "Security/CredentialStuffing"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Alarm for high failed authentication rate
resource "aws_cloudwatch_metric_alarm" "credential_stuffing" {
  alarm_name          = "CredentialStuffingDetection"
  alarm_description   = "Detects potential credential stuffing attacks"
  metric_name         = "FailedAuthentications"
  namespace           = "Security/CredentialStuffing"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.credential_stuffing_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.credential_stuffing_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.credential_stuffing_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Credential Stuffing Attack Detected",
                alert_description_template="High volume of failed authentication attempts from {sourceIPAddress}.",
                investigation_steps=[
                    "Review CloudTrail logs for failed authentication patterns",
                    "Identify targeted usernames and source IP addresses",
                    "Check for successful authentications from same IPs",
                    "Review IAM user activity for compromised accounts",
                    "Correlate with AWS GuardDuty findings",
                ],
                containment_actions=[
                    "Block malicious source IPs via WAF/Security Groups",
                    "Reset passwords for targeted accounts",
                    "Enable MFA for affected users",
                    "Review and revoke suspicious sessions",
                    "Implement IP-based conditional access policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds for legitimate failed logins; whitelist known IP ranges",
            detection_coverage="65% - detects failed attempts but not successful credential stuffing",
            evasion_considerations="Attackers may slow attack rate or use distributed IPs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1110-004-aws-cognito",
            name="AWS Cognito Brute Force Detection",
            description="Detect credential stuffing against AWS Cognito user pools.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, sourceIPAddress, userIdentity.userName, eventName
| filter eventName = "UserAuthentication" AND errorCode = "NotAuthorizedException"
| stats count(*) as failed_logins by sourceIPAddress, bin(5m)
| filter failed_logins > 15
| sort failed_logins desc""",
                terraform_template="""# AWS: Detect credential stuffing against Cognito user pools

variable "cognito_log_group" {
  type        = string
  description = "Cognito CloudWatch log group name"
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

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "cognito_alerts" {
  name         = "cognito-credential-stuffing-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Cognito Credential Stuffing Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cognito_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for failed Cognito authentications
resource "aws_cloudwatch_log_metric_filter" "cognito_failed_auth" {
  name           = "cognito-failed-authentications"
  log_group_name = var.cognito_log_group
  pattern        = "{ $.eventName = \"UserAuthentication\" && $.errorCode = \"NotAuthorizedException\" }"

  metric_transformation {
    name          = "CognitoFailedAuth"
    namespace     = "Security/Cognito"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Alarm for credential stuffing patterns
resource "aws_cloudwatch_metric_alarm" "cognito_stuffing" {
  alarm_name          = "CognitoCredentialStuffing"
  alarm_description   = "Detects credential stuffing against Cognito"
  metric_name         = "CognitoFailedAuth"
  namespace           = "Security/Cognito"
  statistic           = "Sum"
  period              = 300
  threshold           = 30
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.cognito_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.cognito_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.cognito_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Cognito Credential Stuffing Detected",
                alert_description_template="Multiple failed authentication attempts against Cognito user pool from {sourceIPAddress}.",
                investigation_steps=[
                    "Review Cognito CloudWatch logs for attack patterns",
                    "Identify targeted user accounts",
                    "Check for successful logins after failures",
                    "Review user pool advanced security metrics",
                    "Analyse geographic distribution of attempts",
                ],
                containment_actions=[
                    "Enable Cognito advanced security features",
                    "Configure adaptive authentication",
                    "Block malicious IPs via WAF",
                    "Force password reset for targeted accounts",
                    "Enable MFA requirement",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on application user base and legitimate failure patterns",
            detection_coverage="70% - effective for Cognito-backed applications",
            evasion_considerations="Distributed attacks from multiple IPs may evade rate-based detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["AWS Cognito with CloudWatch logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1110-004-gcp-login-failures",
            name="GCP Cloud Logging Authentication Failures",
            description="Detect credential stuffing via GCP authentication logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName="login"
protoPayload.status.message=~"authentication failed" """,
                gcp_terraform_template="""# GCP: Detect credential stuffing via authentication failures

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

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_alerts" {
  project      = var.project_id
  display_name = "Credential Stuffing Email Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for failed authentications
resource "google_logging_metric" "failed_auth" {
  project     = var.project_id
  name        = "credential-stuffing-failed-auth"
  description = "Counts failed authentication attempts"

  filter = <<-EOT
    protoPayload.methodName="login"
    protoPayload.status.message=~"authentication failed"
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

# Step 3: Alert policy for credential stuffing detection
resource "google_monitoring_alert_policy" "credential_stuffing" {
  project      = var.project_id
  display_name = "Credential Stuffing Detection"
  combiner     = "OR"

  conditions {
    display_name = "High failed authentication rate"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.failed_auth.name}\" resource.type=\"global\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Credential Stuffing Attack",
                alert_description_template="High volume of failed authentication attempts detected in GCP environment.",
                investigation_steps=[
                    "Review Cloud Logging for authentication failure patterns",
                    "Identify targeted accounts and source IPs",
                    "Check Cloud Identity logs for successful logins",
                    "Review Security Command Centre findings",
                    "Analyse geographic origin of attempts",
                ],
                containment_actions=[
                    "Block malicious IPs via Cloud Armor",
                    "Enable Cloud Identity 2-step verification",
                    "Configure context-aware access policies",
                    "Reset passwords for targeted accounts",
                    "Review and revoke suspicious sessions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on organisation size and authentication patterns",
            detection_coverage="65% - detects failed attempts but requires tuning",
            evasion_considerations="Slow-rate attacks or distributed IPs may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled with authentication logs"],
        ),
        DetectionStrategy(
            strategy_id="t1110-004-gcp-workspace",
            name="GCP Workspace Login Monitoring",
            description="Detect credential stuffing against Google Workspace accounts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="workspace_admin",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="workspace.googleapis.com/Workspace"
protoPayload.methodName="login"
protoPayload.authenticationInfo.authoritySelector="USER"
severity="ERROR"''',
                gcp_terraform_template="""# GCP: Detect credential stuffing against Workspace accounts

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

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "workspace_alerts" {
  project      = var.project_id
  display_name = "Workspace Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for Workspace failed logins
resource "google_logging_metric" "workspace_failed_login" {
  project     = var.project_id
  name        = "workspace-credential-stuffing"
  description = "Tracks failed Workspace login attempts"

  filter = <<-EOT
    resource.type="workspace.googleapis.com/Workspace"
    protoPayload.methodName="login"
    severity="ERROR"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert for high failure rate
resource "google_monitoring_alert_policy" "workspace_stuffing" {
  project      = var.project_id
  display_name = "Workspace Credential Stuffing"
  combiner     = "OR"

  conditions {
    display_name = "High Workspace login failures"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.workspace_failed_login.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 30

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.workspace_alerts.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP Workspace: Credential Stuffing",
                alert_description_template="Multiple failed login attempts detected against Workspace accounts.",
                investigation_steps=[
                    "Review Workspace Admin audit logs",
                    "Identify targeted user accounts",
                    "Check for successful logins post-failures",
                    "Review suspicious sign-in activity",
                    "Analyse IP addresses and geographic locations",
                ],
                containment_actions=[
                    "Enforce 2-step verification for all users",
                    "Configure security policies for risky logins",
                    "Reset passwords for targeted accounts",
                    "Review and revoke active sessions",
                    "Enable advanced protection programme",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Workspace audit logs provide reliable authentication data",
            detection_coverage="75% - comprehensive Workspace authentication coverage",
            evasion_considerations="Attackers may use valid credentials from breaches",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Google Workspace with Admin audit logging enabled"],
        ),
        # Azure Strategy: Brute Force: Credential Stuffing
        DetectionStrategy(
            strategy_id="t1110004-azure",
            name="Azure Brute Force: Credential Stuffing Detection",
            description=(
                "Azure detection for Brute Force: Credential Stuffing. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "Password spray",
                    "Suspected brute force attack using a valid user",
                    "Suspected successful brute force attack",
                    "Unfamiliar sign-in properties",
                    "Atypical travel",
                ],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Brute Force: Credential Stuffing (T1110.004)
# Microsoft Defender detects Brute Force: Credential Stuffing activity

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
  name                = "defender-t1110-004-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1110-004"
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

                    "Password spray",
                    "Suspected brute force attack using a valid user",
                    "Suspected successful brute force attack",
                    "Unfamiliar sign-in properties",
                    "Atypical travel"
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

  description = "Microsoft Defender detects Brute Force: Credential Stuffing activity"
  display_name = "Defender: Brute Force: Credential Stuffing"
  enabled      = true

  tags = {
    "mitre-technique" = "T1110.004"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Brute Force: Credential Stuffing Detected",
                alert_description_template=(
                    "Brute Force: Credential Stuffing activity detected. "
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
        "t1110-004-aws-cloudtrail",
        "t1110-004-gcp-workspace",
        "t1110-004-aws-cognito",
        "t1110-004-gcp-login-failures",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+25% improvement for Credential Access tactic",
)
