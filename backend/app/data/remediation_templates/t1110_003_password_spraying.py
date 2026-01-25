"""
T1110.003 - Brute Force: Password Spraying

Adversaries use one password or a small list of commonly used passwords against
many accounts to avoid triggering account lockout policies.
Used by APT28, APT29, APT33, HAFNIUM, Lazarus Group.
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
    technique_id="T1110.003",
    technique_name="Brute Force: Password Spraying",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1110/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use one password or a small list of commonly used passwords "
            "against many different accounts to avoid account lockouts. Targets include "
            "SSH, RDP, SMB, LDAP, Kerberos, cloud SSO, federated authentication, and "
            "external email applications like Office 365. Attacks are deliberately "
            "throttled to evade detection thresholds."
        ),
        attacker_goal="Gain valid credentials by trying common passwords across many accounts",
        why_technique=[
            "Bypasses account lockout policies",
            "Lower detection threshold than brute force",
            "Effective against weak password policies",
            "Can leverage cloud SSO and federated auth",
            "Automation tools widely available",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "High-impact credential access technique targeting cloud SSO and federated "
            "authentication. Successful attacks grant valid credentials enabling full "
            "account access, lateral movement, and persistent access."
        ),
        business_impact=[
            "Valid credential compromise",
            "Unauthorised account access",
            "Cloud tenant compromise",
            "Email and data exfiltration",
            "Lateral movement enabler",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1114", "T1021.001", "T1021.004"],
        often_follows=["T1589.001", "T1589.002", "T1594"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1110-003-aws-cloudtrail",
            name="AWS CloudTrail Failed Sign-In Detection",
            description="Detect password spraying via AWS CloudTrail console and API sign-in failures.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, errorMessage
| filter eventName = "ConsoleLogin" and errorMessage = "Failed authentication"
| stats count(*) as failures, count_distinct(userIdentity.principalId) as unique_accounts by sourceIPAddress, bin(1h)
| filter unique_accounts > 5 and failures > 5
| sort failures desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect password spraying via CloudTrail failed logins

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: password-spraying-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for failed logins
  FailedLoginFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: /aws/cloudtrail/logs
      FilterPattern: '{ ($.eventName = "ConsoleLogin") && ($.errorMessage = "Failed authentication") }'
      MetricTransformations:
        - MetricName: FailedConsoleLogins
          MetricNamespace: Security/Authentication
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for high failure rate
  PasswordSprayAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: PasswordSprayingDetected
      AlarmDescription: Multiple failed logins from same source
      MetricName: FailedConsoleLogins
      Namespace: Security/Authentication
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

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
                terraform_template="""# Detect password spraying via CloudTrail failed logins

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "password_spray_alerts" {
  name = "password-spraying-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.password_spray_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for failed logins
resource "aws_cloudwatch_log_metric_filter" "failed_logins" {
  name           = "failed-console-logins"
  log_group_name = "/aws/cloudtrail/logs"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.errorMessage = \"Failed authentication\") }"

  metric_transformation {
    name          = "FailedConsoleLogins"
    namespace     = "Security/Authentication"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for high failure rate
resource "aws_cloudwatch_metric_alarm" "password_spraying" {
  alarm_name          = "PasswordSprayingDetected"
  alarm_description   = "Multiple failed logins from same source"
  metric_name         = "FailedConsoleLogins"
  namespace           = "Security/Authentication"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.password_spray_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.password_spray_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.password_spray_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Password Spraying Attack Detected",
                alert_description_template="Multiple failed login attempts from {sourceIPAddress} across {unique_accounts} accounts.",
                investigation_steps=[
                    "Review source IP address and geolocation",
                    "Check user accounts targeted for any successful logins",
                    "Review CloudTrail logs for patterns (timing, user agents)",
                    "Identify if accounts have MFA enabled",
                    "Check for successful logins after failed attempts",
                ],
                containment_actions=[
                    "Block source IP address via NACL/Security Group",
                    "Enable MFA on targeted accounts",
                    "Reset passwords for affected accounts",
                    "Review and enforce password policies",
                    "Enable GuardDuty for continuous monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on organisation size; exclude known internal IPs",
            detection_coverage="65% - catches AWS console attacks",
            evasion_considerations="Extremely throttled attacks may evade time-based thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1110-003-aws-iam-api",
            name="AWS IAM API Authentication Failures",
            description="Detect password spraying via AWS API authentication failures.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, sourceIPAddress, errorCode
| filter errorCode = "AccessDenied" or errorCode = "UnauthorizedOperation"
| stats count(*) as failures, count_distinct(userIdentity.arn) as unique_identities by sourceIPAddress, bin(1h)
| filter unique_identities > 3 and failures > 10
| sort failures desc""",
                terraform_template="""# Detect API-based password spraying

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "api_spray_alerts" {
  name = "api-password-spraying-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.api_spray_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for API failures
resource "aws_cloudwatch_log_metric_filter" "api_failures" {
  name           = "api-auth-failures"
  log_group_name = "/aws/cloudtrail/logs"
  pattern        = "{ ($.errorCode = \"AccessDenied\") || ($.errorCode = \"UnauthorizedOperation\") }"

  metric_transformation {
    name          = "APIAuthFailures"
    namespace     = "Security/Authentication"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for API spraying
resource "aws_cloudwatch_metric_alarm" "api_spraying" {
  alarm_name          = "APIPasswordSprayingDetected"
  alarm_description   = "Multiple API authentication failures from same source"
  metric_name         = "APIAuthFailures"
  namespace           = "Security/Authentication"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.api_spray_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.api_spray_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.api_spray_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="API Password Spraying Detected",
                alert_description_template="Multiple API authentication failures from {sourceIPAddress}.",
                investigation_steps=[
                    "Review API calls and targeted services",
                    "Check for successful API calls after failures",
                    "Identify access keys being targeted",
                    "Review user agents and tooling signatures",
                    "Check for credential stuffing patterns",
                ],
                containment_actions=[
                    "Block source IP via NACL",
                    "Rotate potentially compromised access keys",
                    "Enable MFA for API access",
                    "Review IAM policies and permissions",
                    "Enable AWS GuardDuty",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate automation tools; adjust threshold per environment",
            detection_coverage="60% - catches API-based attacks",
            evasion_considerations="Slow, distributed attacks may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail API logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1110-003-gcp-failed-auth",
            name="GCP Failed Authentication Detection",
            description="Detect password spraying via GCP Cloud Logging authentication failures.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance" OR resource.type="gae_app"
protoPayload.authenticationInfo.principalEmail!=""
protoPayload.status.code=16 OR protoPayload.status.code=7
severity="ERROR"''',
                gcp_terraform_template="""# GCP: Detect password spraying via Cloud Logging

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "security_email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for failed authentication
resource "google_logging_metric" "failed_auth" {
  project = var.project_id
  name   = "failed-authentication-attempts"
  filter = <<-EOT
    protoPayload.authenticationInfo.principalEmail!=""
    (protoPayload.status.code=16 OR protoPayload.status.code=7)
    severity="ERROR"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "Email of principal attempting authentication"
    }
  }

  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }

}

# Step 3: Create alert policy for password spraying
resource "google_monitoring_alert_policy" "password_spraying" {
  project      = var.project_id
  display_name = "Password Spraying Detected"
  combiner     = "OR"
  conditions {
    display_name = "High authentication failure rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.failed_auth.name}\" resource.type=\"global\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 15
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.security_email.id]
  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Password Spraying Attack Detected",
                alert_description_template="Multiple authentication failures detected across GCP services.",
                investigation_steps=[
                    "Review Cloud Logging for source IPs",
                    "Check targeted service accounts and users",
                    "Review successful authentications after failures",
                    "Check for unusual API access patterns",
                    "Review IAM policy changes",
                ],
                containment_actions=[
                    "Block source IPs via Cloud Armor/VPC firewall",
                    "Enable 2FA for affected accounts",
                    "Rotate service account keys",
                    "Review and enforce password policies",
                    "Enable Security Command Centre Premium",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on organisation authentication patterns",
            detection_coverage="65% - catches GCP authentication attacks",
            evasion_considerations="Distributed or slow attacks may evade time-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled", "Admin Activity logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1110-003-gcp-workspace",
            name="GCP Workspace Login Monitoring",
            description="Detect password spraying against Google Workspace accounts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="audited_resource"
protoPayload.serviceName="login.googleapis.com"
protoPayload.metadata.event.eventName="login_failure"''',
                gcp_terraform_template="""# GCP: Detect Workspace password spraying

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "workspace_alerts" {
  project      = var.project_id
  display_name = "Workspace Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for Workspace login failures
resource "google_logging_metric" "workspace_login_failures" {
  project = var.project_id
  name   = "workspace-login-failures"
  filter = <<-EOT
    resource.type="audited_resource"
    protoPayload.serviceName="login.googleapis.com"
    protoPayload.metadata.event.eventName="login_failure"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }

}

# Step 3: Create alert policy for Workspace spraying
resource "google_monitoring_alert_policy" "workspace_spraying" {
  project      = var.project_id
  display_name = "Workspace Password Spraying"
  combiner     = "OR"
  conditions {
    display_name = "High Workspace login failure rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.workspace_login_failures.name}\""
      duration        = "1800s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "1800s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.workspace_alerts.id]
  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Workspace Password Spraying",
                alert_description_template="Multiple Workspace login failures detected.",
                investigation_steps=[
                    "Review Workspace audit logs for targeted users",
                    "Check source IPs and geolocations",
                    "Identify successful logins after failures",
                    "Review 2FA status for affected accounts",
                    "Check for account compromise indicators",
                ],
                containment_actions=[
                    "Enforce 2-Step Verification for all users",
                    "Block suspicious IPs via context-aware access",
                    "Reset passwords for targeted accounts",
                    "Review Workspace security settings",
                    "Enable security alerts in Admin console",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Workspace login failures are generally reliable indicators",
            detection_coverage="70% - catches Workspace SSO attacks",
            evasion_considerations="Extremely slow attacks over days may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Google Workspace",
                "Admin SDK API enabled",
                "Audit logging enabled",
            ],
        ),
        # Azure Strategy: Brute Force: Password Spraying
        DetectionStrategy(
            strategy_id="t1110003-azure",
            name="Azure Brute Force: Password Spraying Detection",
            description=(
                "Entra ID Protection detects password spraying. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Password spray attack detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Brute Force: Password Spraying (T1110.003)
# Entra ID Protection detects password spraying

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
  name                = "defender-t1110-003-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1110-003"
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
                    "Password spray attack detected",
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

  description = "Entra ID Protection detects password spraying"
  display_name = "Defender: Brute Force: Password Spraying"
  enabled      = true

  tags = {
    "mitre-technique" = "T1110.003"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Brute Force: Password Spraying Detected",
                alert_description_template=(
                    "Brute Force: Password Spraying activity detected. "
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
        "t1110-003-aws-cloudtrail",
        "t1110-003-gcp-workspace",
        "t1110-003-gcp-failed-auth",
        "t1110-003-aws-iam-api",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+15% improvement for Credential Access tactic",
)
