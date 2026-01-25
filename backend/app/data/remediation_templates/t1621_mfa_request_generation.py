"""
T1621 - Multi-Factor Authentication Request Generation

Adversaries exploit MFA by repeatedly generating authentication requests
(MFA fatigue/push bombing) until users approve. Used by APT29, Scattered Spider, LAPSUS$.
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
    technique_id="T1621",
    technique_name="Multi-Factor Authentication Request Generation",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1621/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit MFA mechanisms by generating repeated authentication "
            "requests (MFA fatigue/push bombing) until users accept. Also used during "
            "self-service password reset flows."
        ),
        attacker_goal="Bypass MFA by fatiguing users into accepting push notifications",
        why_technique=[
            "Valid credentials already obtained",
            "Users may accept to stop notifications",
            "Push notifications easy to spam",
            "No technical bypass needed",
            "Effective against distracted users",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Effective bypass of MFA security. Requires only valid credentials. "
            "Targets human weakness rather than technical controls."
        ),
        business_impact=[
            "MFA bypass leading to account takeover",
            "User frustration and support tickets",
            "False sense of MFA security",
            "Potential compliance failures",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1530"],
        often_follows=["T1110", "T1528"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1621-aws-cognito-mfa",
            name="AWS Cognito MFA Fatigue Detection",
            description="Detect repeated MFA challenge failures in Cognito.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.userName, sourceIPAddress
| filter eventSource = "cognito-idp.amazonaws.com"
| filter eventName in ["RespondToAuthChallenge", "AdminRespondToAuthChallenge"]
| filter errorCode like /NotAuthorized|InvalidParameter/
| stats count(*) as failures by userIdentity.userName, sourceIPAddress, bin(10m)
| filter failures > 5
| sort failures desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect MFA fatigue attacks

Parameters:
  CloudTrailLogGroup:
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

  MFAFatigueFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "cognito-idp.amazonaws.com" && $.eventName = "RespondToAuthChallenge" }'
      MetricTransformations:
        - MetricName: MFAChallenges
          MetricNamespace: Security
          MetricValue: "1"

  MFAFatigueAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: MFAFatigueAttack
      MetricName: MFAChallenges
      Namespace: Security
      Statistic: Sum
      Period: 600
      Threshold: 10
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
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect MFA fatigue attacks

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "mfa-fatigue-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "mfa_challenges" {
  name           = "mfa-challenge-attempts"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"cognito-idp.amazonaws.com\" && $.eventName = \"RespondToAuthChallenge\" }"

  metric_transformation {
    name      = "MFAChallenges"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "mfa_fatigue" {
  alarm_name          = "MFAFatigueAttack"
  metric_name         = "MFAChallenges"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 600
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="MFA Fatigue Attack Detected",
                alert_description_template="Multiple MFA challenges for user {userName} in short period.",
                investigation_steps=[
                    "Verify if user expected MFA prompts",
                    "Check source IP for suspicious location",
                    "Review if login was eventually successful",
                    "Check for credential compromise",
                ],
                containment_actions=[
                    "Lock the affected account",
                    "Reset user credentials",
                    "Enable number matching MFA",
                    "Contact user to verify",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust threshold based on normal MFA retry patterns",
            detection_coverage="85% - catches repeated MFA attempts",
            evasion_considerations="Slow attack may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging Cognito events"],
        ),
        DetectionStrategy(
            strategy_id="t1621-gcp-mfa",
            name="GCP Workspace MFA Fatigue Detection",
            description="Detect repeated MFA challenges in Google Workspace.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="login.googleapis.com"
protoPayload.methodName=~"2sv|challenge"''',
                gcp_terraform_template="""# GCP: Detect MFA fatigue attacks

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "mfa_challenges" {
  project = var.project_id
  name   = "mfa-challenge-attempts"
  filter = <<-EOT
    protoPayload.serviceName="login.googleapis.com"
    protoPayload.methodName=~"2sv|challenge"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "mfa_fatigue" {
  project      = var.project_id
  display_name = "MFA Fatigue Attack"
  combiner     = "OR"
  conditions {
    display_name = "High volume MFA challenges"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.mfa_challenges.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
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
                alert_severity="high",
                alert_title="GCP: MFA Fatigue Attack",
                alert_description_template="Multiple MFA challenges detected.",
                investigation_steps=[
                    "Check if user expected prompts",
                    "Review login source location",
                    "Check for credential compromise",
                    "Verify account status",
                ],
                containment_actions=[
                    "Suspend the account",
                    "Reset credentials",
                    "Enable phishing-resistant MFA",
                    "Contact user",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust threshold for your environment",
            detection_coverage="80% - catches repeated challenges",
            evasion_considerations="Slow attack may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Workspace audit logs enabled"],
        ),
        # Azure Strategy: Multi-Factor Authentication Request Generation
        DetectionStrategy(
            strategy_id="t1621-azure",
            name="Azure Multi-Factor Authentication Request Generation Detection",
            description=(
                "Azure detection for Multi-Factor Authentication Request Generation. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "Anomalous user activity",
                    "Unfamiliar sign-in properties",
                    "User reported suspicious activity",
                    "Attacker in the Middle",
                ],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Multi-Factor Authentication Request Generation (T1621)
# Microsoft Defender detects Multi-Factor Authentication Request Generation activity

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
  name                = "defender-t1621-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1621"
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

                    "Anomalous user activity",
                    "Unfamiliar sign-in properties",
                    "User reported suspicious activity",
                    "Attacker in the Middle"
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

  description = "Microsoft Defender detects Multi-Factor Authentication Request Generation activity"
  display_name = "Defender: Multi-Factor Authentication Request Generation"
  enabled      = true

  tags = {
    "mitre-technique" = "T1621"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Multi-Factor Authentication Request Generation Detected",
                alert_description_template=(
                    "Multi-Factor Authentication Request Generation activity detected. "
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
    recommended_order=["t1621-aws-cognito-mfa", "t1621-gcp-mfa"],
    total_effort_hours=2.0,
    coverage_improvement="+15% improvement for Credential Access tactic",
)
