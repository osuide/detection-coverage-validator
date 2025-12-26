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

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "mfa_challenges" {
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
  notification_channels = [google_monitoring_notification_channel.email.id]
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
    ],
    recommended_order=["t1621-aws-cognito-mfa", "t1621-gcp-mfa"],
    total_effort_hours=2.0,
    coverage_improvement="+15% improvement for Credential Access tactic",
)
