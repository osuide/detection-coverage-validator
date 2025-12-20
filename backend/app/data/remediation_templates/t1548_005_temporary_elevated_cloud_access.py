"""
T1548.005 - Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access

Adversaries exploit permission configurations in cloud environments to obtain
short-term elevated access through just-in-time access, account impersonation,
and role passing mechanisms.
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
    technique_id="T1548.005",
    technique_name="Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
    tactic_ids=["TA0004", "TA0005"],  # Privilege Escalation, Defense Evasion
    mitre_url="https://attack.mitre.org/techniques/T1548/005/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit permission configurations in cloud environments "
            "to obtain short-term elevated access. This includes abusing just-in-time "
            "access mechanisms, service account impersonation, and role passing to gain "
            "temporary privileges without permanent role assignments."
        ),
        attacker_goal="Gain temporary elevated privileges through cloud IAM mechanisms",
        why_technique=[
            "Bypasses permanent role assignment monitoring",
            "Just-in-time access may lack approval controls",
            "Service account impersonation enables lateral movement",
            "PassRole/iam.serviceAccountUser widely granted",
            "Temporary tokens harder to trace",
        ],
        known_threat_actors=[],  # No specific threat actors documented in MITRE
        recent_campaigns=[
            Campaign(
                name="StellarParticle Privilege Escalation",
                year=2023,
                description="CrowdStrike analysis documented use of temporary privilege escalation techniques",
                reference_url="https://attack.mitre.org/techniques/T1548/005/",
            )
        ],
        prevalence="uncommon",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Enables privilege escalation with reduced visibility. Temporary nature "
            "makes detection difficult. Can bypass traditional role assignment monitoring."
        ),
        business_impact=[
            "Unauthorised privilege escalation",
            "Lateral movement enabler",
            "Data access beyond authorisation",
            "Compliance violations",
        ],
        typical_attack_phase="privilege_escalation",
        often_precedes=["T1078.004", "T1530", "T1213.003"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1548-005-aws-passrole",
            name="AWS PassRole and AssumeRole Privilege Escalation",
            description="Detect PassRole and AssumeRole events indicating potential privilege escalation.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.roleName, sourceIPAddress
| filter eventName = "PassRole" or eventName = "AssumeRole"
| filter requestParameters.roleName like /Admin|PowerUser|FullAccess/
| stats count(*) as attempts by userIdentity.principalId, requestParameters.roleName, bin(1h)
| filter attempts > 5
| sort attempts desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect AWS PassRole and AssumeRole privilege escalation

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  PassRoleFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "PassRole") || ($.eventName = "AssumeRole") }'
      MetricTransformations:
        - MetricName: PrivilegeEscalationAttempts
          MetricNamespace: Security
          MetricValue: "1"

  PrivilegeEscalationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousPassRoleAssumeRole
      MetricName: PrivilegeEscalationAttempts
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect AWS PassRole and AssumeRole privilege escalation

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "privilege-escalation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "passrole_escalation" {
  name           = "passrole-escalation"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"PassRole\") || ($.eventName = \"AssumeRole\") }"

  metric_transformation {
    name      = "PrivilegeEscalationAttempts"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "privilege_escalation" {
  alarm_name          = "SuspiciousPassRoleAssumeRole"
  metric_name         = "PrivilegeEscalationAttempts"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="AWS Privilege Escalation Detected",
                alert_description_template="Suspicious PassRole/AssumeRole activity from {principalId}.",
                investigation_steps=[
                    "Review CloudTrail for PassRole and AssumeRole events",
                    "Check if roles grant elevated privileges",
                    "Verify identity making the requests",
                    "Check for subsequent suspicious activity",
                    "Review resources created with passed roles",
                ],
                containment_actions=[
                    "Revoke suspicious IAM sessions",
                    "Remove PassRole permissions if not required",
                    "Add SCPs to restrict role assumption",
                    "Enable approval workflow for sensitive roles",
                    "Review and delete unauthorised resources",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter legitimate automation accounts and known admin activities",
            detection_coverage="75% - catches PassRole/AssumeRole patterns",
            evasion_considerations="Low-frequency attacks or using already-compromised high-privilege accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1548-005-aws-sts-token",
            name="AWS STS Token Creation Monitoring",
            description="Detect temporary security credential creation via AWS STS.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.roleArn, userAgent
| filter eventName = "GetSessionToken" or eventName = "GetFederationToken" or eventName = "AssumeRoleWithSAML" or eventName = "AssumeRoleWithWebIdentity"
| stats count(*) as tokens by userIdentity.principalId, requestParameters.roleArn, bin(1h)
| filter tokens > 20
| sort tokens desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious AWS STS temporary token creation

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  STSTokenFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "GetSessionToken") || ($.eventName = "GetFederationToken") || ($.eventName = "AssumeRoleWithSAML") || ($.eventName = "AssumeRoleWithWebIdentity") }'
      MetricTransformations:
        - MetricName: STSTokenCreation
          MetricNamespace: Security
          MetricValue: "1"

  STSTokenAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighSTSTokenCreation
      MetricName: STSTokenCreation
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious AWS STS temporary token creation

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "sts-token-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "sts_tokens" {
  name           = "sts-token-creation"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"GetSessionToken\") || ($.eventName = \"GetFederationToken\") || ($.eventName = \"AssumeRoleWithSAML\") || ($.eventName = \"AssumeRoleWithWebIdentity\") }"

  metric_transformation {
    name      = "STSTokenCreation"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "sts_token_spike" {
  alarm_name          = "HighSTSTokenCreation"
  metric_name         = "STSTokenCreation"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious STS Token Creation",
                alert_description_template="High volume of temporary credentials created by {principalId}.",
                investigation_steps=[
                    "Review STS token creation patterns",
                    "Check identity requesting tokens",
                    "Verify roles being assumed",
                    "Check for unusual source IPs",
                    "Review subsequent API activity with tokens",
                ],
                containment_actions=[
                    "Revoke active sessions if malicious",
                    "Review and restrict STS permissions",
                    "Add MFA requirements for sensitive roles",
                    "Review CloudTrail for token usage",
                    "Update IAM policies to limit token duration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal token creation rates and exclude legitimate automation",
            detection_coverage="60% - catches high-volume token creation",
            evasion_considerations="Low-frequency token creation may go undetected",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1548-005-gcp-impersonation",
            name="GCP Service Account Impersonation Detection",
            description="Detect service account token creation and impersonation attempts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=("GenerateAccessToken" OR "GenerateIdToken" OR "SignJwt" OR "SignBlob")
protoPayload.authenticationInfo.principalEmail!=""
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect service account impersonation

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "sa_impersonation" {
  name   = "service-account-impersonation"
  filter = <<-EOT
    protoPayload.methodName=("GenerateAccessToken" OR "GenerateIdToken" OR "SignJwt" OR "SignBlob")
    protoPayload.authenticationInfo.principalEmail!=""
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "sa_impersonation_alert" {
  display_name = "Service Account Impersonation Detected"
  combiner     = "OR"
  conditions {
    display_name = "High impersonation activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_impersonation.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Service Account Impersonation",
                alert_description_template="Service account token generation detected from {principalEmail}.",
                investigation_steps=[
                    "Review service account token generation logs",
                    "Check principal requesting tokens",
                    "Verify service account permissions",
                    "Check for domain-wide delegation",
                    "Review subsequent API calls with impersonated credentials",
                ],
                containment_actions=[
                    "Revoke service account keys if compromised",
                    "Remove iam.serviceAccountTokenCreator role",
                    "Disable domain-wide delegation if not required",
                    "Add conditions to IAM policies",
                    "Review and rotate service account keys",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate service automation and CI/CD pipelines",
            detection_coverage="70% - catches token generation events",
            evasion_considerations="Low-frequency impersonation or using already-compromised service accounts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled for IAM"],
        ),
        DetectionStrategy(
            strategy_id="t1548-005-gcp-serviceaccount-user",
            name="GCP Service Account User Role Assignment",
            description="Detect assignment of iam.serviceAccountUser role enabling service account attachment.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.iam.admin.v1.SetIamPolicy"
protoPayload.request.policy.bindings.role="roles/iam.serviceAccountUser"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect iam.serviceAccountUser role assignment

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "sa_user_role" {
  name   = "serviceaccount-user-role-assignment"
  filter = <<-EOT
    protoPayload.methodName="google.iam.admin.v1.SetIamPolicy"
    protoPayload.request.policy.bindings.role="roles/iam.serviceAccountUser"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "sa_user_role_alert" {
  display_name = "Service Account User Role Assignment"
  combiner     = "OR"
  conditions {
    display_name = "New iam.serviceAccountUser assignment"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_user_role.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Service Account User Role Assigned",
                alert_description_template="iam.serviceAccountUser role granted, enabling service account attachment.",
                investigation_steps=[
                    "Review IAM policy change logs",
                    "Check who granted the role",
                    "Verify if assignment is legitimate",
                    "Check service account permissions",
                    "Monitor for resource creation with service account",
                ],
                containment_actions=[
                    "Revoke unnecessary iam.serviceAccountUser roles",
                    "Review and restrict service account usage",
                    "Add organisation policy constraints",
                    "Enable approval workflows for sensitive roles",
                    "Review resources created with the service account",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Alert on all assignments, review for legitimacy",
            detection_coverage="80% - catches role assignment events",
            evasion_considerations="Role may be granted through group membership",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for IAM"],
        ),
    ],
    recommended_order=[
        "t1548-005-aws-passrole",
        "t1548-005-gcp-impersonation",
        "t1548-005-aws-sts-token",
        "t1548-005-gcp-serviceaccount-user",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+25% improvement for Privilege Escalation tactic",
)
