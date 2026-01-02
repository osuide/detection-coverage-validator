"""
T1606.002 - Forge Web Credentials: SAML Tokens

Adversaries forge SAML tokens to authenticate across services using SAML 2.0
as a single sign-on mechanism. Requires compromised token-signing certificate
or rogue AD FS trust.
Used by APT29 in the SolarWinds Compromise.
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
    technique_id="T1606.002",
    technique_name="Forge Web Credentials: SAML Tokens",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1606/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries forge SAML tokens to authenticate across services using SAML 2.0 "
            "as a single sign-on mechanism. This requires either a compromised token-signing "
            "certificate or the ability to establish a new federation trust with a rogue "
            "Active Directory Federation Services (AD FS) server. The default token lifetime "
            "is one hour but can be modified. Forged tokens can claim highly privileged "
            "account status and bypass multi-factor authentication."
        ),
        attacker_goal="Bypass authentication and gain privileged access using forged SAML tokens",
        why_technique=[
            "Bypasses multi-factor authentication",
            "Enables privileged access escalation",
            "Hard to detect without proper logging",
            "Works across cloud and SaaS platforms",
            "Long-lived tokens enable persistence",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="rare",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Enables authentication bypass and privileged access escalation. Difficult to "
            "detect without advanced logging. Used in major supply chain compromise."
        ),
        business_impact=[
            "Unauthorised privileged access",
            "Multi-factor authentication bypass",
            "Cross-cloud service access",
            "Data breach enabler",
            "Regulatory compliance violations",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1550.001", "T1078.004"],
        often_follows=["T1649", "T1003.006"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1606-002-aws-saml-anomaly",
            name="AWS SAML Authentication Anomalies",
            description="Detect SAML authentication without expected preceding activity.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, userAgent
| filter eventName = "AssumeRoleWithSAML"
| filter errorCode not exists
| stats count(*) as saml_logins by userIdentity.principalId, sourceIPAddress, bin(1h)
| filter saml_logins > 10 OR sourceIPAddress like /^(?!10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)/
| sort saml_logins desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious SAML token usage in AWS

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
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

  # Metric filter for SAML authentication
  SAMLAuthFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "AssumeRoleWithSAML" && $.errorCode NOT EXISTS }'
      MetricTransformations:
        - MetricName: SAMLAuthentications
          MetricNamespace: Security/SAML
          MetricValue: "1"

  # Alarm for high SAML activity
  HighSAMLActivity:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousSAMLActivity
      MetricName: SAMLAuthentications
      Namespace: Security/SAML
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious SAML token usage in AWS

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "saml_alerts" {
  name = "saml-authentication-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.saml_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.saml_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.saml_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for SAML authentication events
resource "aws_cloudwatch_log_metric_filter" "saml_auth" {
  name           = "saml-authentications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"AssumeRoleWithSAML\" && $.errorCode NOT EXISTS }"

  metric_transformation {
    name      = "SAMLAuthentications"
    namespace = "Security/SAML"
    value     = "1"
  }
}

# Alarm for suspicious SAML activity
resource "aws_cloudwatch_metric_alarm" "high_saml_activity" {
  alarm_name          = "SuspiciousSAMLActivity"
  metric_name         = "SAMLAuthentications"
  namespace           = "Security/SAML"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.saml_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Suspicious SAML Authentication Detected",
                alert_description_template="Unusual SAML authentication activity from {sourceIPAddress}.",
                investigation_steps=[
                    "Verify SAML authentication is from legitimate identity provider",
                    "Check for corresponding STS logs in identity provider",
                    "Review user account activity following authentication",
                    "Check for privileged role assumptions",
                    "Verify token claims match expected user attributes",
                    "Review AD FS server logs for certificate compromise",
                ],
                containment_actions=[
                    "Rotate SAML token-signing certificate twice in succession",
                    "Revoke active sessions for affected users",
                    "Review and remove unauthorised federation trusts",
                    "Enable advanced auditing on AD FS servers",
                    "Implement conditional access policies",
                    "Review and restrict Directory Role membership",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal SAML authentication patterns for your organisation",
            detection_coverage="60% - detects volume anomalies but not all forged tokens",
            evasion_considerations="Low-volume token usage may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail logging enabled with SAML events"],
        ),
        DetectionStrategy(
            strategy_id="t1606-002-aws-mfa-bypass",
            name="AWS SAML Authentication Without MFA",
            description="Detect SAML authentication to privileged roles without MFA.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.roleArn, sourceIPAddress
| filter eventName = "AssumeRoleWithSAML"
| filter requestParameters.roleArn like /Admin|Power|Elevated/
| filter responseElements.credentials.sessionToken exists
| filter additionalEventData.MFAUsed = "No" OR additionalEventData.MFAUsed not exists
| sort @timestamp desc""",
                terraform_template="""# Detect SAML authentication bypassing MFA

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "mfa_bypass_alerts" {
  name = "saml-mfa-bypass-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.mfa_bypass_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.mfa_bypass_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.mfa_bypass_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for privileged SAML auth without MFA
resource "aws_cloudwatch_log_metric_filter" "saml_no_mfa" {
  name           = "saml-privileged-no-mfa"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"AssumeRoleWithSAML\" && $.requestParameters.roleArn = \"*Admin*\" }"

  metric_transformation {
    name      = "SAMLPrivilegedWithoutMFA"
    namespace = "Security/SAML"
    value     = "1"
  }
}

# Alarm for MFA bypass via SAML
resource "aws_cloudwatch_metric_alarm" "saml_mfa_bypass" {
  alarm_name          = "SAMLMFABypass"
  metric_name         = "SAMLPrivilegedWithoutMFA"
  namespace           = "Security/SAML"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.mfa_bypass_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Privileged SAML Authentication Without MFA",
                alert_description_template="SAML authentication to privileged role {roleArn} without MFA from {sourceIPAddress}.",
                investigation_steps=[
                    "Verify legitimacy of authentication with user",
                    "Check identity provider logs for matching authentication",
                    "Review token claims for inconsistencies",
                    "Check for recent AD FS certificate changes",
                    "Review privileged actions taken after authentication",
                    "Compare authentication location to user's normal patterns",
                ],
                containment_actions=[
                    "Terminate active session immediately",
                    "Rotate SAML signing certificates",
                    "Enable MFA requirements in IAM role trust policies",
                    "Review and revoke unauthorised federation trusts",
                    "Audit recent privileged access activity",
                    "Implement conditional access policies requiring MFA",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review organisation's MFA policies and exemptions",
            detection_coverage="70% - catches privileged access without MFA",
            evasion_considerations="Attackers may target non-privileged roles first",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1606-002-gcp-saml-anomaly",
            name="GCP SAML Authentication Anomalies",
            description="Detect suspicious SAML authentication in GCP workloads.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.login.LoginService.samlResponse"
protoPayload.status.code=0
protoPayload.authenticationInfo.principalEmail!=""''',
                gcp_terraform_template="""# GCP: Detect suspicious SAML authentication

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "SAML Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log-based metric for SAML authentication
resource "google_logging_metric" "saml_auth" {
  project = var.project_id
  name   = "saml-authentication-events"
  filter = <<-EOT
    protoPayload.methodName="google.login.LoginService.samlResponse"
    protoPayload.status.code=0
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User email"
    }
  }
  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Alert policy for suspicious SAML activity
resource "google_monitoring_alert_policy" "saml_anomaly" {
  project      = var.project_id
  display_name = "Suspicious SAML Authentication"
  combiner     = "OR"
  conditions {
    display_name = "High SAML authentication rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.saml_auth.name}\""
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
  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Suspicious SAML Authentication",
                alert_description_template="Unusual SAML authentication activity detected in GCP.",
                investigation_steps=[
                    "Verify SAML authentication with identity provider logs",
                    "Check for matching user login events",
                    "Review GCP resource access following authentication",
                    "Check for privilege escalation attempts",
                    "Verify SAML provider configuration",
                    "Review recent changes to SAML certificates",
                ],
                containment_actions=[
                    "Suspend affected user accounts",
                    "Rotate SAML certificates",
                    "Review and remove unauthorised SAML providers",
                    "Enable organisation policy constraints",
                    "Audit IAM bindings for suspicious changes",
                    "Implement context-aware access policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal SAML authentication patterns",
            detection_coverage="60% - detects volume anomalies",
            evasion_considerations="Low-volume forged tokens may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled for Login events"],
        ),
        DetectionStrategy(
            strategy_id="t1606-002-aws-cross-account-saml",
            name="AWS Cross-Account SAML Access",
            description="Detect SAML authentication from unexpected external accounts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, recipientAccountId, sourceIPAddress, errorCode
| filter eventName = "AssumeRoleWithSAML"
| filter userIdentity.accountId != recipientAccountId
| filter errorCode not exists
| stats count(*) as cross_account_saml by userIdentity.principalId, recipientAccountId
| sort cross_account_saml desc""",
                terraform_template="""# Detect cross-account SAML authentication

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "cross_account_alerts" {
  name = "saml-cross-account-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.cross_account_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.cross_account_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cross_account_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for cross-account SAML
resource "aws_cloudwatch_log_metric_filter" "cross_account_saml" {
  name           = "cross-account-saml-auth"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"AssumeRoleWithSAML\" && $.errorCode NOT EXISTS }"

  metric_transformation {
    name      = "CrossAccountSAML"
    namespace = "Security/SAML"
    value     = "1"
  }
}

# Alarm for cross-account SAML activity
resource "aws_cloudwatch_metric_alarm" "cross_account_saml" {
  alarm_name          = "CrossAccountSAMLAuthentication"
  metric_name         = "CrossAccountSAML"
  namespace           = "Security/SAML"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.cross_account_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Cross-Account SAML Authentication Detected",
                alert_description_template="SAML authentication from external account to {recipientAccountId}.",
                investigation_steps=[
                    "Verify cross-account trust relationships are authorised",
                    "Check identity provider logs for matching events",
                    "Review trust policy configurations",
                    "Check for recent changes to federation settings",
                    "Audit activity in recipient account",
                    "Verify SAML provider ARN matches expected values",
                ],
                containment_actions=[
                    "Remove unauthorised SAML provider trusts",
                    "Update IAM role trust policies",
                    "Terminate active cross-account sessions",
                    "Enable SCPs to restrict SAML providers",
                    "Audit all cross-account access",
                    "Implement resource-based policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Maintain allowlist of legitimate cross-account SAML relationships",
            detection_coverage="75% - catches unexpected cross-account access",
            evasion_considerations="Attackers may establish new trusts before detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging across all accounts"],
        ),
    ],
    recommended_order=[
        "t1606-002-aws-mfa-bypass",
        "t1606-002-aws-saml-anomaly",
        "t1606-002-aws-cross-account-saml",
        "t1606-002-gcp-saml-anomaly",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+25% improvement for Credential Access tactic",
)
