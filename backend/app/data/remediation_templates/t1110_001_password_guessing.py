"""
T1110.001 - Brute Force: Password Guessing

Adversaries systematically attempt to gain account access using common passwords
without prior knowledge of legitimate credentials. Targets include SSH, RDP,
cloud services, SSO, and federated authentication systems.
Used by APT28, APT29.
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
    technique_id="T1110.001",
    technique_name="Brute Force: Password Guessing",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1110/001/",

    threat_context=ThreatContext(
        description=(
            "Adversaries systematically attempt to gain account access by guessing "
            "passwords without prior knowledge of credentials. Targets include management "
            "services (SSH, RDP, FTP), databases (MSSQL, MySQL), and cloud applications "
            "(Office 365, SSO, federated authentication). This technique carries risk of "
            "authentication failures and account lockouts."
        ),
        attacker_goal="Gain unauthorised access to accounts through systematic password guessing",
        why_technique=[
            "No prior credential knowledge required",
            "Automated tools widely available",
            "Cloud services expand attack surface",
            "Weak passwords remain common",
            "Distributed attacks avoid rate limits"
        ],
        known_threat_actors=["APT28", "APT29"],
        recent_campaigns=[
            Campaign(
                name="APT28 Kubernetes Password Attacks",
                year=2024,
                description="Leveraged Kubernetes clusters for distributed password guessing sending over 300 authentication attempts per hour per targeted account",
                reference_url="https://attack.mitre.org/groups/G0007/"
            ),
            Campaign(
                name="APT29 Mailbox Targeting",
                year=2024,
                description="Successfully conducted password guessing attacks targeting mailbox lists",
                reference_url="https://attack.mitre.org/groups/G0016/"
            )
        ],
        prevalence="very_common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Highly prevalent credential access technique. Successful attacks enable "
            "unauthorised account access, data theft, and lateral movement. Cloud services "
            "and federated authentication increase attack surface."
        ),
        business_impact=[
            "Unauthorised account access",
            "Data breach via compromised credentials",
            "Account lockouts affecting availability",
            "Cloud service compromise",
            "Lateral movement enabler"
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1078.002", "T1078.003", "T1021.004"],
        often_follows=["T1589.001", "T1589.002"]
    ),

    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1110-001-aws-failed-auth",
            name="AWS Failed Authentication Detection",
            description="Detect repeated failed authentication attempts in CloudTrail.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.principalId, sourceIPAddress, errorCode, errorMessage
| filter errorCode = "AccessDenied" or errorCode = "UnauthorizedOperation" or errorCode = "InvalidUserID.NotFound"
| stats count(*) as failures by sourceIPAddress, userIdentity.principalId, bin(5m)
| filter failures > 10
| sort failures desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect password guessing via failed authentication attempts

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Password Guessing Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for failed authentication
  FailedAuthFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.errorCode = "AccessDenied" || $.errorCode = "UnauthorizedOperation" || $.errorCode = "InvalidUserID.NotFound" }'
      MetricTransformations:
        - MetricName: FailedAuthentications
          MetricNamespace: Security/Auth
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for high failure rate
  FailedAuthAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighFailedAuthentications
      AlarmDescription: Detects potential password guessing attacks
      MetricName: FailedAuthentications
      Namespace: Security/Auth
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions: [!Ref AlertTopic]''',
                terraform_template='''# AWS: Detect password guessing via failed authentication

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "auth_alerts" {
  name         = "password-guessing-alerts"
  display_name = "Password Guessing Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.auth_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for failed authentication
resource "aws_cloudwatch_log_metric_filter" "failed_auth" {
  name           = "failed-authentications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.errorCode = \"AccessDenied\" || $.errorCode = \"UnauthorizedOperation\" || $.errorCode = \"InvalidUserID.NotFound\" }"

  metric_transformation {
    name          = "FailedAuthentications"
    namespace     = "Security/Auth"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for high failure rate
resource "aws_cloudwatch_metric_alarm" "failed_auth_alarm" {
  alarm_name          = "HighFailedAuthentications"
  alarm_description   = "Detects potential password guessing attacks"
  metric_name         = "FailedAuthentications"
  namespace           = "Security/Auth"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.auth_alerts.arn]
}''',
                alert_severity="high",
                alert_title="Password Guessing Attack Detected",
                alert_description_template="Multiple failed authentication attempts detected from {sourceIPAddress} targeting {principalId}.",
                investigation_steps=[
                    "Review source IP address and geolocation",
                    "Check targeted user accounts",
                    "Review authentication timeline",
                    "Check for successful authentications after failures",
                    "Correlate with GuardDuty findings"
                ],
                containment_actions=[
                    "Block source IP in security groups/WAF",
                    "Reset credentials for targeted accounts",
                    "Enable MFA on affected accounts",
                    "Review account lockout policies",
                    "Check for successful compromises"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on legitimate failed login patterns. Exclude service accounts with known retry behaviour.",
            detection_coverage="75% - catches failed authentication patterns",
            evasion_considerations="Slow, distributed attacks below threshold may evade. Successful guesses appear as normal logins.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled and logging to CloudWatch"]
        ),

        DetectionStrategy(
            strategy_id="t1110-001-aws-console-signin",
            name="AWS Console Sign-In Failures",
            description="Detect brute force attempts against AWS Console.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.userName, sourceIPAddress, responseElements.ConsoleLogin
| filter eventName = "ConsoleLogin"
| filter responseElements.ConsoleLogin = "Failure"
| stats count(*) as failures by sourceIPAddress, userIdentity.userName, bin(10m)
| filter failures > 5
| sort failures desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect AWS Console password guessing attempts

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for console alerts
  ConsoleAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for console login failures
  ConsoleFailureFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "ConsoleLogin" && $.responseElements.ConsoleLogin = "Failure" }'
      MetricTransformations:
        - MetricName: ConsoleLoginFailures
          MetricNamespace: Security/Auth
          MetricValue: "1"

  # Step 3: Alarm for console brute force
  ConsoleFailureAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ConsolePasswordGuessing
      MetricName: ConsoleLoginFailures
      Namespace: Security/Auth
      Statistic: Sum
      Period: 600
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref ConsoleAlertTopic]''',
                terraform_template='''# AWS: Detect Console password guessing

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

# Step 1: SNS topic for console alerts
resource "aws_sns_topic" "console_alerts" {
  name = "console-password-guessing-alerts"
}

resource "aws_sns_topic_subscription" "console_email" {
  topic_arn = aws_sns_topic.console_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for console login failures
resource "aws_cloudwatch_log_metric_filter" "console_failures" {
  name           = "console-login-failures"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"ConsoleLogin\" && $.responseElements.ConsoleLogin = \"Failure\" }"

  metric_transformation {
    name      = "ConsoleLoginFailures"
    namespace = "Security/Auth"
    value     = "1"
  }
}

# Step 3: Alarm for console brute force
resource "aws_cloudwatch_metric_alarm" "console_brute_force" {
  alarm_name          = "ConsolePasswordGuessing"
  metric_name         = "ConsoleLoginFailures"
  namespace           = "Security/Auth"
  statistic           = "Sum"
  period              = 600
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.console_alerts.arn]
}''',
                alert_severity="critical",
                alert_title="AWS Console Brute Force Detected",
                alert_description_template="Multiple failed console login attempts from {sourceIPAddress}.",
                investigation_steps=[
                    "Identify targeted user accounts",
                    "Check source IP geolocation",
                    "Review login attempt timeline",
                    "Check for successful logins",
                    "Review MFA status of accounts"
                ],
                containment_actions=[
                    "Enable MFA for all IAM users",
                    "Implement IP allowlisting",
                    "Reset passwords for targeted accounts",
                    "Review IAM password policy",
                    "Enable GuardDuty if not present"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Console login failures are high-fidelity indicators. Adjust threshold for organisation size.",
            detection_coverage="85% - high visibility into console attacks",
            evasion_considerations="Attackers may target API/CLI instead of console",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5",
            prerequisites=["CloudTrail with console sign-in events"]
        ),

        DetectionStrategy(
            strategy_id="t1110-001-gcp-failed-auth",
            name="GCP Failed Authentication Detection",
            description="Detect password guessing via GCP audit logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"google.cloud.identityplatform.*"
protoPayload.status.code!=0
severity="ERROR"''',
                gcp_terraform_template='''# GCP: Detect password guessing attempts

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "auth_email" {
  display_name = "Authentication Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Create log metric for failed authentication
resource "google_logging_metric" "failed_auth" {
  name   = "failed-authentication-attempts"
  filter = <<-EOT
    protoPayload.methodName=~"google.cloud.identityplatform.*"
    protoPayload.status.code!=0
    severity="ERROR"
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

# Step 3: Create alert policy for brute force detection
resource "google_monitoring_alert_policy" "auth_brute_force" {
  display_name = "Password Guessing Detected"
  combiner     = "OR"
  conditions {
    display_name = "High failed authentication rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.failed_auth.name}\" resource.type=\"global\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.auth_email.id]
  alert_strategy {
    auto_close = "1800s"
  }
}''',
                alert_severity="high",
                alert_title="GCP Password Guessing Attack",
                alert_description_template="Multiple failed authentication attempts detected from {source_ip}.",
                investigation_steps=[
                    "Review failed authentication logs",
                    "Check targeted accounts",
                    "Verify source IP geolocation",
                    "Check for successful authentications",
                    "Review Security Command Centre findings"
                ],
                containment_actions=[
                    "Enable Cloud Identity security features",
                    "Implement 2-Step Verification",
                    "Block malicious IPs via Cloud Armor",
                    "Review organisation policies",
                    "Reset compromised credentials"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter out known service accounts and legitimate retry patterns",
            detection_coverage="70% - catches authentication failures",
            evasion_considerations="Slow attacks may stay below threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1110-001-gcp-console-signin",
            name="GCP Console Sign-In Monitoring",
            description="Detect brute force attempts against GCP Console.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.login.LoginService.loginFailure"
protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"''',
                gcp_terraform_template='''# GCP: Monitor console login failures

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "console_alerts" {
  display_name = "Console Login Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
  project      = var.project_id
}

# Step 2: Log metric for console failures
resource "google_logging_metric" "console_failures" {
  name   = "console-login-failures"
  filter = <<-EOT
    protoPayload.methodName="google.login.LoginService.loginFailure"
    protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert for console brute force
resource "google_monitoring_alert_policy" "console_brute_force" {
  display_name = "Console Brute Force Attack"
  combiner     = "OR"
  conditions {
    display_name = "High console login failure rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.console_failures.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 15
      aggregations {
        alignment_period   = "600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.console_alerts.id]
}''',
                alert_severity="critical",
                alert_title="GCP Console Brute Force Attack",
                alert_description_template="Multiple failed console login attempts detected.",
                investigation_steps=[
                    "Review login failure patterns",
                    "Identify targeted accounts",
                    "Check source locations",
                    "Verify MFA status",
                    "Check for successful logins"
                ],
                containment_actions=[
                    "Enforce 2-Step Verification",
                    "Implement context-aware access",
                    "Reset compromised passwords",
                    "Review access controls",
                    "Enable Security Command Centre"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Console failures are reliable indicators",
            detection_coverage="80% - high visibility",
            evasion_considerations="API-based attacks won't appear in console logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Admin Activity audit logs enabled"]
        )
    ],

    recommended_order=[
        "t1110-001-aws-console-signin",
        "t1110-001-aws-failed-auth",
        "t1110-001-gcp-console-signin",
        "t1110-001-gcp-failed-auth"
    ],
    total_effort_hours=3.5,
    coverage_improvement="+25% improvement for Credential Access tactic"
)
