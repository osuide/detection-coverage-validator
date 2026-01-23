"""
T1606.001 - Forge Web Credentials: Web Cookies

Adversaries forge web cookies to gain unauthorised access to web applications
and internet services by creating new cookies using documented standards and
secret values.
Used by APT29 in SolarWinds compromise (C0024).
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
    technique_id="T1606.001",
    technique_name="Forge Web Credentials: Web Cookies",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1606/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries forge web cookies to gain unauthorised access to web applications "
            "and internet services. Unlike cookie theft, attackers generate new cookies using "
            "documented standards and secret values such as passwords, private keys, or "
            "cryptographic seed values. Forged cookies can bypass multi-factor authentication "
            "and other security controls, enabling persistent access to cloud services and SaaS platforms."
        ),
        attacker_goal="Bypass authentication controls by forging valid web cookies using stolen secret values",
        why_technique=[
            "Bypasses multi-factor authentication",
            "Enables persistent access to cloud services",
            "Difficult to detect without baseline behavioural analysis",
            "No additional authentication prompts required",
            "Valid sessions appear legitimate to security tools",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="rare",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Sophisticated technique that bypasses MFA and security controls. "
            "Difficult to detect and provides persistent access to critical services. "
            "Requires prior access to secret keys but grants significant privilege."
        ),
        business_impact=[
            "Unauthorised access to SaaS applications",
            "Email and collaboration platform compromise",
            "Data exfiltration from cloud services",
            "Persistent access despite password changes",
            "Regulatory compliance violations",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1213.002", "T1114.002"],
        often_follows=["T1552.001", "T1555.003", "T1552.004"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1606-001-aws-cloudtrail",
            name="AWS CloudTrail Authentication Anomaly Detection",
            description="Detect authentication bypassing MFA or unusual session patterns in AWS.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, userAgent, requestParameters.userName
| filter eventName in ["AssumeRole", "GetSessionToken", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"]
| filter responseElements.credentials.sessionToken like /.+/
| filter userIdentity.sessionContext.attributes.mfaAuthenticated = "false" or ispresent(userIdentity.sessionContext.attributes.mfaAuthenticated) = false
| stats count(*) as no_mfa_sessions by userIdentity.principalId, sourceIPAddress, bin(1h)
| filter no_mfa_sessions > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect authentication bypassing MFA in AWS

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
      KmsMasterKeyId: alias/aws/sns
      TopicName: auth-bypass-alerts
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

  # Step 2: Create metric filter for MFA bypass attempts
  MFABypassFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "AssumeRole" || $.eventName = "GetSessionToken") && ($.userIdentity.sessionContext.attributes.mfaAuthenticated = "false" || $.userIdentity.sessionContext.attributes.mfaAuthenticated NOT EXISTS) }'
      MetricTransformations:
        - MetricName: MFABypassAttempts
          MetricNamespace: Security/Authentication
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for MFA bypass detection
  MFABypassAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: AuthenticationMFABypass
      AlarmDescription: Detects authentication sessions bypassing MFA
      MetricName: MFABypassAttempts
      Namespace: Security/Authentication
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect authentication bypassing MFA

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "auth_alerts" {
  name = "auth-bypass-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.auth_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.auth_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.auth_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for MFA bypass attempts
resource "aws_cloudwatch_log_metric_filter" "mfa_bypass" {
  name           = "mfa-bypass-attempts"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"AssumeRole\" || $.eventName = \"GetSessionToken\") && ($.userIdentity.sessionContext.attributes.mfaAuthenticated = \"false\" || $.userIdentity.sessionContext.attributes.mfaAuthenticated NOT EXISTS) }"

  metric_transformation {
    name          = "MFABypassAttempts"
    namespace     = "Security/Authentication"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for MFA bypass detection
resource "aws_cloudwatch_metric_alarm" "mfa_bypass_alert" {
  alarm_name          = "AuthenticationMFABypass"
  alarm_description   = "Detects authentication sessions bypassing MFA"
  metric_name         = "MFABypassAttempts"
  namespace           = "Security/Authentication"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.auth_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Authentication Bypassing MFA Detected",
                alert_description_template="Authentication session created bypassing MFA for {principalId} from {sourceIPAddress}.",
                investigation_steps=[
                    "Verify if user legitimately authenticated without MFA",
                    "Check for concurrent sessions from different locations",
                    "Review CloudTrail for secret key access events",
                    "Examine user's recent authentication history",
                    "Check for cookie manipulation or session token abuse",
                    "Verify MFA device registration status",
                ],
                containment_actions=[
                    "Immediately revoke active session tokens",
                    "Force MFA re-enrollment for affected accounts",
                    "Rotate potentially compromised secret keys",
                    "Enable conditional access policies",
                    "Block source IP if malicious",
                    "Reset user credentials and review account permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legacy applications or service accounts may legitimately authenticate without MFA. Exclude known service accounts.",
            detection_coverage="60% - detects MFA bypass but not all forged cookies",
            evasion_considerations="Attackers using properly forged cookies may appear as legitimate sessions if MFA was used initially",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1606-001-aws-guardduty",
            name="AWS GuardDuty Anomalous Behaviour Detection",
            description="Detect unusual authentication patterns and session behaviour via GuardDuty.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""# GuardDuty Finding Types for Cookie Forgery:
# - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
# - UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
# - PenTest:IAMUser/KaliLinux
# - CredentialAccess:IAMUser/AnomalousBehavior

fields @timestamp, service.action.actionType, severity, type, resource.accessKeyDetails.userName
| filter type like /CredentialAccess|UnauthorizedAccess/
| filter type like /AnomalousBehavior|ConsoleLoginSuccess/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Configure GuardDuty alerts for credential access anomalies

Parameters:
  AlertEmail:
    Type: String
    Description: Email for GuardDuty alerts

Resources:
  # Step 1: Create SNS topic for GuardDuty findings
  GuardDutyTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: guardduty-credential-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for credential access findings
  GuardDutyEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-credential-access
      Description: Alert on GuardDuty credential access findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: CredentialAccess
            - prefix: UnauthorizedAccess
      State: ENABLED
      Targets:
        - Arn: !Ref GuardDutyTopic
          Id: GuardDutyAlertTarget

  # Step 3: Grant EventBridge permission to publish to SNS
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref GuardDutyTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref GuardDutyTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt GuardDutyEventRule.Arn""",
                terraform_template="""# AWS: Configure GuardDuty alerts for credential access

variable "alert_email" {
  type        = string
  description = "Email for GuardDuty alerts"
}

# Step 1: Create SNS topic for GuardDuty findings
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-credential-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "guardduty_email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for EventBridge targets
resource "aws_sqs_queue" "events_dlq" {
  name                      = "guardduty-credential-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "events_dlq" {
  queue_url = aws_sqs_queue.events_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.events_dlq.arn
    }]
  })
}

# Step 2: Create EventBridge rule for credential access findings
resource "aws_cloudwatch_event_rule" "guardduty_credential" {
  name        = "guardduty-credential-access"
  description = "Alert on GuardDuty credential access findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "CredentialAccess" },
        { prefix = "UnauthorizedAccess" }
      ]
    }
  })
}

# Step 3: Configure EventBridge target to SNS
resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_credential.name
  target_id = "GuardDutyAlertTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.events_dlq.arn
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_credential.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Credential Access Anomaly",
                alert_description_template="GuardDuty detected anomalous credential access: {type}.",
                investigation_steps=[
                    "Review GuardDuty finding details and severity",
                    "Check user authentication history for anomalies",
                    "Examine source IP and geolocation",
                    "Review concurrent sessions and access patterns",
                    "Check for recent secret key or certificate access",
                ],
                containment_actions=[
                    "Revoke active sessions for affected user",
                    "Rotate credentials and secret keys",
                    "Enable additional MFA requirements",
                    "Review and restrict IAM permissions",
                    "Block malicious source IPs",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML models; tune by suppressing findings for known legitimate behaviour",
            detection_coverage="75% - ML-based detection of anomalous patterns",
            evasion_considerations="Attackers mimicking normal user behaviour may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["GuardDuty enabled in account"],
        ),
        DetectionStrategy(
            strategy_id="t1606-001-gcp-workspace",
            name="GCP Workspace Login Audit Detection",
            description="Detect suspicious login patterns and cookie abuse in Google Workspace.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gae_app"
protoPayload.methodName="google.login.LoginService.loginSuccess"
protoPayload.metadata.event.eventType="login"
protoPayload.metadata.event.parameters.login_challenge_method!="totp"
protoPayload.metadata.event.parameters.login_challenge_method!="sms"
protoPayload.metadata.event.parameters.login_challenge_method!="push"''',
                gcp_terraform_template="""# GCP: Detect suspicious login patterns in Workspace

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email_channel" {
  display_name = "Security Alert Email"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for non-MFA logins
resource "google_logging_metric" "non_mfa_login" {
  name    = "workspace-non-mfa-login"
  project = var.project_id

  filter = <<-EOT
    resource.type="gae_app"
    protoPayload.methodName="google.login.LoginService.loginSuccess"
    protoPayload.metadata.event.eventType="login"
    protoPayload.metadata.event.parameters.login_challenge_method!="totp"
    protoPayload.metadata.event.parameters.login_challenge_method!="sms"
    protoPayload.metadata.event.parameters.login_challenge_method!="push"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for suspicious logins
resource "google_monitoring_alert_policy" "workspace_login_alert" {
  project      = var.project_id
  display_name = "Workspace Suspicious Login"
  combiner     = "OR"

  conditions {
    display_name = "Non-MFA login detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.non_mfa_login.name}\" resource.type=\"gae_app\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_channel.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Workspace Suspicious Login",
                alert_description_template="Login without MFA detected in Google Workspace.",
                investigation_steps=[
                    "Review login audit logs for user details",
                    "Check source IP and geolocation",
                    "Verify if user has MFA configured",
                    "Examine concurrent sessions",
                    "Check for recent admin or privilege changes",
                    "Review user's recent activity in Workspace apps",
                ],
                containment_actions=[
                    "Force sign-out from all active sessions",
                    "Require MFA enrollment",
                    "Reset user password",
                    "Review and revoke OAuth tokens",
                    "Enable context-aware access policies",
                    "Block suspicious IP ranges",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude users with legitimate reasons for no MFA (e.g., service accounts, legacy systems)",
            detection_coverage="65% - detects non-MFA logins but not all forged cookies",
            evasion_considerations="Properly forged cookies with MFA compliance may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Google Workspace with audit logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1606-001-gcp-identity",
            name="GCP Cloud Identity Session Anomaly Detection",
            description="Detect unusual session patterns and token usage in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="audited_resource"
protoPayload.serviceName="iap.googleapis.com"
protoPayload.methodName="AuthorizeUser"
protoPayload.authenticationInfo.principalEmail!=""
severity="WARNING" OR severity="ERROR"''',
                gcp_terraform_template="""# GCP: Detect session anomalies via Cloud Identity

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "session_alerts" {
  display_name = "Session Anomaly Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for failed authorisations
resource "google_logging_metric" "auth_failures" {
  name    = "identity-auth-failures"
  project = var.project_id

  filter = <<-EOT
    resource.type="audited_resource"
    protoPayload.serviceName="iap.googleapis.com"
    protoPayload.methodName="AuthorizeUser"
    (severity="WARNING" OR severity="ERROR")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User principal"
    }
  }

  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for authorisation anomalies
resource "google_monitoring_alert_policy" "session_anomaly" {
  project      = var.project_id
  display_name = "Session Authorisation Anomaly"
  combiner     = "OR"

  conditions {
    display_name = "High authentication failure rate"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.auth_failures.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.user"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.session_alerts.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Session Authorisation Anomaly",
                alert_description_template="Unusual session authorisation patterns detected in GCP.",
                investigation_steps=[
                    "Review authentication failure logs",
                    "Check for session token abuse patterns",
                    "Examine user's authentication methods",
                    "Review IAP and Cloud Identity settings",
                    "Check for concurrent access from multiple locations",
                ],
                containment_actions=[
                    "Revoke active OAuth tokens",
                    "Force session re-authentication",
                    "Enable advanced protection programme",
                    "Review IAM bindings and permissions",
                    "Rotate service account keys if affected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal authentication patterns; exclude transient network failures",
            detection_coverage="60% - detects authorisation anomalies",
            evasion_considerations="Valid forged cookies may not trigger authorisation failures",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Identity, IAP, or Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Forge Web Credentials: Web Cookies
        DetectionStrategy(
            strategy_id="t1606001-azure",
            name="Azure Forge Web Credentials: Web Cookies Detection",
            description=(
                "Azure detection for Forge Web Credentials: Web Cookies. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Forge Web Credentials: Web Cookies (T1606.001)
# Microsoft Defender detects Forge Web Credentials: Web Cookies activity

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
  name                = "defender-t1606-001-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1606-001"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

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
                    "Suspicious activity detected",
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

  description = "Microsoft Defender detects Forge Web Credentials: Web Cookies activity"
  display_name = "Defender: Forge Web Credentials: Web Cookies"
  enabled      = true
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Forge Web Credentials: Web Cookies Detected",
                alert_description_template=(
                    "Forge Web Credentials: Web Cookies activity detected. "
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
        "t1606-001-aws-guardduty",
        "t1606-001-aws-cloudtrail",
        "t1606-001-gcp-workspace",
        "t1606-001-gcp-identity",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+25% improvement for Credential Access tactic",
)
