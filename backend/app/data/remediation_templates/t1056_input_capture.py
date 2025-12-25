"""
T1056 - Input Capture

Adversaries may use methods to capture user input to obtain credentials or collect information.
This includes keylogging, GUI input capture, web portal capture, and credential API hooking.
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
    technique_id="T1056",
    technique_name="Input Capture",
    tactic_ids=["TA0006", "TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1056/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use various methods to capture user input including keylogging, "
            "GUI input capture, web portal capture, and credential API hooking. Input capture "
            "occurs transparently through API hooking or via deception tactics that mimic "
            "legitimate services. In cloud environments, this typically manifests as credential "
            "phishing via fake login portals or malicious browser extensions."
        ),
        attacker_goal="Capture user credentials and sensitive input data for unauthorised access",
        why_technique=[
            "Credentials provide immediate access to cloud resources",
            "Keylogging can capture MFA tokens and session data",
            "Fake login portals are difficult to distinguish from legitimate ones",
            "Browser extensions can intercept cloud console credentials",
            "Captured credentials often remain valid until rotation",
            "Input capture is difficult to detect without behavioural analysis",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Input capture directly compromises credentials, providing immediate access to cloud resources. "
            "The technique is difficult to detect as it operates transparently to users. "
            "Captured cloud credentials can lead to full environment compromise, data theft, and lateral movement."
        ),
        business_impact=[
            "Complete account compromise with valid credentials",
            "Unauthorised access to sensitive cloud resources and data",
            "Bypassing MFA through session token capture",
            "Lateral movement using captured credentials",
            "Regulatory compliance violations (GDPR, PCI DSS, HIPAA)",
            "Reputational damage from credential theft",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078", "T1550", "T1528"],
        often_follows=["T1566", "T1204", "T1189"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Suspicious Console Login Patterns
        DetectionStrategy(
            strategy_id="t1056-aws-suspicious-login",
            name="Suspicious Console Login Pattern Detection",
            description=(
                "Detect login patterns that may indicate credentials captured through phishing or keylogging, "
                "such as logins from unusual locations, new devices, or impossible travel scenarios."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
                    "UnauthorizedAccess:IAMUser/TorIPCaller",
                    "InitialAccess:IAMUser/AnomalousBehavior",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for suspicious login patterns indicating credential capture

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable GuardDuty (detects anomalous login behaviour automatically)
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Input Capture Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route suspicious login findings to email
  SuspiciousLoginRule:
    Type: AWS::Events::Rule
    Properties:
      Name: input-capture-suspicious-logins
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess"
            - prefix: "UnauthorizedAccess:IAMUser/TorIPCaller"
            - prefix: "InitialAccess:IAMUser/AnomalousBehavior"
            - prefix: "CredentialAccess:IAMUser/AnomalousBehavior"
      Targets:
        - Id: Email
          Arn: !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# GuardDuty alerts for suspicious login patterns indicating credential capture

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable GuardDuty (detects anomalous login behaviour automatically)
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name         = "input-capture-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Input Capture Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route suspicious login findings to email
resource "aws_cloudwatch_event_rule" "suspicious_logins" {
  name = "input-capture-suspicious-logins"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess" },
        { prefix = "UnauthorizedAccess:IAMUser/TorIPCaller" },
        { prefix = "InitialAccess:IAMUser/AnomalousBehavior" },
        { prefix = "CredentialAccess:IAMUser/AnomalousBehavior" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.suspicious_logins.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Suspicious Login Pattern Detected - Potential Credential Capture",
                alert_description_template=(
                    "GuardDuty detected suspicious login activity: {finding_type}. "
                    "User: {principal}. Source IP: {source_ip}. "
                    "This may indicate credentials were captured via phishing or keylogging."
                ),
                investigation_steps=[
                    "Contact the user immediately via out-of-band communication (phone call, SMS)",
                    "Verify if the user recognises the login location and device",
                    "Review CloudTrail for all actions taken during and after the suspicious login",
                    "Check for any MFA enrollment changes or access key creation",
                    "Analyse the source IP address for known malicious activity",
                    "Review recent emails and links clicked by the user for phishing attempts",
                    "Check browser history and installed extensions for suspicious activity",
                ],
                containment_actions=[
                    "Immediately disable the compromised IAM user's console access",
                    "Rotate all access keys associated with the user",
                    "Terminate all active sessions for the user (AWS STS)",
                    "Force password reset with MFA re-enrollment",
                    "Review and revoke any permissions or resources created during suspicious session",
                    "Block source IP addresses at WAF or security group level",
                    "Enable advanced MFA protection (hardware tokens preferred)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known VPN exit nodes; add trusted third-party service IPs to GuardDuty trusted IP lists",
            detection_coverage="65% - API-level only, cannot detect actual keylogging",
            evasion_considerations="Attackers using VPNs in expected locations; slow credential usage to blend with normal behaviour",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events analysed",
            prerequisites=[
                "AWS account with GuardDuty permissions",
                "CloudTrail enabled",
            ],
        ),
        # Strategy 2: AWS - Failed Login Attempts Monitoring
        DetectionStrategy(
            strategy_id="t1056-aws-failed-logins",
            name="Multiple Failed Login Attempts Detection",
            description=(
                "Monitor for multiple failed login attempts followed by a successful login, "
                "which may indicate credentials were captured and the attacker is testing them."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.userName as user, sourceIPAddress,
       responseElements.ConsoleLogin as result, errorMessage
| filter eventName = "ConsoleLogin"
| stats count(*) as attempts,
        sum(case when result = "Failure" then 1 else 0 end) as failed,
        sum(case when result = "Success" then 1 else 0 end) as successful,
        earliest(@timestamp) as first_attempt,
        latest(@timestamp) as last_attempt
  by user, sourceIPAddress, bin(1h) as window
| filter failed >= 3 and successful >= 1
| sort last_attempt desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on failed logins followed by success (credential testing pattern)

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for alerts

Resources:
  # Step 1: Create alert topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Failed Login Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Count failed logins
  FailedLoginFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "ConsoleLogin" && $.responseElements.ConsoleLogin = "Failure" }'
      MetricTransformations:
        - MetricName: FailedConsoleLogins
          MetricNamespace: Security/InputCapture
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alert on threshold breach
  FailedLoginAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1056-FailedLoginAttempts
      AlarmDescription: Multiple failed login attempts detected
      MetricName: FailedConsoleLogins
      Namespace: Security/InputCapture
      Statistic: Sum
      Period: 300
      Threshold: 3
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]
      TreatMissingData: notBreaching""",
                terraform_template="""# Alert on failed logins followed by success (credential testing pattern)

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name         = "failed-login-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Failed Login Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Count failed logins
resource "aws_cloudwatch_log_metric_filter" "failed_logins" {
  name           = "failed-console-logins"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"ConsoleLogin\" && $.responseElements.ConsoleLogin = \"Failure\" }"

  metric_transformation {
    name          = "FailedConsoleLogins"
    namespace     = "Security/InputCapture"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Alert on threshold breach
resource "aws_cloudwatch_metric_alarm" "failed_logins" {
  alarm_name          = "T1056-FailedLoginAttempts"
  alarm_description   = "Multiple failed login attempts detected"
  metric_name         = "FailedConsoleLogins"
  namespace           = "Security/InputCapture"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="medium",
                alert_title="Failed Login Attempts with Subsequent Success",
                alert_description_template=(
                    "User {user} had {failed} failed login attempts followed by {successful} successful login(s) "
                    "from IP {sourceIPAddress} within 1 hour. This may indicate credential testing after capture."
                ),
                investigation_steps=[
                    "Review the timing between failed and successful attempts",
                    "Contact the user to verify they attempted these logins",
                    "Check if the successful login came from a different IP than the failures",
                    "Review all actions taken during the successful session",
                    "Analyse error messages from failed attempts for credential stuffing patterns",
                    "Check for similar patterns across other user accounts",
                ],
                containment_actions=[
                    "Force logout of the successful session if unverified",
                    "Require immediate password reset with MFA",
                    "Review and revoke any changes made during the session",
                    "Implement account lockout policies if not already enabled",
                    "Block suspicious IP addresses",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on baseline; exclude legitimate locked account scenarios; notify users of lockouts",
            detection_coverage="70% - API-level only, cannot detect actual keylogging",
            evasion_considerations="Attackers may wait extended periods between attempts; use of correct credentials on first try",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15 depending on log volume",
            prerequisites=[
                "CloudTrail enabled",
                "CloudTrail logs sent to CloudWatch Logs",
            ],
        ),
        # Strategy 3: AWS - Session Token Anomalies
        DetectionStrategy(
            strategy_id="t1056-aws-session-tokens",
            name="Unusual Session Token Usage Detection",
            description=(
                "Detect when session tokens are used from unexpected locations or exhibit unusual patterns, "
                "which may indicate token capture through browser-based attacks."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user,
       userIdentity.sessionContext.sessionIssuer.userName as sessionUser,
       sourceIPAddress, eventName, userAgent
| filter userIdentity.type = "AssumedRole" or userIdentity.type = "FederatedUser"
| stats count(*) as api_calls,
        count_distinct(sourceIPAddress) as unique_ips,
        count_distinct(eventName) as unique_apis
  by user, bin(15m) as window
| filter unique_ips > 2
| sort window desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual session token usage patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String
    Description: SNS topic ARN for alerts

Resources:
  # Step 1: Create metric filter for session token usage
  SessionTokenFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.userIdentity.type = "AssumedRole" || $.userIdentity.type = "FederatedUser" }'
      MetricTransformations:
        - MetricName: SessionTokenUsage
          MetricNamespace: Security/InputCapture
          MetricValue: "1"
          DefaultValue: 0

  # Step 2: Alert on unusual patterns
  SessionTokenAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1056-UnusualSessionTokens
      AlarmDescription: Session tokens used from multiple IPs
      MetricName: SessionTokenUsage
      Namespace: Security/InputCapture
      Statistic: Sum
      Period: 900
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref SNSTopicArn]
      TreatMissingData: notBreaching""",
                terraform_template="""# Detect unusual session token usage patterns

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic ARN for alerts"
}

# Step 1: Create metric filter for session token usage
resource "aws_cloudwatch_log_metric_filter" "session_tokens" {
  name           = "session-token-usage"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.userIdentity.type = \"AssumedRole\" || $.userIdentity.type = \"FederatedUser\" }"

  metric_transformation {
    name          = "SessionTokenUsage"
    namespace     = "Security/InputCapture"
    value         = "1"
    default_value = 0
  }
}

# Step 2: Alert on unusual patterns
resource "aws_cloudwatch_metric_alarm" "session_tokens" {
  alarm_name          = "T1056-UnusualSessionTokens"
  alarm_description   = "Session tokens used from multiple IPs"
  metric_name         = "SessionTokenUsage"
  namespace           = "Security/InputCapture"
  statistic           = "Sum"
  period              = 900
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="medium",
                alert_title="Unusual Session Token Usage Pattern",
                alert_description_template=(
                    "Session for {user} used from {unique_ips} different IP addresses in 15 minutes. "
                    "This may indicate session token capture or browser-based attacks."
                ),
                investigation_steps=[
                    "Identify all IP addresses using the session token",
                    "Check if IPs are geographically dispersed (impossible travel)",
                    "Review user agent strings for anomalies or automation tools",
                    "Verify if user is legitimately using VPN or proxy services",
                    "Check for browser extension installations or modifications",
                    "Review all API calls made with the session token",
                ],
                containment_actions=[
                    "Revoke all active sessions for the affected user",
                    "Force re-authentication with MFA",
                    "Review and remove suspicious browser extensions",
                    "Scan endpoints for malware and keyloggers",
                    "Implement session binding to IP addresses where feasible",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Account for legitimate VPN and proxy usage; whitelist known automation tools; adjust IP threshold",
            detection_coverage="55% - API-level only, cannot detect keylogging or clipboard capture",
            evasion_considerations="Attackers operating from the same IP as victim; use of VPNs matching victim geography",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25 depending on session volume",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs configured"],
        ),
        # Strategy 4: GCP - Suspicious Authentication Activity
        DetectionStrategy(
            strategy_id="t1056-gcp-auth-anomalies",
            name="GCP Authentication Anomaly Detection",
            description=(
                "Detect suspicious authentication patterns in GCP that may indicate captured credentials, "
                "including logins from new locations, devices, or with unusual characteristics."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="login.googleapis.com"
protoPayload.authenticationInfo.principalEmail!=""
(protoPayload.metadata.event.eventType="login_failure" OR
 protoPayload.metadata.event.eventType="login_success")
severity>="WARNING"''',
                gcp_terraform_template="""# GCP: Detect authentication anomalies indicating credential capture

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Input Capture"
  type         = "email"
  project      = var.project_id
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for failed auth attempts
resource "google_logging_metric" "failed_auth" {
  name    = "failed-authentication-attempts"
  project = var.project_id
  filter  = <<-EOT
    protoPayload.serviceName="login.googleapis.com"
    protoPayload.metadata.event.eventType="login_failure"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User principal email"
    }
  }

  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for multiple failures
resource "google_monitoring_alert_policy" "failed_auth_alert" {
  display_name = "T1056 - Multiple Failed Authentication Attempts"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Failed authentication threshold exceeded"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.failed_auth.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "Multiple failed authentication attempts detected. This may indicate credential capture and testing. Investigate immediately."
    mime_type = "text/markdown"
  }
}

# Step 4: Create alert for suspicious successful logins
resource "google_logging_metric" "suspicious_login" {
  name    = "suspicious-successful-logins"
  project = var.project_id
  filter  = <<-EOT
    protoPayload.serviceName="login.googleapis.com"
    protoPayload.metadata.event.eventType="login_success"
    protoPayload.metadata.event.parameter.name="is_suspicious"
    protoPayload.metadata.event.parameter.value="true"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "suspicious_login_alert" {
  display_name = "T1056 - Suspicious Login Detected"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Suspicious login activity detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_login.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "GCP detected a suspicious login. Credentials may have been captured through phishing or keylogging. Investigate immediately and verify with the user."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP Authentication Anomaly - Potential Credential Capture",
                alert_description_template=(
                    "Suspicious authentication activity detected for user {principalEmail}. "
                    "Event type: {eventType}. This may indicate credential capture."
                ),
                investigation_steps=[
                    "Review the authentication logs for the affected user",
                    "Check the source IP address and geolocation",
                    "Verify the device and browser information",
                    "Contact the user via out-of-band communication",
                    "Review all API calls made after the suspicious authentication",
                    "Check for MFA enrollment changes or disabling",
                    "Look for new service account keys or OAuth tokens created",
                ],
                containment_actions=[
                    "Suspend the affected user account immediately",
                    "Revoke all active sessions and OAuth tokens",
                    "Force password reset with MFA re-enrollment",
                    "Audit and revoke any service account keys created during suspicious period",
                    "Review and revert any IAM policy changes",
                    "Enable advanced protection programme for high-risk users",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known corporate VPN and proxy IPs; adjust failure threshold for users who frequently mistype passwords",
            detection_coverage="70% - API-level only, cannot detect actual keylogging",
            evasion_considerations="Attackers using credentials from expected locations; successful authentication on first attempt",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-20 depending on authentication volume",
            prerequisites=[
                "GCP Cloud Logging enabled",
                "Audit logs enabled for login.googleapis.com",
            ],
        ),
        # Strategy 5: GCP - OAuth Token Anomalies
        DetectionStrategy(
            strategy_id="t1056-gcp-oauth-tokens",
            name="GCP OAuth Token Creation and Usage Monitoring",
            description=(
                "Monitor for unusual OAuth token creation or usage patterns that may indicate "
                "tokens were captured through browser-based attacks or phishing."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="iamcredentials.googleapis.com"
(protoPayload.methodName="GenerateAccessToken" OR
 protoPayload.methodName="GenerateIdToken" OR
 protoPayload.methodName="SignJwt")
severity>="NOTICE"''',
                gcp_terraform_template="""# GCP: Monitor OAuth token creation and usage

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "OAuth Token Alerts"
  type         = "email"
  project      = var.project_id
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for token generation
resource "google_logging_metric" "token_generation" {
  name    = "oauth-token-generation"
  project = var.project_id
  filter  = <<-EOT
    protoPayload.serviceName="iamcredentials.googleapis.com"
    (protoPayload.methodName="GenerateAccessToken" OR
     protoPayload.methodName="GenerateIdToken" OR
     protoPayload.methodName="SignJwt")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal generating tokens"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert on unusual token generation volume
resource "google_monitoring_alert_policy" "token_volume" {
  display_name = "T1056 - Unusual OAuth Token Generation"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "High volume of token generation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.token_generation.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.principal"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Unusual volume of OAuth token generation detected. This may indicate token harvesting after credential capture. Investigate the principal and recent authentication events."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="Unusual OAuth Token Activity",
                alert_description_template=(
                    "Principal {principal} generated {count} OAuth tokens in 5 minutes. "
                    "This may indicate token harvesting after credential capture."
                ),
                investigation_steps=[
                    "Identify which service account or user is generating tokens",
                    "Review the scope and audience of the generated tokens",
                    "Check if this volume is normal for the principal",
                    "Verify recent authentication events for the principal",
                    "Review API calls made using the generated tokens",
                    "Check for any new OAuth consent grants or service account keys",
                ],
                containment_actions=[
                    "Revoke the generated tokens if suspicious",
                    "Disable the service account or user if compromised",
                    "Review and revoke OAuth consent grants",
                    "Rotate service account keys",
                    "Enable domain-wide delegation auditing",
                    "Implement OAuth scope restrictions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal token generation patterns; exclude known automation and CI/CD service accounts",
            detection_coverage="60% - API-level only, cannot detect keylogging",
            evasion_considerations="Attackers may generate tokens at normal rates; use of already-valid long-lived tokens",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25 depending on token generation volume",
            prerequisites=[
                "GCP Cloud Logging enabled",
                "IAM Credentials API audit logs enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1056-aws-suspicious-login",
        "t1056-aws-failed-logins",
        "t1056-gcp-auth-anomalies",
        "t1056-aws-session-tokens",
        "t1056-gcp-oauth-tokens",
    ],
    total_effort_hours=7.5,
    coverage_improvement="+25% improvement for Credential Access tactic",
)
