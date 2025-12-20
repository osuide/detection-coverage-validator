"""
T1111 - Multi-Factor Authentication Interception

Adversaries target MFA mechanisms including smart cards, hardware tokens, and
out-of-band authentication to intercept credentials and one-time passcodes.
Used by APT42, Chimera, Kimsuky, LAPSUS$, and Leviathan.
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
    technique_id="T1111",
    technique_name="Multi-Factor Authentication Interception",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1111/",
    threat_context=ThreatContext(
        description=(
            "Adversaries intercept MFA mechanisms including smart cards, hardware tokens, "
            "and out-of-band authentication codes. Attack vectors include keyloggers capturing "
            "passwords and token values, intercepting SMS/email one-time codes, SIM swapping, "
            "and compromising SMS providers to steal authentication codes."
        ),
        attacker_goal="Intercept MFA codes to gain unauthorised access while bypassing multi-factor authentication",
        why_technique=[
            "MFA tokens are often transmitted insecurely",
            "SMS and email can be intercepted",
            "Keyloggers can capture both passwords and token values",
            "SIM swapping enables SMS interception",
            "Hardware tokens vulnerable to proximity attacks",
            "Users assume MFA provides complete security",
        ],
        known_threat_actors=["APT42", "Chimera", "Kimsuky", "LAPSUS$", "Leviathan"],
        recent_campaigns=[
            Campaign(
                name="APT42 SMS Interception",
                year=2024,
                description="Intercepted SMS-based one-time passwords using fake websites capturing MFA tokens",
                reference_url="https://attack.mitre.org/groups/G1042/",
            ),
            Campaign(
                name="Chimera Phone Number Registration",
                year=2023,
                description="Registered alternate phone numbers for compromised users to intercept SMS 2FA codes",
                reference_url="https://attack.mitre.org/groups/G0114/",
            ),
            Campaign(
                name="Kimsuky Custom Interception Tools",
                year=2024,
                description="Deployed proprietary tools to intercept two-factor authentication one-time passwords",
                reference_url="https://attack.mitre.org/groups/G0094/",
            ),
            Campaign(
                name="LAPSUS$ Session Token Replay",
                year=2022,
                description="Replayed stolen session tokens attempting to trigger user approval for MFA prompts",
                reference_url="https://attack.mitre.org/groups/G1004/",
            ),
            Campaign(
                name="Leviathan MFA Token Collection",
                year=2023,
                description="Abused appliance access to collect MFA token values during authentication",
                reference_url="https://attack.mitre.org/groups/G0065/",
            ),
        ],
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Effective bypass of MFA security controls. Enables unauthorised access despite "
            "multi-factor authentication being enabled. Particularly effective against SMS and "
            "email-based MFA. Difficult for users to detect during active attack."
        ),
        business_impact=[
            "Complete bypass of MFA protection",
            "Unauthorised access to protected accounts and resources",
            "Potential compliance violations (PCI DSS, SOC 2)",
            "Loss of trust in security controls",
            "Account takeover and data exfiltration",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1530", "T1537"],
        often_follows=["T1110", "T1566", "T1528"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - SMS MFA Authentication from Unusual Locations
        DetectionStrategy(
            strategy_id="t1111-aws-sms-anomaly",
            name="AWS SMS MFA from Anomalous Locations",
            description="Detect SMS-based MFA authentication attempts from unusual geographic locations or IP addresses.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, awsRegion, errorCode
| filter eventSource = "signin.amazonaws.com"
| filter eventName = "ConsoleLogin"
| filter additionalEventData.MFAUsed = "Yes"
| filter errorCode = "Success"
| stats count(*) as login_attempts by userIdentity.userName, sourceIPAddress, awsRegion, bin(5m)
| filter login_attempts > 1""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect potential MFA interception via anomalous authentication patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: MFA Interception Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for MFA authentication from new locations
  MFALocationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed = "Yes" && $.responseElements.ConsoleLogin = "Success" }'
      MetricTransformations:
        - MetricName: MFAAuthentications
          MetricNamespace: Security/T1111
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alarm for suspicious MFA authentication patterns
  MFAInterceptionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1111-MFAInterception
      AlarmDescription: Alert on potential MFA interception attempts
      MetricName: MFAAuthentications
      Namespace: Security/T1111
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

Outputs:
  AlertTopicArn:
    Description: SNS Topic ARN for MFA alerts
    Value: !Ref AlertTopic""",
                terraform_template="""# Detect potential MFA interception via anomalous authentication patterns

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "mfa_interception_alerts" {
  name         = "mfa-interception-alerts"
  display_name = "MFA Interception Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.mfa_interception_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for MFA authentication from new locations
resource "aws_cloudwatch_log_metric_filter" "mfa_locations" {
  name           = "mfa-authentication-attempts"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ $.eventName = \"ConsoleLogin\" && $.additionalEventData.MFAUsed = \"Yes\" && $.responseElements.ConsoleLogin = \"Success\" }"

  metric_transformation {
    name      = "MFAAuthentications"
    namespace = "Security/T1111"
    value     = "1"
  }
}

# Step 3: Alarm for suspicious MFA authentication patterns
resource "aws_cloudwatch_metric_alarm" "mfa_interception" {
  alarm_name          = "mfa-interception-detection"
  alarm_description   = "Alert on potential MFA interception attempts"
  metric_name         = "MFAAuthentications"
  namespace           = "Security/T1111"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.mfa_interception_alerts.arn]
  treat_missing_data  = "notBreaching"
}

output "alert_topic_arn" {
  description = "SNS Topic ARN for MFA alerts"
  value       = aws_sns_topic.mfa_interception_alerts.arn
}""",
                alert_severity="high",
                alert_title="Potential MFA Interception Detected",
                alert_description_template=(
                    "Suspicious MFA authentication pattern detected for user {userName} from IP {sourceIPAddress}. "
                    "Multiple successful MFA authentications in short time period may indicate token interception."
                ),
                investigation_steps=[
                    "Review authentication source IP and geographic location",
                    "Check if user reports unusual MFA prompts or SMS messages",
                    "Verify if user's mobile number has been changed recently",
                    "Review CloudTrail for account modification events",
                    "Check for SIM swap indicators or phone number changes",
                    "Analyse authentication patterns and timing",
                ],
                containment_actions=[
                    "Contact user via out-of-band communication immediately",
                    "Temporarily disable SMS-based MFA for affected account",
                    "Force re-authentication with phishing-resistant MFA",
                    "Lock account until user confirms legitimate access",
                    "Review and revoke active sessions",
                    "Migrate to hardware security keys or authenticator apps",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on normal user travel patterns and VPN usage",
            detection_coverage="65% - catches location-based anomalies but may miss sophisticated attacks",
            evasion_considerations="Attackers using VPNs matching user's normal locations can evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Console login events logged"],
        ),
        # Strategy 2: AWS - Detect Cognito SMS MFA Code Replay
        DetectionStrategy(
            strategy_id="t1111-aws-cognito-sms",
            name="AWS Cognito SMS Code Replay Detection",
            description="Detect potential replay of SMS MFA codes in Cognito by monitoring rapid authentication attempts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters.challengeName
| filter eventSource = "cognito-idp.amazonaws.com"
| filter eventName in ["RespondToAuthChallenge", "AdminRespondToAuthChallenge"]
| filter requestParameters.challengeName = "SMS_MFA"
| stats count(*) as attempts by userIdentity.userName, sourceIPAddress, bin(2m)
| filter attempts > 2
| sort attempts desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect SMS MFA code replay attempts in Cognito

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Cognito MFA Interception
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for SMS MFA challenges
  SMSMFAFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "cognito-idp.amazonaws.com" && ($.eventName = "RespondToAuthChallenge" || $.eventName = "AdminRespondToAuthChallenge") }'
      MetricTransformations:
        - MetricName: CognitoSMSMFAChallenges
          MetricNamespace: Security/T1111
          MetricValue: "1"

  # Step 3: Alarm for rapid SMS MFA attempts
  SMSReplayAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1111-CognitoSMSReplay
      AlarmDescription: Multiple SMS MFA challenges may indicate code interception
      MetricName: CognitoSMSMFAChallenges
      Namespace: Security/T1111
      Statistic: Sum
      Period: 120
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect SMS MFA code replay attempts in Cognito

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

# Step 1: SNS topic
resource "aws_sns_topic" "cognito_sms_alerts" {
  name         = "cognito-sms-mfa-alerts"
  display_name = "Cognito MFA Interception"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cognito_sms_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for SMS MFA challenges
resource "aws_cloudwatch_log_metric_filter" "sms_mfa" {
  name           = "cognito-sms-mfa-challenges"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ $.eventSource = \"cognito-idp.amazonaws.com\" && ($.eventName = \"RespondToAuthChallenge\" || $.eventName = \"AdminRespondToAuthChallenge\") }"

  metric_transformation {
    name      = "CognitoSMSMFAChallenges"
    namespace = "Security/T1111"
    value     = "1"
  }
}

# Step 3: Alarm for rapid SMS MFA attempts
resource "aws_cloudwatch_metric_alarm" "sms_replay" {
  alarm_name          = "cognito-sms-mfa-replay"
  alarm_description   = "Multiple SMS MFA challenges may indicate code interception"
  metric_name         = "CognitoSMSMFAChallenges"
  namespace           = "Security/T1111"
  statistic           = "Sum"
  period              = 120
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.cognito_sms_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Cognito SMS MFA Code Replay Detected",
                alert_description_template=(
                    "Multiple SMS MFA challenge attempts detected for user pool. "
                    "This pattern may indicate MFA code interception or replay."
                ),
                investigation_steps=[
                    "Identify affected user from CloudTrail logs",
                    "Check if SMS codes were sent to expected phone number",
                    "Review recent phone number changes in user profile",
                    "Verify if user reports receiving unexpected SMS codes",
                    "Check authentication success/failure patterns",
                    "Review IP addresses of authentication attempts",
                ],
                containment_actions=[
                    "Temporarily disable affected user account",
                    "Remove SMS-based MFA and require re-registration",
                    "Migrate user to TOTP-based MFA (authenticator app)",
                    "Verify user's phone number via out-of-band method",
                    "Enable rate limiting on MFA attempts",
                    "Invalidate all existing sessions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Users may legitimately retry MFA codes; adjust threshold for user behaviour",
            detection_coverage="70% - catches rapid replay attempts but not slow-paced attacks",
            evasion_considerations="Attackers spacing out attempts can evade time-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail logging Cognito events",
                "SMS MFA enabled in Cognito",
            ],
        ),
        # Strategy 3: AWS - Phone Number Change Detection
        DetectionStrategy(
            strategy_id="t1111-aws-phone-change",
            name="AWS IAM User Phone Number Modification",
            description="Detect changes to user phone numbers which may indicate SIM swap or account takeover for MFA interception.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.cognito-idp"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "SetUserMFAPreference",
                            "AdminSetUserMFAPreference",
                            "UpdateUserAttributes",
                            "AdminUpdateUserAttributes",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect user phone number changes that may facilitate MFA interception

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Phone Number Change Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for phone number changes
  PhoneChangeRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1111-PhoneNumberChange
      Description: Detect phone number modifications
      EventPattern:
        source: [aws.cognito-idp]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - UpdateUserAttributes
            - AdminUpdateUserAttributes
      State: ENABLED
      Targets:
        - Id: AlertTarget
          Arn: !Ref AlertTopic

  # Step 3: SNS topic policy
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
                terraform_template="""# Detect user phone number changes that may facilitate MFA interception

variable "alert_email" { type = string }

# Step 1: SNS topic
resource "aws_sns_topic" "phone_change_alerts" {
  name         = "phone-number-change-alerts"
  display_name = "Phone Number Change Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.phone_change_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for phone number changes
resource "aws_cloudwatch_event_rule" "phone_change" {
  name        = "phone-number-modification"
  description = "Detect phone number modifications"

  event_pattern = jsonencode({
    source      = ["aws.cognito-idp"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "UpdateUserAttributes",
        "AdminUpdateUserAttributes"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.phone_change.name
  arn  = aws_sns_topic.phone_change_alerts.arn
}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.phone_change_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.phone_change_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="User Phone Number Modified",
                alert_description_template=(
                    "Phone number changed for user {userName}. This may indicate SIM swap or "
                    "account compromise to facilitate SMS MFA interception."
                ),
                investigation_steps=[
                    "Contact user immediately via previous known phone number",
                    "Verify if user initiated the phone number change",
                    "Check source IP and location of the change",
                    "Review recent authentication history",
                    "Check for other account attribute changes",
                    "Investigate potential SIM swap with mobile carrier",
                ],
                containment_actions=[
                    "Immediately lock the affected account",
                    "Revert phone number to original if unauthorised",
                    "Disable SMS-based MFA temporarily",
                    "Force password reset via email verification",
                    "Enable alternative MFA method (TOTP, hardware key)",
                    "Revoke all active sessions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate phone changes occur during onboarding or phone upgrades",
            detection_coverage="95% - catches phone number modifications via Cognito API",
            evasion_considerations="Direct database manipulation would bypass detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "Cognito user pools configured"],
        ),
        # Strategy 4: GCP - SMS MFA Interception Detection
        DetectionStrategy(
            strategy_id="t1111-gcp-sms-intercept",
            name="GCP Workspace SMS MFA Interception",
            description="Detect potential SMS MFA code interception in Google Workspace via unusual authentication patterns.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="login.googleapis.com"
protoPayload.methodName=~"google.login.LoginService.2sv"
severity="WARNING"''',
                gcp_terraform_template="""# GCP: Detect SMS MFA interception attempts

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "MFA Interception Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for SMS 2SV failures
resource "google_logging_metric" "sms_2sv_attempts" {
  name   = "sms-2sv-interception-attempts"
  filter = <<-EOT
    protoPayload.serviceName="login.googleapis.com"
    protoPayload.methodName=~"google.login.LoginService.2sv"
    severity="WARNING"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for SMS interception
resource "google_monitoring_alert_policy" "sms_interception" {
  display_name = "SMS MFA Interception Detected"
  combiner     = "OR"

  conditions {
    display_name = "Multiple SMS 2SV attempts"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sms_2sv_attempts.name}\""
      duration        = "120s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Multiple SMS-based 2-Step Verification attempts detected. Potential MFA code interception."
  }
}""",
                alert_severity="high",
                alert_title="GCP: SMS MFA Interception Suspected",
                alert_description_template=(
                    "Multiple SMS-based 2-Step Verification attempts detected for user {userEmail}. "
                    "Potential MFA code interception or replay attack."
                ),
                investigation_steps=[
                    "Review authentication logs for user",
                    "Check IP addresses and geographic locations",
                    "Verify if user reports unusual SMS messages",
                    "Check for recent phone number changes",
                    "Review account recovery activity",
                    "Check for SIM swap indicators",
                ],
                containment_actions=[
                    "Suspend user account immediately",
                    "Contact user via alternative communication channel",
                    "Disable SMS-based 2SV for affected user",
                    "Require security key or authenticator app re-enrolment",
                    "Force password reset",
                    "Revoke all active sessions and tokens",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on normal retry patterns in your organisation",
            detection_coverage="70% - catches repeated authentication attempts",
            evasion_considerations="Slow-paced attacks may evade time-based thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Google Workspace",
                "Admin audit logs enabled",
                "Login audit logs enabled",
            ],
        ),
        # Strategy 5: GCP - Phone Number Change Detection
        DetectionStrategy(
            strategy_id="t1111-gcp-phone-change",
            name="GCP Workspace Phone Number Modification",
            description="Detect phone number changes that may facilitate SMS MFA interception.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="admin.googleapis.com"
protoPayload.methodName="google.admin.AdminService.changeUser"
protoPayload.request.user.phone=*""",
                gcp_terraform_template="""# GCP: Detect phone number changes for MFA interception

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Phone Change Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for phone number changes
resource "google_logging_metric" "phone_changes" {
  name   = "user-phone-number-changes"
  filter = <<-EOT
    protoPayload.serviceName="admin.googleapis.com"
    protoPayload.methodName="google.admin.AdminService.changeUser"
    protoPayload.request.user.phone=*
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for phone changes
resource "google_monitoring_alert_policy" "phone_change" {
  display_name = "User Phone Number Changed"
  combiner     = "OR"

  conditions {
    display_name = "Phone number modification detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.phone_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "User phone number changed. Verify legitimacy to prevent SMS MFA interception."
  }
}""",
                alert_severity="high",
                alert_title="GCP: User Phone Number Modified",
                alert_description_template=(
                    "Phone number changed for user {userEmail} by {principalEmail}. "
                    "Verify this change to prevent SMS MFA interception."
                ),
                investigation_steps=[
                    "Contact user at previous phone number",
                    "Verify if user authorised the change",
                    "Check who made the modification",
                    "Review authentication logs for suspicious activity",
                    "Check for other account modifications",
                    "Investigate potential SIM swap",
                ],
                containment_actions=[
                    "Revert phone number if unauthorised",
                    "Suspend account until verification complete",
                    "Disable SMS-based 2SV",
                    "Require security key enrolment",
                    "Force password reset",
                    "Enable advanced protection programme",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Phone changes are infrequent; all changes warrant review",
            detection_coverage="100% - catches all phone number changes via Admin API",
            evasion_considerations="Direct database access would bypass detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=["Google Workspace", "Admin audit logs enabled"],
        ),
    ],
    recommended_order=[
        "t1111-aws-phone-change",
        "t1111-gcp-phone-change",
        "t1111-aws-sms-anomaly",
        "t1111-aws-cognito-sms",
        "t1111-gcp-sms-intercept",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+12% improvement for Credential Access tactic",
)
