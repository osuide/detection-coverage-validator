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
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
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
      KmsMasterKeyId: alias/aws/sns
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
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 4: SNS topic policy
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
  kms_master_key_id = "alias/aws/sns"
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
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.mfa_interception_alerts.arn]
}

# Step 4: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.mfa_interception_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.mfa_interception_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
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
      KmsMasterKeyId: alias/aws/sns
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
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 4: SNS topic policy
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
                terraform_template="""# Detect SMS MFA code replay attempts in Cognito

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

# Step 1: SNS topic
resource "aws_sns_topic" "cognito_sms_alerts" {
  name         = "cognito-sms-mfa-alerts"
  kms_master_key_id = "alias/aws/sns"
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
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cognito_sms_alerts.arn]
}

# Step 4: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.cognito_sms_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.cognito_sms_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
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
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Phone Number Change Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: DLQ for EventBridge
  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600

  # Step 3: EventBridge rule for phone number changes
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
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAgeInSeconds: 3600
          DeadLetterConfig:
            Arn: !GetAtt DLQ.Arn

  # Step 4: SNS topic policy with scoped conditions
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublish
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt PhoneChangeRule.Arn""",
                terraform_template="""# Detect user phone number changes that may facilitate MFA interception

variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

# Step 1: SNS topic
resource "aws_sns_topic" "phone_change_alerts" {
  name              = "phone-number-change-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name      = "Phone Number Change Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.phone_change_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: DLQ for EventBridge
resource "aws_sqs_queue" "dlq" {
  name                      = "phone-number-change-alerts-dlq"
  message_retention_seconds = 1209600
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.phone_change.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 3: EventBridge rule for phone number changes
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
  rule      = aws_cloudwatch_event_rule.phone_change.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.phone_change_alerts.arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

# Step 4: SNS topic policy with scoped conditions
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.phone_change_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.phone_change_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.phone_change.arn
        }
      }
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
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "MFA Interception Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for SMS 2SV failures
resource "google_logging_metric" "sms_2sv_attempts" {
  project = var.project_id
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
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

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
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Phone Change Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for phone number changes
resource "google_logging_metric" "phone_changes" {
  project = var.project_id
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
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

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
        # Strategy 6: AWS MFA Fatigue Detection
        DetectionStrategy(
            strategy_id="t1111-aws-mfa-fatigue",
            name="AWS MFA Fatigue/Bombing Detection",
            description=(
                "Detect MFA fatigue attacks where adversaries repeatedly trigger MFA push notifications "
                "or challenges to exhaust users into approving a fraudulent request. Also known as "
                "MFA bombing or push notification spam."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, errorCode
| filter eventSource = "signin.amazonaws.com"
| filter eventName = "ConsoleLogin"
| filter additionalEventData.MFAUsed = "Yes"
| stats count(*) as attempts,
        sum(case errorCode when "FailedAuthentication" then 1 else 0 end) as failed,
        sum(case errorCode when "Success" then 1 else 0 end) as success
        by userIdentity.userName, bin(10m)
| filter attempts > 5 AND failed > 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect MFA fatigue attacks - multiple rapid MFA challenges

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts
  MFAAttemptThreshold:
    Type: Number
    Default: 5
    Description: Number of MFA attempts in 10 minutes to trigger alert

Resources:
  # Step 1: SNS topic with DLQ for reliability
  AlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch metric filter for MFA events
  MFALogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/signin/mfa-fatigue
      RetentionInDays: 30

  MFAChallengeMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref MFALogGroup
      FilterPattern: '{ $.eventSource = "signin.amazonaws.com" && $.additionalEventData.MFAUsed = "Yes" }'
      MetricTransformations:
        - MetricName: MFAChallengeCount
          MetricNamespace: Security/MFAFatigue
          MetricValue: "1"
          Dimensions:
            - Key: UserName
              Value: $.userIdentity.userName

  # Step 3: Alarm for MFA fatigue pattern
  MFAFatigueAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1111-MFA-Fatigue-Detected
      AlarmDescription: Multiple MFA challenges detected - possible MFA fatigue attack
      MetricName: MFAChallengeCount
      Namespace: Security/MFAFatigue
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: !Ref MFAAttemptThreshold
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 4: SNS topic policy
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
                terraform_template="""# AWS MFA Fatigue Detection for T1111

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "mfa_attempt_threshold" {
  type        = number
  default     = 5
  description = "MFA attempts in 10 min to trigger alert"
}

# Step 1: SNS with DLQ
resource "aws_sqs_queue" "alert_dlq" {
  name                      = "mfa-fatigue-alert-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sns_topic" "alerts" {
  name = "mfa-fatigue-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Log group for signin events
resource "aws_cloudwatch_log_group" "mfa_signin" {
  name              = "/aws/signin/mfa-fatigue"
  retention_in_days = 30
}

# Step 3: Metric filter for MFA challenges
resource "aws_cloudwatch_log_metric_filter" "mfa_challenges" {
  name           = "mfa-challenge-count"
  log_group_name = aws_cloudwatch_log_group.mfa_signin.name
  pattern        = "{ $.eventSource = \\"signin.amazonaws.com\\" && $.additionalEventData.MFAUsed = \\"Yes\\" }"

  metric_transformation {
    name      = "MFAChallengeCount"
    namespace = "Security/MFAFatigue"
    value     = "1"
    dimensions = {
      UserName = "$.userIdentity.userName"
    }
  }
}

# Step 4: Alarm for MFA fatigue
resource "aws_cloudwatch_metric_alarm" "mfa_fatigue" {
  alarm_name          = "T1111-MFA-Fatigue-Detected"
  alarm_description   = "Multiple MFA challenges detected - possible MFA fatigue attack"
  metric_name         = "MFAChallengeCount"
  namespace           = "Security/MFAFatigue"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = var.mfa_attempt_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 5: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
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
                alert_severity="critical",
                alert_title="MFA Fatigue Attack Detected",
                alert_description_template=(
                    "User {user} received {attempts} MFA challenges in 10 minutes. "
                    "This pattern indicates a potential MFA fatigue/bombing attack where adversaries "
                    "spam push notifications to exhaust the user into approving access."
                ),
                investigation_steps=[
                    "Contact the user immediately via out-of-band channel (phone call)",
                    "Verify if user approved any MFA prompts they did not initiate",
                    "Check source IPs of MFA challenge requests",
                    "Review CloudTrail for any successful logins",
                    "Check if user's password was compromised (recent data breaches)",
                    "Review phishing reports for targeted campaigns",
                ],
                containment_actions=[
                    "Immediately suspend the user account",
                    "Revoke all active sessions",
                    "Reset password with out-of-band verification",
                    "Disable SMS/push-based MFA temporarily",
                    "Require hardware security key for re-enrolment",
                    "Enable IAM Access Analyser for unusual access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Threshold may need adjustment; exclude test accounts",
            detection_coverage="90% - catches most MFA fatigue attacks",
            evasion_considerations="Very slow attacks below threshold; using stolen session tokens instead",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Signin events logging enabled"],
        ),
        # Strategy 7: GCP MFA Fatigue Detection
        DetectionStrategy(
            strategy_id="t1111-gcp-mfa-fatigue",
            name="GCP 2-Step Verification Fatigue Detection",
            description=(
                "Detect 2-Step Verification fatigue attacks in Google Workspace/Cloud Identity "
                "where adversaries trigger multiple verification prompts to exhaust users."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""-- GCP 2SV Fatigue Detection
-- Detects multiple verification challenges for same user
resource.type="login"
AND protoPayload.methodName=~"2sv"
AND protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
-- Group by user and check for high frequency""",
                gcp_terraform_template="""# GCP: 2-Step Verification Fatigue Detection for T1111

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "verification_threshold" {
  type        = number
  default     = 5
  description = "2SV attempts in 10 min to trigger alert"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s3" {
  project      = var.project_id
  display_name = "Security Alerts - MFA Fatigue"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for 2SV challenges
resource "google_logging_metric" "mfa_fatigue" {
  project     = var.project_id
  name        = "mfa-fatigue-2sv-challenges"
  description = "Count of 2-Step Verification challenges"
  filter      = <<-EOT
    resource.type="login"
    AND (protoPayload.methodName=~"LoginService.challenge"
         OR protoPayload.methodName=~"LoginService.2sv")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User receiving 2SV challenges"
    }
  }

  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for 2SV fatigue
resource "google_monitoring_alert_policy" "mfa_fatigue" {
  project      = var.project_id
  display_name = "T1111 - 2SV Fatigue Attack Detected"
  combiner     = "OR"
  enabled      = true

  conditions {
    display_name = "High 2SV Challenge Rate"
    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/mfa-fatigue-2sv-challenges\\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.verification_threshold
      duration        = "600s"

      aggregations {
        alignment_period   = "600s"
        per_series_aligner = "ALIGN_SUM"
        group_by_fields    = ["metric.label.user"]
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.name]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = <<-EOT
      ## MFA Fatigue Attack Detected

      Multiple 2-Step Verification challenges detected for the same user in a short time period.
      This may indicate an MFA fatigue/bombing attack.

      ### Immediate Actions
      1. Contact user via phone call
      2. Suspend account if compromise confirmed
      3. Revoke all sessions
    EOT
    mime_type = "text/markdown"
  }
}

# Step 4: Log sink for additional analysis
resource "google_logging_project_sink" "mfa_events" {
  project     = var.project_id
  name        = "mfa-fatigue-events-sink"
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/security_logs"
  filter      = <<-EOT
    resource.type="login"
    AND (protoPayload.methodName=~"LoginService.challenge"
         OR protoPayload.methodName=~"LoginService.2sv")
  EOT

  unique_writer_identity = true
}""",
                alert_severity="critical",
                alert_title="GCP: 2-Step Verification Fatigue Attack",
                alert_description_template=(
                    "User {user} received {count} 2-Step Verification challenges in 10 minutes. "
                    "This pattern indicates a potential MFA fatigue attack."
                ),
                investigation_steps=[
                    "Contact user via phone call immediately",
                    "Check if user approved any 2SV prompts they did not initiate",
                    "Review Admin Console login audit logs",
                    "Check source IPs of login attempts",
                    "Verify user's password hasn't been compromised",
                    "Check for phishing emails targeting the user",
                ],
                containment_actions=[
                    "Suspend user account in Admin Console",
                    "Sign out all sessions",
                    "Reset password with verification",
                    "Enrol security key (requires Advanced Protection)",
                    "Review and revoke third-party app access",
                    "Enable Context-Aware Access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust threshold based on organisation size; exclude test users",
            detection_coverage="85% - catches most 2SV fatigue patterns",
            evasion_considerations="Slow attacks; phishing without MFA challenge",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Google Workspace with audit logs",
                "Cloud Logging API enabled",
                "Cloud Monitoring API enabled",
            ],
        ),
        # Azure Strategy: Multi-Factor Authentication Interception
        DetectionStrategy(
            strategy_id="t1111-azure",
            name="Azure Multi-Factor Authentication Interception Detection",
            description=(
                "Azure detection for Multi-Factor Authentication Interception. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Multi-Factor Authentication Interception (T1111)
# Microsoft Defender detects Multi-Factor Authentication Interception activity

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
  name                = "defender-t1111-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1111"
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

  description = "Microsoft Defender detects Multi-Factor Authentication Interception activity"
  display_name = "Defender: Multi-Factor Authentication Interception"
  enabled      = true
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Multi-Factor Authentication Interception Detected",
                alert_description_template=(
                    "Multi-Factor Authentication Interception activity detected. "
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
        "t1111-aws-mfa-fatigue",
        "t1111-gcp-mfa-fatigue",
        "t1111-aws-phone-change",
        "t1111-gcp-phone-change",
        "t1111-aws-sms-anomaly",
        "t1111-aws-cognito-sms",
        "t1111-gcp-sms-intercept",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+12% improvement for Credential Access tactic",
)
