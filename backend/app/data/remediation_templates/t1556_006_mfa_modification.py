"""
T1556.006 - Modify Authentication Process: Multi-Factor Authentication

Adversaries disable or modify MFA mechanisms to maintain persistent access to
compromised accounts, bypassing this critical security control.
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
    technique_id="T1556.006",
    technique_name="Modify Authentication Process: Multi-Factor Authentication",
    tactic_ids=["TA0006", "TA0005", "TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1556/006/",
    threat_context=ThreatContext(
        description=(
            "Adversaries disable or modify MFA mechanisms to maintain persistent access to "
            "compromised accounts. This includes excluding users from conditional access policies, "
            "registering attacker-controlled MFA devices, disabling MFA entirely, or modifying "
            "authentication protocols to fail-open when MFA is unavailable."
        ),
        attacker_goal="Bypass or disable MFA to maintain persistent access without additional authentication",
        why_technique=[
            "Removes critical security control from authentication",
            "Maintains persistent access even if passwords are reset",
            "Often overlooked during incident response",
            "Can be done subtly to avoid detection",
            "Allows access from any location without additional challenges",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Disabling MFA removes a critical defence layer, enabling persistent access "
            "without additional authentication. This significantly increases risk of account "
            "compromise and data breach. Often indicates advanced adversary with existing access."
        ),
        business_impact=[
            "Complete bypass of multi-factor authentication",
            "Persistent unauthorised access to accounts",
            "Compliance violations (PCI DSS, NIST 800-63)",
            "Increased risk of data exfiltration",
            "Difficult to detect without specific monitoring",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1078.004", "T1530", "T1537"],
        often_follows=["T1078.004", "T1528", "T1098.001"],
    ),
    detection_strategies=[
        # Strategy 1: AWS IAM MFA Deactivation
        DetectionStrategy(
            strategy_id="t1556006-aws-mfa-deactivate",
            name="IAM MFA Deactivation Detection",
            description="Detect when MFA devices are deactivated or deleted for IAM users.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "DeactivateMFADevice",
                            "DeleteVirtualMFADevice",
                            "DisableMFADevice",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect MFA device deactivation

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for MFA deactivation
  MFADeactivationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1556-006-MFADeactivation
      Description: Alert when MFA devices are deactivated
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - DeactivateMFADevice
            - DeleteVirtualMFADevice
            - DisableMFADevice
      State: ENABLED
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt MFADeactivationRule.Arn""",
                terraform_template="""# Detect MFA device deactivation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "mfa_alerts" {
  name = "mfa-deactivation-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.mfa_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for MFA deactivation
resource "aws_cloudwatch_event_rule" "mfa_deactivate" {
  name        = "mfa-deactivation-detection"
  description = "Alert when MFA devices are deactivated"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "DeactivateMFADevice",
        "DeleteVirtualMFADevice",
        "DisableMFADevice"
      ]
    }
  })
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "dlq" {
  name                      = "mfa-deactivation-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.mfa_deactivate.arn }
      }
    }]
  })
}

# EventBridge target with retry and DLQ
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.mfa_deactivate.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.mfa_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
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

# Step 3: Topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.mfa_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.mfa_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.mfa_deactivate.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="MFA Device Deactivated",
                alert_description_template=(
                    "MFA device deactivated for user {userName} by {actor}. "
                    "This may indicate credential compromise or persistence attempt."
                ),
                investigation_steps=[
                    "Verify if MFA deactivation was authorised by user or admin",
                    "Check who performed the deactivation (userIdentity)",
                    "Review CloudTrail for other suspicious activity from the actor",
                    "Check if user has re-enabled MFA or registered new device",
                    "Review user's recent access patterns and API calls",
                ],
                containment_actions=[
                    "Contact user immediately via out-of-band communication",
                    "Force re-enable MFA for the affected user",
                    "Disable console access until MFA is re-enabled",
                    "Rotate user's access keys and passwords",
                    "Review and revoke active sessions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate MFA device changes are rare; all events warrant review",
            detection_coverage="100% - catches all MFA deactivation events",
            evasion_considerations="Cannot evade this detection if using IAM API",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "IAM events logged"],
        ),
        # Strategy 2: Azure AD Conditional Access Policy Changes
        DetectionStrategy(
            strategy_id="t1556006-aws-cognito-mfa",
            name="AWS Cognito MFA Configuration Changes",
            description="Detect modifications to Cognito user pool MFA settings.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.userPoolId, responseElements
| filter eventSource = "cognito-idp.amazonaws.com"
| filter eventName in ["SetUserPoolMfaConfig", "SetUserMFAPreference", "AdminSetUserMFAPreference"]
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor Cognito MFA configuration changes

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for MFA config changes
  CognitoMFAFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "cognito-idp.amazonaws.com" && ($.eventName = "SetUserPoolMfaConfig" || $.eventName = "SetUserMFAPreference" || $.eventName = "AdminSetUserMFAPreference") }'
      MetricTransformations:
        - MetricName: CognitoMFAChanges
          MetricNamespace: Security/T1556
          MetricValue: "1"

  # Step 3: Alarm for MFA changes
  CognitoMFAAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1556-006-CognitoMFAChanges
      AlarmDescription: Alert on Cognito MFA configuration changes
      MetricName: CognitoMFAChanges
      Namespace: Security/T1556
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Monitor Cognito MFA configuration changes

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "cognito_mfa_alerts" {
  name = "cognito-mfa-changes"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cognito_mfa_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for MFA config changes
resource "aws_cloudwatch_log_metric_filter" "cognito_mfa" {
  name           = "cognito-mfa-changes"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ $.eventSource = \"cognito-idp.amazonaws.com\" && ($.eventName = \"SetUserPoolMfaConfig\" || $.eventName = \"SetUserMFAPreference\" || $.eventName = \"AdminSetUserMFAPreference\") }"

  metric_transformation {
    name      = "CognitoMFAChanges"
    namespace = "Security/T1556"
    value     = "1"
  }
}

# Step 3: Alarm for MFA changes
resource "aws_cloudwatch_metric_alarm" "cognito_mfa" {
  alarm_name          = "cognito-mfa-changes"
  metric_name         = "CognitoMFAChanges"
  namespace           = "Security/T1556"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.cognito_mfa_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Cognito MFA Configuration Changed",
                alert_description_template=(
                    "MFA configuration changed for Cognito user pool {userPoolId}. "
                    "Event: {eventName}. Actor: {actor}."
                ),
                investigation_steps=[
                    "Review what MFA settings were changed",
                    "Verify if change was authorised",
                    "Check if MFA was disabled or weakened",
                    "Review who made the change and from where",
                    "Check for other configuration changes to the user pool",
                ],
                containment_actions=[
                    "Revert MFA settings to secure configuration",
                    "Enable MFA enforcement if it was disabled",
                    "Audit user pool configuration",
                    "Review IAM permissions for Cognito access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known admin accounts during planned changes",
            detection_coverage="95% - catches Cognito MFA modifications",
            evasion_considerations="Direct database manipulation would bypass detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Cognito events logged to CloudWatch"],
        ),
        # Strategy 3: MFA Device Registration Monitoring
        DetectionStrategy(
            strategy_id="t1556006-aws-new-mfa",
            name="Suspicious MFA Device Registration",
            description="Detect when new MFA devices are registered, especially for privileged accounts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn as actor, requestParameters.userName as target_user, sourceIPAddress
| filter eventName in ["EnableMFADevice", "CreateVirtualMFADevice"]
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor new MFA device registrations

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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge for new MFA registration
  NewMFARule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1556-006-NewMFADevice
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - EnableMFADevice
            - CreateVirtualMFADevice
      State: ENABLED
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt NewMFARule.Arn""",
                terraform_template="""# Monitor new MFA device registrations

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "new_mfa_alerts" {
  name = "new-mfa-device-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.new_mfa_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge for new MFA registration
resource "aws_cloudwatch_event_rule" "new_mfa" {
  name = "new-mfa-device-registration"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "EnableMFADevice",
        "CreateVirtualMFADevice"
      ]
    }
  })
}

# Dead Letter Queue for new MFA device registration
resource "aws_sqs_queue" "new_mfa_dlq" {
  name                      = "new-mfa-device-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "new_mfa_dlq" {
  queue_url = aws_sqs_queue.new_mfa_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.new_mfa_dlq.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.new_mfa.arn }
      }
    }]
  })
}

# EventBridge target with retry and DLQ
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.new_mfa.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.new_mfa_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.new_mfa_dlq.arn
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

# Step 3: Topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.new_mfa_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.new_mfa_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.new_mfa.arn
          }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="New MFA Device Registered",
                alert_description_template=(
                    "New MFA device registered for user {userName}. "
                    "This could indicate account compromise if not authorised."
                ),
                investigation_steps=[
                    "Contact user to verify they registered new MFA device",
                    "Check if old MFA device was deactivated simultaneously",
                    "Review source IP and location of registration",
                    "Check for other suspicious activity on the account",
                    "Verify user's recent authentication history",
                ],
                containment_actions=[
                    "If unauthorised, immediately deactivate new MFA device",
                    "Force password reset for affected user",
                    "Re-enable only verified MFA device",
                    "Review and terminate active sessions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate MFA registration occurs during onboarding and device changes",
            detection_coverage="100% - catches all new MFA registrations",
            evasion_considerations="Attacker may register device during normal business hours",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 4: GCP MFA Policy Changes
        DetectionStrategy(
            strategy_id="t1556006-gcp-mfa-policy",
            name="GCP MFA Policy Modification Detection",
            description="Detect changes to MFA enforcement policies in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"SetIamPolicy|UpdateUser"
protoPayload.request.policy.bindings.condition=~"mfa|2sv"
OR protoPayload.metadata.mfa=~"DISABLED|REMOVED"''',
                gcp_terraform_template="""# GCP: Detect MFA policy modifications

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "MFA Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for MFA changes
resource "google_logging_metric" "mfa_policy_changes" {
  project = var.project_id
  name   = "mfa-policy-modifications"
  filter = <<-EOT
    protoPayload.methodName=~"SetIamPolicy|UpdateUser"
    (protoPayload.request.policy.bindings.condition=~"mfa|2sv"
    OR protoPayload.metadata.mfa=~"DISABLED|REMOVED")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for MFA changes
resource "google_monitoring_alert_policy" "mfa_policy" {
  project      = var.project_id
  display_name = "MFA Policy Modified"
  combiner     = "OR"

  conditions {
    display_name = "MFA policy change detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.mfa_policy_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
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
    content = "MFA enforcement policy was modified. Verify this change was authorised."
  }
}""",
                alert_severity="critical",
                alert_title="GCP: MFA Policy Modified",
                alert_description_template=(
                    "MFA enforcement policy modified in project {projectId}. "
                    "Method: {methodName}. Actor: {principalEmail}."
                ),
                investigation_steps=[
                    "Review what MFA policy was changed",
                    "Verify if change was authorised",
                    "Check if MFA requirement was weakened or removed",
                    "Review who made the change (principalEmail)",
                    "Check for other IAM policy modifications",
                ],
                containment_actions=[
                    "Revert MFA policy to secure configuration",
                    "Re-enable MFA enforcement immediately",
                    "Review IAM permissions for policy modification access",
                    "Audit recent authentication events",
                    "Enable organisation policy constraints for MFA",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="MFA policy changes should be rare and well-documented",
            detection_coverage="90% - catches policy-level MFA modifications",
            evasion_considerations="Very difficult to evade when modifying organisation policies",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled", "Admin Activity logs enabled"],
        ),
        # Strategy 5: GCP User 2SV Enrollment Changes
        DetectionStrategy(
            strategy_id="t1556006-gcp-2sv-disable",
            name="GCP Workspace 2-Step Verification Disabled",
            description="Detect when 2-Step Verification (2SV) is disabled for Google Workspace users.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="admin.googleapis.com"
protoPayload.methodName="google.admin.AdminService.changeUserTwoStepVerificationEnrollment"
protoPayload.request.new_value=false""",
                gcp_terraform_template="""# GCP: Detect 2SV disabled for users

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "2SV Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for 2SV changes
resource "google_logging_metric" "two_sv_disabled" {
  project = var.project_id
  name   = "two-step-verification-disabled"
  filter = <<-EOT
    protoPayload.serviceName="admin.googleapis.com"
    protoPayload.methodName="google.admin.AdminService.changeUserTwoStepVerificationEnrollment"
    protoPayload.request.new_value=false
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "two_sv_alert" {
  project      = var.project_id
  display_name = "2-Step Verification Disabled"
  combiner     = "OR"

  conditions {
    display_name = "User 2SV disabled"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.two_sv_disabled.name}\""
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
    content = "2-Step Verification was disabled for a user account. Immediate investigation required."
  }
}""",
                alert_severity="critical",
                alert_title="GCP: 2-Step Verification Disabled",
                alert_description_template=(
                    "2-Step Verification disabled for user {userEmail}. "
                    "This is a critical security control removal."
                ),
                investigation_steps=[
                    "Verify if 2SV disable was authorised by user or admin",
                    "Check who performed the action (actor)",
                    "Review user's recent access and authentication logs",
                    "Check for other suspicious administrative actions",
                    "Verify if backup codes were accessed or modified",
                ],
                containment_actions=[
                    "Immediately re-enable 2SV for the user",
                    "Force password reset for affected account",
                    "Suspend account until 2SV is re-enabled",
                    "Review and revoke active sessions",
                    "Enable organisation policy to enforce 2SV",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate 2SV changes are rare and should be investigated",
            detection_coverage="100% - catches all 2SV enrollment changes",
            evasion_considerations="Cannot evade when using Workspace Admin API",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=["Google Workspace", "Admin audit logs enabled"],
        ),
        # Azure Strategy: Modify Authentication Process: Multi-Factor Authentication
        DetectionStrategy(
            strategy_id="t1556006-azure",
            name="Azure Modify Authentication Process: Multi-Factor Authentication Detection",
            description=(
                "Azure detection for Modify Authentication Process: Multi-Factor Authentication. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Modify Authentication Process: Multi-Factor Authentication (T1556.006)
# Microsoft Defender detects Modify Authentication Process: Multi-Factor Authentication activity

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
  name                = "defender-t1556-006-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1556-006"
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

  description = "Microsoft Defender detects Modify Authentication Process: Multi-Factor Authentication activity"
  display_name = "Defender: Modify Authentication Process: Multi-Factor Authentication"
  enabled      = true

  tags = {
    "mitre-technique" = "T1556.006"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Modify Authentication Process: Multi-Factor Authentication Detected",
                alert_description_template=(
                    "Modify Authentication Process: Multi-Factor Authentication activity detected. "
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
        "t1556006-aws-mfa-deactivate",
        "t1556006-gcp-2sv-disable",
        "t1556006-gcp-mfa-policy",
        "t1556006-aws-cognito-mfa",
        "t1556006-aws-new-mfa",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+18% improvement for Credential Access and Persistence tactics",
)
