"""
T1098.005 - Account Manipulation: Device Registration

Adversaries register devices to compromised accounts to establish persistence
and bypass security controls. Used by APT29, Scattered Spider, and DEV-0537.
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
    technique_id="T1098.005",
    technique_name="Account Manipulation: Device Registration",
    tactic_ids=["TA0003", "TA0004"],
    mitre_url="https://attack.mitre.org/techniques/T1098/005/",
    threat_context=ThreatContext(
        description=(
            "Adversaries register devices to compromised accounts to establish persistence "
            "and bypass security controls. This includes enrolling devices in MFA systems "
            "(Duo, Okta) or device management platforms (Microsoft Intune, Azure AD). "
            "Attackers exploit weak self-enrollment processes that may only require credentials."
        ),
        attacker_goal="Register malicious devices for persistent access and to bypass conditional access policies",
        why_technique=[
            "Bypasses initial MFA requirements after credential compromise",
            "Circumvents conditional access policies in Azure AD/Intune",
            "Enables internal phishing with reduced suspicion",
            "Provides persistent access even after password resets",
            "Allows device-based authentication from attacker-controlled systems",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Device registration provides reliable persistence and bypasses many security controls. "
            "Registered devices can access resources as if they were legitimate, circumventing "
            "conditional access policies and MFA requirements. Often overlooked during incident response."
        ),
        business_impact=[
            "Persistent unauthorised access to corporate resources",
            "Bypass of conditional access and zero-trust policies",
            "Internal phishing capabilities from trusted devices",
            "Difficult to detect without proper monitoring",
            "Potential for mass device registration DoS attacks",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1114.003", "T1530", "T1537"],
        often_follows=["T1078.004", "T1110", "T1621"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Device Registration in IAM Identity Center
        DetectionStrategy(
            strategy_id="t1098005-aws-device-reg",
            name="AWS IAM Identity Center Device Registration",
            description="Detect when new devices are registered in AWS IAM Identity Center (SSO).",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.sso"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["RegisterDevice", "CreateDevice"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect device registration in IAM Identity Center

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Device Registration Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for device registration
  DeviceRegistrationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: detect-device-registration
      Description: Alert on device registration events
      EventPattern:
        source: [aws.sso]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [RegisterDevice, CreateDevice]
      State: ENABLED
      Targets:
        - Id: AlertTarget
          Arn: !Ref AlertTopic

  # Step 3: SNS topic policy to allow EventBridge
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
                aws:SourceArn: !GetAtt DeviceRegistrationRule.Arn""",
                terraform_template="""# Detect device registration in IAM Identity Center

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "device_alerts" {
  name         = "device-registration-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Device Registration Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.device_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for device registration
resource "aws_cloudwatch_event_rule" "device_registration" {
  name        = "detect-device-registration"
  description = "Alert on device registration events"

  event_pattern = jsonencode({
    source      = ["aws.sso"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["RegisterDevice", "CreateDevice"]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "device-registration-dlq"
  message_retention_seconds = 1209600
}

data "aws_caller_identity" "current" {}

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
      values   = [aws_cloudwatch_event_rule.device_registration.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.device_registration.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.device_alerts.arn

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

# Step 3: SNS topic policy to allow EventBridge
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.device_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.device_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.device_registration.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Device Registered in IAM Identity Center",
                alert_description_template="New device registered for user {userName} from IP {sourceIPAddress}.",
                investigation_steps=[
                    "Verify the device registration was authorised by the user",
                    "Check the source IP address and location",
                    "Review the user's recent authentication history",
                    "Verify the device details match expected corporate devices",
                    "Check for other suspicious activity on the account",
                ],
                containment_actions=[
                    "Deregister the suspicious device immediately",
                    "Force MFA re-registration for the user",
                    "Reset the user's credentials",
                    "Review and revoke any active sessions",
                    "Enable device trust policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Expected during employee onboarding or device replacement - correlate with HR systems",
            detection_coverage="95% - catches all device registration API calls",
            evasion_considerations="Cannot evade if using official APIs; attackers may try to register during business hours",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "IAM Identity Center logging enabled"],
        ),
        # Strategy 2: AWS - Azure AD/Entra ID Device Registration (hybrid)
        DetectionStrategy(
            strategy_id="t1098005-aws-azuread-device",
            name="Azure AD Device Registration Monitoring",
            description="Monitor CloudTrail for Azure AD device registration activities in hybrid environments.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters
| filter eventSource = "sso.amazonaws.com" or eventSource = "identitystore.amazonaws.com"
| filter eventName in ["RegisterDevice", "CreateDevice", "UpdateDevice"]
| stats count(*) as registrations by userIdentity.userName, sourceIPAddress, bin(1h)
| filter registrations > 3
| sort registrations desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor for suspicious device registration patterns

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

  # Step 2: Metric filter for device registrations
  DeviceRegFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = RegisterDevice) || ($.eventName = CreateDevice) }'
      MetricTransformations:
        - MetricName: DeviceRegistrations
          MetricNamespace: Security
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alarm for unusual registration volume
  HighRegistrationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighDeviceRegistrationVolume
      AlarmDescription: Alerts on suspicious device registration activity
      MetricName: DeviceRegistrations
      Namespace: Security
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Monitor for suspicious device registration patterns

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "device-registration-pattern-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for device registrations
resource "aws_cloudwatch_log_metric_filter" "device_registrations" {
  name           = "device-registration-events"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = RegisterDevice) || ($.eventName = CreateDevice) }"

  metric_transformation {
    name      = "DeviceRegistrations"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for unusual registration volume
resource "aws_cloudwatch_metric_alarm" "high_registrations" {
  alarm_name          = "HighDeviceRegistrationVolume"
  alarm_description   = "Alerts on suspicious device registration activity"
  metric_name         = "DeviceRegistrations"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious Device Registration Pattern",
                alert_description_template="Multiple device registrations detected: {registrations} devices in 1 hour.",
                investigation_steps=[
                    "Review which accounts registered multiple devices",
                    "Check if registrations correlate with legitimate business activity",
                    "Verify source IP addresses and geolocations",
                    "Look for signs of automated registration",
                    "Check if dormant accounts are being targeted",
                ],
                containment_actions=[
                    "Suspend accounts with suspicious registrations",
                    "Deregister all suspicious devices",
                    "Implement device registration approval workflow",
                    "Enable device trust requirements",
                    "Review and update conditional access policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on organisation size and device refresh cycles",
            detection_coverage="85% - catches bulk registration patterns",
            evasion_considerations="Slow, targeted registration may evade volume-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch Logs"],
        ),
        # Strategy 3: GCP - Workspace Device Registration
        DetectionStrategy(
            strategy_id="t1098005-gcp-device-reg",
            name="GCP Workspace Device Registration Detection",
            description="Detect when new devices are registered in Google Workspace.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="admin.googleapis.com"
protoPayload.methodName=~"device.register|mobile.register|chrome.register"
OR protoPayload.methodName="google.admin.AdminService.registerDevice"''',
                gcp_terraform_template="""# GCP: Detect device registration in Workspace

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for device registration
resource "google_logging_metric" "device_registration" {
  project = var.project_id
  name   = "workspace-device-registration"
  filter = <<-EOT
    protoPayload.serviceName="admin.googleapis.com"
    (protoPayload.methodName=~"device.register" OR
     protoPayload.methodName=~"mobile.register" OR
     protoPayload.methodName=~"chrome.register" OR
     protoPayload.methodName="google.admin.AdminService.registerDevice")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "device_registration" {
  project      = var.project_id
  display_name = "Workspace Device Registration Alert"
  combiner     = "OR"

  conditions {
    display_name = "Device registration detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.device_registration.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Workspace Device Registered",
                alert_description_template="New device registered in Google Workspace for user {userEmail}.",
                investigation_steps=[
                    "Verify the device registration was user-initiated",
                    "Check the device type and operating system",
                    "Review user's recent authentication history",
                    "Verify the registration location matches expected user location",
                    "Check for signs of account compromise",
                ],
                containment_actions=[
                    "Remove the suspicious device from Workspace",
                    "Revoke device access to corporate resources",
                    "Force user to re-authenticate",
                    "Reset user credentials if compromise suspected",
                    "Enable device approval workflow",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Expected for new employees or device replacements - integrate with IT asset management",
            detection_coverage="95% - catches all Workspace device registrations",
            evasion_considerations="Cannot evade without compromising admin privileges",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Workspace Admin audit logs enabled"],
        ),
        # Strategy 4: GCP - Unusual Device Registration Patterns
        DetectionStrategy(
            strategy_id="t1098005-gcp-device-pattern",
            name="GCP Unusual Device Registration Patterns",
            description="Detect bulk or suspicious device registration patterns in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="admin.googleapis.com"
protoPayload.methodName=~"device.register|mobile.register" """,
                gcp_terraform_template="""# GCP: Detect unusual device registration patterns

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for device registration volume
resource "google_logging_metric" "device_reg_volume" {
  project = var.project_id
  name   = "device-registration-volume"
  filter = <<-EOT
    protoPayload.serviceName="admin.googleapis.com"
    protoPayload.methodName=~"device.register|mobile.register"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User registering device"
    }
  }

  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert for bulk registrations
resource "google_monitoring_alert_policy" "bulk_registration" {
  project      = var.project_id
  display_name = "Bulk Device Registration Pattern"
  combiner     = "OR"

  conditions {
    display_name = "Multiple devices registered"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.device_reg_volume.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Bulk Device Registration Detected",
                alert_description_template="Unusual device registration volume detected: {device_count} devices.",
                investigation_steps=[
                    "Identify which accounts registered multiple devices",
                    "Check if pattern matches legitimate IT operations",
                    "Review device details for anomalies",
                    "Check for compromised admin accounts",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Suspend affected user accounts",
                    "Remove all suspicious devices",
                    "Implement device approval requirements",
                    "Enable advanced device management policies",
                    "Review admin privileges",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist IT admin accounts performing bulk provisioning",
            detection_coverage="80% - catches bulk registration patterns",
            evasion_considerations="Slow registration over extended time may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Workspace Admin API enabled", "Cloud Logging configured"],
        ),
        # Strategy 5: AWS - Dormant Account Device Registration
        DetectionStrategy(
            strategy_id="t1098005-aws-dormant-device",
            name="Dormant Account Device Registration",
            description="Detect device registration for accounts with no recent activity.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.userName, sourceIPAddress
| filter eventName in ["RegisterDevice", "CreateDevice"]
| stats earliest(@timestamp) as device_reg_time by userIdentity.userName
# Correlate with user activity logs to identify dormant accounts""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect device registration on dormant accounts

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

  # Step 2: Lambda to check account activity
  DormantCheckLambda:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.11
      Handler: index.handler
      Role: !GetAtt LambdaRole.Arn
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref AlertTopic
      Code:
        ZipFile: |
          import boto3
          import os
          from datetime import datetime, timedelta

          def handler(event, context):
              # Check if device registration is for dormant account
              # Send alert if account had no activity in 90+ days
              return {'statusCode': 200}

  # Step 3: EventBridge trigger on device registration
  DeviceRegEvent:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.sso]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [RegisterDevice, CreateDevice]
      Targets:
        - Id: CheckDormant
          Arn: !GetAtt DormantCheckLambda.Arn

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: { Service: lambda.amazonaws.com }
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole""",
                terraform_template="""# Detect device registration on dormant accounts

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "dormant-account-device-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Lambda to check account dormancy
resource "aws_lambda_function" "dormant_check" {
  filename      = "dormant_check.zip"
  function_name = "check-dormant-account-device-reg"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }
}

# Step 3: EventBridge rule to trigger Lambda
resource "aws_cloudwatch_event_rule" "device_reg" {
  name = "device-registration-events"

  event_pattern = jsonencode({
    source      = ["aws.sso"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["RegisterDevice", "CreateDevice"]
    }
  })
}

resource "aws_sqs_queue" "dormant_dlq" {
  name                      = "dormant-device-reg-dlq"
  message_retention_seconds = 1209600
}

data "aws_iam_policy_document" "dormant_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sqs_queue.dormant_dlq.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.device_reg.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "dormant_dlq_policy" {
  queue_url = aws_sqs_queue.dormant_dlq.url
  policy    = data.aws_iam_policy_document.dormant_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.device_reg.name
  target_id = "DormantCheck"
  arn       = aws_lambda_function.dormant_check.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dormant_dlq.arn
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

resource "aws_iam_role" "lambda_role" {
  name = "dormant-check-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Device Registered on Dormant Account",
                alert_description_template="Device registered for dormant account {userName} - no activity in {days_dormant} days.",
                investigation_steps=[
                    "Verify account was actually dormant",
                    "Check for recent password reset attempts",
                    "Review how credentials were obtained",
                    "Identify all devices registered to this account",
                    "Check for similar activity on other dormant accounts",
                ],
                containment_actions=[
                    "Immediately deregister the device",
                    "Disable the dormant account",
                    "Force password reset",
                    "Review all dormant accounts for compromise",
                    "Implement automatic dormant account disablement",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Account reactivation for returning employees is expected - integrate with HR systems",
            detection_coverage="70% - requires baseline of account activity",
            evasion_considerations="Attacker could generate activity before registering device",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail", "Lambda", "Historical user activity baseline"],
        ),
        # Azure Strategy: Account Manipulation: Device Registration
        DetectionStrategy(
            strategy_id="t1098005-azure",
            name="Azure Account Manipulation: Device Registration Detection",
            description=(
                "Azure detection for Account Manipulation: Device Registration. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Account Manipulation: Device Registration (T1098.005)
# Microsoft Defender detects Account Manipulation: Device Registration activity

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
  name                = "defender-t1098-005-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1098-005"
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

  description = "Microsoft Defender detects Account Manipulation: Device Registration activity"
  display_name = "Defender: Account Manipulation: Device Registration"
  enabled      = true

  tags = {
    "mitre-technique" = "T1098.005"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Account Manipulation: Device Registration Detected",
                alert_description_template=(
                    "Account Manipulation: Device Registration activity detected. "
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
        "t1098005-aws-device-reg",
        "t1098005-gcp-device-reg",
        "t1098005-aws-azuread-device",
        "t1098005-gcp-device-pattern",
        "t1098005-aws-dormant-device",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+18% improvement for Persistence and Privilege Escalation tactics",
)
