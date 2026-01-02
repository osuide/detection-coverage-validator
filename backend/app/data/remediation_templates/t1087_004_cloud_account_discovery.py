"""
T1087.004 - Account Discovery: Cloud Account

Adversaries enumerate IAM users, roles, and service accounts to
understand the environment and identify targets for privilege escalation.
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
    technique_id="T1087.004",
    technique_name="Account Discovery: Cloud Account",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1087/004/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate IAM users, roles, and service accounts to map "
            "the cloud environment. This reconnaissance helps identify privilege "
            "escalation paths and high-value targets."
        ),
        attacker_goal="Enumerate cloud accounts to identify targets and escalation paths",
        why_technique=[
            "Identifies high-privilege accounts",
            "Reveals privilege escalation opportunities",
            "Maps service account relationships",
            "Identifies inactive or orphaned accounts",
            "Required for targeted attacks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=5,
        severity_reasoning=(
            "Discovery itself is low impact but indicates active reconnaissance. "
            "Typically precedes privilege escalation or lateral movement. "
            "Important early warning signal."
        ),
        business_impact=[
            "Indicates active threat actor in environment",
            "Precursor to privilege escalation",
            "Mapping of sensitive accounts",
            "Early warning opportunity",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1098.001", "T1098.003", "T1078.004"],
        often_follows=["T1078.004", "T1528"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - IAM Enumeration
        DetectionStrategy(
            strategy_id="t1087004-aws-iamenum",
            name="IAM User/Role Enumeration Detection",
            description="Detect bulk IAM list operations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["ListUsers", "ListRoles", "ListGroups", "GetAccountAuthorizationDetails"]
| stats count(*) as enum_count by userIdentity.arn, bin(1h)
| filter enum_count > 10
| sort enum_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM enumeration

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

  # Step 2: Metric filter for IAM list operations
  IAMEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "iam.amazonaws.com" && ($.eventName = "ListUsers" || $.eventName = "ListRoles" || $.eventName = "GetAccountAuthorizationDetails") }'
      MetricTransformations:
        - MetricName: IAMEnumeration
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  IAMEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: IAMEnumeration
      MetricName: IAMEnumeration
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect IAM enumeration

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "iam-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "iam_enum" {
  name           = "iam-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"iam.amazonaws.com\" && ($.eventName = \"ListUsers\" || $.eventName = \"ListRoles\") }"

  metric_transformation {
    name      = "IAMEnumeration"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "iam_enum" {
  alarm_name          = "IAMEnumeration"
  metric_name         = "IAMEnumeration"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="IAM Enumeration Detected",
                alert_description_template="High volume of IAM list operations from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who is performing enumeration",
                    "Check if this is normal behaviour for the user",
                    "Review what IAM data was accessed",
                    "Look for follow-on privilege escalation",
                ],
                containment_actions=[
                    "Review user's permissions",
                    "Check for unauthorised access",
                    "Monitor for privilege escalation attempts",
                    "Consider limiting IAM read permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist security scanning tools and CSPM",
            detection_coverage="80% - volume-based detection",
            evasion_considerations="Slow enumeration may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 2: AWS - GetAccountAuthorizationDetails
        DetectionStrategy(
            strategy_id="t1087004-aws-authdetails",
            name="Full Account Enumeration Detection",
            description="Detect GetAccountAuthorizationDetails which reveals all IAM.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["GetAccountAuthorizationDetails"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect full IAM enumeration

Parameters:
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

  # Dead Letter Queue for failed events
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: auth-details-dlq
      MessageRetentionPeriod: 1209600  # 14 days

  # Step 2: EventBridge for GetAccountAuthorizationDetails
  AuthDetailsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [GetAccountAuthorizationDetails]
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAgeInSeconds: 3600
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn
          InputTransformer:
            InputPathsMap:
              account: $.account
              region: $.region
              time: $.time
              userArn: $.detail.userIdentity.arn
              sourceIp: $.detail.sourceIPAddress
            InputTemplate: |
              "HIGH: Full IAM Enumeration (T1087.004)"
              "Time: <time>"
              "Account: <account> | Region: <region>"
              "User: <userArn>"
              "Source IP: <sourceIp>"
              "Action: GetAccountAuthorizationDetails reveals all IAM policies"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt AuthDetailsRule.Arn

  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref EventDLQ
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt EventDLQ.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt AuthDetailsRule.Arn""",
                terraform_template="""# Detect full IAM enumeration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "auth-details-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "event_dlq" {
  name                      = "auth-details-dlq"
  message_retention_seconds = 1209600  # 14 days
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "auth_details" {
  name = "full-iam-enumeration"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["GetAccountAuthorizationDetails"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.auth_details.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
  }

  input_transformer {
    input_paths = {
      account  = "$.account"
      region   = "$.region"
      time     = "$.time"
      userArn  = "$.detail.userIdentity.arn"
      sourceIp = "$.detail.sourceIPAddress"
    }

    input_template = <<-EOT
"HIGH: Full IAM Enumeration (T1087.004)
Time: <time>
Account: <account> | Region: <region>
User: <userArn>
Source IP: <sourceIp>
Action: GetAccountAuthorizationDetails reveals all IAM policies"
EOT
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.auth_details.arn
        }
      }
    }]
  })
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.event_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.event_dlq.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Full IAM Enumeration Attempted",
                alert_description_template="GetAccountAuthorizationDetails called - complete IAM dump.",
                investigation_steps=[
                    "Identify who called this API",
                    "This reveals all IAM policies and permissions",
                    "Check for follow-on privilege escalation",
                    "Review user's recent activity",
                ],
                containment_actions=[
                    "Review caller's permissions",
                    "Check for data exfiltration",
                    "Monitor for privilege escalation",
                    "Consider restricting IAM read access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist security tools using this API",
            detection_coverage="95% - catches all calls",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: GCP - IAM Enumeration
        DetectionStrategy(
            strategy_id="t1087004-gcp-iamenum",
            name="GCP IAM Enumeration Detection",
            description="Detect enumeration of GCP IAM policies and service accounts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(GetIamPolicy|ListServiceAccounts|testIamPermissions)"''',
                gcp_terraform_template="""# GCP: Detect IAM enumeration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
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

# Step 2: Log-based metric
resource "google_logging_metric" "iam_enum" {
  project = var.project_id
  name   = "iam-enumeration"
  filter = <<-EOT
    protoPayload.methodName=~"(GetIamPolicy|ListServiceAccounts|testIamPermissions)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "iam_enum" {
  project      = var.project_id
  display_name = "IAM Enumeration Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume IAM queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iam_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: IAM Enumeration Detected",
                alert_description_template="High volume of IAM queries detected.",
                investigation_steps=[
                    "Identify the principal performing enumeration",
                    "Check if this is authorised security scanning",
                    "Review what IAM data was accessed",
                    "Look for privilege escalation attempts",
                ],
                containment_actions=[
                    "Review principal's permissions",
                    "Monitor for follow-on attacks",
                    "Consider IAM Conditions",
                    "Audit service account usage",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist security tools and CSPM",
            detection_coverage="75% - volume-based detection",
            evasion_considerations="Slow enumeration may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - testIamPermissions
        DetectionStrategy(
            strategy_id="t1087004-gcp-testperm",
            name="GCP Permission Testing Detection",
            description="Detect testIamPermissions used to find accessible resources.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"testIamPermissions"''',
                gcp_terraform_template="""# GCP: Detect permission testing

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

# Step 2: Log-based metric
resource "google_logging_metric" "test_permissions" {
  project = var.project_id
  name   = "iam-permission-testing"
  filter = <<-EOT
    protoPayload.methodName=~"testIamPermissions"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "test_permissions" {
  project      = var.project_id
  display_name = "IAM Permission Testing"
  combiner     = "OR"

  conditions {
    display_name = "Bulk permission testing"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.test_permissions.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
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
                alert_title="GCP: Permission Testing Detected",
                alert_description_template="Bulk testIamPermissions calls detected.",
                investigation_steps=[
                    "Identify who is testing permissions",
                    "Review which resources were tested",
                    "Check for privilege escalation patterns",
                    "Verify if security tool activity",
                ],
                containment_actions=[
                    "Review the principal's activity",
                    "Monitor for resource access",
                    "Consider restricting test permissions",
                    "Audit recent activities",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Some apps legitimately test permissions",
            detection_coverage="80% - catches bulk testing",
            evasion_considerations="Slow testing evades thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1087004-aws-authdetails",
        "t1087004-aws-iamenum",
        "t1087004-gcp-iamenum",
        "t1087004-gcp-testperm",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+15% improvement for Discovery tactic",
)
