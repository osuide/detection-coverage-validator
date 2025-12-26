"""
T1526 - Cloud Service Discovery

Adversaries enumerate cloud services to identify targets such as
databases, storage, serverless functions, and other managed services.
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
    technique_id="T1526",
    technique_name="Cloud Service Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1526/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate cloud services to identify databases, storage, "
            "serverless functions, and other managed services for targeting."
        ),
        attacker_goal="Discover cloud services for data theft or abuse",
        why_technique=[
            "Identifies valuable data stores",
            "Reveals serverless functions for abuse",
            "Maps service dependencies",
            "Finds misconfigured services",
            "Required for targeted attacks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=5,
        severity_reasoning="Discovery technique indicating reconnaissance. Precedes data theft or service abuse.",
        business_impact=[
            "Reveals service architecture",
            "Enables targeted attacks",
            "Early warning opportunity",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1530", "T1648"],
        often_follows=["T1078.004", "T1580"],
    ),
    detection_strategies=[
        # AWS GuardDuty Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1526-aws-guardduty",
            name="AWS GuardDuty Anomaly Detection",
            description=(
                "AWS GuardDuty detects anomalous cloud service discovery activity. Discovery:IAMUser/AnomalousBehavior identifies when service enumeration APIs like DescribeInstances, ListBuckets, or ListFunctions are called in unusual patterns."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Discovery:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for T1526

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty-T1526-Alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for GuardDuty findings
  GuardDutyRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Capture GuardDuty findings for T1526
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Discovery:IAMUser/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# GuardDuty alerts for T1526

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: SNS Topic
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "guardduty-t1526-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for findings
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-t1526"
  description = "Capture GuardDuty findings for T1526"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Discovery:IAMUser/" }]
    }
  })
}

# Step 3: Target with DLQ and retry
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-t1526-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Step 4: SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty.arn }
      }
    }]
  })
}""",
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML baselines; tune suppression rules for known benign patterns",
            detection_coverage="70% - detects anomalous behaviour but may miss attacks that blend with normal activity",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events",
            prerequisites=[
                "AWS GuardDuty enabled",
                "CloudTrail logging active",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1526-aws-service",
            name="AWS Service Enumeration Detection",
            description="Detect bulk service discovery across AWS.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, eventSource, userIdentity.arn
| filter eventName like /List|Describe/
| stats count(*) as calls by eventSource, userIdentity.arn, bin(1h)
| filter calls > 50
| sort calls desc""",
                terraform_template="""# Detect AWS service enumeration

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "service-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "service_enum" {
  name           = "service-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"List*\" || $.eventName = \"Describe*\" }"
  metric_transformation {
    name      = "ServiceEnumeration"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "service_enum" {
  alarm_name          = "ServiceEnumeration"
  metric_name         = "ServiceEnumeration"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 200
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Cloud Service Enumeration",
                alert_description_template="High volume service discovery from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who is enumerating services",
                    "Check if authorised scanning",
                    "Review services discovered",
                    "Look for follow-on attacks",
                ],
                containment_actions=[
                    "Review user permissions",
                    "Monitor for service abuse",
                    "Consider restricting list permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist monitoring and CSPM tools",
            detection_coverage="70% - volume-based",
            evasion_considerations="Slow enumeration evades",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1526-gcp-service",
            name="GCP Service Enumeration Detection",
            description="Detect bulk service discovery across GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(list|get)"
protoPayload.serviceName=~"(cloudfunctions|run|sql|storage)"''',
                gcp_terraform_template="""# GCP: Detect service enumeration

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "service_enum" {
  name   = "service-enumeration"
  filter = "protoPayload.methodName=~\"(list|get)\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "service_enum" {
  display_name = "Service Enumeration"
  combiner     = "OR"
  conditions {
    display_name = "High volume service queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.service_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 200
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Service Enumeration",
                alert_description_template="High volume service discovery detected.",
                investigation_steps=[
                    "Identify enumerating principal",
                    "Review services discovered",
                    "Check for follow-on attacks",
                ],
                containment_actions=[
                    "Review principal permissions",
                    "Monitor service access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist monitoring tools",
            detection_coverage="70% - volume-based",
            evasion_considerations="Slow enumeration evades",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1526-aws-service", "t1526-gcp-service"],
    total_effort_hours=2.0,
    coverage_improvement="+10% improvement for Discovery tactic",
)
