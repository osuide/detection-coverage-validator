"""
T1485 - Data Destruction

Adversaries destroy data to disrupt availability. In cloud environments,
this includes deleting S3 objects, RDS instances, and storage volumes.
Used by LAPSUS$, Sandworm Team, and ransomware operators.
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
    technique_id="T1485",
    technique_name="Data Destruction",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1485/",
    threat_context=ThreatContext(
        description=(
            "Adversaries destroy data to disrupt availability. In cloud environments, "
            "this includes deleting S3 buckets, RDS instances, storage volumes, and "
            "entire resources to cause maximum damage."
        ),
        attacker_goal="Destroy data to disrupt operations or hide evidence",
        why_technique=[
            "Maximum business disruption",
            "Ransomware pressure tactic",
            "Evidence destruction",
            "Cloud resources easily deleted",
            "May affect backups if not protected",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=10,
        severity_reasoning=(
            "Critical impact - data loss is often irrecoverable. "
            "Can cause complete business disruption. "
            "May destroy evidence of compromise."
        ),
        business_impact=[
            "Data loss",
            "Business disruption",
            "Recovery costs",
            "Potential permanent data loss",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1486"],
    ),
    detection_strategies=[
        # AWS GuardDuty Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1485-aws-guardduty",
            name="AWS GuardDuty Anomaly Detection",
            description=(
                "AWS GuardDuty detects anomalous data destruction patterns including unusual DeleteObject, DeleteBucket, or other destructive API calls. Impact:IAMUser/AnomalousBehavior identifies when destructive APIs are invoked in unusual patterns suggesting malicious activity."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Impact:IAMUser/AnomalousBehavior",
                    "Impact:S3/MaliciousIPCaller",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for T1485

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty-T1485-Alerts
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
      Description: Capture GuardDuty findings for T1485
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Impact:IAMUser/"
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
                terraform_template="""# GuardDuty alerts for T1485

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: SNS Topic
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "guardduty-t1485-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for findings
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-t1485"
  description = "Capture GuardDuty findings for T1485"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Impact:IAMUser/" }]
    }
  })
}

# Step 3: Target with DLQ and retry
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-t1485-dlq"
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
            evasion_considerations="Slow deletion over time, using legitimate admin tools, deleting from approved automation accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events",
            prerequisites=[
                "AWS GuardDuty enabled",
                "CloudTrail logging active",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1485-aws-s3delete",
            name="AWS S3 Bulk Deletion Detection",
            description="Detect bulk deletion of S3 objects or buckets.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["DeleteBucket", "DeleteObject", "DeleteObjects"]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 data destruction

Parameters:
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Dead Letter Queue for failed event deliveries
  AlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: s3-destruction-alerts-dlq
      MessageRetentionPeriod: 1209600  # 14 days

  S3DeleteRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.s3]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [DeleteBucket, DeleteObject, DeleteObjects]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt AlertDLQ.Arn

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
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
                aws:SourceArn: !GetAtt S3DeleteRule.Arn

  # Allow EventBridge to send failed events to DLQ
  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [!Ref AlertDLQ]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt AlertDLQ.Arn""",
                terraform_template="""# Detect S3 data destruction

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-destruction-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed event deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "s3-destruction-alerts-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_rule" "s3_delete" {
  name = "s3-data-destruction"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["DeleteBucket", "DeleteObject", "DeleteObjects"] }
  })
}

data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.s3_delete.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

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
          "aws:SourceArn" = aws_cloudwatch_event_rule.s3_delete.arn
        }
      }
    }]
  })
}

# Allow EventBridge to send failed events to DLQ
resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="S3 Data Deletion",
                alert_description_template="S3 bucket/objects deleted by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify deletion was authorised",
                    "Check what data was deleted",
                    "Review versioning/backup status",
                    "Check for other destructive actions",
                ],
                containment_actions=[
                    "Enable S3 Object Lock",
                    "Enable MFA Delete",
                    "Review delete permissions",
                    "Restore from backups if available",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist lifecycle management and authorised cleanup",
            detection_coverage="95% - catches all deletions",
            evasion_considerations="Cannot evade CloudTrail logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled with S3 data events"],
        ),
        DetectionStrategy(
            strategy_id="t1485-aws-rds",
            name="AWS RDS Deletion Detection",
            description="Detect deletion of RDS databases.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.rds"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["DeleteDBInstance", "DeleteDBCluster"]},
                },
                terraform_template="""# Detect RDS deletion

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "rds-destruction-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed event deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "rds-destruction-alerts-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_rule" "rds_delete" {
  name = "rds-data-destruction"
  event_pattern = jsonencode({
    source      = ["aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["DeleteDBInstance", "DeleteDBCluster"] }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.rds_delete.name
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
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

# Allow EventBridge to send failed events to DLQ
resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="RDS Database Deleted",
                alert_description_template="RDS database deleted by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify deletion was authorised",
                    "Check if snapshot was created",
                    "Review backup status",
                    "Check for other deletions",
                ],
                containment_actions=[
                    "Enable deletion protection",
                    "Review RDS permissions",
                    "Restore from snapshot if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="RDS deletions are typically rare",
            detection_coverage="95% - catches all deletions",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1485-gcp-storage",
            name="GCP Storage Deletion Detection",
            description="Detect deletion of GCS buckets and objects.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"storage.(buckets|objects).delete"''',
                gcp_terraform_template="""# GCP: Detect storage deletion

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "storage_delete" {
  name   = "storage-deletion"
  filter = <<-EOT
    protoPayload.methodName=~"storage.(buckets|objects).delete"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "storage_delete" {
  display_name = "Storage Deletion"
  combiner     = "OR"
  conditions {
    display_name = "Storage deleted"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.storage_delete.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="critical",
                alert_title="GCP: Storage Deletion",
                alert_description_template="GCS bucket/objects deleted.",
                investigation_steps=[
                    "Verify deletion was authorised",
                    "Check what was deleted",
                    "Review backup status",
                    "Check for other deletions",
                ],
                containment_actions=[
                    "Enable Object Versioning",
                    "Enable Retention Policies",
                    "Review IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist lifecycle management",
            detection_coverage="95% - catches all deletions",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1485-aws-s3delete", "t1485-aws-rds", "t1485-gcp-storage"],
    total_effort_hours=2.0,
    coverage_improvement="+25% improvement for Impact tactic",
)
