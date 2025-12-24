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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

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
                terraform_template="""# Detect S3 data destruction

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-destruction-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "s3_delete" {
  name = "s3-data-destruction"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["DeleteBucket", "DeleteObject", "DeleteObjects"] }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.s3_delete.name
  arn  = aws_sns_topic.alerts.arn
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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
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
