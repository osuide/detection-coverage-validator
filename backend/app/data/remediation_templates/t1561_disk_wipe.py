"""
T1561 - Disk Wipe

Adversaries wipe or corrupt raw disk data to disrupt availability. In cloud,
this includes deleting EBS volumes, snapshots, and persistent disks.
Used by APT37, APT38, Shamoon operators, and destructive malware campaigns.
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
    technique_id="T1561",
    technique_name="Disk Wipe",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1561/",
    threat_context=ThreatContext(
        description=(
            "Adversaries wipe or corrupt raw disk data on specific systems or in large "
            "numbers to interrupt availability. In cloud environments, this includes "
            "deleting EBS volumes, snapshots, persistent disks, and wiping boot sectors. "
            "Attackers may target both disk content and disk structures like MBR."
        ),
        attacker_goal="Wipe disk data to disrupt availability and cause maximum operational damage",
        why_technique=[
            "Permanent data destruction",
            "Disrupt system availability",
            "Destroy evidence of compromise",
            "Pressure tactic in destructive attacks",
            "Cloud volumes easily deleted",
            "May prevent system recovery",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="low",
        trend="stable",
        severity_score=10,
        severity_reasoning=(
            "Critical impact - disk wipe can cause permanent data loss and complete "
            "system failure. Often irrecoverable without backups. Used in destructive "
            "attacks targeting critical infrastructure and financial institutions."
        ),
        business_impact=[
            "Permanent data loss",
            "Complete system failure",
            "Extended recovery time",
            "Critical infrastructure disruption",
            "Potential loss of evidence",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1485", "T1486"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1561-aws-volume-delete",
            name="AWS EBS Volume Deletion Detection",
            description="Detect deletion of EBS volumes and snapshots.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["DeleteVolume", "DeleteSnapshot"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EBS volume and snapshot deletion

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  VolumeDeleteRule:
    Type: AWS::Events::Rule
    Properties:
      Name: ebs-volume-deletion
      Description: Alert on EBS volume/snapshot deletion
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [DeleteVolume, DeleteSnapshot]
      State: ENABLED
      Targets:
        - Id: AlertTarget
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt VolumeDeleteRule.Arn""",
                terraform_template="""# Detect EBS volume and snapshot deletion

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "volume_alerts" {
  name = "ebs-volume-deletion-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.volume_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for volume deletion
resource "aws_cloudwatch_event_rule" "volume_delete" {
  name        = "ebs-volume-deletion"
  description = "Alert on EBS volume/snapshot deletion"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["DeleteVolume", "DeleteSnapshot"]
    }
  })
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "dlq" {
  name                      = "ebs-volume-deletion-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.volume_delete.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.volume_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Allow EventBridge to publish to SNS
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.volume_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.volume_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.volume_delete.arn
        }
      }
    }]
  })
}

# SQS queue policy to allow EventBridge to send to DLQ
resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.volume_delete.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="EBS Volume/Snapshot Deleted",
                alert_description_template="EBS volume or snapshot deleted by {userIdentity.arn} in {awsRegion}.",
                investigation_steps=[
                    "Verify deletion was authorised",
                    "Identify which volumes/snapshots were deleted",
                    "Check if backups exist elsewhere",
                    "Review associated EC2 instances",
                    "Check for bulk deletion patterns",
                    "Investigate user/role that performed deletion",
                ],
                containment_actions=[
                    "Enable deletion protection on critical volumes",
                    "Restrict EBS deletion permissions",
                    "Review and restore from backups if available",
                    "Revoke compromised credentials",
                    "Enable MFA for destructive actions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised cleanup processes and lifecycle management",
            detection_coverage="95% - catches all volume deletions",
            evasion_considerations="Cannot evade CloudTrail logging of API calls",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled in all regions"],
        ),
        DetectionStrategy(
            strategy_id="t1561-aws-bulk-delete",
            name="AWS Bulk Volume Deletion Detection",
            description="Detect multiple EBS volume deletions in short timeframe indicating disk wipe attack.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.volumeId, awsRegion
| filter eventSource = "ec2.amazonaws.com"
| filter eventName IN ["DeleteVolume", "DeleteSnapshot"]
| stats count(*) as deletion_count by userIdentity.arn, bin(10m)
| filter deletion_count > 3
| sort deletion_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect bulk EBS volume deletion (potential disk wipe)

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  BulkDeleteFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ec2.amazonaws.com" && ($.eventName = "DeleteVolume" || $.eventName = "DeleteSnapshot") }'
      MetricTransformations:
        - MetricName: EBSVolumeDeletions
          MetricNamespace: Security/DiskWipe
          MetricValue: "1"
          DefaultValue: 0

  BulkDeleteAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: BulkEBSVolumeDeletion
      AlarmDescription: Multiple EBS volumes deleted in short timeframe
      MetricName: EBSVolumeDeletions
      Namespace: Security/DiskWipe
      Statistic: Sum
      Period: 600
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect bulk EBS volume deletion

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "bulk-disk-deletion-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for volume deletions
resource "aws_cloudwatch_log_metric_filter" "bulk_delete" {
  name           = "ebs-bulk-deletion"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ $.eventSource = \"ec2.amazonaws.com\" && ($.eventName = \"DeleteVolume\" || $.eventName = \"DeleteSnapshot\") }"

  metric_transformation {
    name      = "EBSVolumeDeletions"
    namespace = "Security/DiskWipe"
    value     = "1"
    default_value = 0
  }
}

# Alarm for bulk deletions
resource "aws_cloudwatch_metric_alarm" "bulk_delete" {
  alarm_name          = "BulkEBSVolumeDeletion"
  alarm_description   = "Multiple EBS volumes deleted in short timeframe"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EBSVolumeDeletions"
  namespace           = "Security/DiskWipe"
  period              = 600
  statistic           = "Sum"
  threshold           = 3
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Bulk EBS Volume Deletion - Potential Disk Wipe",
                alert_description_template="Multiple EBS volumes deleted in 10 minutes by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify all deleted volumes",
                    "Determine if pattern indicates disk wipe attack",
                    "Check for concurrent destructive actions",
                    "Review account compromise indicators",
                    "Assess business impact",
                    "Verify backup status",
                ],
                containment_actions=[
                    "Immediately revoke credentials",
                    "Isolate affected account/region",
                    "Enable volume deletion protection",
                    "Restore from backups",
                    "Implement SCP to prevent deletions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Three deletions in 10 minutes is unusual for legitimate operations",
            detection_coverage="90% - catches bulk deletion patterns",
            evasion_considerations="Attacker could space out deletions, but reduces impact speed",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logs sent to CloudWatch Logs"],
        ),
        DetectionStrategy(
            strategy_id="t1561-aws-instance-termination",
            name="AWS Mass EC2 Instance Termination",
            description="Detect bulk EC2 instance termination which may indicate disk wipe attack.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["TerminateInstances"]},
                },
                terraform_template="""# Detect EC2 instance termination

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "ec2-termination-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "instance_termination" {
  name        = "ec2-instance-termination"
  description = "Alert on EC2 instance termination"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["TerminateInstances"]
    }
  })
}

# Dead Letter Queue for instance termination events
resource "aws_sqs_queue" "instance_dlq" {
  name                      = "ec2-termination-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.instance_termination.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.instance_dlq.arn
  }
}

data "aws_caller_identity" "current" {}

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
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.instance_termination.arn
        }
      }
    }]
  })
}

# SQS queue policy for instance termination DLQ
resource "aws_sqs_queue_policy" "instance_dlq_policy" {
  queue_url = aws_sqs_queue.instance_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.instance_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.instance_termination.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="EC2 Instances Terminated",
                alert_description_template="EC2 instance(s) terminated by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify termination was authorised",
                    "Identify terminated instances",
                    "Check if termination protection was disabled",
                    "Review for bulk termination pattern",
                    "Assess if snapshots exist",
                ],
                containment_actions=[
                    "Enable termination protection on critical instances",
                    "Review EC2 permissions",
                    "Restore instances from AMIs/snapshots if needed",
                    "Revoke compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist auto-scaling and authorised instance lifecycle management",
            detection_coverage="95% - catches all terminations",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1561-gcp-disk-delete",
            name="GCP Persistent Disk Deletion Detection",
            description="Detect deletion of persistent disks and snapshots in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.disks.delete|compute.snapshots.delete)"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect persistent disk deletion

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log metric for disk deletion
resource "google_logging_metric" "disk_deletion" {
  name   = "persistent-disk-deletion"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.disks.delete|compute.snapshots.delete)"
    severity="NOTICE"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert policy for disk deletion
resource "google_monitoring_alert_policy" "disk_deletion" {
  display_name = "Persistent Disk Deletion"
  combiner     = "OR"

  conditions {
    display_name = "Disk deleted"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.disk_deletion.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "604800s"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Persistent Disk Deleted",
                alert_description_template="Persistent disk or snapshot deleted in GCP.",
                investigation_steps=[
                    "Verify deletion was authorised",
                    "Identify which disks/snapshots were deleted",
                    "Check for associated VM instances",
                    "Review backup status",
                    "Check for bulk deletion patterns",
                    "Investigate principal that performed deletion",
                ],
                containment_actions=[
                    "Restrict compute.disks.delete permissions",
                    "Enable deletion protection on critical disks",
                    "Review IAM policies",
                    "Restore from snapshots if available",
                    "Revoke compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised disk lifecycle management",
            detection_coverage="95% - catches all disk deletions",
            evasion_considerations="Cannot evade Cloud Audit Logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"],
        ),
        DetectionStrategy(
            strategy_id="t1561-gcp-bulk-delete",
            name="GCP Bulk Disk Deletion Detection",
            description="Detect multiple disk deletions indicating potential disk wipe attack.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.disks.delete|compute.snapshots.delete|compute.instances.delete)"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect bulk disk/instance deletion

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Metric for bulk deletions
resource "google_logging_metric" "bulk_deletion" {
  name   = "bulk-compute-deletion"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.disks.delete|compute.snapshots.delete|compute.instances.delete)"
    severity="NOTICE"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert for bulk deletions (>3 in 10 minutes)
resource "google_monitoring_alert_policy" "bulk_deletion" {
  display_name = "Bulk Compute Resource Deletion"
  combiner     = "OR"

  conditions {
    display_name = "Multiple deletions detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.bulk_deletion.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "604800s"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Bulk Disk Deletion - Potential Disk Wipe",
                alert_description_template="Multiple compute resources deleted in short timeframe.",
                investigation_steps=[
                    "Identify all deleted resources",
                    "Determine if pattern indicates disk wipe attack",
                    "Review for concurrent destructive actions",
                    "Check for account compromise",
                    "Assess business impact",
                    "Verify snapshot availability",
                ],
                containment_actions=[
                    "Revoke compromised credentials immediately",
                    "Restrict deletion permissions via IAM",
                    "Restore from snapshots",
                    "Enable deletion protection",
                    "Implement organisation policy constraints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Multiple deletions in 10 minutes unusual for normal operations",
            detection_coverage="90% - catches bulk deletion patterns",
            evasion_considerations="Attacker could space out deletions to evade threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1561-aws-volume-delete",
        "t1561-aws-bulk-delete",
        "t1561-aws-instance-termination",
        "t1561-gcp-disk-delete",
        "t1561-gcp-bulk-delete",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+20% improvement for Impact tactic",
)
