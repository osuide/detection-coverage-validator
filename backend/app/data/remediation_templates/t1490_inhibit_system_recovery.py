"""
T1490 - Inhibit System Recovery

Adversaries delete or disable system recovery features to prevent restoration.
In cloud environments, this includes deleting snapshots, backups, and disabling
automated backup policies. Used by Sandworm, Wizard Spider, Scattered Spider.
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
    technique_id="T1490",
    technique_name="Inhibit System Recovery",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1490/",
    threat_context=ThreatContext(
        description=(
            "Adversaries delete or disable built-in system recovery features to prevent "
            "restoration from backups. In cloud environments, this includes deleting EBS "
            "snapshots, RDS backups, disabling automated backup policies, deleting GCP "
            "snapshots, and removing backup retention policies. This technique is commonly "
            "used to augment ransomware attacks and data destruction operations."
        ),
        attacker_goal="Prevent system recovery to maximise impact of ransomware or data destruction",
        why_technique=[
            "Maximise ransomware pressure by eliminating recovery options",
            "Prevent incident response and forensics",
            "Force victim to pay ransom",
            "Cloud backups easily deleted via API",
            "Automated backup policies can be disabled",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="high",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Critical impact - eliminating recovery capabilities forces organisations "
            "to pay ransom or accept permanent data loss. Commonly precedes ransomware "
            "deployment. High prevalence in cloud environments where backups are API-accessible."
        ),
        business_impact=[
            "Loss of recovery capabilities",
            "Increased ransomware pressure",
            "Extended recovery time",
            "Potential permanent data loss",
            "Higher likelihood of ransom payment",
        ],
        typical_attack_phase="impact",
        often_precedes=["T1486", "T1485"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1490-aws-snapshot-delete",
            name="AWS EBS/RDS Snapshot Deletion",
            description="Detect deletion of EBS snapshots, RDS snapshots, and AMI backups.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2", "aws.rds"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "DeleteSnapshot",
                            "DeleteDBSnapshot",
                            "DeleteDBClusterSnapshot",
                            "DeregisterImage",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect deletion of EBS/RDS snapshots and AMIs

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Snapshot Deletion Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  SnapshotDeleteRule:
    Type: AWS::Events::Rule
    Properties:
      Name: detect-snapshot-deletion
      Description: Alert on EBS/RDS snapshot deletion
      EventPattern:
        source: [aws.ec2, aws.rds]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - DeleteSnapshot
            - DeleteDBSnapshot
            - DeleteDBClusterSnapshot
            - DeregisterImage
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
                aws:SourceArn: !GetAtt SnapshotDeleteRule.Arn""",
                terraform_template="""# Detect deletion of EBS/RDS snapshots and AMIs

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "aws_sns_topic" "snapshot_alerts" {
  name         = "snapshot-deletion-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Snapshot Deletion Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.snapshot_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "snapshot_delete" {
  name        = "detect-snapshot-deletion"
  description = "Alert on EBS/RDS snapshot deletion"

  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "DeleteSnapshot",
        "DeleteDBSnapshot",
        "DeleteDBClusterSnapshot",
        "DeregisterImage"
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "snapshot-delete-dlq"
  message_retention_seconds = 1209600
}

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
      values   = [aws_cloudwatch_event_rule.snapshot_delete.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.snapshot_delete.name
  target_id = "AlertTarget"
  arn       = aws_sns_topic.snapshot_alerts.arn

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

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.snapshot_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.snapshot_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.snapshot_delete.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="AWS Snapshot Deletion Detected",
                alert_description_template="Snapshot deleted by {userIdentity.arn}. Event: {eventName}, Resource: {requestParameters}",
                investigation_steps=[
                    "Verify deletion was authorised and documented",
                    "Identify which snapshots were deleted",
                    "Check for other backup deletions in timeframe",
                    "Review user's recent activity for suspicious behaviour",
                    "Check if automated backups still enabled",
                ],
                containment_actions=[
                    "Revoke access if unauthorised",
                    "Enable snapshot deletion protection",
                    "Create new snapshots immediately",
                    "Review and restrict backup deletion permissions",
                    "Enable MFA for destructive operations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist automated lifecycle policies and authorised backup rotation",
            detection_coverage="95% - catches all snapshot deletion API calls",
            evasion_considerations="Cannot evade CloudTrail logging; attackers may spread deletions over time",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled with management events"],
        ),
        DetectionStrategy(
            strategy_id="t1490-aws-backup-disable",
            name="AWS Backup Policy Modification",
            description="Detect disabling of AWS Backup plans and vault deletion.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.backup"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "DeleteBackupPlan",
                            "DeleteBackupVault",
                            "DeleteBackupSelection",
                            "UpdateBackupPlan",
                            "PutBackupVaultAccessPolicy",
                        ]
                    },
                },
                terraform_template="""# Detect AWS Backup policy modifications

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "aws_sns_topic" "backup_alerts" {
  name         = "backup-policy-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Backup Policy Modification Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.backup_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "backup_changes" {
  name        = "detect-backup-policy-changes"
  description = "Alert on AWS Backup plan/vault changes"

  event_pattern = jsonencode({
    source      = ["aws.backup"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "DeleteBackupPlan",
        "DeleteBackupVault",
        "DeleteBackupSelection",
        "UpdateBackupPlan",
        "PutBackupVaultAccessPolicy"
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "backup-changes-dlq"
  message_retention_seconds = 1209600
}

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
      values   = [aws_cloudwatch_event_rule.backup_changes.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.backup_changes.name
  target_id = "AlertTarget"
  arn       = aws_sns_topic.backup_alerts.arn

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

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.backup_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.backup_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.backup_changes.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="AWS Backup Policy Modified",
                alert_description_template="Backup policy changed by {userIdentity.arn}. Event: {eventName}",
                investigation_steps=[
                    "Verify change was authorised",
                    "Review backup plan modifications",
                    "Check if backups still running",
                    "Verify vault access policies unchanged",
                    "Check for other backup-related changes",
                ],
                containment_actions=[
                    "Restore backup plan if deleted",
                    "Re-enable backup selections",
                    "Review backup vault access policies",
                    "Restrict backup modification permissions",
                    "Enable vault lock for immutability",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Backup plan updates are typically infrequent and documented",
            detection_coverage="90% - catches backup policy changes",
            evasion_considerations="Cannot evade CloudTrail logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1490-aws-s3-versioning",
            name="AWS S3 Versioning Suspension",
            description="Detect suspension of S3 bucket versioning and lifecycle policy changes.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName, userIdentity.arn
| filter eventSource = "s3.amazonaws.com"
| filter eventName IN ["PutBucketVersioning", "PutBucketLifecycle", "DeleteBucketLifecycle"]
| filter requestParameters.versioning.Status = "Suspended" OR eventName LIKE /Delete/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 versioning suspension

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

  VersioningFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "s3.amazonaws.com" && ($.eventName = "PutBucketVersioning" || $.eventName = "DeleteBucketLifecycle") }'
      MetricTransformations:
        - MetricName: S3VersioningChanges
          MetricNamespace: Security
          MetricValue: "1"

  VersioningAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3VersioningSuspended
      AlarmDescription: Alert when S3 versioning is modified
      MetricName: S3VersioningChanges
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect S3 versioning suspension

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "aws_sns_topic" "versioning_alerts" {
  name = "s3-versioning-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.versioning_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "versioning_changes" {
  name           = "s3-versioning-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"s3.amazonaws.com\" && ($.eventName = \"PutBucketVersioning\" || $.eventName = \"DeleteBucketLifecycle\") }"

  metric_transformation {
    name      = "S3VersioningChanges"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "versioning_suspended" {
  alarm_name          = "S3VersioningSuspended"
  alarm_description   = "Alert when S3 versioning is modified"
  metric_name         = "S3VersioningChanges"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.versioning_alerts.arn]
}""",
                alert_severity="high",
                alert_title="S3 Versioning Modified",
                alert_description_template="S3 versioning changed for bucket {requestParameters.bucketName} by {userIdentity.arn}",
                investigation_steps=[
                    "Verify change was authorised",
                    "Check which buckets affected",
                    "Verify if lifecycle policies deleted",
                    "Check for other S3 configuration changes",
                    "Review recent object deletions",
                ],
                containment_actions=[
                    "Re-enable versioning immediately",
                    "Restore lifecycle policies",
                    "Enable MFA Delete",
                    "Review and restrict versioning permissions",
                    "Check for deleted object versions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised infrastructure changes; versioning changes should be rare",
            detection_coverage="90% - catches versioning and lifecycle changes",
            evasion_considerations="Attackers may delete objects without changing versioning",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with S3 data events"],
        ),
        DetectionStrategy(
            strategy_id="t1490-gcp-snapshot-delete",
            name="GCP Snapshot and Backup Deletion",
            description="Detect deletion of GCP Compute snapshots and persistent disk backups.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.snapshots.delete|compute.disks.delete|sqladmin.backupRuns.delete)"
AND severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect snapshot and backup deletion

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "snapshot_delete" {
  project = var.project_id
  name   = "snapshot-deletion-metric"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.snapshots.delete|compute.disks.delete|sqladmin.backupRuns.delete)"
    AND severity="NOTICE"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }

}

resource "google_monitoring_alert_policy" "snapshot_delete" {
  project      = var.project_id
  display_name = "GCP Snapshot/Backup Deletion"
  combiner     = "OR"

  conditions {
    display_name = "Snapshot or backup deleted"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.snapshot_delete.name}\" AND resource.type=\"global\""
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

}""",
                alert_severity="critical",
                alert_title="GCP: Snapshot/Backup Deletion",
                alert_description_template="Snapshot or backup deleted in GCP project",
                investigation_steps=[
                    "Verify deletion was authorised",
                    "Identify which snapshots/backups deleted",
                    "Check for automated backup policy changes",
                    "Review principal's recent activity",
                    "Verify remaining backups are intact",
                ],
                containment_actions=[
                    "Revoke access if unauthorised",
                    "Create new snapshots immediately",
                    "Enable snapshot schedule policies",
                    "Restrict snapshot deletion permissions",
                    "Review IAM roles for backup access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist automated snapshot lifecycle management",
            detection_coverage="95% - catches snapshot and backup deletion operations",
            evasion_considerations="Cannot evade Cloud Audit Logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1490-gcp-backup-policy",
            name="GCP Backup Policy Modification",
            description="Detect changes to Cloud SQL backup configurations and resource policies.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName=~"(sqladmin.instances.update|compute.resourcePolicies.delete)"
AND (protoPayload.request.backupConfiguration.enabled=false OR protoPayload.methodName="compute.resourcePolicies.delete")""",
                gcp_terraform_template="""# GCP: Detect backup policy modifications

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "backup_policy_changes" {
  project = var.project_id
  name   = "backup-policy-modification"
  filter = <<-EOT
    protoPayload.methodName=~"(sqladmin.instances.update|compute.resourcePolicies.delete)"
    AND (
      protoPayload.request.backupConfiguration.enabled=false
      OR protoPayload.methodName="compute.resourcePolicies.delete"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }

}

resource "google_monitoring_alert_policy" "backup_policy_changes" {
  project      = var.project_id
  display_name = "GCP Backup Policy Modified"
  combiner     = "OR"

  conditions {
    display_name = "Backup policy disabled or deleted"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.backup_policy_changes.name}\" AND resource.type=\"global\""
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

}""",
                alert_severity="high",
                alert_title="GCP: Backup Policy Modified",
                alert_description_template="Backup configuration disabled or resource policy deleted",
                investigation_steps=[
                    "Verify change was authorised",
                    "Check which resources affected",
                    "Review backup configuration changes",
                    "Verify automated backups still running",
                    "Check for other policy modifications",
                ],
                containment_actions=[
                    "Re-enable backup configurations",
                    "Restore resource policies",
                    "Restrict backup modification permissions",
                    "Create manual backups immediately",
                    "Review IAM policies for backup access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Backup policy changes are typically rare and documented",
            detection_coverage="85% - catches backup configuration changes",
            evasion_considerations="Cannot evade Cloud Audit Logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Inhibit System Recovery
        DetectionStrategy(
            strategy_id="t1490-azure",
            name="Azure Inhibit System Recovery Detection",
            description=(
                "Monitor backup and recovery inhibition. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Inhibit System Recovery Detection
// Technique: T1490
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.RecoveryServices/vaults/delete"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| project
    TimeGenerated,
    SubscriptionId,
    ResourceGroup,
    Resource,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    Properties
| order by TimeGenerated desc""",
                azure_activity_operations=["Microsoft.RecoveryServices/vaults/delete"],
                azure_terraform_template="""# Azure Detection for Inhibit System Recovery
# MITRE ATT&CK: T1490

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
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
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

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "inhibit-system-recovery-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "inhibit-system-recovery-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Inhibit System Recovery Detection
// Technique: T1490
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.RecoveryServices/vaults/delete"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| project
    TimeGenerated,
    SubscriptionId,
    ResourceGroup,
    Resource,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    Properties
| order by TimeGenerated desc
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects Inhibit System Recovery (T1490) activity in Azure environment"
  display_name = "Inhibit System Recovery Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1490"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Inhibit System Recovery Detected",
                alert_description_template=(
                    "Inhibit System Recovery activity detected. "
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
        "t1490-aws-snapshot-delete",
        "t1490-aws-backup-disable",
        "t1490-aws-s3-versioning",
        "t1490-gcp-snapshot-delete",
        "t1490-gcp-backup-policy",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+28% improvement for Impact tactic",
)
