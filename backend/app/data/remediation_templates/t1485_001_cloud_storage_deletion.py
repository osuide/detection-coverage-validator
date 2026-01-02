"""
T1485.001 - Data Destruction: Cloud Storage Object Deletion

Adversaries exploit cloud storage lifecycle policies to systematically destroy objects.
Threat actors with sufficient permissions can manipulate lifecycle policies to trigger
bulk deletion, often targeting logging buckets to obscure activity and remove forensic evidence.
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
    technique_id="T1485.001",
    technique_name="Data Destruction: Cloud Storage Object Deletion",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1485/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit cloud storage lifecycle policies to systematically destroy "
            "objects in AWS S3, Google Cloud Storage, or Azure Blob Storage. Threat actors "
            "with sufficient permissions can manipulate these policies to trigger bulk deletion. "
            "Beyond extortion and financial theft, adversaries may target logging buckets to "
            "obscure activity and remove forensic evidence."
        ),
        attacker_goal="Destroy data for impact, extortion, or evidence removal",
        why_technique=[
            "Automates bulk deletion of objects",
            "Difficult to reverse once executed",
            "Can target logging buckets for anti-forensics",
            "Leverages legitimate cloud features",
            "May evade traditional deletion monitoring",
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="uncommon",
        trend="emerging",
        severity_score=9,
        severity_reasoning=(
            "High impact technique capable of mass data destruction. Can result in "
            "permanent data loss, business disruption, and evidence destruction. "
            "Particularly dangerous when targeting backup or logging infrastructure."
        ),
        business_impact=[
            "Permanent data loss",
            "Business continuity disruption",
            "Forensic evidence destruction",
            "Regulatory compliance violations",
            "Recovery costs and downtime",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1098", "T1078.004"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: GuardDuty Impact Detection (Recommended)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1485-001-aws-guardduty",
            name="AWS GuardDuty S3 Impact Detection",
            description=(
                "Leverage GuardDuty's ML-based detection for anomalous S3 deletion patterns. "
                "Detects unusual bulk deletions and destructive activity. "
                "See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Impact:S3/AnomalousBehavior.Delete",
                    "Impact:S3/AnomalousBehavior.Permission",
                    "Impact:S3/AnomalousBehavior.Write",
                ],
                terraform_template="""# AWS GuardDuty S3 Impact Detection
# Detects: Impact:S3/AnomalousBehavior.Delete
# See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html

variable "alert_email" {
  type        = string
  description = "Email for impact alerts"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "impact_alerts" {
  name              = "guardduty-impact-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.impact_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Enable GuardDuty with S3 Protection
resource "aws_guardduty_detector" "main" {
  enable = true
  datasources {
    s3_logs {
      enable = true
    }
  }
}

# Step 3: Route Impact findings to SNS
resource "aws_cloudwatch_event_rule" "impact_findings" {
  name        = "guardduty-impact-findings"
  description = "Detect S3 destructive activity via GuardDuty"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Impact:S3/" }]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-s3-impact-dlq"
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
      values   = [aws_cloudwatch_event_rule.impact_findings.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.impact_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.impact_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      findingType = "$.detail.type"
      severity    = "$.detail.severity"
      bucket      = "$.detail.resource.s3BucketDetails[0].name"
      principal   = "$.detail.resource.accessKeyDetails.userName"
      accountId   = "$.account"
    }
    input_template = <<-EOF
      "CRITICAL: GuardDuty S3 Impact Alert"
      "Type: <findingType>"
      "Severity: <severity>"
      "Bucket: <bucket>"
      "Principal: <principal>"
      "Account: <accountId>"
      "Action: Immediately investigate - potential data destruction in progress"
    EOF
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.impact_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.impact_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.impact_findings.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: S3 Destructive Activity Detected",
                alert_description_template=(
                    "GuardDuty detected destructive S3 activity: {type}. "
                    "Bucket {bucket} affected by {principal}."
                ),
                investigation_steps=[
                    "Review the specific GuardDuty finding for full context",
                    "Identify all objects deleted in the time window",
                    "Check S3 versioning status and recover deleted versions",
                    "Verify if lifecycle policies were modified",
                    "Review the principal's recent activity",
                ],
                containment_actions=[
                    "Immediately revoke the principal's credentials",
                    "Enable S3 versioning if not already enabled",
                    "Enable S3 Object Lock on critical buckets",
                    "Restore objects from versioned copies",
                    "Review and restrict deletion permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty's ML learns baseline deletion patterns. "
                "Suppress findings for authorised cleanup automation. "
                "Use trusted IP lists for known admin systems."
            ),
            detection_coverage="90% - ML-based anomaly detection for bulk deletions",
            evasion_considerations="Very slow deletions over time may blend into baseline",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "S3 Protection: ~$0.80 per million S3 events. "
                "See: https://aws.amazon.com/guardduty/pricing/"
            ),
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        # =====================================================================
        # STRATEGY 2: S3 Lifecycle Policy Modification Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1485-001-aws-s3-lifecycle",
            name="AWS S3 Lifecycle Policy Modification Detection",
            description="Detect unauthorised modifications to S3 bucket lifecycle policies.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.bucketName, requestParameters.LifecycleConfiguration
| filter eventName = "PutBucketLifecycle" or eventName = "PutBucketLifecycleConfiguration"
| filter requestParameters.LifecycleConfiguration.Rule.*.Expiration.Days < 7 or requestParameters.LifecycleConfiguration.Rule.*.Expiration.Date exists
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 lifecycle policy modifications for rapid deletion

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: s3-lifecycle-modification-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for lifecycle policy changes
  LifecyclePolicyFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "PutBucketLifecycle") || ($.eventName = "PutBucketLifecycleConfiguration") }'
      MetricTransformations:
        - MetricName: S3LifecyclePolicyChanges
          MetricNamespace: Security/S3
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for lifecycle policy modifications
  LifecyclePolicyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3-Lifecycle-Policy-Modification
      AlarmDescription: Detects modifications to S3 lifecycle policies
      MetricName: S3LifecyclePolicyChanges
      Namespace: Security/S3
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect S3 lifecycle policy modifications for rapid deletion

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "lifecycle_alerts" {
  name = "s3-lifecycle-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.lifecycle_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for lifecycle policy changes
resource "aws_cloudwatch_log_metric_filter" "lifecycle_policy" {
  name           = "s3-lifecycle-policy-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"PutBucketLifecycle\") || ($.eventName = \"PutBucketLifecycleConfiguration\") }"

  metric_transformation {
    name      = "S3LifecyclePolicyChanges"
    namespace = "Security/S3"
    value     = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for lifecycle policy modifications
resource "aws_cloudwatch_metric_alarm" "lifecycle_policy" {
  alarm_name          = "S3-Lifecycle-Policy-Modification"
  alarm_description   = "Detects modifications to S3 lifecycle policies"
  metric_name         = "S3LifecyclePolicyChanges"
  namespace           = "Security/S3"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.lifecycle_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="S3 Lifecycle Policy Modification Detected",
                alert_description_template="S3 lifecycle policy modified on bucket {bucketName} by {principalId}.",
                investigation_steps=[
                    "Identify the principal who modified the lifecycle policy",
                    "Review the lifecycle configuration for deletion rules",
                    "Check if the policy sets rapid expiration (< 7 days)",
                    "Verify if logging or backup buckets were targeted",
                    "Review recent CloudTrail activity for the principal",
                    "Check for any objects already deleted",
                ],
                containment_actions=[
                    "Immediately revert or delete malicious lifecycle policies",
                    "Suspend or revoke credentials of the principal",
                    "Enable S3 Object Lock on critical buckets",
                    "Restore deleted objects from backups if available",
                    "Implement SCPs to restrict PutBucketLifecycle permissions",
                    "Enable MFA Delete on critical buckets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Lifecycle policy changes are infrequent and should be reviewed",
            detection_coverage="90% - catches lifecycle policy modifications",
            evasion_considerations="Adversaries with DeleteObject permissions may delete directly instead",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1485-001-aws-s3-mass-deletion",
            name="AWS S3 Mass Object Deletion Detection",
            description="Detect unusual volume of S3 object deletions.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.bucketName, requestParameters.key
| filter eventName = "DeleteObject" or eventName = "DeleteObjects"
| stats count(*) as deletions by userIdentity.principalId, requestParameters.bucketName, bin(5m)
| filter deletions > 100
| sort deletions desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect mass S3 object deletions

Parameters:
  S3DataEventsLogGroup:
    Type: String
    Description: CloudTrail S3 data events log group
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: s3-mass-deletion-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for mass deletions
  MassDeletionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref S3DataEventsLogGroup
      FilterPattern: '{ ($.eventName = "DeleteObject") || ($.eventName = "DeleteObjects") }'
      MetricTransformations:
        - MetricName: S3ObjectDeletions
          MetricNamespace: Security/S3
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for high deletion rate
  MassDeletionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3-Mass-Object-Deletion
      AlarmDescription: Detects unusually high S3 object deletion rate
      MetricName: S3ObjectDeletions
      Namespace: Security/S3
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect mass S3 object deletions

variable "s3_data_events_log_group" {
  type        = string
  description = "CloudTrail S3 data events log group"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "deletion_alerts" {
  name = "s3-mass-deletion-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.deletion_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for mass deletions
resource "aws_cloudwatch_log_metric_filter" "mass_deletion" {
  name           = "s3-mass-deletion"
  log_group_name = var.s3_data_events_log_group
  pattern        = "{ ($.eventName = \"DeleteObject\") || ($.eventName = \"DeleteObjects\") }"

  metric_transformation {
    name      = "S3ObjectDeletions"
    namespace = "Security/S3"
    value     = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for high deletion rate
resource "aws_cloudwatch_metric_alarm" "mass_deletion" {
  alarm_name          = "S3-Mass-Object-Deletion"
  alarm_description   = "Detects unusually high S3 object deletion rate"
  metric_name         = "S3ObjectDeletions"
  namespace           = "Security/S3"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.deletion_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Mass S3 Object Deletion Detected",
                alert_description_template="High volume of S3 deletions by {principalId} on bucket {bucketName}.",
                investigation_steps=[
                    "Identify the principal performing deletions",
                    "Review the affected bucket and objects",
                    "Check if deletions are authorised activity",
                    "Verify credential compromise indicators",
                    "Review CloudTrail for related suspicious activity",
                    "Check S3 versioning status and deleted versions",
                ],
                containment_actions=[
                    "Suspend or revoke compromised credentials",
                    "Enable S3 versioning if not already enabled",
                    "Restore objects from versions or backups",
                    "Apply bucket policies to restrict deletions",
                    "Enable MFA Delete on critical buckets",
                    "Review and tighten IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on normal deletion patterns; whitelist automated cleanup jobs",
            detection_coverage="80% - catches high-volume deletions",
            evasion_considerations="Low-and-slow deletions may evade threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$20-50",
            prerequisites=[
                "CloudTrail with S3 data events enabled",
                "CloudWatch Logs integration",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1485-001-gcp-storage-lifecycle",
            name="GCP Storage Lifecycle Policy Modification Detection",
            description="Detect unauthorised modifications to Cloud Storage lifecycle policies.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.buckets.update"
protoPayload.request.lifecycle.rule.action.type="Delete"''',
                gcp_terraform_template="""# GCP: Detect Cloud Storage lifecycle policy modifications

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Storage Lifecycle Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Create log-based metric for lifecycle changes
resource "google_logging_metric" "lifecycle_policy" {
  project = var.project_id
  name   = "storage-lifecycle-policy-changes"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.buckets.update"
    protoPayload.request.lifecycle.rule.action.type="Delete"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
  project = var.project_id
}

# Step 3: Create alert policy for lifecycle modifications
resource "google_monitoring_alert_policy" "lifecycle_policy" {
  project      = var.project_id
  display_name = "Storage Lifecycle Policy Modification"
  combiner     = "OR"
  conditions {
    display_name = "Lifecycle policy modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.lifecycle_policy.name}\" resource.type=\"gcs_bucket\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "604800s"
    notification_rate_limit {
      period = "300s"
    }
  }
  project = var.project_id
}""",
                alert_severity="critical",
                alert_title="GCP: Storage Lifecycle Policy Modification",
                alert_description_template="Cloud Storage lifecycle policy modified on bucket.",
                investigation_steps=[
                    "Identify the principal who modified the lifecycle policy",
                    "Review the lifecycle configuration for deletion rules",
                    "Check if the policy sets rapid deletion conditions",
                    "Verify if logging or backup buckets were targeted",
                    "Review recent Cloud Audit Logs for the principal",
                    "Check for any objects already deleted",
                ],
                containment_actions=[
                    "Revert or remove malicious lifecycle policies",
                    "Suspend or revoke compromised credentials",
                    "Enable Object Retention on critical buckets",
                    "Restore deleted objects from backups",
                    "Review and tighten IAM permissions",
                    "Implement Organisation Policy constraints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Lifecycle policy changes are infrequent and should be reviewed",
            detection_coverage="90% - catches lifecycle policy modifications",
            evasion_considerations="Adversaries may use direct object deletion instead",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1485-001-gcp-storage-mass-deletion",
            name="GCP Storage Mass Object Deletion Detection",
            description="Detect unusual volume of Cloud Storage object deletions.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.delete"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect mass Cloud Storage object deletions

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Storage Deletion Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Create log-based metric for object deletions
resource "google_logging_metric" "mass_deletion" {
  project = var.project_id
  name   = "storage-object-deletions"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.delete"
    severity="NOTICE"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
  project = var.project_id
}

# Step 3: Create alert policy for high deletion rate
resource "google_monitoring_alert_policy" "mass_deletion" {
  project      = var.project_id
  display_name = "Storage Mass Object Deletion"
  combiner     = "OR"
  conditions {
    display_name = "High deletion rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.mass_deletion.name}\" resource.type=\"gcs_bucket\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "604800s"
    notification_rate_limit {
      period = "300s"
    }
  }
  project = var.project_id
}""",
                alert_severity="critical",
                alert_title="GCP: Mass Storage Object Deletion",
                alert_description_template="High volume of Cloud Storage object deletions detected.",
                investigation_steps=[
                    "Identify the principal performing deletions",
                    "Review the affected bucket and objects",
                    "Check if deletions are authorised activity",
                    "Verify credential compromise indicators",
                    "Review Cloud Audit Logs for related activity",
                    "Check object versioning status",
                ],
                containment_actions=[
                    "Suspend or revoke compromised credentials",
                    "Enable Object Versioning if not enabled",
                    "Restore objects from versions or backups",
                    "Apply IAM policies to restrict deletions",
                    "Review and tighten service account permissions",
                    "Implement Organisation Policy constraints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on normal deletion patterns; whitelist automated cleanup jobs",
            detection_coverage="80% - catches high-volume deletions",
            evasion_considerations="Low-and-slow deletions may evade threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Cloud Audit Logs with Data Access logs enabled"],
        ),
    ],
    recommended_order=[
        "t1485-001-aws-guardduty",
        "t1485-001-aws-s3-lifecycle",
        "t1485-001-gcp-storage-lifecycle",
        "t1485-001-aws-s3-mass-deletion",
        "t1485-001-gcp-storage-mass-deletion",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+25% improvement for Impact tactic",
)
