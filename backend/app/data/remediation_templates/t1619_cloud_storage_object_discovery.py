"""
T1619 - Cloud Storage Object Discovery

Adversaries enumerate objects in cloud storage infrastructure (S3, GCS, Azure Blob)
to identify valuable data for exfiltration. Tools like Pacu and Peirates are commonly used.

MITRE ATT&CK Reference: https://attack.mitre.org/techniques/T1619/
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
    technique_id="T1619",
    technique_name="Cloud Storage Object Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1619/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate objects in cloud storage infrastructure using APIs "
            "like AWS ListObjectsV2, Azure List Blobs, or GCP ListObjects to identify "
            "valuable data for subsequent exfiltration."
        ),
        attacker_goal="Enumerate cloud storage objects to identify data for exfiltration",
        why_technique=[
            "Identifies valuable data in S3/GCS/Blob storage",
            "Reveals file structures and naming patterns",
            "Helps prioritise exfiltration targets",
            "Can reveal sensitive file types",
            "Precedes data theft (T1530)",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Discovery technique that directly precedes data exfiltration. "
            "High volume object listing often indicates reconnaissance before theft."
        ),
        business_impact=[
            "Reveals sensitive data locations",
            "Precursor to data exfiltration",
            "Early warning opportunity",
            "Indicates compromised credentials",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1530", "T1537"],
        often_follows=["T1078.004", "T1580"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: GuardDuty S3 Discovery Detection (Recommended)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1619-aws-guardduty",
            name="AWS GuardDuty S3 Discovery Detection",
            description=(
                "Leverage GuardDuty's ML-based detection for S3 enumeration patterns. "
                "Detects unusual bucket and object listing activity. "
                "See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Discovery:S3/AnomalousBehavior",
                    "Discovery:S3/MaliciousIPCaller.Custom",
                ],
                terraform_template="""# AWS GuardDuty S3 Discovery Detection
# Detects: Discovery:S3/AnomalousBehavior
# See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html

variable "alert_email" {
  type        = string
  description = "Email for discovery alerts"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "discovery_alerts" {
  name              = "guardduty-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.discovery_alerts.arn
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

# Step 3: Route Discovery findings to SNS
resource "aws_cloudwatch_event_rule" "discovery_findings" {
  name        = "guardduty-discovery-findings"
  description = "Detect S3 discovery activity via GuardDuty"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Discovery:S3/" }]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-discovery-dlq"
  message_retention_seconds = 1209600  # 14 days
}

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
          "aws:SourceArn" = aws_cloudwatch_event_rule.discovery_findings.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.discovery_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.discovery_alerts.arn

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
      "GuardDuty S3 Discovery Alert"
      "Type: <findingType>"
      "Severity: <severity>"
      "Bucket: <bucket>"
      "Principal: <principal>"
      "Account: <accountId>"
      "Action: Review for reconnaissance activity before exfiltration"
    EOF
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.discovery_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.discovery_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.discovery_findings.arn
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="GuardDuty: S3 Discovery Activity Detected",
                alert_description_template=(
                    "GuardDuty detected S3 discovery activity: {type}. "
                    "Bucket {bucket} being enumerated by {principal}."
                ),
                investigation_steps=[
                    "Review the GuardDuty finding for full anomaly context",
                    "Identify all buckets accessed by this principal",
                    "Check for subsequent GetObject (data access) calls",
                    "Verify if the principal normally accesses these buckets",
                    "Look for signs of credential compromise",
                ],
                containment_actions=[
                    "Review and restrict the principal's S3 permissions",
                    "Check for data exfiltration after the enumeration",
                    "Consider rotating the affected credentials",
                    "Enable S3 Block Public Access if not set",
                    "Review bucket policies for overly permissive access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty's ML learns baseline S3 access patterns. "
                "Suppress findings for legitimate backup and inventory tools. "
                "Use trusted IP lists for known automation infrastructure."
            ),
            detection_coverage="85% - ML-based detection of enumeration patterns",
            evasion_considerations="Slow enumeration may blend into baseline activity",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "S3 Protection: ~$0.80 per million S3 events. "
                "See: https://aws.amazon.com/guardduty/pricing/"
            ),
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        # =====================================================================
        # STRATEGY 2: AWS - S3 ListObjects Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1619-aws-s3list",
            name="S3 Object Listing Detection",
            description="Detect high-volume S3 ListObjects API calls indicating enumeration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName, userIdentity.arn, sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["ListObjects", "ListObjectsV2", "ListBucket"]
| stats count(*) as list_calls by userIdentity.arn, requestParameters.bucketName, bin(1h)
| filter list_calls > 100
| sort list_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 object enumeration

Parameters:
  CloudTrailLogGroup:
    Type: String
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

  S3ListFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "s3.amazonaws.com" && ($.eventName = "ListObjects" || $.eventName = "ListObjectsV2") }'
      MetricTransformations:
        - MetricName: S3ObjectListing
          MetricNamespace: Security
          MetricValue: "1"

  S3ListAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3ObjectEnumeration
      MetricName: S3ObjectListing
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 500
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect S3 object enumeration

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "s3_list" {
  name           = "s3-object-listing"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"s3.amazonaws.com\" && ($.eventName = \"ListObjects\" || $.eventName = \"ListObjectsV2\") }"

  metric_transformation {
    name      = "S3ObjectListing"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_enum" {
  alarm_name          = "S3ObjectEnumeration"
  metric_name         = "S3ObjectListing"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 500
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="S3 Object Enumeration Detected",
                alert_description_template="High volume S3 ListObjects calls from {userIdentity.arn} on bucket {bucketName}.",
                investigation_steps=[
                    "Identify who is enumerating objects",
                    "Check which buckets were listed",
                    "Review if legitimate application behaviour",
                    "Check for subsequent GetObject calls",
                ],
                containment_actions=[
                    "Review IAM permissions for S3 list",
                    "Enable S3 Object Lock if not set",
                    "Check for data exfiltration",
                    "Consider bucket policies to restrict listing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist backup tools and CDN refresh processes",
            detection_coverage="85% - catches high-volume listing",
            evasion_considerations="Slow enumeration across many buckets may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        # Strategy 2: GCP - GCS Object Listing
        DetectionStrategy(
            strategy_id="t1619-gcp-gcslist",
            name="GCS Object Listing Detection",
            description="Detect high-volume GCS ListObjects API calls.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.list"''',
                gcp_terraform_template="""# GCP: Detect GCS object enumeration

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "gcs_list" {
  project = var.project_id
  name   = "gcs-object-listing"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.list"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "gcs_enum" {
  project      = var.project_id
  display_name = "GCS Object Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "High volume object listing"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_list.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 500
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
                alert_title="GCP: GCS Object Enumeration",
                alert_description_template="High volume GCS object listing detected.",
                investigation_steps=[
                    "Identify the enumerating principal",
                    "Check which buckets were listed",
                    "Review for subsequent object access",
                    "Verify legitimate application behaviour",
                ],
                containment_actions=[
                    "Review IAM permissions",
                    "Enable VPC Service Controls",
                    "Check for data exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist backup and CDN processes",
            detection_coverage="85% - catches high-volume listing",
            evasion_considerations="Slow enumeration may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs with data access enabled"],
        ),
    ],
    recommended_order=["t1619-aws-guardduty", "t1619-aws-s3list", "t1619-gcp-gcslist"],
    total_effort_hours=2.0,
    coverage_improvement="+15% improvement for Discovery tactic",
)
