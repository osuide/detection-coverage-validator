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
    Campaign,
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
            "Precedes data theft (T1530)"
        ],
        known_threat_actors=["Pacu users", "Peirates operators"],
        recent_campaigns=[
            Campaign(
                name="S3 Bucket Enumeration",
                year=2024,
                description="305% increase in suspicious storage downloads reported by Unit 42",
                reference_url="https://unit42.paloaltonetworks.com/2025-cloud-security-alert-trends/"
            )
        ],
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
            "Indicates compromised credentials"
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1530", "T1537"],
        often_follows=["T1078.004", "T1580"]
    ),

    detection_strategies=[
        # Strategy 1: AWS - S3 ListObjects Detection
        DetectionStrategy(
            strategy_id="t1619-aws-s3list",
            name="S3 Object Listing Detection",
            description="Detect high-volume S3 ListObjects API calls indicating enumeration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, eventName, requestParameters.bucketName, userIdentity.arn, sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["ListObjects", "ListObjectsV2", "ListBucket"]
| stats count(*) as list_calls by userIdentity.arn, requestParameters.bucketName, bin(1h)
| filter list_calls > 100
| sort list_calls desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
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
      Period: 3600
      Threshold: 500
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]''',
                terraform_template='''# Detect S3 object enumeration

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-enum-alerts"
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
  period              = 3600
  threshold           = 500
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}''',
                alert_severity="medium",
                alert_title="S3 Object Enumeration Detected",
                alert_description_template="High volume S3 ListObjects calls from {userIdentity.arn} on bucket {bucketName}.",
                investigation_steps=[
                    "Identify who is enumerating objects",
                    "Check which buckets were listed",
                    "Review if legitimate application behaviour",
                    "Check for subsequent GetObject calls"
                ],
                containment_actions=[
                    "Review IAM permissions for S3 list",
                    "Enable S3 Object Lock if not set",
                    "Check for data exfiltration",
                    "Consider bucket policies to restrict listing"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist backup tools and CDN refresh processes",
            detection_coverage="85% - catches high-volume listing",
            evasion_considerations="Slow enumeration across many buckets may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail S3 data events enabled"]
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
                gcp_terraform_template='''# GCP: Detect GCS object enumeration

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "gcs_list" {
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

  notification_channels = [google_monitoring_notification_channel.email.id]
}''',
                alert_severity="medium",
                alert_title="GCP: GCS Object Enumeration",
                alert_description_template="High volume GCS object listing detected.",
                investigation_steps=[
                    "Identify the enumerating principal",
                    "Check which buckets were listed",
                    "Review for subsequent object access",
                    "Verify legitimate application behaviour"
                ],
                containment_actions=[
                    "Review IAM permissions",
                    "Enable VPC Service Controls",
                    "Check for data exfiltration"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist backup and CDN processes",
            detection_coverage="85% - catches high-volume listing",
            evasion_considerations="Slow enumeration may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs with data access enabled"]
        )
    ],

    recommended_order=["t1619-aws-s3list", "t1619-gcp-gcslist"],
    total_effort_hours=2.0,
    coverage_improvement="+15% improvement for Discovery tactic"
)
