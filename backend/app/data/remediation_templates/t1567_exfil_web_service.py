"""
T1567 - Exfiltration Over Web Service

Adversaries use legitimate web services to exfiltrate data.
Used by APT28, BlackByte, OilRig, Magic Hound.
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
    technique_id="T1567",
    technique_name="Exfiltration Over Web Service",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1567/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use legitimate external web services to exfiltrate data. "
            "This provides cover since organisations typically communicate with these "
            "services, and SSL/TLS encryption hides the data."
        ),
        attacker_goal="Exfiltrate data using legitimate web services to avoid detection",
        why_technique=[
            "Blends with normal traffic",
            "SSL/TLS hides data content",
            "Firewall rules permit traffic",
            "Cloud storage has high capacity",
            "Hard to distinguish from legitimate use",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Data exfiltration via trusted services is hard to detect. "
            "Bypasses traditional DLP and firewall controls."
        ),
        business_impact=[
            "Data breach",
            "Intellectual property theft",
            "Regulatory violations",
            "Reputational damage",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1530", "T1552.001", "T1114.003"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1567-aws-s3upload",
            name="AWS Unusual S3 Cross-Account Upload",
            description="Detect data uploads to external S3 buckets.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName, userIdentity.arn, bytesTransferredOut
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutObject", "UploadPart", "CompleteMultipartUpload"]
| filter requestParameters.bucketName not like /your-org-prefix/
| stats sum(bytesTransferredOut) as total_bytes by userIdentity.arn, requestParameters.bucketName, bin(1h)
| filter total_bytes > 104857600
| sort total_bytes desc""",
                terraform_template="""# Detect exfiltration to external S3

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-exfil-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "external_upload" {
  name           = "external-s3-uploads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"s3.amazonaws.com\" && $.eventName = \"PutObject\" }"

  metric_transformation {
    name      = "ExternalS3Uploads"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "exfil_alert" {
  alarm_name          = "S3ExternalUpload"
  metric_name         = "ExternalS3Uploads"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Data Upload to External S3",
                alert_description_template="Large upload to external bucket {bucketName} by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify bucket ownership",
                    "Review uploaded data",
                    "Check if transfer was authorised",
                    "Review user's recent activity",
                ],
                containment_actions=[
                    "Block external bucket access",
                    "Revoke user credentials",
                    "Enable S3 Block Public Access",
                    "Review bucket policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known partner buckets",
            detection_coverage="70% - catches S3 exfiltration",
            evasion_considerations="May use third-party services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1567-aws-vpc",
            name="AWS VPC Large Outbound Transfer",
            description="Detect large outbound data transfers via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, bytes, action
| filter action = "ACCEPT" and bytes > 100000000
| filter dstAddr not like /^10\\./ and dstAddr not like /^172\\.1[6-9]\\./
| stats sum(bytes) as total_bytes by srcAddr, dstAddr, bin(1h)
| filter total_bytes > 1073741824
| sort total_bytes desc""",
                terraform_template="""# Detect large outbound transfers via VPC Flow Logs

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "outbound-transfer-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "large_outbound" {
  name           = "large-outbound-transfer"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes > 100000000, ...]"

  metric_transformation {
    name      = "LargeOutboundTransfer"
    namespace = "Security"
    value     = "$bytes"
  }
}

resource "aws_cloudwatch_metric_alarm" "exfil_transfer" {
  alarm_name          = "LargeOutboundTransfer"
  metric_name         = "LargeOutboundTransfer"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1073741824
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Large Outbound Data Transfer",
                alert_description_template="Large outbound transfer detected from {srcAddr} to {dstAddr}.",
                investigation_steps=[
                    "Identify destination service",
                    "Review source instance activity",
                    "Check for data staging",
                    "Review access patterns",
                ],
                containment_actions=[
                    "Block destination IP",
                    "Isolate source instance",
                    "Review security groups",
                    "Enable DLP controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known backup/CDN destinations",
            detection_coverage="60% - network-level detection",
            evasion_considerations="Low and slow exfiltration may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1567-gcp-storage",
            name="GCP Cloud Storage External Transfer",
            description="Detect data uploads to external Cloud Storage buckets.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="storage.objects.create"
NOT protoPayload.resourceName=~"projects/YOUR-PROJECT"''',
                gcp_terraform_template="""# GCP: Detect external storage uploads

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "external_upload" {
  name   = "external-storage-uploads"
  filter = <<-EOT
    protoPayload.methodName="storage.objects.create"
    NOT protoPayload.resourceName=~"projects/${var.project_id}"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "external_upload" {
  display_name = "External Storage Upload"
  combiner     = "OR"
  conditions {
    display_name = "Uploads to external buckets"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.external_upload.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: External Storage Upload",
                alert_description_template="Data uploaded to external Cloud Storage bucket.",
                investigation_steps=[
                    "Identify destination bucket",
                    "Review uploaded objects",
                    "Check user authorisation",
                    "Review access patterns",
                ],
                containment_actions=[
                    "Block external bucket access",
                    "Revoke user credentials",
                    "Enable VPC Service Controls",
                    "Review IAM policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known partner projects",
            detection_coverage="70% - catches GCS exfiltration",
            evasion_considerations="May use third-party services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs for GCS enabled"],
        ),
    ],
    recommended_order=["t1567-aws-s3upload", "t1567-gcp-storage", "t1567-aws-vpc"],
    total_effort_hours=5.0,
    coverage_improvement="+18% improvement for Exfiltration tactic",
)
