"""
T1486 - Data Encrypted for Impact

Adversaries encrypt data to disrupt availability (ransomware).
In cloud, includes encrypting S3 objects with SSE-C, RDS encryption changes.
Used by LockBit, Conti, REvil, Black Basta.
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
    technique_id="T1486",
    technique_name="Data Encrypted for Impact",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1486/",
    threat_context=ThreatContext(
        description=(
            "Adversaries encrypt data to disrupt availability and demand ransom. "
            "In cloud environments, this includes encrypting S3 objects with SSE-C "
            "(server-side encryption with customer-provided keys), RDS encryption, "
            "and EBS volume encryption changes."
        ),
        attacker_goal="Encrypt data to disrupt operations and demand ransom",
        why_technique=[
            "Direct financial motivation",
            "Cloud storage easily re-encrypted",
            "SSE-C keys controlled by attacker",
            "Backups may also be encrypted",
            "High pressure on victims",
        ],
        known_threat_actors=["LockBit", "Conti", "REvil", "Black Basta"],
        recent_campaigns=[
            Campaign(
                name="LockBit 3.0 Cloud Ransomware",
                year=2024,
                description="Uses AES-256 and ChaCha20 for encrypting victim data",
                reference_url="https://attack.mitre.org/software/S1070/",
            ),
            Campaign(
                name="Cloud Ransomware Trend",
                year=2024,
                description="Increasing use of cloud-native encryption for ransomware attacks",
                reference_url="https://unit42.paloaltonetworks.com/2025-cloud-security-alert-trends/",
            ),
        ],
        prevalence="moderate",
        trend="increasing",
        severity_score=10,
        severity_reasoning=(
            "Critical impact - ransomware causes major business disruption. "
            "Cloud encryption changes can lock out legitimate users permanently."
        ),
        business_impact=[
            "Complete data inaccessibility",
            "Business operations disruption",
            "Ransom payment pressure",
            "Potential permanent data loss",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1530", "T1485"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1486-aws-ssec",
            name="AWS S3 SSE-C Encryption Detection",
            description="Detect S3 objects being encrypted with customer-provided keys.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName, userIdentity.arn
| filter eventSource = "s3.amazonaws.com"
| filter eventName = "PutObject"
| filter requestParameters.SSECustomerAlgorithm != ""
| stats count(*) as ssec_uploads by userIdentity.arn, requestParameters.bucketName, bin(1h)
| filter ssec_uploads > 10
| sort ssec_uploads desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect potential S3 ransomware via SSE-C

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

  SSECFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "s3.amazonaws.com" && $.eventName = "PutObject" && $.requestParameters.SSECustomerAlgorithm = "*" }'
      MetricTransformations:
        - MetricName: S3SSECUploads
          MetricNamespace: Security
          MetricValue: "1"

  SSECAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: PotentialS3Ransomware
      MetricName: S3SSECUploads
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect potential S3 ransomware via SSE-C

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-ransomware-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "ssec_uploads" {
  name           = "s3-ssec-uploads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"s3.amazonaws.com\" && $.eventName = \"PutObject\" && $.requestParameters.SSECustomerAlgorithm = \"*\" }"

  metric_transformation {
    name      = "S3SSECUploads"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ransomware" {
  alarm_name          = "PotentialS3Ransomware"
  metric_name         = "S3SSECUploads"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Potential S3 Ransomware - SSE-C Encryption",
                alert_description_template="High volume of S3 objects encrypted with customer-provided keys by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify if SSE-C usage was authorised",
                    "Check which buckets affected",
                    "Identify encryption key source",
                    "Check for ransom notes",
                ],
                containment_actions=[
                    "Immediately revoke access",
                    "Check for unaffected backups",
                    "Enable versioning recovery",
                    "Do not pay ransom without counsel",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="SSE-C is rarely used legitimately in most organisations",
            detection_coverage="85% - catches SSE-C based ransomware",
            evasion_considerations="May use SSE-KMS with attacker-controlled key",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1486-aws-kms",
            name="AWS KMS Key Policy Changes",
            description="Detect KMS key policy changes that could lock out legitimate users.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.kms"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "PutKeyPolicy",
                            "CreateKey",
                            "ScheduleKeyDeletion",
                        ]
                    },
                },
                terraform_template="""# Detect KMS key manipulation

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "kms-manipulation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "kms_changes" {
  name = "kms-key-changes"
  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["PutKeyPolicy", "CreateKey", "ScheduleKeyDeletion"] }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.kms_changes.name
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
                alert_severity="high",
                alert_title="KMS Key Policy Changed",
                alert_description_template="KMS key policy modified by {userIdentity.arn}.",
                investigation_steps=[
                    "Review the policy change",
                    "Verify change was authorised",
                    "Check what data encrypted with key",
                    "Verify key still accessible",
                ],
                containment_actions=[
                    "Revert policy if unauthorised",
                    "Review KMS permissions",
                    "Check for data lockout",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="KMS policy changes are infrequent",
            detection_coverage="90% - catches key policy changes",
            evasion_considerations="Cannot evade KMS logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1486-gcp-cmek",
            name="GCP CMEK Key Changes Detection",
            description="Detect changes to customer-managed encryption keys.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"cloudkms.*.UpdateCryptoKeyPrimaryVersion|cloudkms.*.DestroyCryptoKeyVersion"''',
                gcp_terraform_template="""# GCP: Detect CMEK manipulation

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "cmek_changes" {
  name   = "cmek-key-changes"
  filter = <<-EOT
    protoPayload.methodName=~"cloudkms.*Update|cloudkms.*Destroy"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "cmek_changes" {
  display_name = "CMEK Key Changes"
  combiner     = "OR"
  conditions {
    display_name = "Key modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cmek_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="critical",
                alert_title="GCP: CMEK Key Changed",
                alert_description_template="Customer-managed encryption key was modified.",
                investigation_steps=[
                    "Review key version changes",
                    "Verify change was authorised",
                    "Check affected resources",
                    "Verify data still accessible",
                ],
                containment_actions=[
                    "Restore previous key version",
                    "Review KMS permissions",
                    "Check for data lockout",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Key changes are infrequent",
            detection_coverage="90% - catches key manipulation",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1486-aws-ssec", "t1486-aws-kms", "t1486-gcp-cmek"],
    total_effort_hours=2.5,
    coverage_improvement="+22% improvement for Impact tactic",
)
