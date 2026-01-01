"""
T1491 - Defacement

Adversaries modify visual content available internally or externally to impact
content integrity, deliver messaging, intimidate, or claim credit for intrusions.
Used by Sandworm, Cyber Army of Russia, and CyberToufan.
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
    technique_id="T1491",
    technique_name="Defacement",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1491/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify visual content available internally or externally to "
            "impact content integrity. In cloud environments, this includes defacing "
            "websites hosted on S3, GCS buckets, modifying web application content, "
            "and altering public-facing resources to deliver messaging, intimidate, "
            "or claim credit for intrusions."
        ),
        attacker_goal="Modify visual content to damage reputation, intimidate, or deliver messaging",
        why_technique=[
            "Deliver political or ideological messaging",
            "Damage organisation reputation",
            "Claim credit for intrusion",
            "Intimidate victims or stakeholders",
            "Cloud storage easily modified if credentials compromised",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "High reputational impact - defacement damages public trust and brand image. "
            "Often used for political messaging or intimidation. "
            "May indicate deeper compromise requiring investigation."
        ),
        business_impact=[
            "Reputational damage",
            "Loss of customer trust",
            "Regulatory scrutiny",
            "Potential revenue loss",
            "Emergency response costs",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1530", "T1190"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1491-aws-s3web",
            name="AWS S3 Website Content Modification Detection",
            description="Detect unauthorised modifications to S3 objects hosting website content.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName, requestParameters.key, userIdentity.arn
| filter eventSource = "s3.amazonaws.com"
| filter eventName = "PutObject" or eventName = "DeleteObject"
| filter requestParameters.bucketName like /web|site|www|public/
| stats count(*) as modifications by userIdentity.arn, requestParameters.bucketName, bin(15m)
| filter modifications > 5
| sort modifications desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 website defacement attempts

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

  S3WebModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "s3.amazonaws.com") && ($.eventName = "PutObject" || $.eventName = "DeleteObject") && ($.requestParameters.bucketName = "*web*" || $.requestParameters.bucketName = "*site*" || $.requestParameters.bucketName = "*www*" || $.requestParameters.bucketName = "*public*") }'
      MetricTransformations:
        - MetricName: S3WebsiteModifications
          MetricNamespace: Security
          MetricValue: "1"

  S3WebModificationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3WebsiteDefacement
      MetricName: S3WebsiteModifications
      Namespace: Security
      Statistic: Sum
      Period: 900
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect S3 website defacement

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-defacement-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "web_modifications" {
  name           = "s3-website-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.eventName = \"PutObject\" || $.eventName = \"DeleteObject\") && ($.requestParameters.bucketName = \"*web*\" || $.requestParameters.bucketName = \"*site*\" || $.requestParameters.bucketName = \"*www*\" || $.requestParameters.bucketName = \"*public*\") }"

  metric_transformation {
    name      = "S3WebsiteModifications"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "defacement" {
  alarm_name          = "S3WebsiteDefacement"
  metric_name         = "S3WebsiteModifications"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 900
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Potential S3 Website Defacement",
                alert_description_template="Unusual volume of modifications to website S3 bucket by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify changes were authorised",
                    "Compare current content with backups",
                    "Review which files were modified",
                    "Check access logs for suspicious IPs",
                    "Determine if credentials were compromised",
                ],
                containment_actions=[
                    "Restore content from version history or backups",
                    "Revoke compromised credentials",
                    "Enable S3 Object Lock for critical content",
                    "Review bucket policies and IAM permissions",
                    "Enable MFA Delete on production buckets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised deployment pipelines and content management systems",
            detection_coverage="85% - catches bulk modifications to website buckets",
            evasion_considerations="Attackers may modify files slowly to avoid threshold detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with S3 data events"],
        ),
        DetectionStrategy(
            strategy_id="t1491-aws-public-access",
            name="AWS S3 Bucket Public Access Changes",
            description="Detect changes to S3 bucket public access settings that could enable defacement.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "PutBucketAcl",
                            "PutBucketPolicy",
                            "PutBucketWebsite",
                            "DeleteBucketPolicy",
                        ]
                    },
                },
                terraform_template="""# Detect S3 public access changes

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-public-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "public_access" {
  name = "s3-public-access-changes"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["PutBucketAcl", "PutBucketPolicy", "PutBucketWebsite", "DeleteBucketPolicy"] }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "public-access-dlq"
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
      values   = [aws_cloudwatch_event_rule.public_access.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.public_access.name
  arn  = aws_sns_topic.alerts.arn

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
            "aws:SourceArn" = aws_cloudwatch_event_rule.public_access.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="S3 Bucket Public Access Modified",
                alert_description_template="S3 bucket public access settings changed by {userIdentity.arn}.",
                investigation_steps=[
                    "Review the bucket policy or ACL changes",
                    "Verify change was authorised",
                    "Check if bucket hosts public website content",
                    "Review recent object modifications",
                    "Assess if bucket was previously private",
                ],
                containment_actions=[
                    "Revert unauthorised policy changes",
                    "Enable S3 Block Public Access",
                    "Review IAM permissions for bucket modifications",
                    "Audit all public-facing buckets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Bucket policy changes are typically infrequent and controlled",
            detection_coverage="95% - catches all public access configuration changes",
            evasion_considerations="Cannot evade CloudTrail logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1491-gcp-storage-web",
            name="GCP Storage Website Content Modification Detection",
            description="Detect unauthorised modifications to GCS buckets hosting website content.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"storage.objects.(create|update|patch|delete)"
resource.labels.bucket_name=~"(web|www|site|public)"''',
                gcp_terraform_template="""# GCP: Detect website content defacement

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "website_modifications" {
  name   = "gcs-website-modifications"
  filter = <<-EOT
    protoPayload.methodName=~"storage.objects.(create|update|patch|delete)"
    resource.labels.bucket_name=~"(web|www|site|public)"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "website_defacement" {
  display_name = "GCS Website Defacement"
  combiner     = "OR"
  conditions {
    display_name = "High volume of website modifications"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.website_modifications.name}\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "900s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Website Content Modified",
                alert_description_template="Unusual volume of modifications to website GCS bucket detected.",
                investigation_steps=[
                    "Verify changes were authorised",
                    "Compare current content with previous versions",
                    "Review which objects were modified",
                    "Check audit logs for suspicious principals",
                    "Determine if service account credentials were compromised",
                ],
                containment_actions=[
                    "Restore content from object versioning",
                    "Revoke compromised service account keys",
                    "Enable Object Versioning if not enabled",
                    "Review IAM bindings on bucket",
                    "Implement bucket retention policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised deployment service accounts and CI/CD pipelines",
            detection_coverage="85% - catches bulk modifications to website buckets",
            evasion_considerations="Attackers may modify objects slowly to avoid threshold detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Cloud Storage"],
        ),
        DetectionStrategy(
            strategy_id="t1491-gcp-bucket-iam",
            name="GCP Storage Bucket IAM Policy Changes",
            description="Detect changes to GCS bucket IAM policies that could enable defacement.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="storage.setIamPermissions"''',
                gcp_terraform_template="""# GCP: Detect bucket IAM policy changes

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "bucket_iam_changes" {
  name   = "gcs-bucket-iam-changes"
  filter = <<-EOT
    protoPayload.methodName="storage.setIamPermissions"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "bucket_iam_changes" {
  display_name = "GCS Bucket IAM Policy Changed"
  combiner     = "OR"
  conditions {
    display_name = "Bucket IAM modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.bucket_iam_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Bucket IAM Policy Changed",
                alert_description_template="GCS bucket IAM permissions were modified.",
                investigation_steps=[
                    "Review the IAM policy changes",
                    "Verify if allUsers or allAuthenticatedUsers was added",
                    "Check which principal made the change",
                    "Determine if change was authorised",
                    "Assess impact on bucket contents",
                ],
                containment_actions=[
                    "Revert unauthorised IAM policy changes",
                    "Remove public access bindings",
                    "Review organisation policy constraints",
                    "Audit all public-facing buckets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Bucket IAM changes are typically infrequent and controlled",
            detection_coverage="95% - catches all bucket IAM policy changes",
            evasion_considerations="Cannot evade Cloud Audit Logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1491-aws-s3web",
        "t1491-aws-public-access",
        "t1491-gcp-storage-web",
        "t1491-gcp-bucket-iam",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+18% improvement for Impact tactic",
)
