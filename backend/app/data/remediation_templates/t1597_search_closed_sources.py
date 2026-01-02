"""
T1597 - Search Closed Sources

Adversaries gather victim information from paid, private, or restricted sources
including threat intelligence vendors, dark web marketplaces, and business databases.
Used by EXOTIC LILY for reconnaissance.
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
    technique_id="T1597",
    technique_name="Search Closed Sources",
    tactic_ids=["TA0043"],
    mitre_url="https://attack.mitre.org/techniques/T1597/",
    threat_context=ThreatContext(
        description=(
            "Adversaries gather victim information from paid, private, or otherwise "
            "restricted sources including threat intelligence feeds, private databases, "
            "dark web marketplaces, and business intelligence platforms. This intelligence "
            "supports phishing campaigns, capability development, and initial access planning."
        ),
        attacker_goal="Collect detailed victim intelligence from closed sources to support attack planning",
        why_technique=[
            "Access to detailed technical information",
            "Sensitive organisational data available",
            "Employee information for social engineering",
            "Vulnerability intelligence from threat feeds",
            "Occurs outside defender visibility",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="uncommon",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "Pre-compromise reconnaissance technique occurring outside enterprise defences. "
            "Limited direct impact but enables more effective subsequent attacks. "
            "Detection is extremely difficult and preventive controls are largely ineffective."
        ),
        business_impact=[
            "Enhanced attacker reconnaissance",
            "More targeted phishing campaigns",
            "Exposure of organisational information",
            "Social engineering enabler",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1598", "T1566", "T1078"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1597-aws-guardduty",
            name="AWS GuardDuty Threat Intelligence Detection",
            description="Monitor for access attempts from known threat intelligence sources and suspicious IPs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, sourceIPAddress, eventName, userAgent, errorCode
| filter eventSource = "sts.amazonaws.com" or eventSource = "iam.amazonaws.com"
| filter sourceIPAddress in ["tor", "proxy", "vpn"] or userAgent like /curl|wget|python/
| stats count(*) as attempts by sourceIPAddress, userAgent, bin(1h)
| filter attempts > 5
| sort attempts desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor for reconnaissance from suspicious sources

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

  # Monitor GuardDuty findings for reconnaissance
  GuardDutyReconFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.detail.type = "Recon:*" }'
      MetricTransformations:
        - MetricName: ReconnaissanceActivity
          MetricNamespace: Security
          MetricValue: "1"

  ReconAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ReconnaissanceDetected
      MetricName: ReconnaissanceActivity
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Monitor for reconnaissance from suspicious sources

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "reconnaissance-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "recon_activity" {
  name           = "reconnaissance-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.detail.type = \"Recon:*\" }"

  metric_transformation {
    name      = "ReconnaissanceActivity"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "recon_detected" {
  alarm_name          = "ReconnaissanceDetected"
  metric_name         = "ReconnaissanceActivity"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Reconnaissance Activity Detected",
                alert_description_template="GuardDuty detected reconnaissance activity from {sourceIPAddress}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Check source IP reputation",
                    "Review CloudTrail logs for enumeration",
                    "Identify targeted resources",
                    "Check for data exfiltration attempts",
                ],
                containment_actions=[
                    "Block suspicious IP addresses",
                    "Review IAM policies and permissions",
                    "Enable additional monitoring",
                    "Review public exposure of resources",
                    "Update security group rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="GuardDuty may flag legitimate security scanning; tune for your environment",
            detection_coverage="30% - indirect detection of follow-on activity",
            evasion_considerations="Closed source research occurs outside AWS; only follow-on access detectable",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["AWS GuardDuty enabled", "CloudTrail logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1597-aws-public-data",
            name="AWS Public Data Exposure Monitoring",
            description="Monitor for unauthorised access to public S3 buckets and data exposure.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, requestParameters.bucketName, sourceIPAddress, userAgent
| filter eventName = "GetObject" or eventName = "ListBucket"
| filter userIdentity.type = "Anonymous" or errorCode = "AccessDenied"
| stats count(*) as access_attempts by sourceIPAddress, requestParameters.bucketName, bin(1h)
| filter access_attempts > 10
| sort access_attempts desc""",
                terraform_template="""# Monitor public S3 bucket access patterns

variable "cloudtrail_log_group" { type = string }
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

resource "aws_cloudwatch_log_metric_filter" "public_s3_access" {
  name           = "public-s3-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.userIdentity.type = \"Anonymous\" && ($.eventName = \"GetObject\" || $.eventName = \"ListBucket\") }"

  metric_transformation {
    name      = "PublicS3Access"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "public_bucket_enumeration" {
  alarm_name          = "PublicBucketEnumeration"
  metric_name         = "PublicS3Access"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Public S3 Bucket Enumeration Detected",
                alert_description_template="High volume of anonymous access to S3 bucket {bucketName} from {sourceIPAddress}.",
                investigation_steps=[
                    "Review S3 bucket permissions and ACLs",
                    "Check what data was accessed",
                    "Review source IP reputation",
                    "Identify if bucket should be public",
                    "Check for data exfiltration",
                ],
                containment_actions=[
                    "Restrict S3 bucket public access",
                    "Enable S3 Block Public Access",
                    "Review and update bucket policies",
                    "Enable S3 access logging",
                    "Rotate exposed credentials if found",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold for legitimate public buckets (CDN, static sites)",
            detection_coverage="40% - detects enumeration of exposed data",
            evasion_considerations="Low-volume targeted access may not trigger alerts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1597-gcp-public-data",
            name="GCP Public Data Exposure Monitoring",
            description="Monitor for unauthorised access to public GCS buckets and data exposure.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName=~"storage.objects.(get|list)"
protoPayload.authenticationInfo.principalEmail=""
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Monitor public GCS bucket access

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "public_gcs_access" {
  project = var.project_id
  name   = "public-gcs-access"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName=~"storage.objects.(get|list)"
    protoPayload.authenticationInfo.principalEmail=""
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "gcs_enumeration" {
  project      = var.project_id
  display_name = "GCS Public Access Enumeration"
  combiner     = "OR"
  conditions {
    display_name = "High anonymous access rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.public_gcs_access.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Public GCS Bucket Enumeration",
                alert_description_template="High volume of anonymous access to GCS bucket detected.",
                investigation_steps=[
                    "Review GCS bucket IAM policies",
                    "Check what objects were accessed",
                    "Review request patterns and source IPs",
                    "Verify if bucket should be public",
                    "Check for sensitive data exposure",
                ],
                containment_actions=[
                    "Restrict bucket public access",
                    "Update IAM policies",
                    "Enable uniform bucket-level access",
                    "Review and remove allUsers/allAuthenticatedUsers",
                    "Enable data access logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds for legitimate public buckets",
            detection_coverage="40% - detects enumeration of exposed data",
            evasion_considerations="Low-volume targeted access may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["GCS data access logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1597-aws-macie",
            name="AWS Macie Sensitive Data Discovery",
            description="Use AWS Macie to identify and monitor sensitive data that may be exposed.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="macie",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, severity, type, resourcesAffected
| filter source = "aws.macie"
| filter detail.type like /SENSITIVE_DATA|PII/
| stats count(*) as findings by detail.severity, bin(1d)
| sort findings desc""",
                terraform_template="""# Use AWS Macie to monitor for data exposure

variable "alert_email" { type = string }
variable "s3_buckets" {
  description = "S3 buckets to monitor"
  type        = list(string)
}

resource "aws_macie2_account" "main" {}

resource "aws_sns_topic" "alerts" {
  name = "macie-sensitive-data-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for EventBridge targets
resource "aws_sqs_queue" "events_dlq" {
  name                      = "macie-events-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "events_dlq" {
  queue_url = aws_sqs_queue.events_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.events_dlq.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "macie_findings" {
  name        = "macie-sensitive-data-findings"
  description = "Alert on Macie sensitive data findings"

  event_pattern = jsonencode({
    source      = ["aws.macie"]
    detail-type = ["Macie Finding"]
    detail = {
      type     = ["SensitiveData:*", "Policy:*"]
      severity = { numeric = [">", 4] }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.macie_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.events_dlq.arn
  }
  input_transformer {
    input_paths = {
      account = "$.account"
      region  = "$.region"
      time    = "$.time"
      source  = "$.source"
      detail  = "$.detail"
    }

    input_template = <<-EOT
"Security Alert
Time: <time>
Account: <account>
Region: <region>
Source: <source>
Action: Review event details and investigate"
EOT
  }

}

# Allow EventBridge to publish to SNS
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.macie_findings.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Sensitive Data Exposure Detected",
                alert_description_template="AWS Macie detected sensitive data exposure in {bucketName}.",
                investigation_steps=[
                    "Review Macie finding details",
                    "Identify type of sensitive data exposed",
                    "Check bucket access logs",
                    "Determine if data was accessed",
                    "Review bucket permissions",
                ],
                containment_actions=[
                    "Restrict bucket access immediately",
                    "Remove or encrypt sensitive data",
                    "Enable bucket encryption",
                    "Review and update data classification",
                    "Implement data loss prevention controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Macie findings are generally accurate; review severity thresholds",
            detection_coverage="50% - identifies exposed sensitive data",
            evasion_considerations="Only detects data already exposed in S3",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$50-200 depending on data volume",
            prerequisites=["AWS Macie enabled", "S3 buckets configured for scanning"],
        ),
    ],
    recommended_order=[
        "t1597-aws-public-data",
        "t1597-gcp-public-data",
        "t1597-aws-macie",
        "t1597-aws-guardduty",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+15% improvement for Reconnaissance tactic",
)
