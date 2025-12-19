"""
T1595.003 - Wordlist Scanning

Adversaries use iterative probing with wordlists to discover infrastructure, content,
and resources. Targets include web directories, DNS subdomains, and cloud storage buckets.
Used by APT41, Volatile Cedar.
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
    technique_id="T1595.003",
    technique_name="Wordlist Scanning",
    tactic_ids=["TA0043"],
    mitre_url="https://attack.mitre.org/techniques/T1595/003/",

    threat_context=ThreatContext(
        description=(
            "Adversaries use wordlist-based iterative probing to discover infrastructure, "
            "content, and resources. Unlike credential brute forcing, wordlist scanning "
            "targets identification of web directories, DNS subdomains, cloud storage buckets, "
            "and hidden administrative portals using tools like DirBuster, GoBuster, and s3recon."
        ),
        attacker_goal="Discover hidden infrastructure, content, and resources for reconnaissance",
        why_technique=[
            "Identifies hidden administrative portals",
            "Discovers outdated vulnerable pages",
            "Enumerates cloud storage buckets",
            "Maps DNS subdomains",
            "Low-cost automated discovery",
            "Reveals organisation structure"
        ],
        known_threat_actors=["APT41", "Volatile Cedar"],
        recent_campaigns=[
            Campaign(
                name="Volatile Cedar Web Discovery",
                year=2024,
                description="Deployed DirBuster and GoBuster for web directory and DNS subdomain enumeration",
                reference_url="https://attack.mitre.org/techniques/T1595/003/"
            ),
            Campaign(
                name="APT41 Web Server Scanning",
                year=2024,
                description="Used various brute-force tools against web servers for reconnaissance",
                reference_url="https://attack.mitre.org/groups/G0096/"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Pre-compromise reconnaissance technique. Successful scanning reveals attack "
            "surface, hidden resources, and vulnerable endpoints that enable subsequent attacks."
        ),
        business_impact=[
            "Exposes hidden attack surface",
            "Reveals sensitive endpoints",
            "Identifies misconfigured cloud storage",
            "Maps organisation infrastructure",
            "Precursor to exploitation"
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1190", "T1530", "T1110"],
        often_follows=["T1595.001", "T1595.002"]
    ),

    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1595-003-aws-waf-scanning",
            name="AWS WAF Rate-Based Scanning Detection",
            description="Detect wordlist scanning attempts via AWS WAF rate-based rules and logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, httpRequest.clientIp, httpRequest.uri, httpRequest.httpMethod
| filter terminatingRuleId like /Rate/
| stats count(*) as requests, count_distinct(httpRequest.uri) as unique_paths by httpRequest.clientIp, bin(5m)
| filter unique_paths > 20 or requests > 100
| sort requests desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect wordlist scanning via WAF rate limiting

Parameters:
  WAFLogGroup:
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

  # Detect high-rate scanning attempts
  ScanningFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref WAFLogGroup
      FilterPattern: '{ $.terminatingRuleId = "*Rate*" }'
      MetricTransformations:
        - MetricName: WordlistScanning
          MetricNamespace: Security/Reconnaissance
          MetricValue: "1"

  ScanningAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: WordlistScanningDetected
      MetricName: WordlistScanning
      Namespace: Security/Reconnaissance
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]''',
                terraform_template='''# Detect wordlist scanning via WAF rate limiting

variable "waf_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "wordlist-scanning-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "scanning" {
  name           = "wordlist-scanning"
  log_group_name = var.waf_log_group
  pattern        = "{ $.terminatingRuleId = \"*Rate*\" }"

  metric_transformation {
    name      = "WordlistScanning"
    namespace = "Security/Reconnaissance"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "scanning_detected" {
  alarm_name          = "WordlistScanningDetected"
  metric_name         = "WordlistScanning"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}''',
                alert_severity="medium",
                alert_title="Wordlist Scanning Detected",
                alert_description_template="High-volume scanning activity from {clientIp}.",
                investigation_steps=[
                    "Review unique paths requested",
                    "Check for common wordlist patterns (admin, backup, test, api)",
                    "Identify if successful discoveries occurred (200 responses)",
                    "Review source IP reputation",
                    "Check for subsequent exploitation attempts"
                ],
                containment_actions=[
                    "Block scanning IP at WAF/security group",
                    "Review discovered paths for exposure",
                    "Enable stricter rate limiting",
                    "Remove unnecessary exposed endpoints",
                    "Check S3 bucket permissions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate crawlers may trigger; whitelist known good IPs",
            detection_coverage="65% - catches high-rate scanning",
            evasion_considerations="Slow scanning below rate limits, distributed scanning",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["AWS WAF with rate-based rules enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1595-003-aws-cloudtrail-s3",
            name="AWS S3 Bucket Enumeration Detection",
            description="Detect S3 bucket wordlist scanning via CloudTrail.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.principalId, requestParameters.bucketName, errorCode
| filter eventName = "HeadBucket" or eventName = "ListBucket" or eventName = "GetBucketLocation"
| filter errorCode = "NoSuchBucket" or errorCode = "AccessDenied"
| stats count(*) as attempts by userIdentity.principalId, sourceIPAddress, bin(5m)
| filter attempts > 10
| sort attempts desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 bucket enumeration attempts

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

  # Detect bucket enumeration attempts
  BucketEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "HeadBucket" || $.eventName = "ListBucket") && ($.errorCode = "NoSuchBucket" || $.errorCode = "AccessDenied") }'
      MetricTransformations:
        - MetricName: S3BucketEnumeration
          MetricNamespace: Security/Reconnaissance
          MetricValue: "1"

  BucketEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3BucketEnumerationDetected
      MetricName: S3BucketEnumeration
      Namespace: Security/Reconnaissance
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]''',
                terraform_template='''# Detect S3 bucket enumeration attempts

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-enumeration-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "bucket_enum" {
  name           = "s3-bucket-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"HeadBucket\" || $.eventName = \"ListBucket\") && ($.errorCode = \"NoSuchBucket\" || $.errorCode = \"AccessDenied\") }"

  metric_transformation {
    name      = "S3BucketEnumeration"
    namespace = "Security/Reconnaissance"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "bucket_enum_detected" {
  alarm_name          = "S3BucketEnumerationDetected"
  metric_name         = "S3BucketEnumeration"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}''',
                alert_severity="medium",
                alert_title="S3 Bucket Enumeration Detected",
                alert_description_template="Multiple bucket enumeration attempts from {sourceIPAddress}.",
                investigation_steps=[
                    "Review attempted bucket names for patterns",
                    "Check if organisation naming conventions exposed",
                    "Identify any successful discoveries",
                    "Review source IP and user agent",
                    "Check for subsequent access attempts"
                ],
                containment_actions=[
                    "Review S3 bucket naming conventions",
                    "Ensure bucket policies are restrictive",
                    "Block public bucket access organisation-wide",
                    "Enable S3 Block Public Access",
                    "Review bucket ACLs and policies"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Failed bucket requests are strong indicators",
            detection_coverage="75% - catches bucket enumeration",
            evasion_considerations="Slow enumeration, distributed sources",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail with S3 data events enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1595-003-aws-alb-404",
            name="ALB 404 Pattern Detection",
            description="Detect directory brute-forcing via ALB 404 response patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, client_ip, request_url, elb_status_code, user_agent
| filter elb_status_code = 404
| stats count(*) as not_found_count, count_distinct(request_url) as unique_paths by client_ip, bin(5m)
| filter not_found_count > 30 and unique_paths > 15
| sort not_found_count desc''',
                terraform_template='''# Detect directory brute-forcing via ALB logs

variable "alb_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "directory-scanning-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "directory_scan" {
  name           = "directory-scanning"
  log_group_name = var.alb_log_group
  pattern        = "[..., elb_status_code = 404, ...]"

  metric_transformation {
    name      = "DirectoryScanning"
    namespace = "Security/Reconnaissance"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "scanning_detected" {
  alarm_name          = "DirectoryScanningDetected"
  metric_name         = "DirectoryScanning"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}''',
                alert_severity="medium",
                alert_title="Directory Scanning Detected",
                alert_description_template="High volume of 404 errors from {client_ip}.",
                investigation_steps=[
                    "Review requested paths for wordlist patterns",
                    "Check for common scanning tools in user agent",
                    "Identify any successful discoveries (200, 301, 302 responses)",
                    "Review legitimate vs scanning traffic ratio",
                    "Check for follow-up exploitation attempts"
                ],
                containment_actions=[
                    "Block scanning IP address",
                    "Enable WAF with rate limiting",
                    "Remove or protect discovered paths",
                    "Implement request throttling",
                    "Review exposed directory structure"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune thresholds for application traffic patterns",
            detection_coverage="60% - catches directory brute-forcing",
            evasion_considerations="Slow scanning, encoded paths",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["ALB access logging enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1595-003-gcp-lb-scanning",
            name="GCP Load Balancer Scanning Detection",
            description="Detect wordlist scanning via Cloud Load Balancing logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
httpRequest.status >= 400
httpRequest.status < 500''',
                gcp_terraform_template='''# GCP: Detect wordlist scanning via Load Balancer logs

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "lb_scanning" {
  name   = "wordlist-scanning"
  filter = <<-EOT
    resource.type="http_load_balancer"
    httpRequest.status >= 400
    httpRequest.status < 500
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "client_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }
  label_extractors = {
    "client_ip" = "EXTRACT(httpRequest.remoteIp)"
  }
}

resource "google_monitoring_alert_policy" "scanning_detected" {
  display_name = "Wordlist Scanning Detected"
  combiner     = "OR"
  conditions {
    display_name = "High 404 rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.lb_scanning.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}''',
                alert_severity="medium",
                alert_title="GCP: Wordlist Scanning Detected",
                alert_description_template="High volume of scanning activity detected on load balancer.",
                investigation_steps=[
                    "Review requested paths in Cloud Logging",
                    "Check for wordlist patterns",
                    "Identify successful discoveries",
                    "Review source IP addresses",
                    "Check for subsequent attacks"
                ],
                containment_actions=[
                    "Configure Cloud Armor rate limiting",
                    "Block scanning IP addresses",
                    "Review and restrict exposed endpoints",
                    "Enable Cloud Armor security policies",
                    "Review GCS bucket permissions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold for application patterns",
            detection_coverage="60% - catches scanning attempts",
            evasion_considerations="Slow scanning, distributed sources",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Load Balancing with logging enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1595-003-gcp-storage-enum",
            name="GCP Storage Bucket Enumeration Detection",
            description="Detect GCS bucket enumeration via Cloud Audit Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=("storage.buckets.get" OR "storage.buckets.list")
protoPayload.status.code != 0
severity="ERROR"''',
                gcp_terraform_template='''# GCP: Detect GCS bucket enumeration attempts

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "bucket_enum" {
  name   = "gcs-bucket-enumeration"
  filter = <<-EOT
    protoPayload.methodName=("storage.buckets.get" OR "storage.buckets.list")
    protoPayload.status.code != 0
    severity="ERROR"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "bucket_enum_detected" {
  display_name = "GCS Bucket Enumeration Detected"
  combiner     = "OR"
  conditions {
    display_name = "High enumeration rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.bucket_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}''',
                alert_severity="medium",
                alert_title="GCP: GCS Bucket Enumeration Detected",
                alert_description_template="Multiple bucket enumeration attempts detected.",
                investigation_steps=[
                    "Review attempted bucket names",
                    "Check for organisation naming patterns",
                    "Identify successful discoveries",
                    "Review source IP and caller identity",
                    "Check for subsequent access attempts"
                ],
                containment_actions=[
                    "Review GCS bucket naming conventions",
                    "Enable uniform bucket-level access",
                    "Remove public access from buckets",
                    "Implement organisation policies",
                    "Review bucket IAM permissions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Failed bucket requests are strong indicators",
            detection_coverage="70% - catches bucket enumeration",
            evasion_considerations="Slow enumeration, distributed sources",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Audit Logs for GCS enabled"]
        )
    ],

    recommended_order=[
        "t1595-003-aws-s3",
        "t1595-003-gcp-storage-enum",
        "t1595-003-aws-waf-scanning",
        "t1595-003-gcp-lb-scanning",
        "t1595-003-aws-alb-404"
    ],
    total_effort_hours=5.5,
    coverage_improvement="+25% improvement for Reconnaissance tactic"
)
