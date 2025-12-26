"""
T1591 - Gather Victim Org Information

Adversaries collect intelligence about target organisations to inform attack planning.
This includes departmental structures, operational details, and employee roles.
Used by APT28, FIN7, Kimsuky, Lazarus Group, Moonstone Sleet, Volt Typhoon.
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
    technique_id="T1591",
    technique_name="Gather Victim Org Information",
    tactic_ids=["TA0043"],
    mitre_url="https://attack.mitre.org/techniques/T1591/",
    threat_context=ThreatContext(
        description=(
            "Adversaries collect intelligence about target organisations including "
            "departmental structures, operational details, employee roles, business "
            "relationships, and physical locations. This reconnaissance occurs through "
            "phishing, social media, public websites, and accessible datasets to inform "
            "subsequent attacks including phishing campaigns and initial access attempts."
        ),
        attacker_goal="Gather organisational intelligence to plan and customise attacks",
        why_technique=[
            "Enables targeted phishing campaigns",
            "Identifies high-value targets and roles",
            "Reveals business relationships and partners",
            "Uncovers operational tempo and schedules",
            "Occurs outside enterprise defences",
            "Publicly available information reduces risk",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Pre-compromise reconnaissance with limited detection opportunities. "
            "Enables subsequent attack phases but doesn't directly compromise systems. "
            "High prevalence as initial step in targeted attack campaigns."
        ),
        business_impact=[
            "Enables targeted social engineering",
            "Reveals sensitive organisational structure",
            "Exposes business relationships",
            "Identifies high-value targets",
            "Precursor to initial access attempts",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1598", "T1566", "T1078", "T1589"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1591-aws-web-scraping",
            name="AWS: Detect Automated Scraping of Public Resources",
            description="Monitor CloudFront and S3 access logs for automated scraping patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, c-ip, cs-uri-stem, cs-user-agent, sc-bytes
| filter cs-user-agent like /bot|crawler|scraper|spider|curl|wget|python/i
| filter cs-uri-stem like /about|team|contact|careers|press|investor/
| stats count(*) as requests, sum(sc-bytes) as bytes by c-ip, cs-user-agent, bin(1h)
| filter requests > 100 or bytes > 10000000
| sort requests desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect automated scraping of public organisational data

Parameters:
  CloudFrontLogGroup:
    Type: String
    Description: CloudWatch log group for CloudFront access logs
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Web Scraping Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for automated scraping
  ScrapingFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudFrontLogGroup
      FilterPattern: '[timestamp, x-edge-location, sc-bytes, c-ip, cs-method, cs-host, cs-uri-stem, sc-status, cs-referer, cs-user-agent = *bot* || cs-user-agent = *crawler* || cs-user-agent = *scraper*, ...]'
      MetricTransformations:
        - MetricName: AutomatedScraping
          MetricNamespace: Security/Reconnaissance
          MetricValue: "1"

  # Alarm for high scraping activity
  ScrapingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighAutomatedScraping
      AlarmDescription: Potential automated reconnaissance of organisational data
      MetricName: AutomatedScraping
      Namespace: Security/Reconnaissance
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# AWS: Detect automated scraping of public organisational data

variable "cloudfront_log_group" {
  type        = string
  description = "CloudWatch log group for CloudFront access logs"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

data "aws_caller_identity" "current" {}

# SNS topic for alerts
resource "aws_sns_topic" "scraping_alerts" {
  name         = "web-scraping-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Web Scraping Alerts"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.scraping_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.scraping_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.scraping_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for automated scraping
resource "aws_cloudwatch_log_metric_filter" "automated_scraping" {
  name           = "automated-scraping"
  log_group_name = var.cloudfront_log_group
  pattern        = "[timestamp, x-edge-location, sc-bytes, c-ip, cs-method, cs-host, cs-uri-stem, sc-status, cs-referer, cs-user-agent = *bot* || cs-user-agent = *crawler* || cs-user-agent = *scraper*, ...]"

  metric_transformation {
    name      = "AutomatedScraping"
    namespace = "Security/Reconnaissance"
    value     = "1"
  }
}

# Alarm for high scraping activity
resource "aws_cloudwatch_metric_alarm" "scraping_activity" {
  alarm_name          = "HighAutomatedScraping"
  alarm_description   = "Potential automated reconnaissance of organisational data"
  metric_name         = "AutomatedScraping"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.scraping_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Automated Scraping of Organisational Data Detected",
                alert_description_template="High volume of automated requests detected from {c-ip} using {cs-user-agent}.",
                investigation_steps=[
                    "Review source IP and user agent patterns",
                    "Identify which pages were accessed most frequently",
                    "Check for correlation with other reconnaissance activities",
                    "Determine if legitimate search engine or malicious actor",
                    "Review timing patterns and access frequency",
                ],
                containment_actions=[
                    "Implement rate limiting on public pages",
                    "Add CAPTCHA to sensitive organisational pages",
                    "Block confirmed malicious IPs via WAF",
                    "Review and minimise exposed organisational data",
                    "Monitor for subsequent attack phases",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Exclude legitimate search engines and monitoring services by IP/user-agent",
            detection_coverage="40% - detects automated scraping only",
            evasion_considerations="Manual browsing and rate-limited scraping evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["CloudFront with access logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1591-aws-phishing-attempts",
            name="AWS: Detect Reconnaissance Phishing via SES",
            description="Monitor SES for phishing attempts seeking organisational information.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, mail.source, mail.destination, delivery.recipients
| filter mail.commonHeaders.subject like /org chart|organisation|directory|employee list|staff list/i
| filter delivery.smtpResponse like /rejected|bounce|blocked/
| stats count(*) as attempts by mail.source, bin(1d)
| filter attempts > 5
| sort attempts desc""",
                terraform_template="""# AWS: Detect reconnaissance phishing attempts via SES

variable "ses_log_group" {
  type        = string
  description = "CloudWatch log group for SES events"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

data "aws_caller_identity" "current" {}

# SNS topic for alerts
resource "aws_sns_topic" "phishing_alerts" {
  name         = "reconnaissance-phishing-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Reconnaissance Phishing Alerts"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.phishing_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.phishing_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.phishing_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for reconnaissance phishing
resource "aws_cloudwatch_log_metric_filter" "recon_phishing" {
  name           = "reconnaissance-phishing"
  log_group_name = var.ses_log_group
  pattern        = "[org chart, organisation, directory, employee list, staff list]"

  metric_transformation {
    name      = "ReconnaissancePhishing"
    namespace = "Security/Reconnaissance"
    value     = "1"
  }
}

# Alarm for reconnaissance phishing attempts
resource "aws_cloudwatch_metric_alarm" "recon_phishing" {
  alarm_name          = "ReconnaissancePhishingAttempts"
  alarm_description   = "Phishing attempts seeking organisational information"
  metric_name         = "ReconnaissancePhishing"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 86400
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.phishing_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Reconnaissance Phishing Attempts Detected",
                alert_description_template="Multiple phishing attempts seeking organisational data from {mail.source}.",
                investigation_steps=[
                    "Review email content and subjects",
                    "Identify targeted recipients and departments",
                    "Check sender reputation and domain",
                    "Determine if part of broader campaign",
                    "Review any successful deliveries",
                ],
                containment_actions=[
                    "Block sender domains via SES",
                    "Alert targeted employees",
                    "Review and update email filtering rules",
                    "Monitor for follow-up attacks",
                    "Brief security awareness training",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate HR and recruitment communications",
            detection_coverage="30% - detects email-based reconnaissance only",
            evasion_considerations="Social media and phone-based reconnaissance undetected",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["SES with CloudWatch logging configured"],
        ),
        DetectionStrategy(
            strategy_id="t1591-gcp-public-bucket-access",
            name="GCP: Detect Enumeration of Public Storage Buckets",
            description="Monitor Cloud Storage audit logs for systematic bucket enumeration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gcs_bucket"
protoPayload.methodName="storage.buckets.list" OR protoPayload.methodName="storage.objects.list"
protoPayload.authenticationInfo.principalEmail="allUsers" OR protoPayload.authenticationInfo.principalEmail="allAuthenticatedUsers"
protoPayload.status.code!=7""",
                gcp_terraform_template="""# GCP: Detect enumeration of public storage buckets

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Reconnaissance Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Log-based metric for public bucket enumeration
resource "google_logging_metric" "bucket_enumeration" {
  name   = "public-bucket-enumeration"
  filter = <<-EOT
    resource.type="gcs_bucket"
    (protoPayload.methodName="storage.buckets.list" OR protoPayload.methodName="storage.objects.list")
    (protoPayload.authenticationInfo.principalEmail="allUsers" OR protoPayload.authenticationInfo.principalEmail="allAuthenticatedUsers")
    protoPayload.status.code!=7
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "caller_ip"
      value_type  = "STRING"
      description = "IP address of caller"
    }
  }

  label_extractors = {
    "caller_ip" = "EXTRACT(protoPayload.requestMetadata.callerIp)"
  }
}

# Alert policy for bucket enumeration
resource "google_monitoring_alert_policy" "bucket_enumeration" {
  display_name = "Public Bucket Enumeration Detected"
  combiner     = "OR"
  conditions {
    display_name = "High enumeration rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.bucket_enumeration.name}\" resource.type=\"gcs_bucket\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "604800s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Public Bucket Enumeration Detected",
                alert_description_template="Systematic enumeration of public storage buckets from {caller_ip}.",
                investigation_steps=[
                    "Review accessed bucket names and patterns",
                    "Identify source IP geolocation and reputation",
                    "Check for successful data access",
                    "Determine if sensitive organisational data exposed",
                    "Review bucket permissions and public access",
                ],
                containment_actions=[
                    "Review and restrict public bucket access",
                    "Enable Bucket Lock for sensitive data",
                    "Implement VPC Service Controls",
                    "Block malicious IPs via Cloud Armor",
                    "Audit all public storage resources",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate CDN and analytics services by IP range",
            detection_coverage="45% - detects bucket-based reconnaissance",
            evasion_considerations="Private bucket access and API-based reconnaissance harder to detect",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Storage audit logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1591-gcp-workspace-directory",
            name="GCP: Detect Directory Enumeration Attempts",
            description="Monitor Google Workspace audit logs for directory enumeration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="audited_resource"
protoPayload.serviceName="admin.googleapis.com"
protoPayload.methodName=~"directory.users.list|directory.orgunits.list|directory.groups.list"
protoPayload.status.code!=0""",
                gcp_terraform_template="""# GCP: Detect Google Workspace directory enumeration

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Directory Enumeration Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Log-based metric for directory enumeration
resource "google_logging_metric" "directory_enum" {
  name   = "workspace-directory-enumeration"
  filter = <<-EOT
    resource.type="audited_resource"
    protoPayload.serviceName="admin.googleapis.com"
    (protoPayload.methodName=~"directory.users.list" OR
     protoPayload.methodName=~"directory.orgunits.list" OR
     protoPayload.methodName=~"directory.groups.list")
    protoPayload.status.code!=0
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "Email of the caller"
    }
  }

  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Alert policy for directory enumeration
resource "google_monitoring_alert_policy" "directory_enum" {
  display_name = "Workspace Directory Enumeration"
  combiner     = "OR"
  conditions {
    display_name = "Failed enumeration attempts"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.directory_enum.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "604800s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Workspace Directory Enumeration Detected",
                alert_description_template="Multiple directory enumeration attempts by {principal_email}.",
                investigation_steps=[
                    "Review caller identity and authentication method",
                    "Check for compromised credentials",
                    "Identify targeted organisational units",
                    "Review successful vs failed attempts",
                    "Correlate with other suspicious activities",
                ],
                containment_actions=[
                    "Revoke suspicious API credentials",
                    "Review and restrict directory API access",
                    "Enable advanced protection for high-risk users",
                    "Implement context-aware access policies",
                    "Brief affected users on targeted reconnaissance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude legitimate admin and HR service accounts",
            detection_coverage="55% - detects API-based directory access",
            evasion_considerations="Manual browsing and social engineering undetected",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Google Workspace with Admin SDK logging"],
        ),
    ],
    recommended_order=[
        "t1591-aws-web-scraping",
        "t1591-gcp-public-bucket-access",
        "t1591-gcp-workspace-directory",
        "t1591-aws-phishing-attempts",
    ],
    total_effort_hours=10.0,
    coverage_improvement="+15% improvement for Reconnaissance tactic (limited detection opportunities for pre-compromise activity)",
)
