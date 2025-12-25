"""
T1583.006 - Acquire Infrastructure: Web Services

Adversaries register for web-based services during targeting to support later
attack stages. Popular platforms like Google, GitHub, and Twitter are abused
because they blend operations into expected network traffic.
Used by APT17, APT28, APT29, APT32, Lazarus Group, Kimsuky, MuddyWater.
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
    technique_id="T1583.006",
    technique_name="Acquire Infrastructure: Web Services",
    tactic_ids=["TA0042"],
    mitre_url="https://attack.mitre.org/techniques/T1583/006/",
    threat_context=ThreatContext(
        description=(
            "Adversaries register for web-based services during the targeting phase "
            "to support later attack stages. Popular platforms like Google Drive, GitHub, "
            "Dropbox, and social media are abused because they blend malicious operations "
            "into expected network traffic. This approach allows threat actors to obscure "
            "connections to their infrastructure for C2, data exfiltration, and malware hosting."
        ),
        attacker_goal="Register web services to support command and control, data exfiltration, or malware hosting",
        why_technique=[
            "Blends into normal network traffic",
            "Trusted domains bypass security controls",
            "Free and easy to register",
            "Difficult to block legitimate services",
            "Provides plausible deniability",
            "Often has generous bandwidth/storage",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Occurs during pre-compromise phase, making direct prevention difficult. "
            "Successful abuse can enable sophisticated C2 channels and data exfiltration "
            "that bypasses traditional security controls. Detection relies on post-compromise indicators."
        ),
        business_impact=[
            "Enables covert command and control",
            "Facilitates data exfiltration",
            "Difficult to detect and block",
            "Increases attack sophistication",
            "Complicates incident response",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1102", "T1567", "T1071"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1583-006-aws-cloudtrail-web",
            name="AWS CloudTrail Unusual Web Service Access",
            description="Detect unusual access patterns to known cloud storage and web services from AWS resources.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, sourceIPAddress, userAgent, requestParameters.bucketName, eventName
| filter eventSource = "s3.amazonaws.com"
| filter eventName IN ["PutObject", "GetObject", "ListBucket"]
| filter requestParameters.bucketName not like /^(your-org|company|internal)/
| filter userAgent like /(aws-cli|boto3|curl|wget|powershell)/
| stats count(*) as requests by sourceIPAddress, userAgent, bin(1h)
| filter requests > 100
| sort requests desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious web service usage patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  WebServiceAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "s3.amazonaws.com") && ($.userAgent = "*curl*" || $.userAgent = "*wget*" || $.userAgent = "*powershell*") }'
      MetricTransformations:
        - MetricName: SuspiciousWebServiceAccess
          MetricNamespace: Security/WebServices
          MetricValue: "1"

  WebServiceAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousWebServiceAccess
      MetricName: SuspiciousWebServiceAccess
      Namespace: Security/WebServices
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious web service access patterns

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "web_service_alerts" {
  name = "web-service-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.web_service_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "web_service_access" {
  name           = "suspicious-web-service-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.userAgent = \"*curl*\" || $.userAgent = \"*wget*\" || $.userAgent = \"*powershell*\") }"

  metric_transformation {
    name      = "SuspiciousWebServiceAccess"
    namespace = "Security/WebServices"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "web_service_abuse" {
  alarm_name          = "SuspiciousWebServiceAccess"
  metric_name         = "SuspiciousWebServiceAccess"
  namespace           = "Security/WebServices"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.web_service_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious Web Service Access Detected",
                alert_description_template="Unusual web service access from {sourceIPAddress} using {userAgent}.",
                investigation_steps=[
                    "Review the source IP and associated AWS resources",
                    "Check if the user agent matches expected tools",
                    "Examine the accessed buckets and objects",
                    "Correlate with other suspicious activities",
                    "Review IAM credentials and access patterns",
                ],
                containment_actions=[
                    "Disable compromised IAM credentials",
                    "Block suspicious IP addresses",
                    "Review S3 bucket policies",
                    "Enable MFA for sensitive operations",
                    "Implement SCPs to restrict external services",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter out legitimate automation and backup tools. Adjust user agent patterns for your environment.",
            detection_coverage="40% - detects automated tool usage but misses browser-based access",
            evasion_considerations="Attackers can use legitimate browsers or custom user agents to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "CloudWatch Logs integration",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1583-006-aws-vpc-flow",
            name="AWS VPC Flow Logs Web Service Detection",
            description="Detect connections to known cloud storage and file-sharing services via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, bytes
| filter dstaddr like /dropbox|github|pastebin|telegram|discord/
| stats sum(bytes) as totalBytes by srcaddr, dstaddr, bin(1h)
| filter totalBytes > 100000000
| sort totalBytes desc""",
                terraform_template="""# Detect high-volume connections to web services

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "web_service_traffic" {
  name = "web-service-traffic-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.web_service_traffic.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "web_service_connections" {
  name           = "web-service-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]"

  metric_transformation {
    name      = "WebServiceConnections"
    namespace = "Security/Network"
    value     = "$bytes"
  }
}

resource "aws_cloudwatch_metric_alarm" "high_web_service_traffic" {
  alarm_name          = "HighWebServiceTraffic"
  metric_name         = "WebServiceConnections"
  namespace           = "Security/Network"
  statistic           = "Sum"
  period              = 300
  threshold           = 100000000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.web_service_traffic.arn]
}""",
                alert_severity="medium",
                alert_title="High-Volume Web Service Traffic",
                alert_description_template="Significant data transfer to web service from {srcaddr}.",
                investigation_steps=[
                    "Identify the source instance or resource",
                    "Review the destination service",
                    "Check volume and frequency of transfers",
                    "Correlate with authorised activities",
                    "Review instance security and access logs",
                ],
                containment_actions=[
                    "Isolate affected instances",
                    "Block unauthorised destinations via NACLs",
                    "Review and rotate credentials",
                    "Implement DLP controls",
                    "Enable GuardDuty for enhanced detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Exclude known legitimate backup and sync services. Adjust byte thresholds based on baseline.",
            detection_coverage="50% - detects high-volume transfers but requires DNS resolution for accuracy",
            evasion_considerations="Small, frequent transfers may evade volume-based detection. Encrypted traffic hides content.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled", "DNS logging for resolution"],
        ),
        DetectionStrategy(
            strategy_id="t1583-006-gcp-cloud-logging",
            name="GCP Cloud Logging Web Service Access",
            description="Detect unusual access to cloud storage and web services from GCP resources.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName=~"storage.objects.(get|create|list)"
protoPayload.requestMetadata.callerSuppliedUserAgent=~"(curl|wget|powershell|python-requests)"
severity>="WARNING"''',
                gcp_terraform_template="""# GCP: Detect suspicious web service access

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Web Service Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "web_service_access" {
  name   = "suspicious-web-service-access"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName=~"storage.objects.(get|create|list)"
    protoPayload.requestMetadata.callerSuppliedUserAgent=~"(curl|wget|powershell|python-requests)"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "web_service_abuse" {
  display_name = "Suspicious Web Service Access"
  combiner     = "OR"
  conditions {
    display_name = "High access rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.web_service_access.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Suspicious Web Service Access",
                alert_description_template="Unusual web service access detected in GCP project.",
                investigation_steps=[
                    "Review the service account or user",
                    "Check the accessed buckets and objects",
                    "Examine user agent and request patterns",
                    "Correlate with authorised activities",
                    "Review IAM permissions and policies",
                ],
                containment_actions=[
                    "Disable compromised service accounts",
                    "Review and tighten IAM policies",
                    "Enable VPC Service Controls",
                    "Implement organisation policies",
                    "Enable Data Loss Prevention scanning",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known automation tools and CI/CD pipelines. Adjust user agent patterns.",
            detection_coverage="45% - detects automated access but not browser-based",
            evasion_considerations="Custom user agents and browser-based access evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["Cloud Logging enabled", "Storage audit logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1583-006-gcp-vpc-flow",
            name="GCP VPC Flow Logs External Service Detection",
            description="Monitor network connections to external web services from GCP resources.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName=~".*vpc_flows.*"
jsonPayload.connection.dest_ip=~"(.*dropbox.*|.*github.*|.*pastebin.*|.*telegram.*)"
jsonPayload.bytes_sent > 100000000""",
                gcp_terraform_template="""# GCP: Monitor high-volume web service connections

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Network Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "web_service_traffic" {
  name   = "high-web-service-traffic"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~".*vpc_flows.*"
    jsonPayload.bytes_sent > 100000000
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "By"
  }
  value_extractor = "EXTRACT(jsonPayload.bytes_sent)"
}

resource "google_monitoring_alert_policy" "high_traffic" {
  display_name = "High Web Service Traffic"
  combiner     = "OR"
  conditions {
    display_name = "Large data transfer"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.web_service_traffic.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100000000
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: High-Volume Web Service Traffic",
                alert_description_template="Significant data transfer to external web service detected.",
                investigation_steps=[
                    "Identify source VM or service",
                    "Review destination service",
                    "Check data volume and patterns",
                    "Correlate with business activities",
                    "Review VM security and access",
                ],
                containment_actions=[
                    "Isolate affected VMs",
                    "Configure firewall rules to block",
                    "Review and rotate credentials",
                    "Enable VPC Service Controls",
                    "Implement DLP policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Baseline normal traffic patterns and exclude legitimate services. Adjust threshold.",
            detection_coverage="50% - volume-based detection misses small transfers",
            evasion_considerations="Low-and-slow exfiltration evades volume thresholds. Encrypted tunnels hide destinations.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$20-35",
            prerequisites=["VPC Flow Logs enabled", "Cloud DNS logging"],
        ),
    ],
    recommended_order=[
        "t1583-006-aws-cloudtrail-web",
        "t1583-006-gcp-cloud-logging",
        "t1583-006-aws-vpc-flow",
        "t1583-006-gcp-vpc-flow",
    ],
    total_effort_hours=10.0,
    coverage_improvement="+15% improvement for Resource Development tactic detection",
)
