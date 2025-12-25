"""
T1074.002 - Data Staged: Remote Data Staging

Adversaries stage data collected from multiple systems in a central location
on one system before exfiltration. Used to minimise C2 connections and evade detection.
Used by APT28, FIN6, FIN8, Leviathan, menuPass, Sea Turtle, ToddyCat.
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
    technique_id="T1074.002",
    technique_name="Data Staged: Remote Data Staging",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1074/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries stage data collected from multiple systems in a central "
            "location or directory on one system before exfiltration. This includes "
            "using interactive command shells, archiving techniques, and in cloud "
            "environments, creating instances to stage data before transfer. The "
            "technique minimises C2 server connections and helps evade detection."
        ),
        attacker_goal="Stage collected data in a central remote location before exfiltration",
        why_technique=[
            "Minimises C2 server connections",
            "Aggregates data from multiple sources",
            "Evades detection through reduced network activity",
            "Facilitates bulk exfiltration",
            "Exploits normal file transfer features",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Indicates advanced attack phase where adversaries have already collected "
            "data and are preparing for exfiltration. Suggests compromise of multiple "
            "systems and imminent data loss."
        ),
        business_impact=[
            "Data exfiltration preparation",
            "Multiple system compromise indicator",
            "Potential data breach",
            "Compliance violations",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1041", "T1048", "T1567"],
        often_follows=["T1005", "T1039", "T1025", "T1074.001"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1074_002-aws-s3-staging",
            name="AWS S3 Remote Staging Detection",
            description="Detect unusual S3 bucket uploads from EC2 instances that may indicate data staging.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, sourceIPAddress, requestParameters.bucketName, requestParameters.key
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutObject", "CopyObject", "UploadPart"]
| stats count(*) as uploads, sum(requestParameters.contentLength) as totalBytes by sourceIPAddress, requestParameters.bucketName, bin(1h)
| filter uploads > 50 or totalBytes > 1073741824
| sort totalBytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 remote data staging activity

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
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  S3StagingFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "PutObject" || $.eventName = "CopyObject" || $.eventName = "UploadPart") && $.eventSource = "s3.amazonaws.com" }'
      MetricTransformations:
        - MetricName: S3StagingActivity
          MetricNamespace: Security
          MetricValue: "1"

  S3StagingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighS3StagingActivity
      MetricName: S3StagingActivity
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect S3 remote data staging activity

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-staging-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "s3_staging" {
  name           = "s3-staging-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"PutObject\" || $.eventName = \"CopyObject\" || $.eventName = \"UploadPart\") && $.eventSource = \"s3.amazonaws.com\" }"

  metric_transformation {
    name      = "S3StagingActivity"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_staging" {
  alarm_name          = "HighS3StagingActivity"
  metric_name         = "S3StagingActivity"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Potential Remote Data Staging Detected",
                alert_description_template="High volume S3 uploads from {sourceIPAddress} to bucket {bucketName}.",
                investigation_steps=[
                    "Review source IP addresses and EC2 instances",
                    "Check uploaded object sizes and patterns",
                    "Verify bucket ownership and permissions",
                    "Review CloudTrail for related user activity",
                    "Check for compression or archive files",
                ],
                containment_actions=[
                    "Block suspicious source IP addresses",
                    "Review and restrict S3 bucket permissions",
                    "Enable S3 versioning and object lock",
                    "Quarantine suspicious objects",
                    "Review EC2 instance security",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on normal backup and data transfer patterns",
            detection_coverage="65% - catches bulk S3 staging",
            evasion_considerations="Attackers may use rate limiting or smaller batches",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1074_002-aws-vpc-transfer",
            name="AWS VPC Flow Logs - Inter-Instance Transfer",
            description="Detect unusual data transfers between EC2 instances that may indicate staging.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, bytes, packets
| filter action = "ACCEPT"
| filter dstport in [22, 445, 3389, 2049]
| stats sum(bytes) as totalBytes, count(*) as flows by srcaddr, dstaddr, dstport, bin(1h)
| filter totalBytes > 10737418240
| sort totalBytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect large inter-instance data transfers

Parameters:
  VPCFlowLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  LargeTransferFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport="22" || destport="445" || destport="2049", protocol, packets, bytes>1073741824, start, end, action="ACCEPT", flowlogstatus]'
      MetricTransformations:
        - MetricName: LargeInstanceTransfers
          MetricNamespace: Security
          MetricValue: "1"

  LargeTransferAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighInterInstanceTransfer
      MetricName: LargeInstanceTransfers
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect large inter-instance data transfers

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "instance-transfer-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "large_transfers" {
  name           = "large-instance-transfers"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport=\"22\" || destport=\"445\" || destport=\"2049\", protocol, packets, bytes>1073741824, start, end, action=\"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "LargeInstanceTransfers"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "large_transfers" {
  alarm_name          = "HighInterInstanceTransfer"
  metric_name         = "LargeInstanceTransfers"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Large Inter-Instance Data Transfer Detected",
                alert_description_template="Significant data transfer from {srcaddr} to {dstaddr} on port {dstport}.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review instance roles and permissions",
                    "Check for file transfer tools (scp, rsync, robocopy)",
                    "Analyse transferred data types",
                    "Review instance activity logs",
                ],
                containment_actions=[
                    "Isolate suspicious instances",
                    "Review security group rules",
                    "Disable unnecessary file sharing protocols",
                    "Audit instance access",
                    "Check for data exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known backup and database replication traffic",
            detection_coverage="60% - detects large network transfers",
            evasion_considerations="Slow transfers or encrypted tunnels may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-40",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1074_002-gcp-gcs-staging",
            name="GCP Cloud Storage Remote Staging Detection",
            description="Detect unusual Cloud Storage bucket uploads from Compute Engine that may indicate staging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
OR protoPayload.methodName="storage.objects.copy"''',
                gcp_terraform_template="""# GCP: Detect Cloud Storage remote data staging

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "gcs_staging" {
  name   = "gcs-staging-activity"
  filter = <<-EOT
    resource.type="gcs_bucket"
    (protoPayload.methodName="storage.objects.create" OR
     protoPayload.methodName="storage.objects.copy")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "gcs_staging" {
  display_name = "High GCS Staging Activity"
  combiner     = "OR"
  conditions {
    display_name = "High upload rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_staging.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Potential Remote Data Staging",
                alert_description_template="High volume Cloud Storage uploads detected.",
                investigation_steps=[
                    "Review source Compute Engine instances",
                    "Check uploaded object sizes and patterns",
                    "Verify bucket ownership and IAM permissions",
                    "Review audit logs for related activity",
                    "Check for archive or compressed files",
                ],
                containment_actions=[
                    "Review and restrict bucket IAM permissions",
                    "Enable object versioning and retention",
                    "Quarantine suspicious objects",
                    "Review Compute Engine instance security",
                    "Block suspicious service accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on normal backup patterns",
            detection_coverage="65% - catches bulk GCS staging",
            evasion_considerations="Rate limiting or smaller batches may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["Cloud Storage audit logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1074_002-gcp-vpc-transfer",
            name="GCP VPC Flow Logs - Inter-Instance Transfer",
            description="Detect unusual data transfers between Compute Engine instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.dest_port:(22 OR 445 OR 2049 OR 3389)
jsonPayload.bytes_sent>1073741824""",
                gcp_terraform_template="""# GCP: Detect large inter-instance transfers

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "large_transfers" {
  name   = "large-instance-transfers"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.dest_port:(22 OR 445 OR 2049 OR 3389)
    jsonPayload.bytes_sent>1073741824
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "large_transfers" {
  display_name = "High Inter-Instance Transfer"
  combiner     = "OR"
  conditions {
    display_name = "Large data transfer"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.large_transfers.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Large Inter-Instance Transfer",
                alert_description_template="Significant data transfer between Compute Engine instances.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review instance service accounts and IAM roles",
                    "Check for file transfer tools",
                    "Analyse transferred data types",
                    "Review instance activity logs",
                ],
                containment_actions=[
                    "Isolate suspicious instances",
                    "Review firewall rules",
                    "Disable unnecessary protocols",
                    "Audit instance access",
                    "Check for data exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known backup and replication traffic",
            detection_coverage="60% - detects large network transfers",
            evasion_considerations="Encrypted tunnels or slow transfers may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-40",
            prerequisites=["VPC Flow Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1074_002-aws-s3-staging",
        "t1074_002-gcp-gcs-staging",
        "t1074_002-aws-vpc-transfer",
        "t1074_002-gcp-vpc-transfer",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+18% improvement for Collection tactic",
)
