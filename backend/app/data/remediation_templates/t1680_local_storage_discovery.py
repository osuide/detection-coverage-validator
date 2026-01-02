"""
T1680 - Local Storage Discovery

Adversaries enumerate local drives, disks, and volumes with attributes like total/free
space and serial numbers. This supports ransomware encryption preparation, lateral
movement, or direct volume access.
Used by APT29, APT41, Chimera, Kimsuky, Lazarus Group, Volt Typhoon.
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
    technique_id="T1680",
    technique_name="Local Storage Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1680/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate local drives, disks, and volumes with attributes like "
            "total/free space and serial numbers. This supports ransomware encryption "
            "preparation, lateral movement, or direct volume access. Implementation varies "
            "by platform: ESXi systems use esxcli commands; Windows uses wmic logicaldisk "
            "or PowerShell's Get-PSDrive; Linux employs parted, lsblk, fdisk, or df; "
            "macOS uses diskutil; cloud providers offer CLI tools like AWS describe-volumes."
        ),
        attacker_goal="Enumerate local storage to prepare for ransomware encryption or data exfiltration",
        why_technique=[
            "Identifies valuable data locations for exfiltration",
            "Determines available storage for staging data",
            "Prepares ransomware encryption targets",
            "Discovers volume serial numbers for persistence",
            "Enables direct volume access bypassing file system",
            "Cloud storage enumeration reveals attached EBS/persistent disks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=5,
        severity_reasoning=(
            "Local storage discovery is a reconnaissance technique that enables follow-on "
            "attacks like ransomware encryption and data exfiltration. Moderate severity as "
            "it's a precursor activity rather than directly damaging, but critical for "
            "ransomware operations targeting cloud infrastructure."
        ),
        business_impact=[
            "Precursor to ransomware encryption",
            "Identifies high-value data locations",
            "Enables targeted data exfiltration",
            "Reveals backup storage locations",
            "Compromises disaster recovery planning",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1486", "T1005", "T1560", "T1074"],
        often_follows=["T1078", "T1059"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1680-aws-ebs-enumeration",
            name="AWS EBS Volume Enumeration Detection",
            description="Detect enumeration of EBS volumes and storage attributes via CloudTrail.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, sourceIPAddress
| filter eventName in ["DescribeVolumes", "DescribeVolumeStatus", "DescribeVolumeAttribute", "DescribeSnapshots", "DescribeSnapshotAttribute"]
| stats count(*) as api_calls by userIdentity.principalId, sourceIPAddress, bin(5m)
| filter api_calls > 50
| sort api_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EBS volume enumeration activity

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: ebs-enumeration-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId

  EBSEnumerationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "DescribeVolumes" || $.eventName = "DescribeSnapshots" }'
      MetricTransformations:
        - MetricName: EBSEnumerationCount
          MetricNamespace: Security/StorageDiscovery
          MetricValue: "1"

  EBSEnumerationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighEBSEnumeration
      MetricName: EBSEnumerationCount
      Namespace: Security/StorageDiscovery
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect EBS volume enumeration activity

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "ebs-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "ebs_enumeration" {
  name           = "ebs-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"DescribeVolumes\" || $.eventName = \"DescribeSnapshots\" }"

  metric_transformation {
    name      = "EBSEnumerationCount"
    namespace = "Security/StorageDiscovery"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ebs_enumeration" {
  alarm_name          = "HighEBSEnumeration"
  metric_name         = "EBSEnumerationCount"
  namespace           = "Security/StorageDiscovery"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="EBS Volume Enumeration Detected",
                alert_description_template="High volume of EBS storage enumeration API calls from {principalId}",
                investigation_steps=[
                    "Identify the principal making enumeration calls",
                    "Check if this is authorised automation or user activity",
                    "Review what volumes and snapshots were accessed",
                    "Check for subsequent snapshot creation or volume modifications",
                    "Look for data exfiltration indicators",
                ],
                containment_actions=[
                    "Temporarily restrict EC2 read permissions",
                    "Enable additional CloudTrail logging",
                    "Review and rotate access credentials",
                    "Implement resource-based policies on sensitive volumes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known automation roles and backup services",
            detection_coverage="70% - catches API-based enumeration",
            evasion_considerations="Adversaries may use slower enumeration rates",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1680-aws-ssm-storage-commands",
            name="AWS SSM Storage Discovery Commands",
            description="Detect storage enumeration commands via Systems Manager Run Command.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @message like /wmic.*logicaldisk|Get-PSDrive|fsutil|lsblk|fdisk|df -h|diskutil/
| stats count(*) as commands by bin(1h)
| filter commands > 5
| sort commands desc""",
                terraform_template="""# Detect storage discovery commands via SSM

variable "ssm_log_group" {
  type        = string
  description = "SSM Run Command log group"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "ssm-storage-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "storage_commands" {
  name           = "storage-discovery-commands"
  log_group_name = var.ssm_log_group
  pattern        = "?wmic ?logicaldisk ?Get-PSDrive ?fsutil ?lsblk ?fdisk ?diskutil"

  metric_transformation {
    name      = "StorageDiscoveryCommands"
    namespace = "Security/StorageDiscovery"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "storage_discovery" {
  alarm_name          = "StorageDiscoveryCommands"
  metric_name         = "StorageDiscoveryCommands"
  namespace           = "Security/StorageDiscovery"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Storage Discovery Commands Detected",
                alert_description_template="Storage enumeration commands detected via SSM Run Command",
                investigation_steps=[
                    "Review SSM session history for the instance",
                    "Identify the user or role that initiated commands",
                    "Check for follow-on ransomware indicators",
                    "Review instance for unauthorised software",
                ],
                containment_actions=[
                    "Isolate affected instance",
                    "Revoke SSM session permissions",
                    "Capture memory and disk forensics",
                    "Review backup integrity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised system administration activities",
            detection_coverage="60% - requires SSM logging enabled",
            evasion_considerations="Adversaries may use alternative enumeration methods",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["SSM Run Command logging to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1680-gcp-disk-enumeration",
            name="GCP Persistent Disk Enumeration Detection",
            description="Detect enumeration of GCP persistent disks and snapshots.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance" OR resource.type="gce_disk"
protoPayload.methodName=~"compute.disks.list|compute.disks.get|compute.snapshots.list|compute.snapshots.get"
severity>=NOTICE""",
                gcp_terraform_template="""# GCP: Detect persistent disk enumeration

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Storage Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "disk_enumeration" {
  project = var.project_id
  name   = "disk-enumeration-count"
  filter = <<-EOT
    resource.type="gce_instance" OR resource.type="gce_disk"
    protoPayload.methodName=~"compute.disks.list|compute.disks.get|compute.snapshots.list"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "disk_enumeration" {
  project      = var.project_id
  display_name = "GCP Disk Enumeration Alert"
  combiner     = "OR"

  conditions {
    display_name = "High disk enumeration rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.disk_enumeration.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
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
                alert_title="GCP: Disk Enumeration Detected",
                alert_description_template="High volume of persistent disk enumeration in GCP project",
                investigation_steps=[
                    "Identify the service account or user making calls",
                    "Review what disks and snapshots were enumerated",
                    "Check for snapshot creation or export activity",
                    "Look for VM creation with enumerated disks",
                ],
                containment_actions=[
                    "Restrict compute.disks.list permission",
                    "Enable VPC Service Controls",
                    "Review and rotate service account keys",
                    "Enable additional audit logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude Terraform/Deployment Manager service accounts",
            detection_coverage="70% - catches API-based enumeration",
            evasion_considerations="Adversaries may use slower rates to avoid detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["GCP Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1680-gcp-os-storage-commands",
            name="GCP OS Login Storage Discovery Commands",
            description="Detect storage enumeration commands in GCP instances via OS Config.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
textPayload=~"lsblk|fdisk|parted|df -h|blkid|mount"
severity>=INFO""",
                gcp_terraform_template="""# GCP: Detect OS-level storage discovery commands

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "OS Storage Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "os_storage_commands" {
  project = var.project_id
  name   = "os-storage-discovery-commands"
  filter = <<-EOT
    resource.type="gce_instance"
    textPayload=~"lsblk|fdisk -l|parted -l|blkid"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "os_storage_discovery" {
  project      = var.project_id
  display_name = "GCP OS Storage Discovery Alert"
  combiner     = "OR"

  conditions {
    display_name = "Storage discovery commands detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.os_storage_commands.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: OS Storage Discovery Commands",
                alert_description_template="Storage enumeration commands detected on GCP instance",
                investigation_steps=[
                    "Identify the user session running commands",
                    "Review OS Login audit logs",
                    "Check for ransomware indicators",
                    "Examine instance metadata access",
                ],
                containment_actions=[
                    "Terminate suspicious SSH sessions",
                    "Snapshot instance for forensics",
                    "Disable OS Login for the instance",
                    "Review IAM bindings",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Exclude system administration and maintenance windows",
            detection_coverage="50% - requires command logging enabled",
            evasion_considerations="Commands may be obfuscated or run via scripts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["OS Config agent with command logging"],
        ),
    ],
    recommended_order=[
        "t1680-aws-ebs-enumeration",
        "t1680-gcp-disk-enumeration",
        "t1680-aws-ssm-storage-commands",
        "t1680-gcp-os-storage-commands",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+15% improvement for Discovery tactic",
)
