"""
T1052 - Exfiltration Over Physical Medium

Adversaries attempt to exfiltrate data via removable storage devices.
Used in air-gapped network compromises and high-security environments.
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
    technique_id="T1052",
    technique_name="Exfiltration Over Physical Medium",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1052/",

    threat_context=ThreatContext(
        description=(
            "Adversaries attempt to exfiltrate data via removable storage devices such as "
            "USB drives, external hard drives, mobile phones, or other portable media. In "
            "air-gapped or highly restricted networks, physical media may be the only viable "
            "exfiltration method. Attackers mount external devices, copy sensitive files, and "
            "remove the media from the environment."
        ),
        attacker_goal="Steal data using removable storage devices to bypass network-based security controls",
        why_technique=[
            "Bypasses network monitoring and DLP controls",
            "Effective in air-gapped environments",
            "Difficult to detect without endpoint monitoring",
            "High data transfer capacity",
            "Leaves minimal network forensic evidence"
        ],
        known_threat_actors=["APT28 (Fancy Bear)", "Equation Group", "Agent.BTZ", "USB-based malware campaigns"],
        recent_campaigns=[
            Campaign(
                name="Agent.BTZ USB Propagation",
                year=2008,
                description="Notable malware that spread via USB drives and was used to breach classified networks",
                reference_url="https://attack.mitre.org/techniques/T1052/"
            ),
            Campaign(
                name="Stuxnet USB Infiltration",
                year=2010,
                description="Used USB drives to infiltrate air-gapped industrial control systems",
                reference_url="https://attack.mitre.org/techniques/T1052/"
            ),
            Campaign(
                name="Industrial Espionage via USB",
                year=2023,
                description="Multiple incidents of insider threats using USB drives to exfiltrate intellectual property",
                reference_url="https://attack.mitre.org/techniques/T1052/"
            )
        ],
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Physical media exfiltration bypasses most network security controls and is "
            "particularly dangerous in sensitive environments. Insider threats and sophisticated "
            "attackers frequently use this technique. Detection requires endpoint-level monitoring."
        ),
        business_impact=[
            "Data breach and intellectual property theft",
            "Compliance violations (GDPR, HIPAA, PCI-DSS)",
            "Loss of classified or sensitive information",
            "Insider threat incidents",
            "Reputational damage"
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1005", "T1074", "T1560"]
    ),

    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1052-aws-usb",
            name="AWS EC2 USB Device Monitoring via CloudWatch Agent",
            description="Detect USB device insertion and file access on EC2 instances using CloudWatch Agent custom logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, device_name, mount_point, user, file_count, bytes_transferred
| filter event_type = "usb_mount" or event_type = "mass_file_copy"
| filter bytes_transferred > 10485760 or file_count > 100
| stats sum(bytes_transferred) as total_bytes, max(file_count) as files by device_name, user, bin(5m)
| filter total_bytes > 52428800 or files > 500
| sort total_bytes desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: USB device monitoring via CloudWatch Agent on EC2 instances

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create CloudWatch Log Group for USB events
  USBEventLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/ec2/usb-events
      RetentionInDays: 90

  # Step 2: Create metric filter for USB device insertion
  USBMountFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref USBEventLogGroup
      FilterPattern: '[timestamp, event_type="usb_mount", device, mount_point, user, ...]'
      MetricTransformations:
        - MetricName: USBDeviceMounts
          MetricNamespace: Security/USB
          MetricValue: "1"

  # Step 3: Alert on suspicious USB activity
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: usb-activity-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  USBMountAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Suspicious-USB-Activity
      AlarmDescription: USB device mounted on EC2 instance
      MetricName: USBDeviceMounts
      Namespace: Security/USB
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

Outputs:
  LogGroupName:
    Description: CloudWatch Log Group for USB events
    Value: !Ref USBEventLogGroup
  SNSTopicArn:
    Description: SNS Topic for alerts
    Value: !Ref AlertTopic''',
                terraform_template='''# USB device monitoring via CloudWatch Agent on EC2 instances

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create CloudWatch Log Group for USB events
resource "aws_cloudwatch_log_group" "usb_events" {
  name              = "/aws/ec2/usb-events"
  retention_in_days = 90

  tags = {
    Purpose = "USB device monitoring"
    Security = "true"
  }
}

# Step 2: Create metric filter for USB device insertion
resource "aws_cloudwatch_log_metric_filter" "usb_mount" {
  name           = "usb-device-mounts"
  log_group_name = aws_cloudwatch_log_group.usb_events.name
  pattern        = "[timestamp, event_type=\"usb_mount\", device, mount_point, user, ...]"

  metric_transformation {
    name      = "USBDeviceMounts"
    namespace = "Security/USB"
    value     = "1"
  }
}

# Step 3: Alert on suspicious USB activity
resource "aws_sns_topic" "usb_alerts" {
  name = "usb-activity-alerts"

  tags = {
    Purpose = "USB security alerts"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.usb_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "usb_mount" {
  alarm_name          = "Suspicious-USB-Activity"
  alarm_description   = "USB device mounted on EC2 instance"
  metric_name         = "USBDeviceMounts"
  namespace           = "Security/USB"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.usb_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Severity = "High"
  }
}''',
                alert_severity="high",
                alert_title="USB Device Activity Detected",
                alert_description_template="USB device {device_name} mounted on instance by {user}. {bytes_transferred} bytes transferred, {file_count} files accessed.",
                investigation_steps=[
                    "Identify the EC2 instance and user account",
                    "Review USB device serial number and type",
                    "Check files accessed or copied to the device",
                    "Verify if USB usage was authorised",
                    "Review user's recent activity and access patterns",
                    "Check for data staging before USB insertion"
                ],
                containment_actions=[
                    "Disable USB ports via instance policy",
                    "Isolate the affected EC2 instance",
                    "Revoke user credentials immediately",
                    "Review and copy suspicious files for forensics",
                    "Implement USB device control policies"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised USB devices by serial number; exclude system maintenance windows",
            detection_coverage="75% - catches USB device usage on monitored instances",
            evasion_considerations="Requires CloudWatch Agent configuration; attackers may disable agent",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$20-40",
            prerequisites=["CloudWatch Agent installed on EC2 instances", "Custom USB monitoring script configured"]
        ),

        DetectionStrategy(
            strategy_id="t1052-aws-instance-connect",
            name="AWS Systems Manager Session Activity",
            description="Monitor for unusual file staging or compression that may precede physical exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, eventName, userIdentity.arn, requestParameters.instanceId, responseElements
| filter eventSource = "ssm.amazonaws.com"
| filter eventName in ["SendCommand"]
| filter requestParameters.documentName = "AWS-RunShellScript"
| filter requestParameters.parameters.commands[0] like /tar|zip|7z|rar|rsync|dd|mount/
| stats count(*) as command_count by userIdentity.arn, requestParameters.instanceId, bin(1h)
| filter command_count > 5
| sort command_count desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor for data staging activities via Systems Manager

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: data-staging-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Filter for data staging commands
  DataStagingFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "SendCommand" && $.requestParameters.documentName = "AWS-RunShellScript" && ($.requestParameters.parameters.commands[0] = "*tar*" || $.requestParameters.parameters.commands[0] = "*zip*" || $.requestParameters.parameters.commands[0] = "*mount*") }'
      MetricTransformations:
        - MetricName: DataStagingCommands
          MetricNamespace: Security/DataExfil
          MetricValue: "1"

  # Step 3: Alert on data staging activity
  DataStagingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Data-Staging-Activity
      AlarmDescription: Detected file compression or staging commands
      MetricName: DataStagingCommands
      Namespace: Security/DataExfil
      Statistic: Sum
      Period: 3600
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic''',
                terraform_template='''# Monitor for data staging activities via Systems Manager

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "staging_alerts" {
  name = "data-staging-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.staging_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Filter for data staging commands
resource "aws_cloudwatch_log_metric_filter" "data_staging" {
  name           = "data-staging-commands"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"SendCommand\" && $.requestParameters.documentName = \"AWS-RunShellScript\" && ($.requestParameters.parameters.commands[0] = \"*tar*\" || $.requestParameters.parameters.commands[0] = \"*zip*\" || $.requestParameters.parameters.commands[0] = \"*mount*\") }"

  metric_transformation {
    name      = "DataStagingCommands"
    namespace = "Security/DataExfil"
    value     = "1"
  }
}

# Step 3: Alert on data staging activity
resource "aws_cloudwatch_metric_alarm" "data_staging" {
  alarm_name          = "Data-Staging-Activity"
  alarm_description   = "Detected file compression or staging commands"
  metric_name         = "DataStagingCommands"
  namespace           = "Security/DataExfil"
  statistic           = "Sum"
  period              = 3600
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.staging_alerts.arn]
}''',
                alert_severity="medium",
                alert_title="Data Staging Activity Detected",
                alert_description_template="Detected {command_count} data staging commands from {userIdentity.arn} on instance {instanceId}.",
                investigation_steps=[
                    "Review the specific commands executed",
                    "Identify files being compressed or staged",
                    "Check for subsequent file transfers or USB activity",
                    "Verify user authorisation for the activity",
                    "Review user's access to sensitive data"
                ],
                containment_actions=[
                    "Suspend user's SSM access",
                    "Review and secure staged files",
                    "Enable additional endpoint monitoring",
                    "Implement data loss prevention controls"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist routine backup and archival operations; adjust command pattern matching",
            detection_coverage="60% - catches preparation activities before exfiltration",
            evasion_considerations="Attackers may use obfuscated commands or work directly on instance console",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "Systems Manager configured"]
        ),

        DetectionStrategy(
            strategy_id="t1052-gcp-disk-attach",
            name="GCP External Disk Attachment Monitoring",
            description="Detect attachment of external persistent disks to compute instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.attachDisk"
NOT protoPayload.request.source=~"projects/YOUR-PROJECT"''',
                gcp_terraform_template='''# GCP: Detect external disk attachments

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Physical Media"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Create log-based metric for disk attachments
resource "google_logging_metric" "disk_attach" {
  name    = "external-disk-attachments"
  project = var.project_id
  filter  = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="v1.compute.instances.attachDisk"
    NOT protoPayload.request.source=~"projects/${var.project_id}"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "disk_attach" {
  display_name = "External Disk Attachment Detected"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Disk attached to instance"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.disk_attach.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }
}''',
                alert_severity="high",
                alert_title="GCP: External Disk Attached to Instance",
                alert_description_template="External persistent disk attached to compute instance.",
                investigation_steps=[
                    "Identify the instance and attached disk",
                    "Verify disk ownership and origin",
                    "Check for file copy operations after attachment",
                    "Review user authorisation for disk operations",
                    "Examine instance activity logs",
                    "Check for data access patterns"
                ],
                containment_actions=[
                    "Detach the external disk immediately",
                    "Snapshot the disk for forensic analysis",
                    "Isolate the affected instance",
                    "Revoke user's compute.instances.attachDisk permission",
                    "Review organisation policy for disk constraints"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known backup or migration disks; exclude authorised maintenance windows",
            detection_coverage="80% - catches external disk usage",
            evasion_considerations="Attackers may use project-internal disks or snapshots",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Logging enabled", "Compute Engine API audit logs enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1052-gcp-file-operations",
            name="GCP Large File Transfer Detection",
            description="Monitor for large file staging and compression operations via OS logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
jsonPayload.command=~"(tar|zip|7z|rsync|dd|gzip|bzip2).*"
jsonPayload.file_size > 104857600''',
                gcp_terraform_template='''# GCP: Monitor large file operations

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - File Operations"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create metric for large file operations
resource "google_logging_metric" "file_staging" {
  name   = "large-file-staging"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.message=~".*tar .*" OR
     jsonPayload.message=~".*zip .*" OR
     jsonPayload.message=~".*rsync .*" OR
     jsonPayload.message=~".*dd .*")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert for suspicious file operations
resource "google_monitoring_alert_policy" "file_staging" {
  display_name = "Large File Staging Activity"
  combiner     = "OR"

  conditions {
    display_name = "Compression or large file operations detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.file_staging.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Large file staging operations detected. This may indicate preparation for data exfiltration."
    mime_type = "text/markdown"
  }
}''',
                alert_severity="medium",
                alert_title="GCP: Large File Staging Detected",
                alert_description_template="Large file compression or staging operations detected on compute instance.",
                investigation_steps=[
                    "Identify the instance and user executing commands",
                    "Review specific commands and file paths",
                    "Check destination of staged files",
                    "Look for subsequent disk attachment or transfer activity",
                    "Verify business justification for file operations"
                ],
                containment_actions=[
                    "Monitor instance for external device connections",
                    "Review and restrict user permissions",
                    "Enable additional OS-level auditing",
                    "Implement file integrity monitoring"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude scheduled backup jobs and data processing pipelines",
            detection_coverage="65% - catches file preparation activities",
            evasion_considerations="Requires OS-level logging configuration; attackers may disable logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["Cloud Logging agent installed", "OS audit logs enabled"]
        )
    ],

    recommended_order=[
        "t1052-gcp-disk-attach",
        "t1052-aws-usb",
        "t1052-aws-instance-connect",
        "t1052-gcp-file-operations"
    ],
    total_effort_hours=9.0,
    coverage_improvement="+15% improvement for Exfiltration tactic"
)
