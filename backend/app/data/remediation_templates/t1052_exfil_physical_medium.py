"""
T1052 - Exfiltration Over Physical Medium

Adversaries attempt to exfiltrate data via removable storage devices.
Used in air-gapped network compromises and high-security environments.

IMPORTANT DETECTION LIMITATIONS:
Cloud-native APIs (AWS CloudTrail/EventBridge, GCP Cloud Logging) CANNOT detect
physical USB device insertions or file copies to removable media. These are
OS/hardware layer events not exposed via cloud APIs.

What cloud detection CAN do:
- Monitor AWS/GCP API calls for disk attachments (cloud disks, not USB)
- Detect data staging activities (compression, large file operations)
- Monitor cloud storage uploads for anomalies

What requires endpoint agents:
- Real-time USB device insertion detection
- File copy monitoring to removable media
- DLP (Data Loss Prevention) for physical media

For comprehensive exfiltration detection, deploy endpoint security:
- AWS: GuardDuty Runtime Monitoring, CrowdStrike, Carbon Black
- GCP: Chronicle Security, CrowdStrike, SentinelOne
- Cross-platform: OSSEC, Wazuh, Microsoft Defender for Endpoint
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
            "Leaves minimal network forensic evidence",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
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
            "Reputational damage",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1005", "T1074", "T1560"],
    ),
    detection_strategies=[
        # Strategy 1: Endpoint Agent for Real USB/File Copy Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1052-endpoint-agent",
            name="Endpoint Agent Deployment for USB Exfiltration Detection (Recommended)",
            description=(
                "Deploy endpoint security agents for real-time USB device and file copy detection. "
                "This is the ONLY reliable method to detect data exfiltration via physical media. "
                "Cloud APIs cannot see USB insertions or file copy operations to removable devices."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Exfiltration:Runtime/SuspiciousDataTransfer",
                    "Execution:Runtime/NewBinaryExecuted",
                    "DefenseEvasion:Runtime/FilelessExecution",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Enable GuardDuty Runtime Monitoring for endpoint-level exfiltration detection.
  This is the RECOMMENDED approach for detecting data exfiltration activities.
  For USB-specific detection, combine with auditd rules or third-party EDR.

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Enable GuardDuty with Runtime Monitoring
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: RUNTIME_MONITORING
          Status: ENABLED
          AdditionalConfiguration:
            - Name: EC2_AGENT_MANAGEMENT
              Status: ENABLED

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Exfiltration Security Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route runtime findings to alerts
  ExfiltrationFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1052-ExfiltrationAlerts
      Description: Alert on suspicious data exfiltration activity
      # Physical medium exfiltration not directly detectable - use data movement indicators
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Exfiltration:S3/"
            - prefix: "Exfiltration:IAMUser/"
            - "Execution:Runtime/SuspiciousCommand"
          severity:
            - numeric:
                - ">="
                - 4
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic

Outputs:
  GuardDutyDetectorId:
    Description: GuardDuty detector with runtime monitoring
    Value: !Ref GuardDutyDetector
  AdditionalRecommendations:
    Description: For USB-specific detection
    Value: |
      GuardDuty Runtime Monitoring detects suspicious data transfer activity.
      For USB-specific file copy detection, also configure:
      - auditd rules: auditctl -w /media -p wa -k usb_file_copy
      - Third-party EDR with DLP capabilities
      - Group Policy USB restrictions (Windows)""",
                terraform_template="""# Enable GuardDuty Runtime Monitoring for exfiltration detection
# This is the RECOMMENDED approach for detecting data theft activities.

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Enable GuardDuty with Runtime Monitoring
resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "exfil_alerts" {
  name         = "exfiltration-security-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Exfiltration Security Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.exfil_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route runtime findings to alerts
resource "aws_cloudwatch_event_rule" "exfiltration_findings" {
  name        = "guardduty-exfiltration-findings"
  description = "Alert on suspicious data exfiltration activity"

  # Physical medium exfiltration not directly detectable - use data movement indicators
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Exfiltration:S3/" },
        { prefix = "Exfiltration:IAMUser/" },
        "Execution:Runtime/SuspiciousCommand"
      ]
      # Severity >= 4 (MEDIUM or above) to filter noise
      severity = [{ numeric = [">=", 4] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.exfiltration_findings.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.exfil_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.exfil_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.exfil_alerts.arn
    }]
  })
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

# RECOMMENDED: For comprehensive USB exfiltration detection:
# - auditd rules for file operations on /media, /mnt, /run/media
# - Third-party EDR with Data Loss Prevention (DLP) features
# - Device control policies via Group Policy or MDM""",
                alert_severity="critical",
                alert_title="Data Exfiltration Activity Detected",
                alert_description_template="GuardDuty Runtime Monitoring detected suspicious data transfer activity that may indicate exfiltration via physical media.",
                investigation_steps=[
                    "Review the GuardDuty finding details",
                    "Identify the affected EC2 instance and user",
                    "Check for recently mounted block devices (lsblk, mount)",
                    "Review file access logs for sensitive data access",
                    "Check /var/log/syslog or dmesg for USB device messages",
                    "Examine files accessed or copied during suspicious period",
                    "Check for compression or encryption of files prior to transfer",
                ],
                containment_actions=[
                    "Isolate the affected instance immediately",
                    "Block USB storage via udev rules or Group Policy",
                    "Capture disk image for forensic analysis",
                    "Rotate credentials accessible from the instance",
                    "Review data accessed and notify data owners",
                    "Implement enhanced monitoring on similar systems",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate backup operations and authorised data transfer processes",
            detection_coverage="65% - detects suspicious data transfer activity. Combine with auditd for USB-specific detection.",
            evasion_considerations="Sophisticated attackers may use encryption or slow exfiltration. Combine with USB device control policies.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="See AWS GuardDuty pricing page for current rates",
            prerequisites=[
                "AWS account with GuardDuty access",
                "EC2 instances with SSM agent for automated deployment",
            ],
        ),
        # Strategy 2: Real-Time Block Device Detection for USB Exfiltration
        DetectionStrategy(
            strategy_id="t1052-aws-realtime-block-device",
            name="AWS Real-Time Block Device Monitoring (Endpoint Agent via SSM)",
            description=(
                "Deploy real-time block device detection to alert when external storage devices are "
                "connected to EC2 instances. Uses Linux udev rules and systemd to provide SUB-SECOND "
                "alerting, enabling rapid response to potential USB-based data exfiltration. The same "
                "device connection that enables exfiltration becomes the detection signal. See T1200 "
                "(Hardware Additions) for full SSM Document implementation details."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, ts, host, event, devkernel, devpath
| filter event = "block_device_add"
| stats count(*) as device_adds by host, bin(1h)
| filter device_adds > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Real-time detection of storage device connections for exfiltration monitoring.
  Alerts when USB drives or external storage are connected to EC2.
  See T1200 template for full SSM Document implementation.

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts
  LogGroupName:
    Type: String
    Default: /security/block-device-monitor

Resources:
  # Step 1: SNS topic for exfiltration alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Exfiltration Device Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic

  # Step 2: CloudWatch Log Group
  BlockDeviceLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Ref LogGroupName
      RetentionInDays: 30

  # Step 3: Metric filter for storage device connections
  ExfilDeviceMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref BlockDeviceLogGroup
      FilterPattern: '{ $.event = "block_device_add" }'
      MetricTransformations:
        - MetricName: ExfiltrationDeviceConnected
          MetricNamespace: Security/DataExfil
          MetricValue: "1"

  # Step 4: High-priority alarm for potential exfiltration
  ExfilDeviceAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1052-ExfiltrationDeviceDetected
      AlarmDescription: Storage device connected - immediate exfiltration risk
      MetricName: ExfiltrationDeviceConnected
      Namespace: Security/DataExfil
      Statistic: Sum
      Period: 60
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

Outputs:
  Note:
    Description: Implementation
    Value: "Deploy SSM Document from T1200 template. Tag instances with BlockDeviceMonitor=true"
""",
                terraform_template="""# Real-time storage device detection for exfiltration monitoring
# See T1200 template for full SSM Document implementation.

variable "alert_email" {
  type        = string
  description = "Email for exfiltration alerts"
}

variable "log_group_name" {
  type    = string
  default = "/security/block-device-monitor"
}

# Step 1: SNS Topic for alerts
resource "aws_sns_topic" "exfil_alerts" {
  name         = "exfiltration-device-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Exfiltration Device Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.exfil_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "alerts_policy" {
  arn = aws_sns_topic.exfil_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.exfil_alerts.arn
    }]
  })
}

# Step 2: CloudWatch Log Group + Metric Filter + Alarm
resource "aws_cloudwatch_log_group" "block_device_monitor" {
  name              = var.log_group_name
  retention_in_days = 30
}

resource "aws_cloudwatch_log_metric_filter" "exfil_device" {
  name           = "exfiltration-device-connected"
  log_group_name = aws_cloudwatch_log_group.block_device_monitor.name
  pattern        = "{ $.event = \"block_device_add\" }"

  metric_transformation {
    name      = "ExfiltrationDeviceConnected"
    namespace = "Security/DataExfil"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "exfil_device" {
  alarm_name          = "T1052-exfiltration-device-detected"
  alarm_description   = "Storage device connected - immediate exfiltration risk"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  threshold           = 1
  period              = 60
  statistic           = "Sum"
  namespace           = "Security/DataExfil"
  metric_name         = "ExfiltrationDeviceConnected"
  treat_missing_data  = "notBreaching"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.exfil_alerts.arn]
}

# NOTE: Deploy SSM Document from T1200 template to enable detection
# Tag instances with BlockDeviceMonitor=true to receive the SSM association""",
                alert_severity="critical",
                alert_title="Exfiltration Device Connected (Real-Time Detection)",
                alert_description_template="External storage device {devkernel} connected to host {host} at {ts}. IMMEDIATE exfiltration risk - investigate promptly.",
                investigation_steps=[
                    "URGENT: This is a potential active exfiltration attempt",
                    "Identify the EC2 instance from the CloudWatch log stream",
                    "Check the device details (devkernel, lsblk output) for device type",
                    "Review recent user activity and authentication on the instance",
                    "Check for file copy commands (cp, rsync, tar) executed after device connection",
                    "Review which sensitive data may be accessible from the instance",
                    "Check for data staging activity (compression, archiving) prior to connection",
                    "Correlate with data access logs from S3, RDS, or other data stores",
                ],
                containment_actions=[
                    "IMMEDIATELY isolate the instance via security groups",
                    "Block all egress traffic if not already isolated",
                    "Do NOT allow the device to be removed until forensic capture",
                    "Capture memory dump and disk image for forensic analysis",
                    "If device was removed, attempt to identify device serial number from logs",
                    "Rotate all credentials accessible from the instance",
                    "Notify data protection team and potentially legal/compliance",
                    "Implement USB device control policies to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Root device automatically suppressed. Correlate with user activity to distinguish admin maintenance from exfiltration.",
            detection_coverage="85% - real-time detection of storage device connections. Best cloud-native approach for exfiltration monitoring.",
            evasion_considerations="Attackers may use network exfiltration instead of USB. Combine with VPC Flow Logs and DLP for comprehensive coverage.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "SSM agent installed on instances",
                "CloudWatch Agent installed for log shipping",
                "Deploy SSM Document from T1200 template",
                "Tag instances with BlockDeviceMonitor=true",
            ],
        ),
        # Strategy 3: Data Staging Detection (Cloud API Level)
        DetectionStrategy(
            strategy_id="t1052-aws-data-staging",
            name="AWS Data Staging Activity Detection (Cloud API Level)",
            description=(
                "Monitor for data staging activities (compression, large file operations) via Systems Manager "
                "that may precede physical media exfiltration. This detects PREPARATION for exfiltration, "
                "not the actual USB file copy. Combine with endpoint agents for comprehensive coverage."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.instanceId, responseElements
| filter eventSource = "ssm.amazonaws.com"
| filter eventName in ["SendCommand"]
| filter requestParameters.documentName = "AWS-RunShellScript"
| filter requestParameters.parameters.commands[0] like /tar|zip|7z|rar|rsync|dd|mount/
| stats count(*) as command_count by userIdentity.arn, requestParameters.instanceId, bin(1h)
| filter command_count > 5
| sort command_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Monitor for data staging activities via Systems Manager.
  NOTE: This detects preparation for exfiltration, not USB file copies.
  For USB detection, deploy endpoint agents.

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
      KmsMasterKeyId: alias/aws/sns
      TopicName: data-staging-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Filter for data staging commands
  DataStagingFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "SendCommand" && $.requestParameters.documentName = "AWS-RunShellScript" }'
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
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

Outputs:
  Note:
    Description: Detection scope
    Value: "Detects data staging via SSM. Does NOT detect USB file copies. Deploy endpoint agents for USB detection."
""",
                terraform_template="""# Monitor for data staging activities via Systems Manager
# NOTE: This detects PREPARATION for exfiltration, not USB file copies.
# For USB detection, deploy endpoint agents.

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
  kms_master_key_id = "alias/aws/sns"
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
  pattern        = "{ $.eventName = \"SendCommand\" && $.requestParameters.documentName = \"AWS-RunShellScript\" }"

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
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.staging_alerts.arn]
}

# NOTE: This detection monitors SSM commands only.
# For USB file copy detection, deploy:
# - GuardDuty Runtime Monitoring
# - Third-party EDR with DLP features
# - auditd with file operation rules""",
                alert_severity="medium",
                alert_title="Data Staging Activity Detected",
                alert_description_template="Detected {command_count} data staging commands from {userIdentity.arn} on instance {instanceId}. May precede physical media exfiltration.",
                investigation_steps=[
                    "Review the specific commands executed",
                    "Identify files being compressed or staged",
                    "Check for subsequent USB device activity (requires endpoint agent)",
                    "Verify user authorisation for the activity",
                    "Review user's access to sensitive data",
                    "Check for large file transfers or cloud storage uploads",
                ],
                containment_actions=[
                    "Suspend user's SSM access",
                    "Review and secure staged files",
                    "Enable endpoint monitoring for USB activity",
                    "Implement data loss prevention controls",
                    "Review and restrict sensitive data access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist routine backup and archival operations; exclude DevOps automation",
            detection_coverage="40% - detects data staging only. Cannot detect USB file copies without endpoint agents.",
            evasion_considerations="Attackers may stage data without using SSM, or work directly on instance console",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15 depending on CloudTrail log volume",
            prerequisites=["CloudTrail enabled", "Systems Manager configured"],
        ),
        # Strategy 3: GCP - External Disk Attachment Monitoring
        DetectionStrategy(
            strategy_id="t1052-gcp-disk-attach",
            name="GCP External Disk Attachment Monitoring (Cloud API Level)",
            description=(
                "Detect attachment of external persistent disks to compute instances via GCP API. "
                "LIMITATION: This detects cloud-level disk attachments, NOT physical USB devices. "
                "For USB detection, deploy endpoint security solutions."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.attachDisk"
NOT protoPayload.request.source=~"projects/YOUR-PROJECT"''',
                gcp_terraform_template="""# GCP: Detect external disk attachments (cloud-level, not USB)
# LIMITATION: This does NOT detect physical USB devices.

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Exfiltration Alerts (Cloud Disk)"
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
  display_name = "External Disk Attachment (Cloud API)"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "External disk attached via GCP API"
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

  documentation {
    content   = <<-EOT
      # External Disk Attachment Detected (Cloud API Level)

      A GCP API call attached an external disk to a Compute Engine instance.

      **LIMITATION**: This detects CLOUD DISK attachments via API only.
      Physical USB device insertions are NOT detected.

      For USB exfiltration detection, deploy:
      - Chronicle Security with endpoint agents
      - Third-party EDR (CrowdStrike, SentinelOne)
      - OSSEC/Wazuh with auditd rules
    EOT
    mime_type = "text/markdown"
  }
}

# NOTE: For USB/physical media detection, deploy endpoint agents""",
                alert_severity="high",
                alert_title="GCP: External Disk Attached to Instance",
                alert_description_template="External persistent disk attached to compute instance via GCP API. Note: This is a cloud API event, not USB detection.",
                investigation_steps=[
                    "Identify the instance and attached disk source",
                    "Verify disk attachment was authorised",
                    "Check for file copy operations after attachment",
                    "Review user permissions and recent activity",
                    "Examine instance activity logs for data staging",
                    "Check for subsequent disk detachment or snapshot creation",
                ],
                containment_actions=[
                    "Detach the external disk immediately",
                    "Snapshot the disk for forensic analysis",
                    "Isolate the affected instance",
                    "Revoke user's compute.instances.attachDisk permission",
                    "Review organisation policy for disk constraints",
                    "Deploy endpoint monitoring for USB detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known backup or migration disks; exclude authorised maintenance windows",
            detection_coverage="50% - detects cloud disk attachments only. Does NOT detect USB devices.",
            evasion_considerations="Physical USB/media exfiltration completely bypasses this detection. Requires endpoint agents.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15 depending on Cloud Logging volume",
            prerequisites=[
                "Cloud Logging enabled",
                "Compute Engine API audit logs enabled",
            ],
        ),
        # Strategy 4: GCP - Large File Operations Monitoring
        DetectionStrategy(
            strategy_id="t1052-gcp-file-staging",
            name="GCP Large File Staging Detection (OS Logging Required)",
            description=(
                "Monitor for large file staging and compression operations via OS logs forwarded to Cloud Logging. "
                "LIMITATION: Requires Ops Agent configuration for OS log forwarding. Without setup, detection is 0%. "
                "This detects data STAGING, not USB file copies."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(logName=~"logs/syslog" OR logName=~"logs/audit")
AND (
  jsonPayload.message=~".*(tar|zip|7z|gzip|bzip2).*"
  OR jsonPayload.message=~".*rsync.*"
  OR jsonPayload.message=~".*dd.*of=.*"
)""",
                gcp_terraform_template="""# GCP: Monitor large file operations (requires OS logging setup)
# IMPORTANT: This requires Ops Agent with OS log forwarding.
# Without configuration, detection provides 0% coverage.

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "File Staging Alerts (OS Logs)"
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
    (logName=~"logs/syslog" OR logName=~"logs/audit")
    AND (
      jsonPayload.message=~".*(tar|zip|7z|gzip|bzip2).*"
      OR jsonPayload.message=~".*rsync.*"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert for suspicious file operations
resource "google_monitoring_alert_policy" "file_staging" {
  display_name = "Large File Staging Activity (OS Logs)"
  combiner     = "OR"

  conditions {
    display_name = "Compression or large file operations detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.file_staging.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = <<-EOT
      # Large File Staging Detected (OS-Level Logs)

      Detected file compression or large file operations in OS logs.
      This may indicate preparation for data exfiltration.

      **PREREQUISITE**: Ops Agent must be installed and configured.
      **LIMITATION**: This detects STAGING, not USB file copies.

      For USB exfiltration detection, deploy endpoint agents.
    EOT
    mime_type = "text/markdown"
  }
}

# IMPORTANT: You must install Ops Agent and configure audit logging.
# This detection only works with OS logs forwarded to Cloud Logging.""",
                alert_severity="medium",
                alert_title="GCP: Large File Staging Detected (OS Logs)",
                alert_description_template="Large file compression or staging operations detected in OS logs. May indicate exfiltration preparation.",
                investigation_steps=[
                    "Identify the instance and user executing commands",
                    "Review specific commands and file paths",
                    "Check destination of staged files",
                    "Look for subsequent disk attachment or USB activity (requires endpoint agent)",
                    "Verify business justification for file operations",
                    "Review network egress for file transfers",
                ],
                containment_actions=[
                    "Monitor instance for external device connections",
                    "Review and restrict user permissions",
                    "Enable additional endpoint-level auditing",
                    "Implement file integrity monitoring",
                    "Review staged files for sensitive data",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude scheduled backup jobs and data processing pipelines",
            detection_coverage="35% - ONLY works with Ops Agent configured. Detects staging only, not USB exfiltration.",
            evasion_considerations="Requires manual OS logging setup. Attackers may disable logging or use alternative staging methods.",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-4 hours (includes Ops Agent deployment)",
            estimated_monthly_cost="$10-25 depending on log volume",
            prerequisites=[
                "Ops Agent installed on instances",
                "Audit logging or syslog forwarding configured",
                "Cloud Logging enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1052-endpoint-agent",
        "t1052-aws-realtime-block-device",  # Best cloud-native for USB exfiltration detection
        "t1052-gcp-disk-attach",
        "t1052-aws-data-staging",
        "t1052-gcp-file-staging",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+12% improvement for Exfiltration tactic (endpoint agents required for USB detection)",
)
