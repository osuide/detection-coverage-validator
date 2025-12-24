"""
T1091 - Replication Through Removable Media

Adversaries exploit removable media to spread malware across systems, particularly
air-gapped networks. Attack leverages Autorun features and may involve modified
USB devices, including malicious charging cables and mobile devices.

IMPORTANT DETECTION LIMITATIONS:
Cloud-native APIs (AWS CloudTrail/EventBridge, GCP Cloud Logging) CANNOT directly
detect physical USB device insertions. This is an OS/hardware-layer signal.

Detection capabilities by environment:
- AWS WorkSpaces: USB redirection IS logged natively (good coverage)
- EC2/GCE instances: Requires OS-level logging (syslog/Windows Events) forwarded
  to cloud logging - NOT automatic, requires manual configuration
- On-premises: Requires endpoint agents or local auditd configuration

For real-time USB detection on EC2/GCE, deploy endpoint security solutions:
- AWS: GuardDuty Runtime Monitoring, CrowdStrike, SentinelOne, Carbon Black
- GCP: Chronicle Security, CrowdStrike, SentinelOne
- Cross-platform: OSSEC, Wazuh with auditd rules
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
    technique_id="T1091",
    technique_name="Replication Through Removable Media",
    tactic_ids=["TA0001", "TA0008"],  # Initial Access, Lateral Movement
    mitre_url="https://attack.mitre.org/techniques/T1091/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit removable media such as USB drives, external hard drives, "
            "and mobile devices to spread malware across systems. This technique is particularly "
            "effective against air-gapped networks and isolated environments. In cloud contexts, "
            "attackers target cloud workspaces, virtual desktop infrastructure (VDI), and EC2 "
            "instances where USB passthrough or device mounting is enabled. Notable malware using "
            "this vector includes Stuxnet, Conficker, Agent.btz, and Raspberry Robin."
        ),
        attacker_goal="Spread malware via removable media to compromise isolated or air-gapped systems",
        why_technique=[
            "Bypasses network-based security controls",
            "Effective against air-gapped and isolated networks",
            "Social engineering component makes detection difficult",
            "Can spread automatically via Autorun functionality",
            "Difficult to prevent in environments requiring USB access",
            "Works across network boundaries",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="FIN7 USB Ransomware Campaign",
                year=2021,
                description="FIN7 mailed USB drives containing ransomware to retail and hospitality companies, disguised as COVID-19 safety guidelines or customer complaints",
                reference_url="https://attack.mitre.org/groups/G0046/",
            ),
            Campaign(
                name="Raspberry Robin Worm",
                year=2022,
                description="Widespread worm spreading via USB drives and external drives, observed deploying additional malware including IcedID and Bumblebee",
                reference_url="https://attack.mitre.org/software/S1040/",
            ),
            Campaign(
                name="Gamaredon USB Spreading",
                year=2023,
                description="Gamaredon Group used USB-spreading malware to compromise Ukrainian government networks and spread laterally across air-gapped systems",
                reference_url="https://attack.mitre.org/groups/G0047/",
            ),
            Campaign(
                name="Agent.btz Pentagon Breach",
                year=2008,
                description="Nation-state malware spread via infected USB drive into classified US military networks, leading to creation of US Cyber Command",
                reference_url="https://attack.mitre.org/techniques/T1091/",
            ),
        ],
        prevalence="moderate",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "High severity due to ability to bypass network controls and compromise air-gapped "
            "systems. Particularly dangerous for critical infrastructure and high-security "
            "environments. Historical precedent shows this vector can compromise highly secure "
            "networks (Stuxnet, Agent.btz). Social engineering component makes prevention difficult."
        ),
        business_impact=[
            "Compromise of air-gapped or isolated systems",
            "Bypass of network security controls",
            "Introduction of malware to secure environments",
            "Potential for widespread lateral movement",
            "Compliance violations in regulated environments",
            "Data exfiltration from isolated networks",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1059.001", "T1071", "T1105", "T1570", "T1204.002"],
        often_follows=["T1566.001", "T1195.003"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - WorkSpaces USB Device Detection (Native Support)
        DetectionStrategy(
            strategy_id="t1091-aws-workspaces-usb",
            name="AWS WorkSpaces USB Redirection Monitoring (Native)",
            description=(
                "Detect USB device connections to Amazon WorkSpaces virtual desktops. "
                "WorkSpaces DOES log USB redirection events natively when enabled. "
                "This is the most reliable USB detection method for AWS VDI environments."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, userIdentity.principalId
| filter @message like /USB/ or @message like /removable/ or @message like /storage device/
| filter @message like /connected|attached|mounted/
| stats count(*) as deviceConnections by userIdentity.principalId, bin(1h)
| filter deviceConnections > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Detect USB device connections in AWS WorkSpaces.
  NOTE: This works for WorkSpaces (VDI) which logs USB redirection natively.
  For EC2 instances, see endpoint agent recommendations.

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: WorkSpaces USB Device Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch Log Group for WorkSpaces
  WorkSpacesLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/workspaces/usb-monitoring
      RetentionInDays: 30

  # Step 3: Metric filter for USB connections
  USBConnectionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref WorkSpacesLogGroup
      FilterPattern: '[timestamp, workspace, level, msg="*USB*connect*" || msg="*removable*" || msg="*storage device*"]'
      MetricTransformations:
        - MetricName: WorkSpacesUSBConnections
          MetricNamespace: Security/RemovableMedia
          MetricValue: "1"

  # Step 4: CloudWatch alarm
  USBConnectionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: WorkSpaces-USB-Device-Connected
      AlarmDescription: Alert when USB devices connect to WorkSpaces
      MetricName: WorkSpacesUSBConnections
      Namespace: Security/RemovableMedia
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

Outputs:
  Scope:
    Description: Detection scope
    Value: "WorkSpaces VDI only. For EC2/GCE USB detection, deploy endpoint agents."
""",
                terraform_template="""# AWS: Detect USB device connections in WorkSpaces (Native Support)
# NOTE: WorkSpaces logs USB redirection natively. For EC2, deploy endpoint agents.

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "usb_alerts" {
  name         = "workspaces-usb-device-alerts"
  display_name = "WorkSpaces USB Device Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.usb_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "workspaces_usb" {
  name              = "/aws/workspaces/usb-monitoring"
  retention_in_days = 30
}

# Step 3: Metric filter for USB connections
resource "aws_cloudwatch_log_metric_filter" "usb_connection" {
  name           = "workspaces-usb-connections"
  log_group_name = aws_cloudwatch_log_group.workspaces_usb.name
  pattern        = "[timestamp, workspace, level, msg=\"*USB*connect*\" || msg=\"*removable*\" || msg=\"*storage device*\"]"

  metric_transformation {
    name      = "WorkSpacesUSBConnections"
    namespace = "Security/RemovableMedia"
    value     = "1"
  }
}

# Step 4: CloudWatch alarm for USB connections
resource "aws_cloudwatch_metric_alarm" "usb_connection" {
  alarm_name          = "WorkSpaces-USB-Device-Connected"
  alarm_description   = "Alert when USB devices connect to WorkSpaces"
  metric_name         = "WorkSpacesUSBConnections"
  namespace           = "Security/RemovableMedia"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.usb_alerts.arn]
  treat_missing_data  = "notBreaching"
}

# NOTE: This detection works for WorkSpaces only.
# For EC2 USB detection, deploy:
# - GuardDuty Runtime Monitoring
# - Third-party EDR (CrowdStrike, SentinelOne, Carbon Black)
# - OSSEC/Wazuh with auditd USB rules""",
                alert_severity="high",
                alert_title="USB Device Connected to WorkSpace",
                alert_description_template="USB or removable storage device connected to WorkSpace {workspaceId} by user {principalId}.",
                investigation_steps=[
                    "Identify the WorkSpace and user involved",
                    "Determine if USB access is authorised for this user",
                    "Review files accessed or transferred during connection",
                    "Check for autorun.inf or suspicious executable files",
                    "Examine WorkSpace security logs for malware indicators",
                    "Verify the business justification for USB usage",
                    "Check if device is registered in asset management system",
                ],
                containment_actions=[
                    "Disable USB redirection for affected WorkSpace if unauthorised",
                    "Quarantine WorkSpace for forensic analysis if malware suspected",
                    "Run antimalware scan on WorkSpace",
                    "Review and restrict USB access policies organisation-wide",
                    "Enable USB device allowlisting if supported",
                    "Implement data loss prevention (DLP) for removable media",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised users and job roles requiring USB access; implement device registration system",
            detection_coverage="75% - native WorkSpaces USB logging. Does NOT cover EC2 instances.",
            evasion_considerations="Only covers WorkSpaces VDI. EC2 instances require endpoint agents for USB detection.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "WorkSpaces deployed",
                "USB redirection configured and logged",
                "CloudWatch Logs enabled",
            ],
        ),
        # Strategy 2: AWS/GCP - Endpoint Agent for Real USB Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1091-endpoint-agent",
            name="Endpoint Agent Deployment for Real-Time USB Detection (Recommended)",
            description=(
                "Deploy endpoint security agents for real-time USB device detection on EC2/GCE instances. "
                "This is the ONLY reliable method to detect USB insertions on cloud compute instances. "
                "Cloud APIs cannot see USB/hardware layer events."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/SuspiciousTool",
                    "DefenseEvasion:Runtime/FilelessExecution",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Enable GuardDuty Runtime Monitoring for endpoint-level USB/malware detection.
  This is the RECOMMENDED approach for detecting malicious activity from removable media.

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
      DisplayName: Removable Media Security Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route runtime findings to alerts
  RuntimeFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1091-RemovableMediaAlerts
      Description: Alert on suspicious execution potentially from removable media
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "Execution:Runtime/"
            - prefix: "DefenseEvasion:Runtime/"
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
  Recommendation:
    Description: Additional recommendations
    Value: |
      GuardDuty Runtime Monitoring detects malicious execution from any source.
      For specific USB device tracking, also configure:
      - auditd rules: auditctl -w /dev/sd* -p wa -k usb_block_device
      - Third-party EDR with USB device control""",
                terraform_template="""# Enable GuardDuty Runtime Monitoring for EC2 USB/malware detection
# This is the RECOMMENDED approach for detecting malicious activity
# that may originate from removable media.

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
resource "aws_sns_topic" "runtime_alerts" {
  name         = "removable-media-security-alerts"
  display_name = "Removable Media Security Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.runtime_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route runtime findings to alerts
resource "aws_cloudwatch_event_rule" "runtime_findings" {
  name        = "guardduty-runtime-findings"
  description = "Alert on suspicious execution potentially from removable media"

  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "Execution:Runtime/" },
        { prefix = "DefenseEvasion:Runtime/" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.runtime_findings.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.runtime_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.runtime_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.runtime_alerts.arn
    }]
  })
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID with runtime monitoring"
  value       = aws_guardduty_detector.main.id
}

# RECOMMENDED: For comprehensive USB security, also deploy:
# - auditd rules for USB block devices
# - Third-party EDR with USB device control policies
# - Group Policy USB restrictions (Windows)""",
                alert_severity="high",
                alert_title="Suspicious Execution - Potential Removable Media Malware",
                alert_description_template="GuardDuty Runtime Monitoring detected suspicious execution that may indicate malware from removable media.",
                investigation_steps=[
                    "Review the GuardDuty finding details and process tree",
                    "Identify the affected EC2 instance",
                    "Check for recent block device attachments (lsblk)",
                    "Review /var/log/syslog or dmesg for USB device messages",
                    "Examine executed binaries and scripts",
                    "Check for autorun indicators or suspicious files",
                    "Analyse network connections from affected processes",
                ],
                containment_actions=[
                    "Isolate the affected instance immediately",
                    "Terminate suspicious processes",
                    "Block USB storage via udev rules or Group Policy",
                    "Capture memory and disk for forensic analysis",
                    "Rotate credentials accessible from the instance",
                    "Deploy USB device control policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate binaries and DevOps automation. Exclude known deployment tools.",
            detection_coverage="70% - detects malicious execution from any source including removable media. Best option for EC2.",
            evasion_considerations="Sophisticated attacks may use fileless techniques. Combine with auditd rules for USB device logging.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per EC2 instance",
            prerequisites=[
                "AWS account with GuardDuty access",
                "EC2 instances with SSM agent",
            ],
        ),
        # Strategy 3: GCP - OS-Level USB Detection (Requires Configuration)
        DetectionStrategy(
            strategy_id="t1091-gcp-usb-os-logging",
            name="GCP Compute Instance USB Monitoring via OS Logging (Requires Setup)",
            description=(
                "Detect USB device connections to GCP Compute Engine instances via OS-level logging. "
                "LIMITATION: This requires manual configuration of OS logging (syslog/Windows Events) "
                "to forward to Cloud Logging via Ops Agent. Without this setup, detection is 0%."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(logName=~"logs/syslog" OR logName=~"logs/windows")
AND (
  jsonPayload.message=~".*USB.*connect.*"
  OR jsonPayload.message=~".*removable.*storage.*"
  OR jsonPayload.message=~".*mass storage.*"
  OR jsonPayload.message=~".*usb-storage.*"
  OR textPayload=~".*USB.*device.*attached.*"
)""",
                gcp_terraform_template="""# GCP: Detect USB device connections via OS-level logging
# IMPORTANT: This requires Ops Agent configuration on each instance.
# Without OS logging setup, this detection provides 0% coverage.

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "USB Device Alerts (OS-Level)"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for USB connections
resource "google_logging_metric" "usb_connection" {
  project = var.project_id
  name    = "usb-device-os-logs"

  filter = <<-EOT
    resource.type="gce_instance"
    (logName=~"logs/syslog" OR logName=~"logs/windows")
    AND (
      jsonPayload.message=~".*USB.*connect.*"
      OR jsonPayload.message=~".*removable.*storage.*"
      OR jsonPayload.message=~".*mass storage.*"
      OR jsonPayload.message=~".*usb-storage.*"
      OR textPayload=~".*USB.*device.*attached.*"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Alert policy for USB connections
resource "google_monitoring_alert_policy" "usb_alert" {
  project      = var.project_id
  display_name = "USB Device Connection (OS-Level Logs)"
  combiner     = "OR"

  conditions {
    display_name = "USB device detected in OS logs"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.usb_connection.name}\" AND resource.type=\"gce_instance\""
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
      # USB Device Detected (OS-Level Logging)

      USB or removable storage device connection detected in OS syslog/Windows Event logs.

      **PREREQUISITE**: This detection ONLY works if:
      1. Ops Agent is installed on instances
      2. Syslog/Windows Event forwarding is configured

      Without these prerequisites, no USB events will be captured.

      For real-time USB detection without manual config, consider:
      - Chronicle Security with endpoint integration
      - Third-party EDR (CrowdStrike, SentinelOne)
    EOT
    mime_type = "text/markdown"
  }
}

# IMPORTANT: You must install and configure Ops Agent on each instance:
# https://cloud.google.com/logging/docs/agent/ops-agent/
#
# For Linux:
#   curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
#   sudo bash add-google-cloud-ops-agent-repo.sh --also-install
#
# Ensure /etc/rsyslog.d/ or journald forwards kernel USB messages.""",
                alert_severity="high",
                alert_title="GCP: USB Device Detected (OS-Level Logs)",
                alert_description_template="USB or removable storage device detected on instance {instance_name} via OS logs.",
                investigation_steps=[
                    "Identify the Compute instance and project",
                    "Review OS logs for USB device details (vendor, product ID)",
                    "Check if USB passthrough was authorised",
                    "Examine files accessed after device connection",
                    "Run malware scan on instance",
                    "Verify user authentication around connection time",
                    "Check for autorun scripts or suspicious executables",
                ],
                containment_actions=[
                    "Block USB storage via udev rules",
                    "Quarantine instance for forensic analysis",
                    "Run antimalware scan on affected instance",
                    "Implement organisation policy restricting USB access",
                    "Enable VM Manager for inventory tracking",
                    "Document incident and update security policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised instances and USB devices; establish device registration process",
            detection_coverage="50% - ONLY works with Ops Agent and OS logging configured. 0% without configuration.",
            evasion_considerations="Requires manual OS logging setup. Short-lived USB connections may be missed. Attackers can disable logging.",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-4 hours (includes Ops Agent deployment)",
            estimated_monthly_cost="$10-30",
            prerequisites=[
                "Ops Agent installed on instances",
                "Syslog/Windows Event forwarding configured",
                "Cloud Logging enabled",
            ],
        ),
        # Strategy 4: AWS/GCP - Cloud Storage Upload Correlation (Supplementary)
        DetectionStrategy(
            strategy_id="t1091-cloud-storage-upload",
            name="Cloud Storage Upload Anomaly Detection (Supplementary)",
            description=(
                "Detect unusual file upload patterns that may indicate data transfer from removable media. "
                "NOTE: This is a SUPPLEMENTARY detection that should be correlated with USB detection. "
                "High false positive rate when used alone - best used with endpoint agent data."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="s3",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "PutObject",
                            "UploadPart",
                            "CompleteMultipartUpload",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Detect suspicious S3 uploads (supplementary to USB detection).
  NOTE: High false positive rate - correlate with endpoint USB detection.

Parameters:
  AlertEmail:
    Type: String
  MonitoredBucket:
    Type: String
    Description: S3 bucket to monitor

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: S3 Upload Anomaly Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  S3UploadRule:
    Type: AWS::Events::Rule
    Properties:
      Name: t1091-s3-upload-anomaly
      EventPattern:
        source: [aws.s3]
        detail-type: ["AWS API Call via CloudTrail"]
        detail:
          eventName: [PutObject, UploadPart]
          requestParameters:
            bucketName: [!Ref MonitoredBucket]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  TopicPolicy:
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
  Note:
    Description: Usage note
    Value: "Supplementary detection only. Correlate with endpoint USB detection for accuracy."
""",
                terraform_template="""# S3 Upload Anomaly Detection (Supplementary to USB detection)
# NOTE: High false positive rate - correlate with endpoint USB detection.

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

variable "monitored_bucket" {
  type        = string
  description = "S3 bucket to monitor"
}

resource "aws_sns_topic" "upload_alerts" {
  name = "s3-upload-anomaly-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.upload_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "s3_upload" {
  name        = "t1091-s3-upload-anomaly"
  description = "Detect S3 uploads for correlation with USB detection"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutObject", "UploadPart"]
      requestParameters = {
        bucketName = [var.monitored_bucket]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.s3_upload.name
  target_id = "UploadAlert"
  arn       = aws_sns_topic.upload_alerts.arn
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.upload_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.upload_alerts.arn
    }]
  })
}

# NOTE: This detection has HIGH false positive rate.
# Use in combination with endpoint USB detection for correlation.""",
                alert_severity="low",
                alert_title="S3 Upload Detected (Correlation Signal)",
                alert_description_template="File upload to {bucketName} - correlate with USB detection signals for removable media investigation.",
                investigation_steps=[
                    "Correlate with endpoint USB detection signals",
                    "Identify upload source IP and user",
                    "Review file metadata and content type",
                    "Check for concurrent USB device connections",
                    "Scan uploaded files for malware",
                    "Verify business justification for upload",
                ],
                containment_actions=[
                    "Quarantine suspicious files",
                    "Run malware scanning on uploads",
                    "Review bucket access policies",
                    "Enable S3 Object Lock if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Establish baseline upload patterns; whitelist automated processes; correlate with endpoint detection",
            detection_coverage="30% - supplementary signal only. Cannot detect USB directly. Must correlate with endpoint detection.",
            evasion_considerations="Very high false positive rate. Cannot distinguish USB uploads from legitimate transfers without endpoint correlation.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "S3 data events logged"],
        ),
    ],
    recommended_order=[
        "t1091-endpoint-agent",
        "t1091-aws-workspaces-usb",
        "t1091-gcp-usb-os-logging",
        "t1091-cloud-storage-upload",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+15% improvement for Initial Access and Lateral Movement tactics (endpoint agents required for full coverage)",
)
