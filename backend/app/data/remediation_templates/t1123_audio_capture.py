"""
T1123 - Audio Capture

Adversaries capture audio to collect intelligence from microphones or voice/video call applications.
This technique involves exploiting system APIs or applications to record audio for later exfiltration.

IMPORTANT DETECTION LIMITATIONS:
Cloud-native APIs (CloudTrail, EventBridge, Cloud Logging) CANNOT detect microphone
access or audio recording. Audio capture is an OS-level operation using device APIs
(ALSA, PulseAudio, CoreAudio, Windows Audio) that generate no cloud events.

What cloud detection CAN see:
- Audio file uploads to cloud storage (post-capture)
- Execution of known audio tools via SSM commands
- Network traffic patterns from audio streaming

What requires endpoint agents:
- Real-time microphone access detection
- Detection of audio recording APIs
- Process monitoring for audio capture tools

Coverage reality:
- Cloud API monitoring: ~5% (post-capture file detection only)
- With OS logging + file monitoring: ~25%
- With endpoint agent (EDR): ~65-75%

For comprehensive detection, deploy endpoint security with audio device access monitoring.
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
    technique_id="T1123",
    technique_name="Audio Capture",
    tactic_ids=["TA0009"],  # Collection
    mitre_url="https://attack.mitre.org/techniques/T1123/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit computer peripherals like microphones and webcams, or integrated "
            "applications for voice/video calls, to record audio for intelligence gathering. In cloud "
            "environments, attackers may compromise EC2 instances, GCE VMs, or containers running "
            "communication services to capture audio streams. The technique involves malware or scripts "
            "interacting with devices through operating system APIs to capture audio, which is subsequently "
            "written to disk for later exfiltration."
        ),
        attacker_goal="Capture audio from compromised systems for intelligence gathering and surveillance",
        why_technique=[
            "Collect sensitive verbal communications and conversations",
            "Gather intelligence from voice/video conferencing systems",
            "Capture authentication codes spoken aloud",
            "Monitor business discussions and strategic planning",
            "Collect personally identifiable information from voice interactions",
            "Difficult to detect as legitimate applications use microphones",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Audio capture represents a significant privacy and security risk, particularly in "
            "environments handling sensitive communications. In cloud environments running "
            "communication platforms, VoIP services, or contact centres, audio capture can expose "
            "confidential business discussions, customer data, and authentication information. "
            "The technique is difficult to detect as legitimate applications routinely access audio devices."
        ),
        business_impact=[
            "Exposure of confidential business communications",
            "Privacy violations and regulatory compliance breaches",
            "Loss of competitive intelligence and trade secrets",
            "Compromise of multi-factor authentication codes",
            "Reputational damage from surveillance disclosure",
            "Legal liability from unauthorised recordings",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1041", "T1048", "T1567"],  # Exfiltration techniques
        often_follows=["T1078.004", "T1190", "T1566"],  # Initial access techniques
    ),
    detection_strategies=[
        # Strategy 1: AWS - Unusual Audio/Media Processing Activity
        DetectionStrategy(
            strategy_id="t1123-aws-media-access",
            name="AWS GuardDuty Runtime Monitoring for Media Device Access",
            description=(
                "Detect suspicious process execution patterns on EC2 instances that may indicate "
                "audio capture activity, including access to audio device drivers and unusual media processing."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/ReverseShell",
                    "Execution:Runtime/ProcessInjection",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect audio capture activity via GuardDuty Runtime Monitoring

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

  # Step 2: Create SNS topic for alerts
  AudioCaptureAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Audio Capture Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route suspicious execution findings to SNS
  SuspiciousExecutionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1123-AudioCaptureDetection
      Description: Alert on potential audio capture activity
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Execution:Runtime"
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref AudioCaptureAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AudioCaptureAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AudioCaptureAlertTopic""",
                terraform_template="""# AWS: Detect audio capture activity via GuardDuty

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
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "audio_capture_alerts" {
  name         = "audio-capture-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Audio Capture Detection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.audio_capture_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route suspicious execution findings to SNS
resource "aws_cloudwatch_event_rule" "audio_capture" {
  name        = "guardduty-audio-capture-detection"
  description = "Alert on potential audio capture activity"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Execution:Runtime" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.audio_capture.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.audio_capture_alerts.arn
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.audio_capture_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.audio_capture_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="AWS: Potential Audio Capture Activity Detected",
                alert_description_template=(
                    "Suspicious process execution detected on instance {instance_id} that may indicate "
                    "audio capture activity. Finding: {finding_type}. Process: {process_name}."
                ),
                investigation_steps=[
                    "Review the GuardDuty finding details for process execution information",
                    "Check if the instance hosts legitimate communication or media services",
                    "Examine running processes for audio capture tools (arecord, ffmpeg, sox)",
                    "Review file system for recently created audio files (.wav, .mp3, .aiff)",
                    "Check network connections for data exfiltration to unusual destinations",
                    "Examine CloudTrail logs for instance role credential usage",
                ],
                containment_actions=[
                    "Isolate the instance by modifying security group rules",
                    "Create a forensic snapshot for detailed investigation",
                    "Terminate suspicious processes accessing audio devices",
                    "Review and remove any unauthorised audio capture tools",
                    "Rotate instance credentials and access keys",
                    "Assess if similar activity exists on other instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist instances running legitimate VoIP, conferencing, or media processing services",
            detection_coverage="15% - detects audio file creation/upload patterns only. Microphone access NOT detected without endpoint agent.",
            evasion_considerations="Attackers may use legitimate tools or disguise processes to avoid detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per instance per month for Runtime Monitoring",
            prerequisites=[
                "GuardDuty enabled",
                "SSM Agent on EC2 instances for Runtime Monitoring",
            ],
        ),
        # Strategy 2: AWS - Audio File Creation Monitoring
        DetectionStrategy(
            strategy_id="t1123-aws-audio-files",
            name="Monitor Audio File Creation via CloudWatch Logs",
            description=(
                "Detect creation of audio files on EC2 instances by monitoring file system "
                "activity logs for common audio file extensions and suspicious locations."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, instanceId, fileName, filePath, processName
| filter fileName like /.wav$|.mp3$|.aiff$|.flac$|.ogg$|.m4a$/
| filter filePath like /tmp|temp|var.tmp|home.*Downloads/
| stats count() as audioFileCount by instanceId, processName, bin(10m)
| filter audioFileCount > 5
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor audio file creation on EC2 instances

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing instance file activity logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create metric filter for audio file creation
  AudioFileFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, file="*.wav" || file="*.mp3" || file="*.aiff"]'
      MetricTransformations:
        - MetricName: AudioFileCreation
          MetricNamespace: Security/T1123
          MetricValue: "1"

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create alarm for excessive audio file creation
  AudioFileAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1123-AudioFileCreation
      AlarmDescription: Excessive audio file creation detected
      MetricName: AudioFileCreation
      Namespace: Security/T1123
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Monitor audio file creation

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing instance file activity logs"
}

variable "alert_email" {
  type = string
}

# Step 1: Create metric filter for audio file creation
resource "aws_cloudwatch_log_metric_filter" "audio_files" {
  name           = "audio-file-creation"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, file=\"*.wav\" || file=\"*.mp3\" || file=\"*.aiff\"]"

  metric_transformation {
    name      = "AudioFileCreation"
    namespace = "Security/T1123"
    value     = "1"
  }
}

# Step 2: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "audio-file-creation-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for excessive audio file creation
resource "aws_cloudwatch_metric_alarm" "audio_files" {
  alarm_name          = "T1123-AudioFileCreation"
  alarm_description   = "Excessive audio file creation detected"
  metric_name         = "AudioFileCreation"
  namespace           = "Security/T1123"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious Audio File Creation Detected",
                alert_description_template=(
                    "Multiple audio files created on instance {instance_id}. "
                    "Process: {process_name}. Location: {file_path}. "
                    "This may indicate audio capture activity."
                ),
                investigation_steps=[
                    "Identify the process creating audio files",
                    "Review file timestamps and sizes",
                    "Check if the instance runs legitimate audio processing services",
                    "Examine file content to determine if they contain recorded audio",
                    "Search for data exfiltration attempts of these files",
                    "Review user sessions active during file creation",
                ],
                containment_actions=[
                    "Quarantine suspicious audio files for analysis",
                    "Terminate the process creating audio files if unauthorised",
                    "Review and restrict file system permissions",
                    "Enable file integrity monitoring on sensitive directories",
                    "Implement DLP policies to prevent audio file exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist media servers, conferencing platforms, and audio processing workflows",
            detection_coverage="70% - requires CloudWatch agent with file monitoring enabled",
            evasion_considerations="Attackers may use custom extensions or encrypt files to avoid detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15 depending on log volume",
            prerequisites=[
                "CloudWatch Logs Agent with file monitoring",
                "File system activity logging enabled",
            ],
        ),
        # Strategy 3: AWS - Audio Processing Tool Detection
        DetectionStrategy(
            strategy_id="t1123-aws-audio-tools",
            name="Detect Audio Capture Tools via Process Monitoring",
            description=(
                "Monitor for execution of known audio capture and recording tools such as "
                "arecord, ffmpeg, sox, pulseaudio utilities, and custom recording scripts."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, instanceId, processName, commandLine, parentProcess
| filter processName like /arecord|ffmpeg.*-f alsa|sox.*rec|parecord|parec|alsaloop|gst-launch.*pulsesrc/
| stats count() as executions by instanceId, processName, commandLine
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect audio capture tool execution

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing process execution logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create metric filter for audio tools
  AudioToolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process="arecord" || process="ffmpeg" || process="sox" || process="parecord"]'
      MetricTransformations:
        - MetricName: AudioCaptureTools
          MetricNamespace: Security/T1123
          MetricValue: "1"

  # Step 2: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create alarm for tool execution
  AudioToolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1123-AudioCaptureToolDetected
      AlarmDescription: Audio capture tool execution detected
      MetricName: AudioCaptureTools
      Namespace: Security/T1123
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect audio capture tool execution

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing process execution logs"
}

variable "alert_email" {
  type = string
}

# Step 1: Create metric filter for audio tools
resource "aws_cloudwatch_log_metric_filter" "audio_tools" {
  name           = "audio-capture-tools"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process=\"arecord\" || process=\"ffmpeg\" || process=\"sox\" || process=\"parecord\"]"

  metric_transformation {
    name      = "AudioCaptureTools"
    namespace = "Security/T1123"
    value     = "1"
  }
}

# Step 2: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "audio-tool-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for tool execution
resource "aws_cloudwatch_metric_alarm" "audio_tools" {
  alarm_name          = "T1123-AudioCaptureToolDetected"
  alarm_description   = "Audio capture tool execution detected"
  metric_name         = "AudioCaptureTools"
  namespace           = "Security/T1123"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Audio Capture Tool Execution Detected",
                alert_description_template=(
                    "Audio capture tool detected on instance {instance_id}. "
                    "Tool: {process_name}. Command: {command_line}. "
                    "Immediate investigation required."
                ),
                investigation_steps=[
                    "Identify who executed the audio capture tool",
                    "Review the full command line for capture parameters (duration, quality)",
                    "Check if the tool is part of a legitimate application workflow",
                    "Examine the parent process and execution context",
                    "Search for output files specified in the command",
                    "Review network activity for potential exfiltration",
                ],
                containment_actions=[
                    "Terminate the audio capture process immediately",
                    "Remove unauthorised audio tools from the instance",
                    "Review and remove any captured audio files",
                    "Restrict installation of audio processing packages",
                    "Implement application whitelisting to prevent unauthorised tools",
                    "Review user access and revoke if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist instances with legitimate audio processing requirements and approved tools",
            detection_coverage="85% - requires CloudWatch agent with process monitoring enabled",
            evasion_considerations="Attackers may rename tools or use custom scripts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudWatch Logs with process execution logging",
                "Process monitoring enabled",
            ],
        ),
        # Strategy 4: GCP - Audio Capture Detection via Cloud Logging
        DetectionStrategy(
            strategy_id="t1123-gcp-audio-capture",
            name="GCP: Detect Audio Capture Activity on GCE Instances",
            description=(
                "Monitor GCP Cloud Logging for audio capture tool execution and suspicious "
                "audio device access on Compute Engine instances."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(protoPayload.request.commandLine=~"arecord|ffmpeg.*alsa|sox.*rec|parecord|gst-launch.*pulsesrc"
OR textPayload=~"dev.snd|dev.dsp|ALSA.*capture|PulseAudio.*record")""",
                gcp_terraform_template="""# GCP: Detect audio capture activity

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Audio Capture Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for audio capture
resource "google_logging_metric" "audio_capture" {
  project = var.project_id
  name    = "audio-capture-detection"
  filter  = <<-EOT
    resource.type="gce_instance"
    (protoPayload.request.commandLine=~"arecord|ffmpeg.*alsa|sox.*rec|parecord"
    OR textPayload=~"/dev/snd|/dev/dsp|ALSA.*capture")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where audio capture was detected"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "audio_capture" {
  project      = var.project_id
  display_name = "T1123: Audio Capture Activity Detected"
  combiner     = "OR"
  conditions {
    display_name = "Audio capture tool execution"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.audio_capture.name}\" resource.type=\"gce_instance\""
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
    auto_close = "1800s"
  }
  documentation {
    content   = "Audio capture activity detected on GCE instance. Investigate for unauthorised audio recording."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Audio Capture Activity Detected",
                alert_description_template=(
                    "Audio capture activity detected on GCE instance {instance_id}. "
                    "Command: {command_line}. Investigate immediately for unauthorised audio recording."
                ),
                investigation_steps=[
                    "Review the Cloud Logging entry for full command details",
                    "Check the instance's service account permissions",
                    "Identify if the instance hosts legitimate audio services",
                    "Examine storage buckets for uploaded audio files",
                    "Review recent API calls made by the instance's service account",
                    "Check VPC Flow Logs for data exfiltration patterns",
                ],
                containment_actions=[
                    "Stop the GCE instance to prevent further audio capture",
                    "Create a snapshot for forensic analysis",
                    "Search for and secure any captured audio files",
                    "Revoke the instance's service account credentials",
                    "Update firewall rules to prevent data exfiltration",
                    "Review and remove unauthorised audio capture tools",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude instances running authorised VoIP, transcription, or media processing services",
            detection_coverage="75% - requires Ops Agent with process monitoring enabled",
            evasion_considerations="Custom tools or obfuscated commands may bypass pattern matching",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Logging API enabled",
                "Ops Agent installed on GCE instances",
            ],
        ),
        # Strategy 5: GCP - Audio File Upload Detection
        DetectionStrategy(
            strategy_id="t1123-gcp-audio-upload",
            name="GCP: Detect Audio File Uploads to Cloud Storage",
            description=(
                "Monitor Cloud Storage for uploads of audio files from compute instances, "
                "which may indicate exfiltration of captured audio recordings."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
protoPayload.resourceName=~".*\\.(wav|mp3|aiff|flac|ogg|m4a)$"
protoPayload.authenticationInfo.principalEmail=~".*gserviceaccount.com$"''',
                gcp_terraform_template="""# GCP: Detect audio file uploads to Cloud Storage

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Audio Upload Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for audio uploads
resource "google_logging_metric" "audio_uploads" {
  project = var.project_id
  name    = "audio-file-uploads"
  filter  = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.create"
    protoPayload.resourceName=~".*\\.(wav|mp3|aiff|flac|ogg|m4a)$"
    protoPayload.authenticationInfo.principalEmail=~".*gserviceaccount.com$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "Service account uploading audio files"
    }
    labels {
      key         = "bucket_name"
      value_type  = "STRING"
      description = "Target bucket for audio files"
    }
  }

  label_extractors = {
    principal_email = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    bucket_name     = "EXTRACT(resource.labels.bucket_name)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "audio_uploads" {
  project      = var.project_id
  display_name = "T1123: Suspicious Audio File Upload Detected"
  combiner     = "OR"
  conditions {
    display_name = "Audio files uploaded from compute instances"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.audio_uploads.name}\" resource.type=\"gcs_bucket\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.principal_email"]
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "3600s"
  }
  documentation {
    content   = "Multiple audio files uploaded to Cloud Storage by compute instance. Investigate for data exfiltration."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Suspicious Audio File Upload Detected",
                alert_description_template=(
                    "Multiple audio files uploaded to Cloud Storage bucket {bucket_name} "
                    "by service account {principal_email}. This may indicate audio capture exfiltration."
                ),
                investigation_steps=[
                    "Identify the source instance associated with the service account",
                    "Review the uploaded audio files for content",
                    "Check file creation timestamps on the source instance",
                    "Examine the bucket's access logs for unusual activity",
                    "Review instance logs for audio capture tool execution",
                    "Assess if the upload pattern is legitimate for the workload",
                ],
                containment_actions=[
                    "Quarantine uploaded audio files for forensic review",
                    "Revoke the service account's storage permissions temporarily",
                    "Enable object versioning and retention on the bucket",
                    "Implement bucket-level DLP scanning for sensitive content",
                    "Review and restrict network egress from compute instances",
                    "Enable VPC Service Controls to limit data exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist service accounts for legitimate media processing and transcription services",
            detection_coverage="80% - API-level detection, does not require endpoint agent",
            evasion_considerations="Attackers may encrypt files or use different extensions before upload",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Cloud Audit Logs enabled for Cloud Storage",
                "Data Access logs enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1123-aws-audio-tools",
        "t1123-gcp-audio-capture",
        "t1123-aws-media-access",
        "t1123-aws-audio-files",
        "t1123-gcp-audio-upload",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+15% improvement for Collection tactic",
)
