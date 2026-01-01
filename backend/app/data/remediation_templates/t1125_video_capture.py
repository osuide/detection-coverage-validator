"""
T1125 - Video Capture

Adversaries may leverage peripheral devices (webcams) or applications to capture video
recordings for intelligence gathering purposes.

IMPORTANT DETECTION LIMITATIONS:
Cloud-native APIs (CloudTrail, EventBridge, Cloud Logging) CANNOT detect webcam
access or video recording. Video capture is an OS-level operation using device APIs
(V4L2, DirectShow, AVFoundation) that generate no cloud events.

What cloud detection CAN see:
- Video file uploads to cloud storage (post-capture)
- Execution of known video tools via SSM commands
- Network traffic patterns from video streaming

What requires endpoint agents:
- Real-time camera/webcam access detection
- Detection of video recording APIs
- Process monitoring for video capture tools

Coverage reality:
- Cloud API monitoring: ~5% (post-capture file detection only)
- With OS logging + file monitoring: ~20%
- With endpoint agent (EDR): ~60-70%

For comprehensive detection, deploy endpoint security with camera device access monitoring.
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
    technique_id="T1125",
    technique_name="Video Capture",
    tactic_ids=["TA0009"],  # Collection
    mitre_url="https://attack.mitre.org/techniques/T1125/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit webcams or video applications to capture video recordings for "
            "intelligence gathering. In cloud environments, attackers may compromise EC2 or GCE "
            "instances with attached USB devices, desktop streaming instances, or leverage API "
            "access to video conferencing platforms to record sensitive meetings, environments, "
            "or user activities. Attackers interface with OS/application APIs to record video or "
            "images, then exfiltrate the files for reconnaissance or espionage purposes."
        ),
        attacker_goal="Capture video recordings from webcams for surveillance and intelligence gathering",
        why_technique=[
            "Enables surveillance of physical environments and personnel",
            "Captures sensitive visual information from meetings and workspaces",
            "Provides intelligence on security controls and physical layouts",
            "Can be used for targeted social engineering attacks",
            "Often goes undetected as legitimate camera usage",
            "Video conferencing API access provides covert recording capability",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="rare",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Video capture enables serious privacy violations and intelligence gathering. "
            "In cloud environments with remote work capabilities, compromised instances "
            "with webcam access or video conferencing API abuse can expose sensitive business "
            "meetings, physical security layouts, and confidential discussions. High severity "
            "due to the privacy impact and value of captured intelligence for targeted attacks."
        ),
        business_impact=[
            "Privacy violations and exposure of sensitive discussions",
            "Intelligence gathering on physical security measures",
            "Exposure of confidential business strategies and meetings",
            "Regulatory compliance violations (GDPR, privacy laws)",
            "Reputational damage from surveillance incidents",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1048", "T1041", "T1567"],
        often_follows=["T1078.004", "T1190", "T1566"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Unusual Camera Device Access on EC2
        DetectionStrategy(
            strategy_id="t1125-aws-camera-access",
            name="AWS GuardDuty Runtime Monitoring for Camera Access",
            description="Detect suspicious camera device access or video capture library usage on EC2 instances through runtime monitoring.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/ReverseShell",
                    "Execution:Runtime/SuspiciousTool",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect video capture activity on EC2 instances

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
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Video Capture Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route runtime findings to email
  RuntimeActivityRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1125-VideoCaptureDetection
      Description: Alert on suspicious runtime activity that may indicate video capture
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Execution:Runtime"
            - prefix: "CredentialAccess:Runtime"
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref SecurityAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SecurityAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt RuntimeActivityRule.Arn""",
                terraform_template="""# GuardDuty Runtime Monitoring for video capture detection

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
resource "aws_sns_topic" "video_capture_alerts" {
  name         = "video-capture-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Video Capture Detection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.video_capture_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route runtime findings to email
resource "aws_cloudwatch_event_rule" "runtime_activity" {
  name        = "guardduty-video-capture-detection"
  description = "Alert on suspicious runtime activity"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Execution:Runtime" },
        { prefix = "CredentialAccess:Runtime" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.runtime_activity.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.video_capture_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.video_capture_dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

resource "aws_sqs_queue" "video_capture_dlq" {
  name                      = "video-capture-alerts-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "video_capture_dlq_policy" {
  queue_url = aws_sqs_queue.video_capture_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.video_capture_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.runtime_activity.arn
        }
      }
    }]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.video_capture_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.video_capture_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.runtime_activity.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Suspicious Runtime Activity Detected",
                alert_description_template=(
                    "Suspicious runtime activity detected on instance {instance_id} that may indicate "
                    "video capture or surveillance activity. Finding: {finding_type}. Process: {process_name}."
                ),
                investigation_steps=[
                    "Review the GuardDuty finding details and affected instance",
                    "Check for processes accessing video device files (/dev/video*)",
                    "Examine CloudWatch logs for camera library loading (avicap32.dll, mf.dll)",
                    "Review network connections for video file exfiltration",
                    "Check for large video files in unusual locations",
                    "Investigate recent user sessions and authentication activity",
                ],
                containment_actions=[
                    "Isolate the instance by modifying security groups",
                    "Create a forensic snapshot for investigation",
                    "Review and remove unauthorised video capture software",
                    "Disable USB device passthrough if enabled",
                    "Audit IAM permissions for the instance role",
                    "Terminate the instance if compromise is confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised video conferencing and remote desktop instances",
            detection_coverage="15% - detects video file upload patterns only. Webcam access NOT detected without endpoint agent.",
            evasion_considerations="Legitimate video conferencing applications may mask malicious activity",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per instance per month for Runtime Monitoring",
            prerequisites=["GuardDuty enabled", "SSM Agent on EC2 instances"],
        ),
        # Strategy 2: AWS - Video File Creation and Exfiltration
        DetectionStrategy(
            strategy_id="t1125-aws-video-files",
            name="Detect Video File Creation and Exfiltration",
            description="Monitor for creation of video files in unusual locations and subsequent exfiltration attempts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, fileName, fileSize
| filter @message like /\\.mp4|\\.avi|\\.mov|\\.wmv|\\.flv|\\.mkv|\\.webm/
| filter @message like /\\/tmp|\\/var\\/tmp|unusual|capture|recording/
| stats count() as video_files, sum(fileSize) as total_size by instanceId, bin(1h)
| filter video_files > 3 or total_size > 100000000
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect video file creation and exfiltration

Parameters:
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Monitor S3 for video uploads to unusual locations
  VideoUploadRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.s3]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [PutObject, CompleteMultipartUpload]
          requestParameters:
            key:
              - suffix: .mp4
              - suffix: .avi
              - suffix: .mov
              - suffix: .wmv
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy to allow EventBridge
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
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt VideoUploadRule.Arn""",
                terraform_template="""# Detect video file creation and exfiltration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "video-file-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Monitor S3 for video uploads
resource "aws_cloudwatch_event_rule" "video_upload" {
  name        = "video-file-upload-detection"
  description = "Detect video file uploads to S3"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutObject", "CompleteMultipartUpload"]
      requestParameters = {
        key = [
          { suffix = ".mp4" },
          { suffix = ".avi" },
          { suffix = ".mov" },
          { suffix = ".wmv" }
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.video_upload.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.video_upload_dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

resource "aws_sqs_queue" "video_upload_dlq" {
  name                      = "video-upload-alerts-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "video_upload_dlq_policy" {
  queue_url = aws_sqs_queue.video_upload_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.video_upload_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.video_upload.arn
        }
      }
    }]
  })
}

# Step 3: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
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
            "aws:SourceArn" = aws_cloudwatch_event_rule.video_upload.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Video File Upload Detected",
                alert_description_template=(
                    "Video file upload detected to S3 bucket {bucket_name}. File: {key}. "
                    "This may indicate video capture and exfiltration activity."
                ),
                investigation_steps=[
                    "Identify the source instance or principal that uploaded the file",
                    "Download and review the video file contents (if appropriate)",
                    "Check CloudTrail for the upload source IP address",
                    "Review other files uploaded by the same principal",
                    "Examine the instance for video capture software",
                    "Check for additional exfiltration methods (network transfers)",
                ],
                containment_actions=[
                    "Quarantine or delete the suspicious video files",
                    "Block the uploading principal's credentials",
                    "Review and restrict S3 bucket policies",
                    "Enable S3 Object Lock for critical buckets",
                    "Implement bucket policies to restrict video file uploads",
                    "Enable GuardDuty S3 Protection for anomaly detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised video storage buckets and media processing workflows",
            detection_coverage="70% - API-level detection, does not require endpoint agent",
            evasion_considerations="Attackers may rename files, use encryption, or exfiltrate via alternative channels",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with S3 data events"],
        ),
        # Strategy 3: AWS - Video Conferencing API Abuse
        DetectionStrategy(
            strategy_id="t1125-aws-conferencing-api",
            name="Detect Video Conferencing API Abuse",
            description="Monitor for suspicious usage of video conferencing APIs (Amazon Chime SDK, third-party integrations) that could enable covert recording.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, requestParameters
| filter eventSource = "chime.amazonaws.com"
| filter eventName in ["CreateMediaCapturePipeline", "StartMeetingTranscription", "CreateAttendee"]
| stats count() as api_calls by userIdentity.principalId, eventName, bin(1h)
| filter api_calls > 10
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Amazon Chime SDK recording abuse

Parameters:
  AlertEmail:
    Type: String
  CloudTrailLogGroup:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for Chime recording API calls
  ChimeRecordingFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "chime.amazonaws.com" && ($.eventName = "CreateMediaCapturePipeline" || $.eventName = "StartMeetingTranscription") }'
      MetricTransformations:
        - MetricName: ChimeRecordingActivity
          MetricNamespace: Security/T1125
          MetricValue: "1"

  # Step 3: Alarm for unusual recording activity
  RecordingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1125-ChimeRecordingAbuse
      AlarmDescription: Unusual Chime recording API usage detected
      MetricName: ChimeRecordingActivity
      Namespace: Security/T1125
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect Amazon Chime SDK recording abuse

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "chime-recording-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for Chime recording API calls
resource "aws_cloudwatch_log_metric_filter" "chime_recording" {
  name           = "chime-recording-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"chime.amazonaws.com\" && ($.eventName = \"CreateMediaCapturePipeline\" || $.eventName = \"StartMeetingTranscription\") }"

  metric_transformation {
    name      = "ChimeRecordingActivity"
    namespace = "Security/T1125"
    value     = "1"
  }
}

# Step 3: Alarm for unusual recording activity
resource "aws_cloudwatch_metric_alarm" "recording_abuse" {
  alarm_name          = "T1125-ChimeRecordingAbuse"
  alarm_description   = "Unusual Chime recording API usage detected"
  metric_name         = "ChimeRecordingActivity"
  namespace           = "Security/T1125"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Video Conferencing Recording Abuse Detected",
                alert_description_template=(
                    "Unusual video conferencing recording activity detected. Principal: {principal_id}. "
                    "API calls: {api_calls}. This may indicate unauthorised meeting recording."
                ),
                investigation_steps=[
                    "Identify which meetings were recorded without authorisation",
                    "Review the principal's permissions and recent authentication",
                    "Check if recording notifications were properly sent to participants",
                    "Examine where recorded media was stored or streamed",
                    "Review access logs for the media storage location",
                    "Verify if the activity aligns with legitimate use cases",
                ],
                containment_actions=[
                    "Revoke the principal's credentials immediately",
                    "Delete unauthorised recordings from storage",
                    "Review and restrict Chime SDK permissions",
                    "Implement resource-based policies requiring approval for recording",
                    "Enable CloudTrail logging for all Chime API calls",
                    "Notify affected meeting participants of unauthorised recording",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal recording patterns for authorised services and users",
            detection_coverage="65% - API-level only, cannot detect local screen recording",
            evasion_considerations="Attackers may use compromised legitimate accounts or third-party platforms",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "Amazon Chime SDK in use"],
        ),
        # Strategy 4: GCP - Video Device Access Detection
        DetectionStrategy(
            strategy_id="t1125-gcp-camera-access",
            name="GCP: Detect Camera Device Access on Compute Instances",
            description="Monitor GCP Cloud Logging for processes accessing video devices or camera libraries on GCE instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(textPayload=~"/dev/video|camera|webcam|video4linux|v4l2"
OR protoPayload.request.commandLine=~"ffmpeg.*video|gstreamer.*camera|opencv")
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Detect camera device access on GCE instances

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
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for camera access
resource "google_logging_metric" "camera_access" {
  project = var.project_id
  name    = "camera-device-access"
  filter  = <<-EOT
    resource.type="gce_instance"
    (textPayload=~"/dev/video|camera|webcam|video4linux|v4l2"
    OR protoPayload.request.commandLine=~"ffmpeg.*video|gstreamer.*camera")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance accessing camera devices"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "camera_access" {
  project      = var.project_id
  display_name = "T1125: Camera Device Access Detected"
  combiner     = "OR"
  conditions {
    display_name = "Camera device access activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.camera_access.name}\" resource.type=\"gce_instance\""
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
    content   = "Camera or video device access detected on GCE instance. Investigate for unauthorised video capture activity."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Camera Device Access Detected",
                alert_description_template=(
                    "Camera or video device access detected on GCE instance {instance_id}. "
                    "This may indicate video capture or surveillance activity."
                ),
                investigation_steps=[
                    "Review the Cloud Logging entry for full command details",
                    "Check which processes are accessing video devices",
                    "Examine the instance's installed software and recent changes",
                    "Review network connections for video file transfers",
                    "Check Cloud Storage for uploaded video files",
                    "Verify if the instance legitimately requires camera access",
                ],
                containment_actions=[
                    "Stop the GCE instance to prevent further recording",
                    "Create a disk snapshot for forensic analysis",
                    "Remove video capture software and unauthorised applications",
                    "Review and restrict USB device passthrough settings",
                    "Update firewall rules to block suspicious outbound traffic",
                    "Audit service account permissions for the instance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist instances legitimately used for video processing or conferencing",
            detection_coverage="75% - requires Ops Agent with device monitoring enabled",
            evasion_considerations="Minimal logging or disabled Ops Agent may prevent detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Logging API enabled",
                "Ops Agent installed on GCE instances",
            ],
        ),
        # Strategy 5: GCP - Video File Storage Monitoring
        DetectionStrategy(
            strategy_id="t1125-gcp-video-storage",
            name="GCP: Monitor Cloud Storage for Video Files",
            description="Detect uploads of video files to Cloud Storage buckets that may indicate video capture and exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
protoPayload.resourceName=~".*\\.(mp4|avi|mov|wmv|flv|mkv|webm)$"''',
                gcp_terraform_template="""# GCP: Monitor Cloud Storage for video file uploads

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
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for video uploads
resource "google_logging_metric" "video_uploads" {
  project = var.project_id
  name    = "video-file-uploads"
  filter  = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.create"
    protoPayload.resourceName=~".*\\.(mp4|avi|mov|wmv|flv|mkv|webm)$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "bucket_name"
      value_type  = "STRING"
      description = "Bucket receiving video uploads"
    }
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal uploading videos"
    }
  }

  label_extractors = {
    bucket_name = "EXTRACT(resource.labels.bucket_name)"
    principal   = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "video_uploads" {
  project      = var.project_id
  display_name = "T1125: Video File Upload Detected"
  combiner     = "OR"
  conditions {
    display_name = "Video file uploaded to Cloud Storage"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.video_uploads.name}\" resource.type=\"gcs_bucket\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "3600s"
  }
  documentation {
    content   = "Video files uploaded to Cloud Storage. Investigate for potential video capture and exfiltration activity."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Video File Upload Detected",
                alert_description_template=(
                    "Video files uploaded to Cloud Storage bucket {bucket_name} by {principal}. "
                    "Multiple video uploads detected - investigate for unauthorised recording."
                ),
                investigation_steps=[
                    "Identify the principal that uploaded the video files",
                    "Review the source IP address and location",
                    "Check the video file metadata and timestamps",
                    "Examine the bucket's access controls and policies",
                    "Review other objects uploaded by the same principal",
                    "Check for corresponding camera access logs on GCE instances",
                ],
                containment_actions=[
                    "Quarantine or delete suspicious video files",
                    "Revoke the uploading principal's credentials",
                    "Review and restrict Cloud Storage bucket IAM policies",
                    "Enable uniform bucket-level access for better control",
                    "Implement organisation policies to restrict video uploads",
                    "Enable VPC Service Controls for Cloud Storage",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised media storage buckets and video processing pipelines",
            detection_coverage="80% - API-level detection, does not require endpoint agent",
            evasion_considerations="Renamed extensions or encrypted files may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Storage audit logs enabled"],
        ),
    ],
    recommended_order=[
        "t1125-aws-camera-access",
        "t1125-gcp-camera-access",
        "t1125-aws-video-files",
        "t1125-gcp-video-storage",
        "t1125-aws-conferencing-api",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+15% improvement for Collection tactic",
)
