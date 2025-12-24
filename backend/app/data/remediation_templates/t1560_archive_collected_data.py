"""
T1560 - Archive Collected Data

Adversaries compress and/or encrypt collected data before exfiltration to obfuscate
information and reduce network transmission volume. Used by APT28, Lazarus Group, APT32,
and numerous other threat actors.
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
    technique_id="T1560",
    technique_name="Archive Collected Data",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1560/",
    threat_context=ThreatContext(
        description=(
            "Adversaries compress and/or encrypt collected data before exfiltration to "
            "obfuscate information and reduce network transmission volume. These operations "
            "occur prior to data transfer and may utilise compression utilities, third-party "
            "libraries, or custom implementation methods. In cloud environments, attackers "
            "may use native tools or cloud APIs to archive data from EC2 instances, containers, "
            "or serverless functions before transferring it out."
        ),
        attacker_goal="Compress and encrypt stolen data to evade detection during exfiltration",
        why_technique=[
            "Reduces network traffic volume, making exfiltration less noticeable",
            "Encryption obfuscates data from DLP and content inspection",
            "Compression utilities are commonly used, blending in with normal activity",
            "Single archive file easier to exfiltrate than multiple files",
            "Cloud instances often have archiving tools pre-installed",
        ],
        known_threat_actors=[
            "APT28",
            "APT32",
            "Lazarus Group",
            "Dragonfly",
            "FIN6",
            "Patchwork",
            "Axiom",
            "Ke3chang",
            "menuPass",
            "Leviathan",
        ],
        recent_campaigns=[
            Campaign(
                name="APT28 DNC Compromise",
                year=2016,
                description="Used publicly available compression tools to gather and compress documents from Democratic National Committee networks",
                reference_url="https://attack.mitre.org/groups/G0007/",
            ),
            Campaign(
                name="Lazarus RomeoDelta",
                year=2020,
                description="Deployed RAR compression and RomeoDelta malware for archiving and encryption workflows before exfiltration",
                reference_url="https://attack.mitre.org/campaigns/C0022/",
            ),
            Campaign(
                name="Agent Tesla Exfiltration",
                year=2021,
                description="Implemented 3DES encryption before command-and-control transmission of stolen credentials and data",
                reference_url="https://attack.mitre.org/software/S0331/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Archive operations typically indicate imminent data exfiltration. "
            "Compression and encryption make detection more difficult and suggest "
            "a sophisticated adversary. Common across APT groups and ransomware operators."
        ),
        business_impact=[
            "Data exfiltration and intellectual property theft",
            "Regulatory compliance violations (GDPR, CCPA, HIPAA)",
            "Loss of competitive advantage",
            "Potential ransomware or extortion leverage",
            "Reputational damage from data breach",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1041", "T1567", "T1537"],
        often_follows=["T1005", "T1039", "T1074", "T1530"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Archive Utility Execution on EC2
        DetectionStrategy(
            strategy_id="t1560-aws-ec2-archiving",
            name="AWS EC2 Archive Utility Execution Detection",
            description=(
                "Detect execution of archiving utilities (tar, zip, 7z, rar, gzip) on EC2 instances "
                "using CloudWatch Logs from SSM or GuardDuty runtime monitoring."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, instance_id, user, command, working_directory
| filter command like /tar|zip|7z|rar|gzip|bzip2|xz|compress/
| filter command like /-c|-z|-j|-x|--create|--compress/
| stats count(*) as archive_count by instance_id, user, bin(5m) as time_window
| filter archive_count >= 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect archive utility execution on EC2 instances

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  ProcessLogGroup:
    Type: String
    Description: CloudWatch log group containing process execution logs
    Default: /aws/ssm/process-logs

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Archive Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for archive utility execution
  ArchiveUtilityFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ProcessLogGroup
      FilterPattern: '[time, instance, user, command=*tar* || command=*zip* || command=*7z* || command=*rar* || command=*gzip*]'
      MetricTransformations:
        - MetricName: ArchiveUtilityExecutions
          MetricNamespace: Security/T1560
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for suspicious archive activity
  ArchiveActivityAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1560-ArchiveUtilityDetection
      AlarmDescription: Multiple archive utility executions detected
      MetricName: ArchiveUtilityExecutions
      Namespace: Security/T1560
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# AWS: Detect archive utility execution on EC2 instances

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "process_log_group" {
  type        = string
  description = "CloudWatch log group containing process execution logs"
  default     = "/aws/ssm/process-logs"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "archive_alerts" {
  name         = "archive-detection-alerts"
  display_name = "Archive Detection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.archive_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for archive utility execution
resource "aws_cloudwatch_log_metric_filter" "archive_utility" {
  name           = "archive-utility-executions"
  log_group_name = var.process_log_group
  pattern        = "[time, instance, user, command=*tar* || command=*zip* || command=*7z* || command=*rar* || command=*gzip*]"

  metric_transformation {
    name      = "ArchiveUtilityExecutions"
    namespace = "Security/T1560"
    value     = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious archive activity
resource "aws_cloudwatch_metric_alarm" "archive_activity" {
  alarm_name          = "T1560-ArchiveUtilityDetection"
  alarm_description   = "Multiple archive utility executions detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ArchiveUtilityExecutions"
  namespace           = "Security/T1560"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.archive_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.archive_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.archive_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Suspicious Archive Utility Activity Detected",
                alert_description_template=(
                    "Archive utilities executed {archive_count} times on instance {instance_id} "
                    "by user {user} within 5 minutes. This may indicate data collection before exfiltration."
                ),
                investigation_steps=[
                    "Identify which archive utilities were executed and their command-line arguments",
                    "Determine what files or directories were archived",
                    "Check the destination of created archive files",
                    "Review network connections from the instance during and after archiving",
                    "Verify if the user account should be performing archiving operations",
                    "Examine created archive files for sensitive data",
                    "Check for subsequent file transfer or upload activity",
                ],
                containment_actions=[
                    "Isolate the EC2 instance by modifying security group rules",
                    "Revoke credentials for the compromised user account",
                    "Take EBS snapshot for forensic analysis",
                    "Block outbound network connections if exfiltration is suspected",
                    "Review and remove any created archive files containing sensitive data",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate backup jobs, build processes, and log rotation tasks; adjust threshold based on environment",
            detection_coverage="60% - requires process logging enabled on instances",
            evasion_considerations="Attackers may use custom scripts, rename utilities, or use library-based compression",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30 (depends on log volume)",
            prerequisites=[
                "SSM Agent installed on EC2 instances",
                "Process execution logging configured",
                "CloudWatch Logs enabled",
            ],
        ),
        # Strategy 2: AWS - Large Archive File Creation Detection
        DetectionStrategy(
            strategy_id="t1560-aws-large-archives",
            name="Large Archive File Creation Detection",
            description=(
                "Detect creation of large archive files (.zip, .tar.gz, .7z, .rar) that may contain "
                "collected data ready for exfiltration."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, instance_id, file_path, file_size, user
| filter file_path like /\\.(zip|tar\\.gz|tgz|7z|rar|gz|bz2|xz)$/
| filter file_size >= 10485760
| stats count(*) as archive_count, sum(file_size) as total_size by instance_id, user, bin(10m) as time_window
| filter archive_count >= 2 or total_size >= 52428800
| sort total_size desc""",
                terraform_template="""# AWS: Detect large archive file creation

variable "alert_email" {
  type = string
}

variable "file_event_log_group" {
  type    = string
  default = "/aws/ssm/file-events"
}

resource "aws_sns_topic" "large_archive_alerts" {
  name = "large-archive-detection"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.large_archive_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "large_archives" {
  name           = "large-archive-creation"
  log_group_name = var.file_event_log_group
  pattern        = "[time, instance, user, path=*.zip || path=*.tar.gz || path=*.7z || path=*.rar, size>=10485760]"

  metric_transformation {
    name      = "LargeArchiveCreation"
    namespace = "Security/T1560"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "large_archive" {
  alarm_name          = "T1560-LargeArchiveCreation"
  alarm_description   = "Large archive files created on EC2 instances"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "LargeArchiveCreation"
  namespace           = "Security/T1560"
  period              = 600
  statistic           = "Sum"
  threshold           = 2
  alarm_actions       = [aws_sns_topic.large_archive_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Large Archive Files Created",
                alert_description_template=(
                    "User {user} created {archive_count} archive files totalling {total_size} bytes "
                    "on instance {instance_id}. This may indicate data staging before exfiltration."
                ),
                investigation_steps=[
                    "Identify the archive files created and their locations",
                    "Examine archive contents if possible (may be encrypted)",
                    "Review what source directories/files were archived",
                    "Check for network activity following archive creation",
                    "Verify if this activity aligns with legitimate backup schedules",
                    "Investigate the user account's recent activity",
                ],
                containment_actions=[
                    "Quarantine the archive files",
                    "Block network egress from the instance",
                    "Suspend the user account pending investigation",
                    "Review S3 access logs for upload attempts",
                    "Check CloudTrail for API calls related to data transfer",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known backup directories and scheduled backup times; whitelist backup service accounts",
            detection_coverage="70% - detects large-scale archiving activity",
            evasion_considerations="Attackers may create smaller archives or use encrypted containers",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "File system monitoring enabled",
                "CloudWatch Logs configured",
            ],
        ),
        # Strategy 3: AWS - S3 Archive Upload Detection
        DetectionStrategy(
            strategy_id="t1560-aws-s3-upload",
            name="S3 Archive File Upload Detection",
            description=(
                "Detect when archive files are uploaded to S3 buckets, which may indicate "
                "staged data ready for exfiltration or already exfiltrated to external accounts."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
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
                        ],
                        "requestParameters": {
                            "key": [
                                {"suffix": ".zip"},
                                {"suffix": ".tar"},
                                {"suffix": ".tar.gz"},
                                {"suffix": ".tgz"},
                                {"suffix": ".7z"},
                                {"suffix": ".rar"},
                                {"suffix": ".gz"},
                                {"suffix": ".bz2"},
                            ]
                        },
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect archive file uploads to S3

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for archive uploads
  S3ArchiveUploadRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1560-S3ArchiveUpload
      Description: Detect archive file uploads to S3
      EventPattern:
        source:
          - aws.s3
        detail-type:
          - "AWS API Call via CloudTrail"
        detail:
          eventName:
            - PutObject
            - UploadPart
            - CompleteMultipartUpload
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic
          InputTransformer:
            InputPathsMap:
              bucket: "$.detail.requestParameters.bucketName"
              key: "$.detail.requestParameters.key"
              user: "$.detail.userIdentity.arn"
              ip: "$.detail.sourceIPAddress"
            InputTemplate: |
              "Archive file uploaded to S3: <key> in bucket <bucket> by <user> from IP <ip>"

  # Step 3: Configure SNS topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# AWS: Detect archive file uploads to S3

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "s3_archive_alerts" {
  name = "s3-archive-upload-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.s3_archive_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for archive uploads
resource "aws_cloudwatch_event_rule" "s3_archive_upload" {
  name        = "T1560-S3ArchiveUpload"
  description = "Detect archive file uploads to S3"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutObject", "UploadPart", "CompleteMultipartUpload"]
      requestParameters = {
        key = [
          { suffix = ".zip" },
          { suffix = ".tar" },
          { suffix = ".tar.gz" },
          { suffix = ".tgz" },
          { suffix = ".7z" },
          { suffix = ".rar" },
          { suffix = ".gz" },
          { suffix = ".bz2" }
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.s3_archive_upload.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.s3_archive_alerts.arn

  input_transformer {
    input_paths = {
      bucket = "$.detail.requestParameters.bucketName"
      key    = "$.detail.requestParameters.key"
      user   = "$.detail.userIdentity.arn"
      ip     = "$.detail.sourceIPAddress"
    }
    input_template = "\"Archive file uploaded to S3: <key> in bucket <bucket> by <user> from IP <ip>\""
  }
}

# Step 3: Configure SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.s3_archive_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.s3_archive_alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Archive File Uploaded to S3",
                alert_description_template=(
                    "Archive file {key} uploaded to bucket {bucket} by {user} from IP {ip}. "
                    "Verify this is authorised activity."
                ),
                investigation_steps=[
                    "Identify the S3 bucket and verify if it's internal or external",
                    "Review the archive file size and contents",
                    "Check if the bucket has cross-account access configured",
                    "Verify the user's authorisation to upload to this bucket",
                    "Review CloudTrail for subsequent download or copy operations",
                    "Check source IP reputation and geolocation",
                ],
                containment_actions=[
                    "Quarantine the uploaded archive file",
                    "Review bucket access policies and remove suspicious grants",
                    "Revoke credentials for compromised accounts",
                    "Enable S3 Object Lock to prevent deletion",
                    "Block external access to the bucket if applicable",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist known backup buckets and automated backup processes; filter legitimate CI/CD pipelines",
            detection_coverage="80% - catches S3-based staging and exfiltration",
            evasion_considerations="Attackers may use non-standard extensions or upload to external cloud storage",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "S3 bucket logging enabled",
            ],
        ),
        # Strategy 4: GCP - Archive Utility Execution Detection
        DetectionStrategy(
            strategy_id="t1560-gcp-archiving",
            name="GCP Archive Utility Execution Detection",
            description=(
                "Detect execution of archiving utilities on GCP Compute Engine instances using "
                "Cloud Logging to identify potential data collection and staging."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.start"
OR (
  jsonPayload.command=~"tar|zip|7z|rar|gzip|bzip2"
  AND jsonPayload.command=~"-c|-z|-j|--create|--compress"
)""",
                gcp_terraform_template="""# GCP: Detect archive utility execution

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Archive Detection Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for archive utility execution
resource "google_logging_metric" "archive_utility" {
  name   = "archive-utility-executions"
  filter = <<-EOT
    resource.type="gce_instance"
    (
      jsonPayload.command=~"tar|zip|7z|rar|gzip|bzip2"
      AND jsonPayload.command=~"-c|-z|-j|--create|--compress"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where archive utility was executed"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy for archive activity
resource "google_monitoring_alert_policy" "archive_activity" {
  display_name = "T1560 - Archive Utility Execution"
  combiner     = "OR"

  conditions {
    display_name = "Archive utility executed multiple times"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.archive_utility.name}\" resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content = "Archive utility executed multiple times on GCE instance. This may indicate data collection before exfiltration (MITRE ATT&CK T1560)."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Archive Utility Execution Detected",
                alert_description_template=(
                    "Archive utilities executed multiple times on GCE instance {instance_id}. "
                    "This may indicate data collection before exfiltration."
                ),
                investigation_steps=[
                    "Identify which archive utilities were executed",
                    "Review command-line arguments and target directories",
                    "Check what files were archived",
                    "Examine network connections from the instance",
                    "Verify the user account's authorisation",
                    "Look for subsequent data transfer activity",
                ],
                containment_actions=[
                    "Isolate the instance using firewall rules",
                    "Suspend compromised user accounts",
                    "Take disk snapshot for forensic analysis",
                    "Review and remove suspicious archive files",
                    "Check VPC Flow Logs for data exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate backup jobs and build processes; adjust threshold based on baseline",
            detection_coverage="60% - requires process logging on instances",
            evasion_considerations="Attackers may use custom scripts or library-based compression",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Logging enabled",
                "Process execution logging configured on instances",
            ],
        ),
        # Strategy 5: GCP - Cloud Storage Archive Upload Detection
        DetectionStrategy(
            strategy_id="t1560-gcp-gcs-upload",
            name="GCP Cloud Storage Archive Upload Detection",
            description=(
                "Detect when archive files are uploaded to Google Cloud Storage buckets, "
                "which may indicate data staging or exfiltration."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
protoPayload.resourceName=~"\\.(zip|tar|tar\\.gz|tgz|7z|rar|gz|bz2)$"''',
                gcp_terraform_template="""# GCP: Detect archive file uploads to Cloud Storage

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "GCS Archive Upload Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for archive uploads
resource "google_logging_metric" "gcs_archive_upload" {
  name   = "gcs-archive-uploads"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.create"
    protoPayload.resourceName=~"\\.(zip|tar|tar\\.gz|tgz|7z|rar|gz|bz2)$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "bucket_name"
      value_type  = "STRING"
      description = "GCS bucket name"
    }
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "User or service account"
    }
  }

  label_extractors = {
    "bucket_name" = "EXTRACT(resource.labels.bucket_name)"
    "principal"   = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for archive uploads
resource "google_monitoring_alert_policy" "gcs_archive_upload" {
  display_name = "T1560 - Archive Upload to Cloud Storage"
  combiner     = "OR"

  conditions {
    display_name = "Archive file uploaded to GCS"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_archive_upload.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Archive file uploaded to Cloud Storage. Verify this is authorised activity and not data exfiltration (MITRE ATT&CK T1560)."
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Archive File Uploaded to Cloud Storage",
                alert_description_template=(
                    "Archive file uploaded to GCS bucket {bucket_name} by {principal}. "
                    "Verify this is authorised activity."
                ),
                investigation_steps=[
                    "Identify the GCS bucket and object name",
                    "Review the archive file size and metadata",
                    "Check bucket IAM policies for external access",
                    "Verify the principal's authorisation to upload",
                    "Review audit logs for subsequent download activity",
                    "Check if the bucket is publicly accessible",
                ],
                containment_actions=[
                    "Quarantine the uploaded archive object",
                    "Review and restrict bucket IAM policies",
                    "Suspend compromised service accounts",
                    "Enable Object Versioning for recovery",
                    "Configure VPC Service Controls to prevent exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist backup buckets and CI/CD service accounts; filter legitimate automated processes",
            detection_coverage="85% - comprehensive coverage of GCS uploads",
            evasion_considerations="Attackers may use non-standard file extensions or direct network exfiltration",
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
        "t1560-aws-s3-upload",
        "t1560-gcp-gcs-upload",
        "t1560-aws-ec2-archiving",
        "t1560-gcp-archiving",
        "t1560-aws-large-archives",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+30% improvement for Collection tactic",
)
