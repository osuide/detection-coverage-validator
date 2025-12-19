"""
T1074 - Data Staged

Adversaries may stage collected data in a central location or directory prior to exfiltration.
Data may be kept in separate files or combined into one file through techniques such as archive creation.
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
    technique_id="T1074",
    technique_name="Data Staged",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1074/",

    threat_context=ThreatContext(
        description=(
            "Adversaries may stage collected data in a central location or directory prior to exfiltration. "
            "Data may be consolidated from multiple systems or sources into temporary staging directories, "
            "compressed into archives, or moved to public-facing storage locations before being exfiltrated. "
            "This technique minimises the number of connections to command and control infrastructure and "
            "reduces the likelihood of detection during the exfiltration phase."
        ),
        attacker_goal="Consolidate and prepare stolen data for efficient exfiltration",
        why_technique=[
            "Minimises connections to C2 infrastructure by batching data transfers",
            "Enables compression to reduce exfiltration time and bandwidth",
            "Allows preparation of data without immediate exfiltration risk",
            "Facilitates organised theft of large data volumes",
            "Can blend staging activities with normal user behaviour"
        ],
        known_threat_actors=[
            "INC Ransom",
            "Scattered Spider",
            "Volt Typhoon",
            "Wizard Spider",
            "Turla",
            "Siamesekitten"
        ],
        recent_campaigns=[
            Campaign(
                name="Volt Typhoon Espionage",
                year=2023,
                description="Staged sensitive data in temporary directories on compromised systems before exfiltration",
                reference_url="https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/"
            ),
            Campaign(
                name="Scattered Spider MGM Attack",
                year=2023,
                description="Staged data from cloud environments into centralised locations before exfiltration and extortion",
                reference_url="https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/"
            ),
            Campaign(
                name="Turla QUIETCANARY",
                year=2024,
                description="Used staging techniques to consolidate data from ESXi environments into password-protected archives",
                reference_url="https://www.mandiant.com/resources/blog/turla-galaxy-opportunity"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Data staging is a critical precursor to exfiltration and data theft. "
            "Whilst staging itself doesn't result in immediate data loss, it indicates an imminent "
            "exfiltration attempt and provides a crucial detection opportunity before data leaves the environment. "
            "Common in ransomware and APT operations."
        ),
        business_impact=[
            "Precursor to data breach and exfiltration",
            "Indicator of advanced persistent threat activity",
            "Potential intellectual property theft",
            "Regulatory compliance violations if data is exfiltrated",
            "Operational disruption from investigation and remediation"
        ],
        typical_attack_phase="collection",
        often_precedes=["T1567", "T1537", "T1048"],
        often_follows=["T1005", "T1074.001", "T1074.002", "T1039"]
    ),

    detection_strategies=[
        # Strategy 1: AWS - Large File Operations to Temporary Locations
        DetectionStrategy(
            strategy_id="t1074-aws-staging-files",
            name="Detect Data Staging in EC2 Instances",
            description=(
                "Monitor CloudWatch Logs and CloudTrail for file operations that consolidate "
                "data into temporary directories or staging locations on EC2 instances."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn as user, eventName, requestParameters.instanceId as instance,
       sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["RunInstances", "StartInstances", "CreateVolume", "AttachVolume"]
| stats count(*) as activity_count by user, instance, bin(1h) as hour_window
| filter activity_count >= 5
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect data staging activities in EC2 instances

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Data Staging Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for unusual file operations
  FileOperationMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = CreateVolume) || ($.eventName = AttachVolume) || ($.eventName = CopySnapshot) }'
      MetricTransformations:
        - MetricName: DataStagingActivity
          MetricNamespace: Security/T1074
          MetricValue: "1"

  # Step 3: CloudWatch alarm for staging activity
  StagingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1074-DataStagingDetected
      AlarmDescription: Potential data staging activity detected
      MetricName: DataStagingActivity
      Namespace: Security/T1074
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref AlertTopic

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
            Resource: !Ref AlertTopic''',
                terraform_template='''# Detect data staging activities in EC2 instances

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "staging_alerts" {
  name         = "data-staging-alerts"
  display_name = "Data Staging Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.staging_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for unusual file operations
resource "aws_cloudwatch_log_metric_filter" "staging_activity" {
  name           = "data-staging-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = CreateVolume) || ($.eventName = AttachVolume) || ($.eventName = CopySnapshot) }"

  metric_transformation {
    name      = "DataStagingActivity"
    namespace = "Security/T1074"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm for staging activity
resource "aws_cloudwatch_metric_alarm" "staging_alarm" {
  alarm_name          = "T1074-DataStagingDetected"
  alarm_description   = "Potential data staging activity detected"
  metric_name         = "DataStagingActivity"
  namespace           = "Security/T1074"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.staging_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.staging_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.staging_alerts.arn
    }]
  })
}''',
                alert_severity="high",
                alert_title="Potential Data Staging Activity Detected",
                alert_description_template=(
                    "Unusual volume operations detected in account. "
                    "Instance: {instance}. User: {user}. "
                    "This may indicate data consolidation prior to exfiltration."
                ),
                investigation_steps=[
                    "Review the EC2 instance(s) involved in the activity",
                    "Check CloudWatch Logs for file system operations",
                    "Examine recent EBS volume attachments and snapshots",
                    "Verify the user/role performing these operations",
                    "Review network connections from the instance",
                    "Check S3 access logs for potential exfiltration destinations"
                ],
                containment_actions=[
                    "Isolate the instance by modifying security groups",
                    "Create forensic snapshot before termination",
                    "Revoke IAM credentials for the user/role",
                    "Block outbound network connections",
                    "Review and rotate any credentials on the instance"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal volume operations; exclude backup and DR automation roles",
            detection_coverage="65% - covers volume-based staging",
            evasion_considerations="Gradual staging over extended periods; use of existing volumes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs configured"]
        ),

        # Strategy 2: AWS - S3 Staging Bucket Activity
        DetectionStrategy(
            strategy_id="t1074-aws-s3-staging",
            name="S3 Bucket Data Staging Detection",
            description=(
                "Detect unusual volumes of data being uploaded to S3 buckets, which may indicate "
                "staging of data before exfiltration to external accounts or services."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn as user, requestParameters.bucketName as bucket,
       eventName, bytesTransferredIn
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutObject", "UploadPart", "CompleteMultipartUpload"]
| stats count(*) as upload_count, sum(bytesTransferredIn) as total_bytes
  by user, bucket, bin(1h) as hour_window
| filter upload_count >= 50 or total_bytes >= 1073741824
| sort total_bytes desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 data staging activity

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: S3 Staging Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for bulk S3 uploads
  S3StagingMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = PutObject) || ($.eventName = UploadPart) || ($.eventName = CompleteMultipartUpload) }'
      MetricTransformations:
        - MetricName: S3StagingUploads
          MetricNamespace: Security/T1074
          MetricValue: "1"

  # Step 3: Alarm for unusual upload volume
  S3StagingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1074-S3DataStaging
      AlarmDescription: High volume S3 uploads may indicate data staging
      MetricName: S3StagingUploads
      Namespace: Security/T1074
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 50
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref AlertTopic

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
            Resource: !Ref AlertTopic''',
                terraform_template='''# Detect S3 data staging activity

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "s3_staging_alerts" {
  name         = "s3-staging-alerts"
  display_name = "S3 Staging Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.s3_staging_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for bulk S3 uploads
resource "aws_cloudwatch_log_metric_filter" "s3_staging" {
  name           = "s3-staging-uploads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = PutObject) || ($.eventName = UploadPart) || ($.eventName = CompleteMultipartUpload) }"

  metric_transformation {
    name      = "S3StagingUploads"
    namespace = "Security/T1074"
    value     = "1"
  }
}

# Step 3: Alarm for unusual upload volume
resource "aws_cloudwatch_metric_alarm" "s3_staging" {
  alarm_name          = "T1074-S3DataStaging"
  alarm_description   = "High volume S3 uploads may indicate data staging"
  metric_name         = "S3StagingUploads"
  namespace           = "Security/T1074"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 50
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.s3_staging_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.s3_staging_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.s3_staging_alerts.arn
    }]
  })
}''',
                alert_severity="medium",
                alert_title="High Volume S3 Upload Activity",
                alert_description_template=(
                    "User {user} uploaded {upload_count} objects ({total_bytes} bytes) to bucket {bucket} in 1 hour. "
                    "This may indicate data staging for exfiltration."
                ),
                investigation_steps=[
                    "Identify the bucket and objects being uploaded",
                    "Review S3 bucket policies for cross-account access",
                    "Check if the bucket has public access enabled",
                    "Verify the user's normal upload patterns",
                    "Review recent bucket lifecycle policies",
                    "Check for any bucket replication rules"
                ],
                containment_actions=[
                    "Enable S3 Block Public Access if not configured",
                    "Review and restrict bucket policies",
                    "Revoke user credentials if unauthorised",
                    "Enable S3 Object Lock on sensitive buckets",
                    "Delete staged data if confirmed malicious"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal upload patterns; exclude data pipeline and backup roles",
            detection_coverage="75% - covers S3-based staging",
            evasion_considerations="Gradual uploads over time; use of legitimate-looking bucket names",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["CloudTrail S3 data events enabled", "CloudWatch Logs configured"]
        ),

        # Strategy 3: GCP - Storage Bucket Staging Detection
        DetectionStrategy(
            strategy_id="t1074-gcp-storage-staging",
            name="GCP Cloud Storage Data Staging Detection",
            description=(
                "Monitor Google Cloud Storage for unusual volumes of data uploads that may "
                "indicate staging of data before exfiltration."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
OR protoPayload.methodName="storage.objects.compose"
OR protoPayload.methodName="storage.multipartUploads.create"''',
                gcp_terraform_template='''# GCP: Detect Cloud Storage data staging

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for storage uploads
resource "google_logging_metric" "storage_staging" {
  name   = "gcs-data-staging"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName=~"storage.objects.(create|compose)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for high upload volume
resource "google_monitoring_alert_policy" "staging_alert" {
  display_name = "GCS Data Staging Activity"
  combiner     = "OR"

  conditions {
    display_name = "High volume GCS uploads"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.storage_staging.name}\""
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
    notification_rate_limit {
      period = "3600s"
    }
  }
}''',
                alert_severity="medium",
                alert_title="GCP: High Volume Storage Upload Activity",
                alert_description_template=(
                    "High volume of uploads detected to Cloud Storage bucket. "
                    "This may indicate data staging prior to exfiltration."
                ),
                investigation_steps=[
                    "Identify which buckets received the uploads",
                    "Review the principal performing the uploads",
                    "Check bucket IAM policies for external access",
                    "Verify if bucket has public access configured",
                    "Review recent bucket lifecycle policies",
                    "Check for cross-project bucket access"
                ],
                containment_actions=[
                    "Remove public access from buckets",
                    "Review and restrict bucket IAM bindings",
                    "Enable VPC Service Controls",
                    "Revoke service account credentials if compromised",
                    "Delete staged data if confirmed malicious"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal upload patterns; exclude data pipeline service accounts",
            detection_coverage="75% - covers GCS-based staging",
            evasion_considerations="Gradual uploads over time; use of legitimate service accounts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["Cloud Audit Logs enabled for Cloud Storage"]
        ),

        # Strategy 4: GCP - Compute Instance Volume Activity
        DetectionStrategy(
            strategy_id="t1074-gcp-compute-staging",
            name="GCP Compute Instance Disk Staging Detection",
            description=(
                "Monitor Google Compute Engine for unusual disk operations that may indicate "
                "data consolidation on instances before exfiltration."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_disk" OR resource.type="gce_instance"
protoPayload.methodName=~"compute.disks.(create|attach|createSnapshot)"
OR protoPayload.methodName=~"compute.instances.(attachDisk|start)"''',
                gcp_terraform_template='''# GCP: Detect compute instance disk staging

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for disk operations
resource "google_logging_metric" "disk_staging" {
  name   = "gce-disk-staging"
  filter = <<-EOT
    resource.type=("gce_disk" OR "gce_instance")
    protoPayload.methodName=~"compute.disks.(create|attach|createSnapshot)"
    OR protoPayload.methodName=~"compute.instances.(attachDisk|start)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for unusual disk activity
resource "google_monitoring_alert_policy" "disk_staging_alert" {
  display_name = "GCE Disk Staging Activity"
  combiner     = "OR"

  conditions {
    display_name = "Unusual disk operations"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.disk_staging.name}\""
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
    notification_rate_limit {
      period = "3600s"
    }
  }
}''',
                alert_severity="high",
                alert_title="GCP: Unusual Compute Disk Activity",
                alert_description_template=(
                    "High volume of disk operations detected. "
                    "This may indicate data staging on compute instances."
                ),
                investigation_steps=[
                    "Identify the instances performing disk operations",
                    "Review recent disk attachments and snapshots",
                    "Check the principal creating/attaching disks",
                    "Examine instance network connections",
                    "Review Cloud Logging for file operations",
                    "Check for unusual snapshot sharing"
                ],
                containment_actions=[
                    "Isolate the instance using firewall rules",
                    "Create forensic disk snapshot",
                    "Revoke service account credentials",
                    "Review and restrict compute IAM permissions",
                    "Delete suspicious disks after investigation"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal disk operations; exclude infrastructure automation accounts",
            detection_coverage="70% - covers disk-based staging",
            evasion_considerations="Use of existing disks; gradual data movement",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"]
        )
    ],

    recommended_order=[
        "t1074-aws-s3-staging",
        "t1074-gcp-storage-staging",
        "t1074-aws-staging-files",
        "t1074-gcp-compute-staging"
    ],
    total_effort_hours=6.0,
    coverage_improvement="+28% improvement for Collection tactic"
)
