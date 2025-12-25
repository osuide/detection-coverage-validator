"""
T1025 - Data from Removable Media

Adversaries may search connected removable media on compromised systems to locate files of interest.
Sensitive data can be collected from optical drives, USB devices, and other removable storage before exfiltration.

CROSS-REFERENCE: For real-time USB/block device connection detection on EC2 instances,
see T1200 (Hardware Additions) which provides udev + systemd based real-time alerting
when removable storage devices are connected. This detection enables early warning
before data collection can occur.
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
    technique_id="T1025",
    technique_name="Data from Removable Media",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1025/",
    threat_context=ThreatContext(
        description=(
            "Adversaries search connected removable media on compromised systems to locate files of interest. "
            "Sensitive data can be collected from optical drives, USB devices, and other removable storage before exfiltration. "
            "In cloud environments, this manifests as mounting external volumes, attaching third-party storage, or accessing "
            "data from imported snapshots and disk images. Attackers may use interactive command shells or automated collection "
            "methods to enumerate and copy data from these sources."
        ),
        attacker_goal="Collect sensitive data from removable or externally-attached storage media",
        why_technique=[
            "Removable media often contains sensitive data not protected by network security controls",
            "Users may store backups, archives, or confidential data on external drives",
            "Cloud instances can mount external EBS volumes or attach storage from other accounts",
            "Imported disk images and snapshots may contain historical sensitive data",
            "Automated scripts can quickly enumerate and exfiltrate data from attached media",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="uncommon",
        trend="stable",
        severity_score=6,
        severity_reasoning=(
            "Whilst less common in cloud environments, data collection from removable or attached storage "
            "can expose sensitive information that bypasses standard network monitoring. This technique is "
            "particularly concerning in hybrid environments where on-premises systems can attach external volumes "
            "or in scenarios involving imported snapshots from untrusted sources. The severity is moderate due to "
            "limited applicability in pure cloud environments but increases significantly in hybrid deployments."
        ),
        business_impact=[
            "Exposure of sensitive data stored on external media",
            "Potential data breach from backup drives or archives",
            "Intellectual property theft from development/testing media",
            "Compromise of air-gapped or isolated network data",
            "Regulatory compliance violations if sensitive data is exfiltrated",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1567", "T1048", "T1041"],
        often_follows=["T1082", "T1083", "T1005"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EBS Volume Attachment Monitoring
        DetectionStrategy(
            strategy_id="t1025-aws-volume-attach",
            name="Monitor External EBS Volume Attachments",
            description=(
                "Detect when EBS volumes from external accounts or unusual sources are attached to EC2 instances, "
                "which may indicate attempts to access data from removable/external storage."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, requestParameters.volumeId as volume,
       requestParameters.instanceId as instance, responseElements.attachTime,
       sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "AttachVolume"
| stats count(*) as attach_count by user, instance, volume, bin(1h) as hour_window
| filter attach_count >= 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor EBS volume attachments for T1025 detection

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
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Volume Attachment Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for volume attachments
  VolumeAttachMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = AttachVolume) || ($.eventName = CreateVolume) }'
      MetricTransformations:
        - MetricName: ExternalVolumeAttachment
          MetricNamespace: Security/T1025
          MetricValue: "1"

  # Step 3: CloudWatch alarm for suspicious attachments
  VolumeAttachAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1025-ExternalVolumeAttachment
      AlarmDescription: Suspicious EBS volume attachment detected
      MetricName: ExternalVolumeAttachment
      Namespace: Security/T1025
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 5
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Monitor EBS volume attachments for T1025 detection

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "volume_alerts" {
  name         = "ebs-volume-attachment-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Volume Attachment Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.volume_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for volume attachments
resource "aws_cloudwatch_log_metric_filter" "volume_attach" {
  name           = "external-volume-attachments"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = AttachVolume) || ($.eventName = CreateVolume) }"

  metric_transformation {
    name      = "ExternalVolumeAttachment"
    namespace = "Security/T1025"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm for suspicious attachments
resource "aws_cloudwatch_metric_alarm" "volume_attach_alarm" {
  alarm_name          = "T1025-ExternalVolumeAttachment"
  alarm_description   = "Suspicious EBS volume attachment detected"
  metric_name         = "ExternalVolumeAttachment"
  namespace           = "Security/T1025"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.volume_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.volume_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.volume_alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Suspicious EBS Volume Attachment Activity",
                alert_description_template=(
                    "Multiple EBS volume attachments detected. "
                    "Instance: {instance}. Volume: {volume}. User: {user}. "
                    "This may indicate data collection from external storage."
                ),
                investigation_steps=[
                    "Identify the source of the EBS volume being attached",
                    "Verify if the volume originated from a trusted account",
                    "Review the instance's recent activity and network connections",
                    "Check CloudWatch Logs for file access patterns on the volume",
                    "Determine if the user has legitimate need to attach volumes",
                    "Examine the volume for sensitive data or unusual contents",
                ],
                containment_actions=[
                    "Detach suspicious volumes from instances",
                    "Create snapshot of volume for forensic analysis",
                    "Revoke IAM permissions for unauthorized volume operations",
                    "Isolate the instance using security group modifications",
                    "Review and restrict EBS volume attachment policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal volume operations; exclude infrastructure automation roles and backup systems",
            detection_coverage="70% - covers external volume access attempts",
            evasion_considerations="Slow attachment over time; use of volumes from trusted accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs configured"],
        ),
        # Strategy 2: AWS - Snapshot Import and Access
        DetectionStrategy(
            strategy_id="t1025-aws-snapshot-import",
            name="Detect Snapshot Import and Data Access",
            description=(
                "Monitor for imported snapshots from external accounts and subsequent data access, "
                "which may indicate collection of data from external or removable media equivalents."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventName,
       requestParameters.snapshotId as snapshot,
       requestParameters.description, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["ImportSnapshot", "CopySnapshot", "CreateVolume"]
| filter requestParameters.snapshotId like /snap-/
| stats count(*) as operation_count by user, snapshot, bin(1h) as hour_window
| filter operation_count >= 2
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect snapshot import and access for T1025

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
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Snapshot Import Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for snapshot operations
  SnapshotImportMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = ImportSnapshot) || ($.eventName = CopySnapshot) }'
      MetricTransformations:
        - MetricName: SnapshotImportActivity
          MetricNamespace: Security/T1025
          MetricValue: "1"

  # Step 3: Alarm for snapshot import activity
  SnapshotImportAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1025-SnapshotImport
      AlarmDescription: Snapshot import activity may indicate external data access
      MetricName: SnapshotImportActivity
      Namespace: Security/T1025
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 3
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect snapshot import and access for T1025

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "snapshot_alerts" {
  name         = "snapshot-import-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Snapshot Import Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.snapshot_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for snapshot operations
resource "aws_cloudwatch_log_metric_filter" "snapshot_import" {
  name           = "snapshot-import-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = ImportSnapshot) || ($.eventName = CopySnapshot) }"

  metric_transformation {
    name      = "SnapshotImportActivity"
    namespace = "Security/T1025"
    value     = "1"
  }
}

# Step 3: Alarm for snapshot import activity
resource "aws_cloudwatch_metric_alarm" "snapshot_import_alarm" {
  alarm_name          = "T1025-SnapshotImport"
  alarm_description   = "Snapshot import activity may indicate external data access"
  metric_name         = "SnapshotImportActivity"
  namespace           = "Security/T1025"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.snapshot_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.snapshot_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.snapshot_alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Snapshot Import Activity Detected",
                alert_description_template=(
                    "Snapshot import/copy operations detected. "
                    "Snapshot: {snapshot}. User: {user}. "
                    "This may indicate access to external data sources."
                ),
                investigation_steps=[
                    "Identify the source account of the imported snapshot",
                    "Review snapshot sharing permissions and history",
                    "Check if volumes were created from the snapshot",
                    "Examine instances that accessed volumes from imported snapshots",
                    "Verify the business justification for the snapshot import",
                    "Review data classification of the snapshot contents",
                ],
                containment_actions=[
                    "Remove snapshot sharing permissions",
                    "Delete imported snapshots if unauthorized",
                    "Revoke access for the user performing imports",
                    "Review and restrict snapshot import policies",
                    "Implement snapshot encryption requirements",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist disaster recovery and migration workflows; exclude known backup account IDs",
            detection_coverage="65% - covers snapshot-based data access",
            evasion_considerations="Use of snapshots from trusted accounts; gradual data extraction",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs configured"],
        ),
        # Strategy 3: AWS - Systems Manager Session Manager File Access
        DetectionStrategy(
            strategy_id="t1025-aws-ssm-file-access",
            name="Monitor SSM Session File System Enumeration",
            description=(
                "Detect when users connect to instances via Systems Manager Session Manager and perform "
                "file enumeration commands that may indicate searching for data on attached volumes."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, requestParameters.target as instance,
       eventName, responseElements.sessionId
| filter eventSource = "ssm.amazonaws.com"
| filter eventName in ["StartSession", "ResumeSession"]
| stats count(*) as session_count by user, instance, bin(1h) as hour_window
| filter session_count >= 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor SSM Session Manager for file enumeration

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
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      DisplayName: SSM Session Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for SSM sessions
  SSMSessionMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = StartSession) || ($.eventName = ResumeSession) }'
      MetricTransformations:
        - MetricName: SSMSessionActivity
          MetricNamespace: Security/T1025
          MetricValue: "1"

  # Step 3: Alarm for unusual session activity
  SSMSessionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1025-SSMSessionActivity
      AlarmDescription: High frequency SSM sessions may indicate data enumeration
      MetricName: SSMSessionActivity
      Namespace: Security/T1025
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 5
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Monitor SSM Session Manager for file enumeration

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "ssm_alerts" {
  name         = "ssm-session-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "SSM Session Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for SSM sessions
resource "aws_cloudwatch_log_metric_filter" "ssm_sessions" {
  name           = "ssm-session-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = StartSession) || ($.eventName = ResumeSession) }"

  metric_transformation {
    name      = "SSMSessionActivity"
    namespace = "Security/T1025"
    value     = "1"
  }
}

# Step 3: Alarm for unusual session activity
resource "aws_cloudwatch_metric_alarm" "ssm_session_alarm" {
  alarm_name          = "T1025-SSMSessionActivity"
  alarm_description   = "High frequency SSM sessions may indicate data enumeration"
  metric_name         = "SSMSessionActivity"
  namespace           = "Security/T1025"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.ssm_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.ssm_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssm_alerts.arn
    }]
  })
}""",
                alert_severity="low",
                alert_title="Unusual SSM Session Activity",
                alert_description_template=(
                    "High frequency of SSM sessions detected. "
                    "Instance: {instance}. User: {user}. Sessions: {session_count}. "
                    "This may indicate file system enumeration."
                ),
                investigation_steps=[
                    "Review SSM Session Manager logs for commands executed",
                    "Check if file enumeration commands (ls, find, du) were used",
                    "Identify which volumes or directories were accessed",
                    "Verify the user's authorization to access the instance",
                    "Examine any data transfers that occurred during sessions",
                    "Review the instance's attached volumes and their sources",
                ],
                containment_actions=[
                    "Terminate active SSM sessions if suspicious",
                    "Revoke SSM access for the user if unauthorized",
                    "Enable SSM session logging to S3 for detailed audit trail",
                    "Implement SSM session document restrictions",
                    "Review and update IAM policies for SSM access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Baseline normal administrative access patterns; exclude DevOps and support teams",
            detection_coverage="50% - provides visibility into interactive instance access",
            evasion_considerations="Use of legitimate administrative credentials; mimicking normal operations",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "SSM Session Manager enabled"],
        ),
        # Strategy 4: GCP - Persistent Disk Attachment Monitoring
        DetectionStrategy(
            strategy_id="t1025-gcp-disk-attach",
            name="GCP Persistent Disk Attachment Detection",
            description=(
                "Monitor Google Compute Engine for persistent disk attachments from external projects or sources, "
                "which may indicate attempts to access data from external storage."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.attachDisk"
OR protoPayload.methodName="beta.compute.instances.attachDisk"
OR protoPayload.methodName="v1.compute.disks.insert"''',
                gcp_terraform_template="""# GCP: Monitor persistent disk attachments

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

# Step 2: Log-based metric for disk attachments
resource "google_logging_metric" "disk_attach" {
  name   = "gce-disk-attachments"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~"compute.instances.attachDisk"
    OR protoPayload.methodName="v1.compute.disks.insert"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for disk attachments
resource "google_monitoring_alert_policy" "disk_attach_alert" {
  display_name = "GCE Disk Attachment Activity"
  combiner     = "OR"

  conditions {
    display_name = "Unusual disk attachment activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.disk_attach.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
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
}""",
                alert_severity="medium",
                alert_title="GCP: Persistent Disk Attachment Activity",
                alert_description_template=(
                    "Unusual persistent disk attachment activity detected. "
                    "This may indicate access to external storage media."
                ),
                investigation_steps=[
                    "Identify the source project of the attached disk",
                    "Review the principal performing the disk attachment",
                    "Check if the disk originated from a trusted source",
                    "Examine instance activity logs for file access patterns",
                    "Verify business justification for the disk attachment",
                    "Review disk sharing permissions across projects",
                ],
                containment_actions=[
                    "Detach suspicious disks from instances",
                    "Create disk snapshot for forensic analysis",
                    "Revoke service account permissions if compromised",
                    "Implement VPC Service Controls to restrict cross-project access",
                    "Review and update compute IAM policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal disk operations; exclude infrastructure automation service accounts",
            detection_coverage="70% - covers external disk access attempts",
            evasion_considerations="Use of disks from trusted projects; gradual data access patterns",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"],
        ),
        # Strategy 5: GCP - Disk Image Import Detection
        DetectionStrategy(
            strategy_id="t1025-gcp-image-import",
            name="GCP Disk Image Import Monitoring",
            description=(
                "Detect when disk images are imported from external sources or storage buckets, "
                "which may indicate collection of data from removable media equivalents."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_image"
protoPayload.methodName="v1.compute.images.insert"
OR protoPayload.methodName="beta.compute.images.import"
OR protoPayload.methodName="v1.compute.images.create"''',
                gcp_terraform_template="""# GCP: Monitor disk image imports

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

# Step 2: Log-based metric for image imports
resource "google_logging_metric" "image_import" {
  name   = "gce-image-imports"
  filter = <<-EOT
    resource.type="gce_image"
    protoPayload.methodName=~"compute.images.(insert|import|create)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for image imports
resource "google_monitoring_alert_policy" "image_import_alert" {
  display_name = "GCE Image Import Activity"
  combiner     = "OR"

  conditions {
    display_name = "Disk image import detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.image_import.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2
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
}""",
                alert_severity="medium",
                alert_title="GCP: Disk Image Import Activity",
                alert_description_template=(
                    "Disk image import activity detected. "
                    "This may indicate access to external data sources."
                ),
                investigation_steps=[
                    "Identify the source location of the imported image",
                    "Review the principal performing the image import",
                    "Check if the image source is from a trusted location",
                    "Examine if instances were created from the imported image",
                    "Verify the business justification for the import",
                    "Review image sharing permissions and access controls",
                ],
                containment_actions=[
                    "Delete imported images if unauthorized",
                    "Revoke service account credentials if compromised",
                    "Implement organisation policy constraints on image sources",
                    "Review and restrict image import permissions",
                    "Enable image encryption requirements",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist migration and disaster recovery workflows; document legitimate image sources",
            detection_coverage="60% - covers image-based data access",
            evasion_considerations="Use of images from trusted storage buckets; mimicking migration patterns",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"],
        ),
    ],
    recommended_order=[
        "t1025-aws-volume-attach",
        "t1025-gcp-disk-attach",
        "t1025-aws-snapshot-import",
        "t1025-gcp-image-import",
        "t1025-aws-ssm-file-access",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+22% improvement for Collection tactic",
)
