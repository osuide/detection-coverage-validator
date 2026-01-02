"""
T1578.004 - Revert Cloud Instance

Adversaries revert changes to cloud instances to conceal malicious activities
and eliminate forensic artifacts by restoring VM or storage snapshots.
Part of the Defense Evasion tactic.
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
    technique_id="T1578.004",
    technique_name="Revert Cloud Instance",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1578/004/",
    threat_context=ThreatContext(
        description=(
            "Adversaries revert changes to cloud instances to conceal malicious activities "
            "and eliminate forensic artifacts. This is accomplished by restoring VM or storage "
            "snapshots via cloud management dashboards or APIs. An alternative method involves "
            "leveraging ephemeral storage attached to compute instances, which resets automatically "
            "when VMs stop or restart."
        ),
        attacker_goal="Destroy forensic evidence and conceal malicious activities by reverting cloud instances to previous states",
        why_technique=[
            "Eliminates forensic artifacts and logs",
            "Removes malware or backdoors after use",
            "Conceals unauthorised modifications",
            "Resets instances to clean state",
            "Exploits legitimate cloud features",
            "Difficult to prevent without impacting operations",
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="uncommon",
        trend="emerging",
        severity_score=7,
        severity_reasoning=(
            "High impact on forensic investigations and incident response. Successful "
            "execution can destroy critical evidence of compromise, making attribution "
            "and remediation significantly more difficult."
        ),
        business_impact=[
            "Loss of forensic evidence",
            "Impaired incident response",
            "Difficulty determining breach scope",
            "Compliance and audit challenges",
            "Potential for repeated exploitation",
        ],
        typical_attack_phase="defense_evasion",
        often_precedes=[],
        often_follows=["T1098", "T1556", "T1552"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1578-004-aws-snapshot-restore",
            name="AWS EC2 Snapshot Restoration Detection",
            description="Detect suspicious EC2 instance restores from snapshots via CloudTrail.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.instanceId, requestParameters.snapshotId, sourceIPAddress
| filter eventName = "CreateImage" or eventName = "CreateSnapshot" or eventName = "RestoreFromSnapshot" or eventName = "CreateVolume"
| filter requestParameters.snapshotId like /snap-/
| stats count(*) as restores by userIdentity.principalId, sourceIPAddress, bin(5m)
| filter restores > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious snapshot restoration activities

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: snapshot-restore-alerts
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

  # Step 2: Create metric filter for snapshot operations
  SnapshotRestoreFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "CreateVolume") && ($.requestParameters.snapshotId = "snap-*") }'
      MetricTransformations:
        - MetricName: SnapshotRestores
          MetricNamespace: Security/CloudDefense
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for suspicious activity
  SnapshotRestoreAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousSnapshotRestore
      AlarmDescription: Alert on snapshot restoration activity
      MetricName: SnapshotRestores
      Namespace: Security/CloudDefense
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# AWS: Detect suspicious snapshot restoration activities

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "snapshot-restore-alerts"
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

# Step 2: Create metric filter for snapshot operations
resource "aws_cloudwatch_log_metric_filter" "snapshot_restores" {
  name           = "snapshot-restores"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"CreateVolume\") && ($.requestParameters.snapshotId = \"snap-*\") }"

  metric_transformation {
    name          = "SnapshotRestores"
    namespace     = "Security/CloudDefense"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious activity
resource "aws_cloudwatch_metric_alarm" "snapshot_restore" {
  alarm_name          = "SuspiciousSnapshotRestore"
  alarm_description   = "Alert on snapshot restoration activity"
  metric_name         = "SnapshotRestores"
  namespace           = "Security/CloudDefense"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious Snapshot Restoration Detected",
                alert_description_template="Snapshot restoration activity detected from {principalId} at {sourceIPAddress}.",
                investigation_steps=[
                    "Verify the identity and authorisation of the principal",
                    "Check if snapshot restore was scheduled or expected",
                    "Review timeline: snapshot creation and restoration times",
                    "Examine source IP and geolocation",
                    "Investigate what was on the instance before restore",
                    "Check for related suspicious CloudTrail events",
                    "Review instance access logs before restoration",
                ],
                containment_actions=[
                    "Isolate affected instances immediately",
                    "Create forensic snapshot before further changes",
                    "Revoke credentials used for restoration",
                    "Enable snapshot deletion protection",
                    "Review and restrict snapshot permissions",
                    "Implement stricter IAM policies for snapshot operations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Expected during disaster recovery, legitimate rollbacks, and scheduled maintenance. Create exceptions for authorised automation roles and maintenance windows.",
            detection_coverage="80% - covers snapshot-based restoration",
            evasion_considerations="Attackers using legitimate administrator credentials or during maintenance windows may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "CloudTrail logs sent to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1578-004-aws-rapid-snapshot",
            name="AWS Rapid Snapshot Creation and Restoration",
            description="Detect rapid snapshot creation followed by immediate restoration patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.instanceId, sourceIPAddress
| filter eventName = "CreateSnapshot" or eventName = "CreateImage" or eventName = "CreateVolume"
| sort @timestamp asc
| stats count(*) as operations by userIdentity.principalId, bin(10m)
| filter operations > 2""",
                terraform_template="""# AWS: Detect rapid snapshot creation and restoration sequences

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "rapid-snapshot-alerts"
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

# Step 2: Create metric filter for rapid snapshot operations
resource "aws_cloudwatch_log_metric_filter" "rapid_snapshots" {
  name           = "rapid-snapshot-operations"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"CreateSnapshot\") || ($.eventName = \"CreateImage\") || ($.eventName = \"CreateVolume\") }"

  metric_transformation {
    name          = "RapidSnapshotOps"
    namespace     = "Security/CloudDefense"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for unusual snapshot activity patterns
resource "aws_cloudwatch_metric_alarm" "rapid_snapshot" {
  alarm_name          = "RapidSnapshotActivity"
  alarm_description   = "Alert on rapid snapshot creation/restoration sequences"
  metric_name         = "RapidSnapshotOps"
  namespace           = "Security/CloudDefense"
  statistic           = "Sum"
  period              = 600
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Rapid Snapshot Operations Detected",
                alert_description_template="Multiple snapshot operations in short timeframe by {principalId}.",
                investigation_steps=[
                    "Identify the account performing operations",
                    "Check if activity matches maintenance schedules",
                    "Review sequence: create snapshot → restore pattern",
                    "Examine time gaps between operations",
                    "Check for other suspicious activity by same principal",
                    "Verify business justification for operations",
                ],
                containment_actions=[
                    "Contact account owner to verify legitimacy",
                    "Temporarily restrict snapshot permissions if suspicious",
                    "Preserve forensic snapshots",
                    "Review IAM policies for excessive permissions",
                    "Enable MFA for sensitive snapshot operations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Common during automated backup processes and disaster recovery testing. Whitelist known automation roles and scheduled backup windows.",
            detection_coverage="60% - pattern-based detection",
            evasion_considerations="Attackers can space out operations or use multiple accounts to avoid detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudTrail logs sent to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1578-004-aws-unusual-source",
            name="AWS Snapshot Operations from Unusual Locations",
            description="Detect snapshot operations from new or unusual geographic locations or IP addresses.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, sourceIPAddress, awsRegion
| filter eventName = "CreateSnapshot" or eventName = "CreateImage" or eventName = "RestoreFromSnapshot" or eventName = "CreateVolume"
| filter sourceIPAddress not like /^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)/
| stats count(*) as operations by sourceIPAddress, awsRegion, userIdentity.principalId
| sort operations desc""",
                terraform_template="""# AWS: Detect snapshot operations from unusual locations

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "unusual-snapshot-location-alerts"
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

# Step 2: Create metric filter for external snapshot operations
resource "aws_cloudwatch_log_metric_filter" "external_snapshot_ops" {
  name           = "external-snapshot-operations"
  log_group_name = var.cloudtrail_log_group
  # Filter for snapshot operations from non-internal IPs
  pattern        = "{ (($.eventName = \"CreateSnapshot\") || ($.eventName = \"CreateImage\") || ($.eventName = \"CreateVolume\")) && ($.sourceIPAddress != \"10.*\") && ($.sourceIPAddress != \"172.16.*\") && ($.sourceIPAddress != \"192.168.*\") }"

  metric_transformation {
    name          = "ExternalSnapshotOps"
    namespace     = "Security/CloudDefense"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for operations from unusual sources
resource "aws_cloudwatch_metric_alarm" "external_snapshot" {
  alarm_name          = "UnusualSnapshotLocation"
  alarm_description   = "Alert on snapshot operations from external/unusual IPs"
  metric_name         = "ExternalSnapshotOps"
  namespace           = "Security/CloudDefense"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Snapshot Operation from Unusual Location",
                alert_description_template="Snapshot operation from unusual IP {sourceIPAddress} by {principalId}.",
                investigation_steps=[
                    "Geolocate source IP address",
                    "Check if IP matches known corporate ranges",
                    "Verify if user typically works from this location",
                    "Review recent authentication events for account",
                    "Check for concurrent logins from multiple locations",
                    "Examine other API calls from same source IP",
                ],
                containment_actions=[
                    "Verify account ownership immediately",
                    "Force password reset if suspicious",
                    "Block source IP if confirmed malicious",
                    "Revoke active sessions for the account",
                    "Review and rotate access keys",
                    "Implement IP allowlisting for sensitive operations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Expected for remote workers, VPN changes, and cloud-based CI/CD systems. Maintain allowlist of known legitimate external IP ranges.",
            detection_coverage="70% - location-based detection",
            evasion_considerations="Attackers using compromised internal systems or VPNs may appear legitimate",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudTrail logs sent to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1578-004-gcp-snapshot-restore",
            name="GCP Compute Engine Snapshot Operations",
            description="Detect suspicious snapshot restoration activities in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_snapshot" OR resource.type="gce_disk"
(protoPayload.methodName="v1.compute.snapshots.insert" OR
 protoPayload.methodName="v1.compute.disks.createSnapshot" OR
 protoPayload.methodName="beta.compute.disks.createSnapshot" OR
 protoPayload.methodName="v1.compute.disks.insert")
protoPayload.request.sourceDisk:*""",
                gcp_terraform_template="""# GCP: Detect snapshot restoration activities

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Snapshot Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for snapshot operations
resource "google_logging_metric" "snapshot_operations" {
  project = var.project_id
  name    = "snapshot-restore-operations"
  filter  = <<-EOT
    resource.type="gce_snapshot" OR resource.type="gce_disk"
    (protoPayload.methodName="v1.compute.snapshots.insert" OR
     protoPayload.methodName="v1.compute.disks.createSnapshot" OR
     protoPayload.methodName="v1.compute.disks.insert")
    protoPayload.request.sourceDisk:*
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "User performing operation"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for snapshot activity
resource "google_monitoring_alert_policy" "snapshot_restore" {
  project      = var.project_id
  display_name = "Suspicious Snapshot Restoration"
  combiner     = "OR"

  conditions {
    display_name = "Snapshot restoration detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.snapshot_operations.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
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
                alert_severity="high",
                alert_title="GCP: Snapshot Restoration Detected",
                alert_description_template="Snapshot operation detected in GCP project.",
                investigation_steps=[
                    "Identify the principal performing the operation",
                    "Verify authorisation and business justification",
                    "Review snapshot source and creation time",
                    "Check for related suspicious activities",
                    "Examine audit logs for the affected instance",
                    "Verify if operation aligns with change management",
                ],
                containment_actions=[
                    "Suspend suspicious service accounts",
                    "Create forensic snapshot before changes",
                    "Restrict snapshot permissions",
                    "Enable organisation policy constraints",
                    "Review IAM bindings for compute resources",
                    "Implement VPC Service Controls for additional protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Common during disaster recovery and scheduled maintenance. Create exceptions for authorised automation service accounts.",
            detection_coverage="80% - comprehensive snapshot operation coverage",
            evasion_considerations="Attackers with project owner permissions may disable logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled", "Cloud Monitoring API enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1578-004-gcp-rapid-snapshot",
            name="GCP Rapid Snapshot Activity Pattern",
            description="Detect rapid sequences of snapshot creation and restoration in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_snapshot" OR resource.type="gce_disk"
protoPayload.methodName:("compute.snapshots.insert" OR "compute.disks.createSnapshot" OR "compute.disks.insert")
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect rapid snapshot operation patterns

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Rapid Snapshot Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for rapid snapshot operations
resource "google_logging_metric" "rapid_snapshots" {
  project = var.project_id
  name    = "rapid-snapshot-operations"
  filter  = <<-EOT
    resource.type="gce_snapshot" OR resource.type="gce_disk"
    protoPayload.methodName:("compute.snapshots.insert" OR "compute.disks.createSnapshot" OR "compute.disks.insert")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert for rapid activity
resource "google_monitoring_alert_policy" "rapid_snapshot" {
  project      = var.project_id
  display_name = "Rapid Snapshot Operations"
  combiner     = "OR"

  conditions {
    display_name = "Multiple snapshot operations in short period"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.rapid_snapshots.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "3600s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Rapid Snapshot Operations",
                alert_description_template="Multiple snapshot operations detected in short timeframe.",
                investigation_steps=[
                    "Review sequence of operations",
                    "Identify accounts involved",
                    "Check against scheduled maintenance",
                    "Verify automation patterns",
                    "Review time gaps between operations",
                    "Check for other anomalous behaviour",
                ],
                containment_actions=[
                    "Verify legitimacy with account owners",
                    "Restrict permissions if suspicious",
                    "Review service account keys",
                    "Implement organisation policies",
                    "Enable additional audit logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Expected during automated backup cycles and DR testing. Whitelist known automation patterns and service accounts.",
            detection_coverage="60% - pattern-based detection",
            evasion_considerations="Attackers can space operations or use multiple projects to evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled", "Cloud Monitoring API enabled"],
        ),
    ],
    recommended_order=[
        "t1578-004-aws-snapshot-restore",
        "t1578-004-gcp-snapshot-restore",
        "t1578-004-aws-rapid-snapshot",
        "t1578-004-aws-unusual-source",
        "t1578-004-gcp-rapid-snapshot",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+15% improvement for Defense Evasion tactic",
)
