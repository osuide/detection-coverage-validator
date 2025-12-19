"""
T1083 - File and Directory Discovery

Adversaries enumerate files and directories to identify information within a file system.
This reconnaissance informs targeting decisions and subsequent actions such as data theft.

MITRE ATT&CK Reference: https://attack.mitre.org/techniques/T1083/
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
    technique_id="T1083",
    technique_name="File and Directory Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1083/",

    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate files and directories or search specific locations "
            "within a file system. This reconnaissance activity helps attackers understand "
            "the environment, locate valuable data, and plan subsequent actions such as "
            "credential theft or data exfiltration."
        ),
        attacker_goal="Enumerate files and directories to locate valuable data and understand system layout",
        why_technique=[
            "Identifies sensitive data locations",
            "Reveals system structure and organisation",
            "Locates configuration files with credentials",
            "Discovers backup files and archives",
            "Maps out exfiltration targets",
            "Required for targeted data theft"
        ],
        known_threat_actors=[
            "APT28",
            "APT32",
            "APT38",
            "APT39",
            "APT41",
            "Lazarus Group",
            "Kimsuky",
            "Dragonfly",
            "MuddyWater",
            "Scattered Spider"
        ],
        recent_campaigns=[
            Campaign(
                name="Cloud Instance File Enumeration",
                year=2024,
                description="Attackers enumerate EC2/GCE instances for sensitive files after initial access",
                reference_url="https://www.datadoghq.com/state-of-cloud-security/"
            ),
            Campaign(
                name="Container File Discovery",
                year=2024,
                description="Adversaries search container filesystems for secrets and credentials",
                reference_url="https://unit42.paloaltonetworks.com/2025-cloud-security-alert-trends/"
            )
        ],
        prevalence="common",
        trend="stable",
        severity_score=5,
        severity_reasoning=(
            "File discovery is a standard reconnaissance technique that precedes more "
            "damaging actions. Whilst low-impact itself, it indicates active threat "
            "actor presence and often leads to credential theft or data exfiltration. "
            "Important early warning signal."
        ),
        business_impact=[
            "Indicates active reconnaissance in environment",
            "Precursor to data exfiltration",
            "Often precedes credential theft",
            "Early warning opportunity for incident response",
            "Reveals system layout to adversaries"
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1552.001", "T1530", "T1005", "T1039"],
        often_follows=["T1078.004", "T1078.001", "T1190"]
    ),

    detection_strategies=[
        # Strategy 1: AWS - EC2 SSM Command Execution Monitoring
        DetectionStrategy(
            strategy_id="t1083-aws-ssmcommands",
            name="EC2 File Enumeration via SSM",
            description="Detect file discovery commands executed via AWS Systems Manager.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn, requestParameters.instanceId, responseElements.command.commandId
| filter eventSource = "ssm.amazonaws.com"
| filter eventName = "SendCommand"
| filter requestParameters.documentName in ["AWS-RunShellScript", "AWS-RunPowerShellScript"]
| filter requestParameters.parameters.commands.0 like /(?i)(ls|dir|find|tree|locate|get-childitem)/
| stats count(*) as command_count by userIdentity.arn, bin(1h)
| filter command_count > 5
| sort command_count desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect file discovery commands via SSM

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: File Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for file discovery commands
  FileDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ssm.amazonaws.com" && $.eventName = "SendCommand" && ($.requestParameters.documentName = "AWS-RunShellScript" || $.requestParameters.documentName = "AWS-RunPowerShellScript") }'
      MetricTransformations:
        - MetricName: FileDiscoveryCommands
          MetricNamespace: Security/Discovery
          MetricValue: "1"

  # Step 3: CloudWatch alarm
  FileDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: FileDiscoveryDetected
      AlarmDescription: Detects file enumeration commands via SSM
      MetricName: FileDiscoveryCommands
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 3600
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic''',
                terraform_template='''# Detect file discovery commands via SSM

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "file_discovery_alerts" {
  name         = "file-discovery-alerts"
  display_name = "File Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.file_discovery_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for file discovery commands
resource "aws_cloudwatch_log_metric_filter" "file_discovery" {
  name           = "file-discovery-commands"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ssm.amazonaws.com\" && $.eventName = \"SendCommand\" && ($.requestParameters.documentName = \"AWS-RunShellScript\" || $.requestParameters.documentName = \"AWS-RunPowerShellScript\") }"

  metric_transformation {
    name      = "FileDiscoveryCommands"
    namespace = "Security/Discovery"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "file_discovery" {
  alarm_name          = "FileDiscoveryDetected"
  alarm_description   = "Detects file enumeration commands via SSM"
  metric_name         = "FileDiscoveryCommands"
  namespace           = "Security/Discovery"
  statistic           = "Sum"
  period              = 3600
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.file_discovery_alerts.arn]
}''',
                alert_severity="medium",
                alert_title="File Discovery Commands Detected",
                alert_description_template="Multiple file enumeration commands executed via SSM by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify the user/role executing commands",
                    "Review the specific commands run via SSM",
                    "Check which instances were targeted",
                    "Determine if this is authorised administrative activity",
                    "Look for follow-on data access or exfiltration",
                    "Review CloudTrail for additional suspicious activity"
                ],
                containment_actions=[
                    "Review SSM Session Manager logs for full command history",
                    "Disable compromised credentials if unauthorised",
                    "Restrict SSM SendCommand permissions",
                    "Enable session logging to S3 for forensics",
                    "Consider requiring MFA for SSM access",
                    "Audit instance security groups and network access"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised automation tools and DevOps scripts. Consider time-of-day baselines for administrative activity.",
            detection_coverage="70% - covers SSM-based enumeration, misses direct SSH/RDP access",
            evasion_considerations="Adversaries may use direct SSH/RDP instead of SSM, or execute commands slowly to avoid thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch", "SSM enabled on EC2 instances"]
        ),

        # Strategy 2: AWS - CloudWatch Logs for ECS/Lambda File Access
        DetectionStrategy(
            strategy_id="t1083-aws-containerfile",
            name="Container File System Enumeration",
            description="Detect file enumeration in ECS tasks and Lambda functions via CloudWatch Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, @message, @logStream
| filter @message like /(?i)(ls -la|find \/|tree \/|dir \/s|locate .*)/
| stats count(*) as enum_count by @logStream, bin(15m)
| filter enum_count > 3
| sort enum_count desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect file enumeration in containers

Parameters:
  ECSLogGroup:
    Type: String
    Description: ECS/Lambda log group name
  AlertEmail:
    Type: String
    Description: Email address for alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Container File Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for file enumeration patterns
  ContainerEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ECSLogGroup
      FilterPattern: '[timestamp, request_id, level, msg="*ls -la*" || msg="*find /*" || msg="*tree*"]'
      MetricTransformations:
        - MetricName: ContainerFileEnumeration
          MetricNamespace: Security/Discovery
          MetricValue: "1"

  # Step 3: CloudWatch alarm
  ContainerEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ContainerFileEnumeration
      AlarmDescription: Detects file enumeration in container logs
      MetricName: ContainerFileEnumeration
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 900
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic''',
                terraform_template='''# Detect file enumeration in containers

variable "ecs_log_group" {
  type        = string
  description = "ECS/Lambda log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "container_enum_alerts" {
  name         = "container-file-enumeration-alerts"
  display_name = "Container File Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.container_enum_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for file enumeration patterns
resource "aws_cloudwatch_log_metric_filter" "container_enum" {
  name           = "container-file-enumeration"
  log_group_name = var.ecs_log_group
  pattern        = "[timestamp, request_id, level, msg=\"*ls -la*\" || msg=\"*find /*\" || msg=\"*tree*\"]"

  metric_transformation {
    name      = "ContainerFileEnumeration"
    namespace = "Security/Discovery"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "container_enum" {
  alarm_name          = "ContainerFileEnumeration"
  alarm_description   = "Detects file enumeration in container logs"
  metric_name         = "ContainerFileEnumeration"
  namespace           = "Security/Discovery"
  statistic           = "Sum"
  period              = 900
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.container_enum_alerts.arn]
}''',
                alert_severity="medium",
                alert_title="Container File Enumeration Detected",
                alert_description_template="File discovery commands detected in container logs for {logStream}.",
                investigation_steps=[
                    "Identify which container/task is performing enumeration",
                    "Review container image source and provenance",
                    "Check if enumeration matches expected application behaviour",
                    "Examine container IAM role permissions",
                    "Look for subsequent credential access or data exfiltration",
                    "Review container network connections"
                ],
                containment_actions=[
                    "Isolate suspicious containers from network",
                    "Review and restrict container IAM roles",
                    "Audit container image for malicious code",
                    "Enable AWS GuardDuty runtime monitoring",
                    "Consider using read-only root filesystems",
                    "Implement least-privilege container policies"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="High false positives from legitimate scripts. Filter by specific log patterns and known application behaviour. Consider excluding health check scripts.",
            detection_coverage="50% - depends on application logging verbosity",
            evasion_considerations="Attackers can avoid logging by redirecting output or using binary tools",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["ECS/Lambda logging to CloudWatch enabled", "Detailed application logging"]
        ),

        # Strategy 3: GCP - VM Instance Command Monitoring
        DetectionStrategy(
            strategy_id="t1083-gcp-vmcommands",
            name="GCP VM File Discovery Detection",
            description="Detect file enumeration commands on GCE instances via OS Config and Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="google.cloud.osconfig.v1.OsConfigService.ExecutePatchJob"
OR
(resource.type="gce_instance" AND
 jsonPayload.message=~"(ls -la|find /|tree /|locate )")''',
                gcp_terraform_template='''# GCP: Detect file discovery on VM instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "File Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for file discovery
resource "google_logging_metric" "file_discovery" {
  name   = "file-discovery-commands"
  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName="google.cloud.osconfig.v1.OsConfigService.ExecutePatchJob"
    OR jsonPayload.message=~"(ls -la|find /|tree /|locate )")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "file_discovery" {
  display_name = "File Discovery Detected on GCE"
  combiner     = "OR"

  conditions {
    display_name = "High volume file enumeration"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.file_discovery.name}\""
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

  alert_strategy {
    auto_close = "1800s"
  }
}''',
                alert_severity="medium",
                alert_title="GCP: File Discovery Commands Detected",
                alert_description_template="File enumeration commands detected on GCE instances.",
                investigation_steps=[
                    "Identify which GCE instances are affected",
                    "Review OS Login audit logs for user sessions",
                    "Check if commands match authorised maintenance",
                    "Examine instance service account permissions",
                    "Look for lateral movement or data exfiltration",
                    "Review VPC flow logs for suspicious network activity"
                ],
                containment_actions=[
                    "Isolate affected instances if unauthorised",
                    "Disable compromised service accounts",
                    "Enable VPC Service Controls",
                    "Review and restrict OS Login access",
                    "Implement BeyondCorp Enterprise for zero trust",
                    "Enable shielded VM with secure boot"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised automation and patch management. Consider time-based filtering for maintenance windows.",
            detection_coverage="60% - depends on OS logging configuration",
            evasion_considerations="Attackers may disable logging or use native binaries without logged output",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Logging enabled on GCE instances", "OS Config API enabled for patch management"]
        ),

        # Strategy 4: GCP - GCS Bucket Enumeration
        DetectionStrategy(
            strategy_id="t1083-gcp-gcsenum",
            name="GCS Bucket Object Discovery",
            description="Detect enumeration of GCS bucket contents beyond normal access patterns.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.list"
protoPayload.status.code!=403
protoPayload.status.code!=404''',
                gcp_terraform_template='''# GCP: Detect GCS bucket enumeration

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "GCS Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for bucket enumeration
resource "google_logging_metric" "gcs_enumeration" {
  name   = "gcs-bucket-enumeration"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.list"
    protoPayload.status.code!=403
    protoPayload.status.code!=404
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "gcs_enumeration" {
  display_name = "GCS Bucket Enumeration Detected"
  combiner     = "OR"

  conditions {
    display_name = "Unusual bucket listing activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_enumeration.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}''',
                alert_severity="medium",
                alert_title="GCP: GCS Bucket Enumeration Detected",
                alert_description_template="High volume of GCS bucket listing operations detected.",
                investigation_steps=[
                    "Identify the principal performing enumeration",
                    "Review which buckets were accessed",
                    "Check if this matches expected application patterns",
                    "Examine service account or user permissions",
                    "Look for subsequent object downloads",
                    "Review for potential data exfiltration"
                ],
                containment_actions=[
                    "Review and restrict bucket IAM permissions",
                    "Enable VPC Service Controls on buckets",
                    "Implement bucket access logging",
                    "Consider private bucket access only",
                    "Enable uniform bucket-level access",
                    "Review service account keys and rotate if needed"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup systems and CDN refresh processes. Adjust threshold based on normal application behaviour.",
            detection_coverage="75% - catches most bucket enumeration",
            evasion_considerations="Slow enumeration across many buckets may evade volume thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs with data access enabled for GCS"]
        )
    ],

    recommended_order=[
        "t1083-aws-ssmcommands",
        "t1083-gcp-gcsenum",
        "t1083-gcp-vmcommands",
        "t1083-aws-containerfile"
    ],
    total_effort_hours=5.5,
    coverage_improvement="+12% improvement for Discovery tactic"
)
