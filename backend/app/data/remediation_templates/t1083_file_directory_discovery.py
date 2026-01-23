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
            "Required for targeted data theft",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
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
            "Reveals system layout to adversaries",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1552.001", "T1530", "T1005", "T1039"],
        often_follows=["T1078.004", "T1078.001", "T1190"],
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
                query="""fields @timestamp, userIdentity.arn, requestParameters.instanceId, responseElements.command.commandId
| filter eventSource = "ssm.amazonaws.com"
| filter eventName = "SendCommand"
| filter requestParameters.documentName in ["AWS-RunShellScript", "AWS-RunPowerShellScript"]
| filter requestParameters.parameters.commands.0 like /(?i)(ls|dir|find|tree|locate|get-childitem)/
| stats count(*) as command_count by userIdentity.arn, bin(1h)
| filter command_count > 5
| sort command_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
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
      KmsMasterKeyId: alias/aws/sns
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
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect file discovery commands via SSM

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
  kms_master_key_id = "alias/aws/sns"
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
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.file_discovery_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "file_discovery_alerts" {
  arn = aws_sns_topic.file_discovery_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.file_discovery_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="File Discovery Commands Detected",
                alert_description_template="Multiple file enumeration commands executed via SSM by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify the user/role executing commands",
                    "Review the specific commands run via SSM",
                    "Check which instances were targeted",
                    "Determine if this is authorised administrative activity",
                    "Look for follow-on data access or exfiltration",
                    "Review CloudTrail for additional suspicious activity",
                ],
                containment_actions=[
                    "Review SSM Session Manager logs for full command history",
                    "Disable compromised credentials if unauthorised",
                    "Restrict SSM SendCommand permissions",
                    "Enable session logging to S3 for forensics",
                    "Consider requiring MFA for SSM access",
                    "Audit instance security groups and network access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised automation tools and DevOps scripts. Consider time-of-day baselines for administrative activity.",
            detection_coverage="70% - covers SSM-based enumeration, misses direct SSH/RDP access",
            evasion_considerations="Adversaries may use direct SSH/RDP instead of SSM, or execute commands slowly to avoid thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail logging to CloudWatch",
                "SSM enabled on EC2 instances",
            ],
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
                query="""fields @timestamp, @message, @logStream
| filter @message like /(?i)(ls -la|find \\/|tree \\/|dir \\/s|locate .*)/
| stats count(*) as enum_count by @logStream, bin(15m)
| filter enum_count > 3
| sort enum_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
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
      KmsMasterKeyId: alias/aws/sns
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
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect file enumeration in containers

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
  kms_master_key_id = "alias/aws/sns"
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
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.container_enum_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "container_enum_alerts" {
  arn = aws_sns_topic.container_enum_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.container_enum_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Container File Enumeration Detected",
                alert_description_template="File discovery commands detected in container logs for {logStream}.",
                investigation_steps=[
                    "Identify which container/task is performing enumeration",
                    "Review container image source and provenance",
                    "Check if enumeration matches expected application behaviour",
                    "Examine container IAM role permissions",
                    "Look for subsequent credential access or data exfiltration",
                    "Review container network connections",
                ],
                containment_actions=[
                    "Isolate suspicious containers from network",
                    "Review and restrict container IAM roles",
                    "Audit container image for malicious code",
                    "Enable AWS GuardDuty runtime monitoring",
                    "Consider using read-only root filesystems",
                    "Implement least-privilege container policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="High false positives from legitimate scripts. Filter by specific log patterns and known application behaviour. Consider excluding health check scripts.",
            detection_coverage="50% - depends on application logging verbosity",
            evasion_considerations="Attackers can avoid logging by redirecting output or using binary tools",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "ECS/Lambda logging to CloudWatch enabled",
                "Detailed application logging",
            ],
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
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName="google.cloud.osconfig.v1.OsConfigService.ExecutePatchJob"
OR
(resource.type="gce_instance" AND
 jsonPayload.message=~"(ls -la|find /|tree /|locate )")""",
                gcp_terraform_template="""# GCP: Detect file discovery on VM instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "File Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for file discovery
resource "google_logging_metric" "file_discovery" {
  project = var.project_id
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
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: File Discovery Commands Detected",
                alert_description_template="File enumeration commands detected on GCE instances.",
                investigation_steps=[
                    "Identify which GCE instances are affected",
                    "Review OS Login audit logs for user sessions",
                    "Check if commands match authorised maintenance",
                    "Examine instance service account permissions",
                    "Look for lateral movement or data exfiltration",
                    "Review VPC flow logs for suspicious network activity",
                ],
                containment_actions=[
                    "Isolate affected instances if unauthorised",
                    "Disable compromised service accounts",
                    "Enable VPC Service Controls",
                    "Review and restrict OS Login access",
                    "Implement BeyondCorp Enterprise for zero trust",
                    "Enable shielded VM with secure boot",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised automation and patch management. Consider time-based filtering for maintenance windows.",
            detection_coverage="60% - depends on OS logging configuration",
            evasion_considerations="Attackers may disable logging or use native binaries without logged output",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Logging enabled on GCE instances",
                "OS Config API enabled for patch management",
            ],
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
                gcp_logging_query="""resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.list"
protoPayload.status.code!=403
protoPayload.status.code!=404""",
                gcp_terraform_template="""# GCP: Detect GCS bucket enumeration

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "GCS Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for bucket enumeration
resource "google_logging_metric" "gcs_enumeration" {
  project = var.project_id
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
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: GCS Bucket Enumeration Detected",
                alert_description_template="High volume of GCS bucket listing operations detected.",
                investigation_steps=[
                    "Identify the principal performing enumeration",
                    "Review which buckets were accessed",
                    "Check if this matches expected application patterns",
                    "Examine service account or user permissions",
                    "Look for subsequent object downloads",
                    "Review for potential data exfiltration",
                ],
                containment_actions=[
                    "Review and restrict bucket IAM permissions",
                    "Enable VPC Service Controls on buckets",
                    "Implement bucket access logging",
                    "Consider private bucket access only",
                    "Enable uniform bucket-level access",
                    "Review service account keys and rotate if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup systems and CDN refresh processes. Adjust threshold based on normal application behaviour.",
            detection_coverage="75% - catches most bucket enumeration",
            evasion_considerations="Slow enumeration across many buckets may evade volume thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs with data access enabled for GCS"],
        ),
        # Azure Strategy: File and Directory Discovery
        DetectionStrategy(
            strategy_id="t1083-azure",
            name="Azure File and Directory Discovery Detection",
            description=(
                "Azure detection for File and Directory Discovery. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// File and Directory Discovery Detection
// Technique: T1083
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc""",
                azure_terraform_template="""# Azure Detection for File and Directory Discovery
# MITRE ATT&CK: T1083

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

variable "resource_group_name" {
  type        = string
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "file-and-directory-discovery-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "file-and-directory-discovery-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// File and Directory Discovery Detection
// Technique: T1083
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects File and Directory Discovery (T1083) activity in Azure environment"
  display_name = "File and Directory Discovery Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1083"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: File and Directory Discovery Detected",
                alert_description_template=(
                    "File and Directory Discovery activity detected. "
                    "Caller: {Caller}. Resource: {Resource}."
                ),
                investigation_steps=[
                    "Review Azure Activity Log for full operation details",
                    "Check caller identity and verify if authorised",
                    "Review affected resources and assess impact",
                    "Check for related activities in the same time window",
                    "Verify against change management records",
                ],
                containment_actions=[
                    "Disable compromised user/service principal if unauthorised",
                    "Revoke active sessions using Entra ID",
                    "Review and restrict Azure RBAC permissions",
                    "Enable additional Defender for Cloud protections",
                    "Implement Azure Policy to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Allowlist known automation accounts and CI/CD service principals. "
                "Use Azure Policy to define expected behaviour baselines."
            ),
            detection_coverage="70% - Azure-native detection for cloud operations",
            evasion_considerations=(
                "Attackers may use legitimate credentials from expected locations. "
                "Combine with Defender for Cloud for ML-based anomaly detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-50 (Log Analytics + Defender)",
            prerequisites=[
                "Azure subscription with Log Analytics workspace",
                "Defender for Cloud enabled (recommended)",
                "Appropriate Azure RBAC permissions for deployment",
            ],
        ),
    ],
    recommended_order=[
        "t1083-aws-ssmcommands",
        "t1083-gcp-gcsenum",
        "t1083-gcp-vmcommands",
        "t1083-aws-containerfile",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+12% improvement for Discovery tactic",
)
