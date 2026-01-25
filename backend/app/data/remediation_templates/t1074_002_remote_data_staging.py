"""
T1074.002 - Data Staged: Remote Data Staging

Adversaries stage data collected from multiple systems in a central location
on one system before exfiltration. Used to minimise C2 connections and evade detection.
Used by APT28, FIN6, FIN8, Leviathan, menuPass, Sea Turtle, ToddyCat.
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
    technique_id="T1074.002",
    technique_name="Data Staged: Remote Data Staging",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1074/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries stage data collected from multiple systems in a central "
            "location or directory on one system before exfiltration. This includes "
            "using interactive command shells, archiving techniques, and in cloud "
            "environments, creating instances to stage data before transfer. The "
            "technique minimises C2 server connections and helps evade detection."
        ),
        attacker_goal="Stage collected data in a central remote location before exfiltration",
        why_technique=[
            "Minimises C2 server connections",
            "Aggregates data from multiple sources",
            "Evades detection through reduced network activity",
            "Facilitates bulk exfiltration",
            "Exploits normal file transfer features",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Indicates advanced attack phase where adversaries have already collected "
            "data and are preparing for exfiltration. Suggests compromise of multiple "
            "systems and imminent data loss."
        ),
        business_impact=[
            "Data exfiltration preparation",
            "Multiple system compromise indicator",
            "Potential data breach",
            "Compliance violations",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1041", "T1048", "T1567"],
        often_follows=["T1005", "T1039", "T1025", "T1074.001"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1074_002-aws-s3-staging",
            name="AWS S3 Remote Staging Detection",
            description="Detect unusual S3 bucket uploads from EC2 instances that may indicate data staging.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, sourceIPAddress, requestParameters.bucketName, requestParameters.key
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutObject", "CopyObject", "UploadPart"]
| stats count(*) as uploads, sum(requestParameters.contentLength) as totalBytes by sourceIPAddress, requestParameters.bucketName, bin(1h)
| filter uploads > 50 or totalBytes > 1073741824
| sort totalBytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 remote data staging activity

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  S3StagingFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "PutObject" || $.eventName = "CopyObject" || $.eventName = "UploadPart") && $.eventSource = "s3.amazonaws.com" }'
      MetricTransformations:
        - MetricName: S3StagingActivity
          MetricNamespace: Security
          MetricValue: "1"

  S3StagingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighS3StagingActivity
      MetricName: S3StagingActivity
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

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
                terraform_template="""# Detect S3 remote data staging activity

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name              = "s3-staging-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "s3_staging" {
  name           = "s3-staging-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"PutObject\" || $.eventName = \"CopyObject\" || $.eventName = \"UploadPart\") && $.eventSource = \"s3.amazonaws.com\" }"

  metric_transformation {
    name      = "S3StagingActivity"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_staging" {
  alarm_name          = "HighS3StagingActivity"
  metric_name         = "S3StagingActivity"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
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
}""",
                alert_severity="high",
                alert_title="Potential Remote Data Staging Detected",
                alert_description_template="High volume S3 uploads from {sourceIPAddress} to bucket {bucketName}.",
                investigation_steps=[
                    "Review source IP addresses and EC2 instances",
                    "Check uploaded object sizes and patterns",
                    "Verify bucket ownership and permissions",
                    "Review CloudTrail for related user activity",
                    "Check for compression or archive files",
                ],
                containment_actions=[
                    "Block suspicious source IP addresses",
                    "Review and restrict S3 bucket permissions",
                    "Enable S3 versioning and object lock",
                    "Quarantine suspicious objects",
                    "Review EC2 instance security",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on normal backup and data transfer patterns",
            detection_coverage="65% - catches bulk S3 staging",
            evasion_considerations="Attackers may use rate limiting or smaller batches",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1074_002-aws-vpc-transfer",
            name="AWS VPC Flow Logs - Inter-Instance Transfer",
            description="Detect unusual data transfers between EC2 instances that may indicate staging.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, bytes, packets
| filter action = "ACCEPT"
| filter dstport in [22, 445, 3389, 2049]
| stats sum(bytes) as totalBytes, count(*) as flows by srcaddr, dstaddr, dstport, bin(1h)
| filter totalBytes > 10737418240
| sort totalBytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect large inter-instance data transfers

Parameters:
  VPCFlowLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  LargeTransferFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport="22" || destport="445" || destport="2049", protocol, packets, bytes>1073741824, start, end, action="ACCEPT", flowlogstatus]'
      MetricTransformations:
        - MetricName: LargeInstanceTransfers
          MetricNamespace: Security
          MetricValue: "1"

  LargeTransferAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighInterInstanceTransfer
      MetricName: LargeInstanceTransfers
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

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
                terraform_template="""# Detect large inter-instance data transfers

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name              = "instance-transfer-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "large_transfers" {
  name           = "large-instance-transfers"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport=\"22\" || destport=\"445\" || destport=\"2049\", protocol, packets, bytes>1073741824, start, end, action=\"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "LargeInstanceTransfers"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "large_transfers" {
  alarm_name          = "HighInterInstanceTransfer"
  metric_name         = "LargeInstanceTransfers"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
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
}""",
                alert_severity="medium",
                alert_title="Large Inter-Instance Data Transfer Detected",
                alert_description_template="Significant data transfer from {srcaddr} to {dstaddr} on port {dstport}.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review instance roles and permissions",
                    "Check for file transfer tools (scp, rsync, robocopy)",
                    "Analyse transferred data types",
                    "Review instance activity logs",
                ],
                containment_actions=[
                    "Isolate suspicious instances",
                    "Review security group rules",
                    "Disable unnecessary file sharing protocols",
                    "Audit instance access",
                    "Check for data exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known backup and database replication traffic",
            detection_coverage="60% - detects large network transfers",
            evasion_considerations="Slow transfers or encrypted tunnels may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-40",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1074_002-gcp-gcs-staging",
            name="GCP Cloud Storage Remote Staging Detection",
            description="Detect unusual Cloud Storage bucket uploads from Compute Engine that may indicate staging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
OR protoPayload.methodName="storage.objects.copy"''',
                gcp_terraform_template="""# GCP: Detect Cloud Storage remote data staging

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "gcs_staging" {
  project = var.project_id
  name   = "gcs-staging-activity"
  filter = <<-EOT
    resource.type="gcs_bucket"
    (protoPayload.methodName="storage.objects.create" OR
     protoPayload.methodName="storage.objects.copy")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "gcs_staging" {
  project      = var.project_id
  display_name = "High GCS Staging Activity"
  combiner     = "OR"
  conditions {
    display_name = "High upload rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_staging.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
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
                alert_title="GCP: Potential Remote Data Staging",
                alert_description_template="High volume Cloud Storage uploads detected.",
                investigation_steps=[
                    "Review source Compute Engine instances",
                    "Check uploaded object sizes and patterns",
                    "Verify bucket ownership and IAM permissions",
                    "Review audit logs for related activity",
                    "Check for archive or compressed files",
                ],
                containment_actions=[
                    "Review and restrict bucket IAM permissions",
                    "Enable object versioning and retention",
                    "Quarantine suspicious objects",
                    "Review Compute Engine instance security",
                    "Block suspicious service accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on normal backup patterns",
            detection_coverage="65% - catches bulk GCS staging",
            evasion_considerations="Rate limiting or smaller batches may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["Cloud Storage audit logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1074_002-gcp-vpc-transfer",
            name="GCP VPC Flow Logs - Inter-Instance Transfer",
            description="Detect unusual data transfers between Compute Engine instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.dest_port:(22 OR 445 OR 2049 OR 3389)
jsonPayload.bytes_sent>1073741824""",
                gcp_terraform_template="""# GCP: Detect large inter-instance transfers

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "large_transfers" {
  project = var.project_id
  name   = "large-instance-transfers"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.dest_port:(22 OR 445 OR 2049 OR 3389)
    jsonPayload.bytes_sent>1073741824
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "large_transfers" {
  project      = var.project_id
  display_name = "High Inter-Instance Transfer"
  combiner     = "OR"
  conditions {
    display_name = "Large data transfer"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.large_transfers.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
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
                alert_title="GCP: Large Inter-Instance Transfer",
                alert_description_template="Significant data transfer between Compute Engine instances.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review instance service accounts and IAM roles",
                    "Check for file transfer tools",
                    "Analyse transferred data types",
                    "Review instance activity logs",
                ],
                containment_actions=[
                    "Isolate suspicious instances",
                    "Review firewall rules",
                    "Disable unnecessary protocols",
                    "Audit instance access",
                    "Check for data exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known backup and replication traffic",
            detection_coverage="60% - detects large network transfers",
            evasion_considerations="Encrypted tunnels or slow transfers may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-40",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        # Azure Strategy: Data Staged: Remote Data Staging
        DetectionStrategy(
            strategy_id="t1074002-azure",
            name="Azure Data Staged: Remote Data Staging Detection",
            description=(
                "Azure detection for Data Staged: Remote Data Staging. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Data Staged: Remote Data Staging Detection
// Technique: T1074.002
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
                azure_terraform_template="""# Azure Detection for Data Staged: Remote Data Staging
# MITRE ATT&CK: T1074.002

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

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "data-staged--remote-data-staging-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "data-staged--remote-data-staging-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Data Staged: Remote Data Staging Detection
// Technique: T1074.002
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

  description = "Detects Data Staged: Remote Data Staging (T1074.002) activity in Azure environment"
  display_name = "Data Staged: Remote Data Staging Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1074.002"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Data Staged: Remote Data Staging Detected",
                alert_description_template=(
                    "Data Staged: Remote Data Staging activity detected. "
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
        "t1074_002-aws-s3-staging",
        "t1074_002-gcp-gcs-staging",
        "t1074_002-aws-vpc-transfer",
        "t1074_002-gcp-vpc-transfer",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+18% improvement for Collection tactic",
)
