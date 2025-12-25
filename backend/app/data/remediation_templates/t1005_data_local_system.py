"""
T1005 - Data from Local System

Adversaries may search local system sources such as file systems, configuration files,
databases, or process memory to find files of interest and sensitive data prior to exfiltration.
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
    technique_id="T1005",
    technique_name="Data from Local System",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1005/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may search local system sources—including file systems, configuration files, "
            "databases, VM files, and process memory—to locate files of interest and sensitive information "
            "prior to exfiltration. Threat actors use command interpreters, CLI tools, and scripts to "
            "systematically enumerate directories, search for specific file types, and access configuration "
            "files containing credentials or sensitive data. In cloud environments, this includes accessing "
            "instance metadata, local databases, application logs, and temporary files."
        ),
        attacker_goal="Locate and collect sensitive data from local systems for exfiltration or intelligence gathering",
        why_technique=[
            "Local systems often contain sensitive data in configuration files and databases",
            "Credentials are frequently stored in clear text in local files",
            "Application logs may contain authentication tokens or API keys",
            "Instance metadata can provide cloud credentials and configuration details",
            "Database dumps and backups stored locally contain valuable information",
            "SSH keys and certificates enable lateral movement",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Local data collection is a critical precursor to data exfiltration and represents "
            "one of the most common techniques used by both APT groups and ransomware operators. "
            "The technique is difficult to prevent entirely as it mimics legitimate user and application "
            "behaviour, but detection is possible through monitoring unusual file access patterns, "
            "recursive directory enumeration, and access to sensitive file locations."
        ),
        business_impact=[
            "Exposure of credentials enabling further compromise",
            "Intellectual property and trade secret theft",
            "Regulatory compliance violations (GDPR, HIPAA, PCI DSS)",
            "Data breach notification requirements",
            "Ransomware extortion leverage",
            "Loss of customer trust and competitive advantage",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1074", "T1560", "T1567", "T1048"],
        often_follows=["T1083", "T1082", "T1057", "T1552.001"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Unusual File Access Patterns via SSM
        DetectionStrategy(
            strategy_id="t1005-aws-ssm-commands",
            name="Detect Data Collection Commands via Systems Manager",
            description=(
                "Monitor AWS Systems Manager Session Manager and Run Command for execution of "
                "commands commonly used to search and collect data from local file systems, "
                "such as recursive directory listings, file searches, and data archiving."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, requestParameters.documentName,
       requestParameters.parameters as params, responseElements.command.commandId
| filter eventSource = "ssm.amazonaws.com"
| filter eventName in ["SendCommand", "StartSession"]
| filter requestParameters.documentName in ["AWS-RunShellScript", "AWS-RunPowerShellScript"]
| filter requestParameters.parameters like /find|grep|locate|tar|zip|7z|rar|gzip/
  or requestParameters.parameters like /Get-ChildItem.*-Recurse|Select-String|Compress-Archive/
| stats count(*) as command_count by user, bin(1h) as hour_window
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect data collection via SSM commands for T1005

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
      DisplayName: Data Collection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for data collection commands
  DataCollectionMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ssm.amazonaws.com" && ( $.eventName = "SendCommand" || $.eventName = "StartSession" ) }'
      MetricTransformations:
        - MetricName: SSMDataCollectionCommands
          MetricNamespace: Security/T1005
          MetricValue: "1"

  # Step 3: CloudWatch alarm for suspicious activity
  DataCollectionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1005-SSM-Collection-Activity
      AlarmDescription: SSM SendCommand/StartSession observed (potential collection channel)
      MetricName: SSMDataCollectionCommands
      Namespace: Security/T1005
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching
      TreatMissingData: notBreaching

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
                terraform_template="""# Detect data collection via SSM commands for T1005

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "data_collection_alerts" {
  name         = "data-collection-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Data Collection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.data_collection_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for data collection commands
resource "aws_cloudwatch_log_metric_filter" "data_collection" {
  name           = "ssm-data-collection-commands"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ $.eventSource = \"ssm.amazonaws.com\" && ( $.eventName = \"SendCommand\" || $.eventName = \"StartSession\" ) }"

  metric_transformation {
    name      = "SSMDataCollectionCommands"
    namespace = "Security/T1005"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm for suspicious activity
resource "aws_cloudwatch_metric_alarm" "data_collection" {
  alarm_name          = "T1005-SSM-Collection-Activity"
  alarm_description   = "SSM SendCommand/StartSession observed (potential collection channel)"
  metric_name         = "SSMDataCollectionCommands"
  namespace           = "Security/T1005"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.data_collection_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.data_collection_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.data_collection_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Suspicious Data Collection Activity Detected",
                alert_description_template=(
                    "User {user} executed data collection commands via SSM. "
                    "Command ID: {commandId}. Document: {documentName}. "
                    "This may indicate unauthorised data harvesting."
                ),
                investigation_steps=[
                    "Review the specific commands executed via SSM Session Manager",
                    "Identify which instances were targeted",
                    "Verify the user's authorisation to access these instances",
                    "Check CloudWatch Logs for command output and results",
                    "Review subsequent file transfer or exfiltration attempts",
                    "Examine S3 access logs for potential data staging",
                    "Check for unusual network connections from affected instances",
                ],
                containment_actions=[
                    "Revoke SSM access for the suspicious user/role",
                    "Isolate affected instances using security group modifications",
                    "Terminate active SSM sessions",
                    "Create forensic snapshots of affected instances",
                    "Review and restrict SSM permissions organisation-wide",
                    "Enable enhanced SSM session logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate administrative activities; exclude known automation roles and scheduled maintenance tasks",
            detection_coverage="70% - covers SSM-based data collection activities",
            evasion_considerations="Attackers may use obfuscated commands, run commands directly on instances, or use alternative remote access methods",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudTrail enabled",
                "CloudWatch Logs configured",
                "SSM Session Manager logging enabled",
            ],
        ),
        # Strategy 2: AWS - Sensitive File Access Monitoring
        DetectionStrategy(
            strategy_id="t1005-aws-sensitive-files",
            name="Monitor Access to Sensitive Configuration Files",
            description=(
                "Detect access to common locations storing credentials and sensitive data, "
                "including AWS credentials, application configuration files, SSH keys, "
                "and database connection strings on EC2 instances."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, instance_id, user, file_path, process_name
| filter file_path like /\\.aws\\/credentials|\\.ssh\\/|id_rsa|\\.env|application\\.properties|database\\.yml|web\\.config/
| stats count(*) as access_count by instance_id, user, file_path, bin(5m) as time_window
| filter access_count >= 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor access to sensitive configuration files for T1005

Parameters:
  LogGroupName:
    Type: String
    Description: CloudWatch Logs group containing instance audit logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Sensitive File Access Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for sensitive file access
  SensitiveFileMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: '[time, instance, user, action="open", file_path="*credentials*" || file_path="*id_rsa*" || file_path="*.env*" || file_path="*.pem*"]'
      MetricTransformations:
        - MetricName: SensitiveFileAccess
          MetricNamespace: Security/T1005
          MetricValue: "1"

  # Step 3: Alarm for sensitive file access
  SensitiveFileAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1005-SensitiveFileAccess
      AlarmDescription: Access to sensitive configuration files detected
      MetricName: SensitiveFileAccess
      Namespace: Security/T1005
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching
      TreatMissingData: notBreaching

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
                terraform_template="""# Monitor access to sensitive configuration files for T1005

variable "log_group_name" {
  type        = string
  description = "CloudWatch Logs group containing instance audit logs"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "sensitive_file_alerts" {
  name         = "sensitive-file-access-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Sensitive File Access Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.sensitive_file_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for sensitive file access
resource "aws_cloudwatch_log_metric_filter" "sensitive_files" {
  name           = "sensitive-file-access"
  log_group_name = var.log_group_name
  pattern        = "[time, instance, user, action=\"open\", file_path=\"*credentials*\" || file_path=\"*id_rsa*\" || file_path=\"*.env*\" || file_path=\"*.pem*\"]"

  metric_transformation {
    name      = "SensitiveFileAccess"
    namespace = "Security/T1005"
    value     = "1"
  }
}

# Step 3: Alarm for sensitive file access
resource "aws_cloudwatch_metric_alarm" "sensitive_files" {
  alarm_name          = "T1005-SensitiveFileAccess"
  alarm_description   = "Access to sensitive configuration files detected"
  metric_name         = "SensitiveFileAccess"
  namespace           = "Security/T1005"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.sensitive_file_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.sensitive_file_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.sensitive_file_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Sensitive File Access Detected",
                alert_description_template=(
                    "Multiple accesses to sensitive files detected on instance {instance_id}. "
                    "User: {user}. File: {file_path}. Access count: {access_count}. "
                    "This may indicate credential harvesting."
                ),
                investigation_steps=[
                    "Identify which sensitive files were accessed",
                    "Review the user account accessing the files",
                    "Check if the access pattern is normal for this user/instance",
                    "Examine process tree to identify accessing application",
                    "Review CloudTrail for subsequent API calls using potentially stolen credentials",
                    "Check for file copying or exfiltration attempts",
                    "Verify instance security posture and patch status",
                ],
                containment_actions=[
                    "Rotate all credentials that may have been accessed",
                    "Disable or delete compromised user accounts",
                    "Review and revoke API keys and access tokens",
                    "Enable file integrity monitoring on sensitive paths",
                    "Implement stronger file permissions and encryption",
                    "Isolate the instance for forensic investigation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Configure allowlists for known application processes; exclude legitimate backup and configuration management tools",
            detection_coverage="65% - depends on OS-level logging configuration",
            evasion_considerations="Attackers may use legitimate tools, access files through alternative paths, or employ rootkits to hide file access",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "CloudWatch Logs agent installed on instances",
                "OS-level file access auditing enabled",
                "Centralised logging configured",
            ],
        ),
        # Strategy 3: GCP - Data Collection via Cloud Shell
        DetectionStrategy(
            strategy_id="t1005-gcp-cloud-shell",
            name="Detect Data Collection in Cloud Shell Sessions",
            description=(
                "Monitor Google Cloud Shell for execution of commands used to search and collect "
                "data, including recursive directory searches, file archiving, and database queries."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="cloud_shell_instance"
protoPayload.methodName="google.cloudshell.v1.CloudShellService.ExecuteCommand"
(protoPayload.request.command=~"find|grep|locate|tar|gzip|zip|7z"
OR protoPayload.request.command=~"gsutil|gcloud|bq query"
OR protoPayload.request.command=~"cat.*credentials|cat.*config|cat.*key")""",
                gcp_terraform_template="""# GCP: Detect data collection in Cloud Shell sessions

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

# Step 2: Log-based metric for data collection commands
resource "google_logging_metric" "cloud_shell_collection" {
  name   = "cloud-shell-data-collection"
  filter = <<-EOT
    resource.type="cloud_shell_instance"
    protoPayload.methodName="google.cloudshell.v1.CloudShellService.ExecuteCommand"
    (protoPayload.request.command=~"find|grep|locate|tar|gzip|zip"
    OR protoPayload.request.command=~"cat.*credentials|cat.*config|cat.*key")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for suspicious commands
resource "google_monitoring_alert_policy" "shell_collection_alert" {
  display_name = "Cloud Shell Data Collection Activity"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious data collection commands"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cloud_shell_collection.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
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

  documentation {
    content = "Suspicious data collection commands detected in Cloud Shell. Investigate the user's activity and verify authorisation."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Data Collection Commands in Cloud Shell",
                alert_description_template=(
                    "Suspicious data collection commands detected in Cloud Shell. "
                    "User: {user}. Command pattern indicates potential data harvesting."
                ),
                investigation_steps=[
                    "Review the specific commands executed in Cloud Shell",
                    "Identify the user principal and verify their authorisation",
                    "Check for data transfers to Cloud Storage or external destinations",
                    "Review subsequent API calls and resource access",
                    "Examine whether collected data was exfiltrated",
                    "Check Cloud Storage access logs for staging activities",
                    "Verify if credentials were accessed or exported",
                ],
                containment_actions=[
                    "Disable the user's Cloud Shell access",
                    "Revoke user credentials and service account keys",
                    "Review and restrict IAM permissions",
                    "Enable VPC Service Controls to prevent data exfiltration",
                    "Rotate any exposed credentials or API keys",
                    "Block external data transfers if ongoing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude known administrative users and scheduled automation tasks; baseline normal Cloud Shell usage patterns",
            detection_coverage="75% - covers Cloud Shell-based data collection",
            evasion_considerations="Attackers may use Compute Engine instances directly, obfuscate commands, or employ alternative tools",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Audit Logs enabled for Cloud Shell"],
        ),
        # Strategy 4: GCP - VM Instance File Access Monitoring
        DetectionStrategy(
            strategy_id="t1005-gcp-vm-file-access",
            name="Monitor Compute Instance File Access Patterns",
            description=(
                "Detect unusual file access patterns on GCP Compute Engine instances, "
                "including recursive directory enumeration and access to sensitive configuration files."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(jsonPayload.command=~"find.*-type f|grep -r|locate"
OR jsonPayload.file_path=~"/home/.*/.ssh/|/root/.ssh/|/etc/.*credentials|application.*properties|database.*yml")
severity>="WARNING"''',
                gcp_terraform_template="""# GCP: Monitor Compute instance file access patterns

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

# Step 2: Log-based metric for file access
resource "google_logging_metric" "vm_file_access" {
  name   = "gce-sensitive-file-access"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.command=~"find.*-type f|grep -r|locate"
    OR jsonPayload.file_path=~"/home/.*/\\.ssh/|/root/\\.ssh/|/etc/.*credentials")
    severity>="WARNING"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance identifier"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Alert policy for suspicious file access
resource "google_monitoring_alert_policy" "file_access_alert" {
  display_name = "GCE Sensitive File Access"
  combiner     = "OR"

  conditions {
    display_name = "Multiple sensitive file accesses"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.vm_file_access.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.instance_id"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    notification_rate_limit {
      period = "3600s"
    }
  }

  documentation {
    content = "Multiple accesses to sensitive files detected on Compute instance. Investigate for potential credential theft or data collection."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Sensitive File Access on Compute Instance",
                alert_description_template=(
                    "Multiple accesses to sensitive files detected on instance {instance_id}. "
                    "This may indicate credential harvesting or configuration file theft."
                ),
                investigation_steps=[
                    "Identify the specific files accessed on the instance",
                    "Review the user or service account accessing the files",
                    "Check instance metadata and startup scripts for anomalies",
                    "Examine network connections from the instance",
                    "Review Cloud Logging for command history",
                    "Verify instance image source and integrity",
                    "Check for lateral movement to other instances",
                ],
                containment_actions=[
                    "Isolate the instance using firewall rules",
                    "Create a disk snapshot for forensic analysis",
                    "Rotate credentials that may have been compromised",
                    "Review and restrict instance service account permissions",
                    "Enable OS Login for better access control",
                    "Implement file integrity monitoring",
                    "Consider instance rebuild from trusted image",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal administrative activities; exclude configuration management and monitoring tools; adjust threshold based on instance role",
            detection_coverage="70% - requires proper logging agent configuration",
            evasion_considerations="Attackers may disable logging agents, use obfuscation, or access files through kernel-level mechanisms",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=[
                "Cloud Logging agent installed on instances",
                "OS-level audit logging enabled",
                "Structured logging configured",
            ],
        ),
    ],
    recommended_order=[
        "t1005-aws-ssm-commands",
        "t1005-gcp-cloud-shell",
        "t1005-aws-sensitive-files",
        "t1005-gcp-vm-file-access",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+32% improvement for Collection tactic",
)
