"""
T1554 - Compromise Host Software Binary

Adversaries modify host software binaries to establish persistent access by
replacing or infecting legitimate application binaries with backdoors.
UNC3886 and APT5 used this technique to backdoor VPN appliances.
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
    technique_id="T1554",
    technique_name="Compromise Host Software Binary",
    tactic_ids=["TA0003", "TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1554/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify host software binaries to establish persistent access by "
            "replacing or infecting legitimate application binaries with backdoors. This can "
            "involve patching malicious functionality into executables (such as IAT Hooking) "
            "before normal execution resumes. Common targets include SSH clients, FTP applications, "
            "web browsers, and system utilities that are regularly executed by users or services."
        ),
        attacker_goal="Establish persistence by backdooring legitimate system binaries",
        why_technique=[
            "Persists across reboots and updates",
            "Executes with privileges of legitimate binary",
            "Difficult to detect without file integrity monitoring",
            "Bypasses application-layer security controls",
            "Maintains access even if initial compromise method is closed",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="rare",
        trend="stable",
        severity_score=9,
        severity_reasoning=(
            "Extremely difficult to detect without file integrity monitoring. "
            "Provides persistent access with legitimate binary's privileges. "
            "Used by sophisticated APT groups targeting critical infrastructure. "
            "Can credential harvesting and bypass security controls."
        ),
        business_impact=[
            "Persistent backdoor access to critical systems",
            "Credential theft from compromised binaries",
            "Complete system compromise",
            "Difficult and time-consuming remediation",
            "Potential supply chain impact",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1078", "T1552.001", "T1041"],
        often_follows=["T1068", "T1190", "T1078.004"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 binary integrity monitoring via EventBridge
        DetectionStrategy(
            strategy_id="t1554-aws-fim",
            name="AWS File Integrity Monitoring for System Binaries",
            description="Monitor critical system binaries for unauthorised modifications using CloudWatch and EventBridge.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @message like /file_integrity/
| filter @message like /usr.bin|[/]bin|usr.local.bin|opt.aws/
| filter @message like /MODIFIED|CHANGED|REPLACED/
| stats count(*) as modifications by bin(5m)
| filter modifications > 0""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor system binary modifications for backdoor detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: binary-modification-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch Log Group for FIM events
  FIMLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/ec2/file-integrity-monitoring
      RetentionInDays: 90

  # Step 3: Metric filter for binary modifications
  BinaryModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FIMLogGroup
      FilterPattern: '[timestamp, event_type=MODIFIED|CHANGED, file_path=/usr/bin/*|/bin/*|/usr/local/bin/*]'
      MetricTransformations:
        - MetricName: SystemBinaryModifications
          MetricNamespace: Security/FileIntegrity
          MetricValue: "1"
          DefaultValue: 0

  # Step 4: Alarm on binary modifications
  BinaryModificationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SystemBinaryModified
      AlarmDescription: Critical system binary modified outside maintenance window
      MetricName: SystemBinaryModifications
      Namespace: Security/FileIntegrity
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
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
                terraform_template="""# Monitor system binary modifications for backdoor detection

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "binary_alerts" {
  name = "binary-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.binary_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Log Group for FIM events
resource "aws_cloudwatch_log_group" "fim" {
  name              = "/aws/ec2/file-integrity-monitoring"
  retention_in_days = 90
}

# Step 3: Metric filter for binary modifications
resource "aws_cloudwatch_log_metric_filter" "binary_mods" {
  name           = "system-binary-modifications"
  log_group_name = aws_cloudwatch_log_group.fim.name
  pattern        = "[timestamp, event_type=MODIFIED|CHANGED, file_path=/usr/bin/*|/bin/*|/usr/local/bin/*]"

  metric_transformation {
    name      = "SystemBinaryModifications"
    namespace = "Security/FileIntegrity"
    value     = "1"
    default_value = 0
  }
}

# Step 4: Alarm on binary modifications
resource "aws_cloudwatch_metric_alarm" "binary_modified" {
  alarm_name          = "SystemBinaryModified"
  alarm_description   = "Critical system binary modified outside maintenance window"
  metric_name         = "SystemBinaryModifications"
  namespace           = "Security/FileIntegrity"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.binary_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.binary_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.binary_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="System Binary Modified - Potential Backdoor",
                alert_description_template="Critical system binary modified on EC2 instance. File: {file_path}. Timestamp: {timestamp}.",
                investigation_steps=[
                    "Identify which binary was modified and when",
                    "Check if modification occurred during authorised maintenance window",
                    "Compare binary hash against known-good version",
                    "Review CloudTrail for associated EC2/Systems Manager activity",
                    "Check for other indicators of compromise on the instance",
                ],
                containment_actions=[
                    "Isolate affected instance immediately",
                    "Capture memory dump and disk snapshot for forensics",
                    "Restore binary from known-good backup or AMI",
                    "Review all running processes for suspicious activity",
                    "Rotate credentials that may have been compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised package management and system update times; baseline normal update patterns",
            detection_coverage="85% - catches unauthorised binary modifications if FIM agent deployed",
            evasion_considerations="Attacker could disable FIM agent; requires agent on all critical instances",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20 depending on instance count",
            prerequisites=[
                "File integrity monitoring agent (OSSEC/Wazuh/AIDE) installed on EC2 instances",
                "Agent configured to send events to CloudWatch Logs",
            ],
        ),
        # Strategy 2: AWS - Unsigned binary execution detection
        DetectionStrategy(
            strategy_id="t1554-aws-unsigned",
            name="Detect Unsigned or Anomalously-Signed Binary Execution",
            description="Monitor for execution of unsigned binaries or binaries with suspicious signatures after file modifications.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, process_name, process_path, signature_status
| filter signature_status in ["unsigned", "invalid", "unknown"]
| filter process_path like /usr.bin|[/]bin|usr.local.bin/
| stats count(*) by process_name, signature_status, bin(1h)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on unsigned binary execution in critical directories

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group receiving process execution events
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for unsigned binaries
  UnsignedBinaryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '{ $.signature_status = "unsigned" || $.signature_status = "invalid" }'
      MetricTransformations:
        - MetricName: UnsignedBinaryExecution
          MetricNamespace: Security/ProcessMonitoring
          MetricValue: "1"

  # Step 3: Alarm on threshold
  UnsignedBinaryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnsignedBinaryExecution
      MetricName: UnsignedBinaryExecution
      Namespace: Security/ProcessMonitoring
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
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
                terraform_template="""# Alert on unsigned binary execution in critical directories

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group receiving process execution events"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "unsigned-binary-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for unsigned binaries
resource "aws_cloudwatch_log_metric_filter" "unsigned" {
  name           = "unsigned-binary-execution"
  log_group_name = var.cloudwatch_log_group
  pattern        = "{ $.signature_status = \"unsigned\" || $.signature_status = \"invalid\" }"

  metric_transformation {
    name      = "UnsignedBinaryExecution"
    namespace = "Security/ProcessMonitoring"
    value     = "1"
  }
}

# Step 3: Alarm on threshold
resource "aws_cloudwatch_metric_alarm" "unsigned" {
  alarm_name          = "UnsignedBinaryExecution"
  metric_name         = "UnsignedBinaryExecution"
  namespace           = "Security/ProcessMonitoring"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
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
                alert_title="Unsigned Binary Execution Detected",
                alert_description_template="Unsigned or invalidly-signed binary executed from system directory. Binary: {process_name}. Path: {process_path}.",
                investigation_steps=[
                    "Identify the unsigned binary and its parent process",
                    "Check file creation/modification time",
                    "Verify if binary should be signed",
                    "Compare hash against known malware databases",
                    "Review recent file system changes on the host",
                ],
                containment_actions=[
                    "Quarantine the unsigned binary",
                    "Kill process if still running",
                    "Isolate affected instance",
                    "Restore from known-good snapshot",
                    "Implement code signing verification policy",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate unsigned binaries; exclude development/testing systems; whitelist known unsigned utilities",
            detection_coverage="70% - requires process monitoring with signature validation",
            evasion_considerations="Attacker could obtain valid code signing certificate; not all systems validate signatures",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "Process monitoring agent with signature validation",
                "CloudWatch Logs integration",
            ],
        ),
        # Strategy 3: GCP - VM binary integrity monitoring
        DetectionStrategy(
            strategy_id="t1554-gcp-fim",
            name="GCP VM Binary Integrity Monitoring",
            description="Monitor GCE instances for modifications to critical system binaries using Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
jsonPayload.event_type="file_modified"
jsonPayload.file_path=~"/usr/bin/.*|/bin/.*|/usr/local/bin/.*"
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Monitor system binary modifications

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Binary Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for binary modifications
resource "google_logging_metric" "binary_modifications" {
  project = var.project_id
  name   = "system-binary-modifications"
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.event_type="file_modified"
    (jsonPayload.file_path=~"/usr/bin/.*" OR
     jsonPayload.file_path=~"/bin/.*" OR
     jsonPayload.file_path=~"/usr/local/bin/.*")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where modification occurred"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Alert policy for binary modifications
resource "google_monitoring_alert_policy" "binary_alert" {
  project      = var.project_id
  display_name = "System Binary Modified"
  combiner     = "OR"

  conditions {
    display_name = "Binary modification detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.binary_modifications.name}\" resource.type=\"gce_instance\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
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

  documentation {
    content   = "System binary modified on GCE instance. Investigate immediately for potential backdoor."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: System Binary Modified",
                alert_description_template="Critical system binary modified on GCE instance {instance_id}. Path: {file_path}.",
                investigation_steps=[
                    "Identify modified binary and instance",
                    "Check Cloud Audit Logs for SSH/OS Login activity",
                    "Review Cloud Logging for related system events",
                    "Verify against authorised maintenance schedules",
                    "Check instance metadata for unauthorised changes",
                ],
                containment_actions=[
                    "Stop affected GCE instance",
                    "Create disk snapshot for forensics",
                    "Restore from known-good image or snapshot",
                    "Review VPC firewall rules and IAM permissions",
                    "Scan other instances in the same project",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised package management times; whitelist OS patch management tools",
            detection_coverage="80% - requires FIM agent on GCE instances",
            evasion_considerations="Attacker could disable logging agent; requires agent deployment",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "Ops Agent or third-party FIM solution deployed on GCE instances",
                "Cloud Logging API enabled",
            ],
        ),
        # Strategy 4: GCP - Detect binary changes via Cloud Asset Inventory
        DetectionStrategy(
            strategy_id="t1554-gcp-asset-inventory",
            name="GCP Binary Hash Change Detection via Asset Inventory",
            description="Use Cloud Asset Inventory to track changes to critical binaries across GCE instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_asset",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="ExportAssets"
protoPayload.request.outputConfig.gcsDestination.uri=~".*binary-inventory.*"
severity>=NOTICE""",
                gcp_terraform_template="""# GCP: Track binary hash changes via Cloud Asset Inventory

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

variable "inventory_bucket" {
  type        = string
  description = "GCS bucket for asset inventory exports"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Binary Hash Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Cloud Scheduler for periodic inventory
resource "google_cloud_scheduler_job" "inventory_export" {
  name     = "binary-inventory-export"
  schedule = "0 */6 * * *"  # Every 6 hours
  project  = var.project_id
  region   = "us-central1"

  http_target {
    http_method = "POST"
    uri         = "https://cloudasset.googleapis.com/v1/projects/${var.project_id}:exportAssets"

    oauth_token {
      service_account_email = google_service_account.inventory.email
    }

    body = base64encode(jsonencode({
      outputConfig = {
        gcsDestination = {
          uri = "gs://${var.inventory_bucket}/binary-inventory"
        }
      }
      assetTypes = ["compute.googleapis.com/Instance"]
    }))
  }
}

# Step 3: Service account for inventory exports
resource "google_service_account" "inventory" {
  account_id   = "binary-inventory-exporter"
  display_name = "Binary Inventory Exporter"
  project      = var.project_id
}

resource "google_project_iam_member" "asset_viewer" {
  project = var.project_id
  role    = "roles/cloudasset.viewer"
  member  = "serviceAccount:${google_service_account.inventory.email}"
}

resource "google_storage_bucket_iam_member" "inventory_writer" {
  bucket = var.inventory_bucket
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.inventory.email}"
}""",
                alert_severity="medium",
                alert_title="GCP: Binary Inventory Export Completed",
                alert_description_template="Binary inventory exported. Review for hash changes indicating potential backdoors.",
                investigation_steps=[
                    "Compare current inventory with previous baseline",
                    "Identify binaries with changed hashes",
                    "Verify changes against authorised update schedules",
                    "Investigate instances with unexpected binary modifications",
                    "Review Cloud Audit Logs for the affected instances",
                ],
                containment_actions=[
                    "Isolate instances with modified binaries",
                    "Restore binaries from known-good golden images",
                    "Update baseline inventory after authorised changes",
                    "Implement Binary Authorization for containers",
                    "Enable OS Config for centralised patch management",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal update patterns; exclude test/development instances; track authorised patch schedules",
            detection_coverage="75% - periodic detection, not real-time",
            evasion_considerations="Changes between inventory scans may go undetected; requires custom comparison logic",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4-5 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Cloud Asset API enabled",
                "GCS bucket for inventory storage",
                "Custom comparison script or tool",
            ],
        ),
        # Azure Strategy: Compromise Host Software Binary
        DetectionStrategy(
            strategy_id="t1554-azure",
            name="Azure Compromise Host Software Binary Detection",
            description=(
                "Azure detection for Compromise Host Software Binary. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Compromise Host Software Binary (T1554)
# Microsoft Defender detects Compromise Host Software Binary activity

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
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1554-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1554"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (
                    "Suspicious activity detected",
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Compromise Host Software Binary activity"
  display_name = "Defender: Compromise Host Software Binary"
  enabled      = true

  tags = {
    "mitre-technique" = "T1554"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Compromise Host Software Binary Detected",
                alert_description_template=(
                    "Compromise Host Software Binary activity detected. "
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
        "t1554-aws-fim",
        "t1554-gcp-fim",
        "t1554-aws-unsigned",
        "t1554-gcp-asset-inventory",
    ],
    total_effort_hours=12.0,
    coverage_improvement="+18% improvement for Persistence and Defence Evasion tactics",
)
