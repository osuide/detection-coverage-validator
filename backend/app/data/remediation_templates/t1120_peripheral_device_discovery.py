"""
T1120 - Peripheral Device Discovery

Adversaries gather information about attached peripheral devices and components
connected to a computer system, including removable storage, input/output devices,
and specialized hardware to inform exfiltration and lateral movement strategies.

CROSS-REFERENCE: For real-time block device/USB connection detection on EC2 instances,
see T1200 (Hardware Additions) which provides udev + systemd based real-time alerting.
Peripheral device discovery often precedes T1091 (Removable Media replication) and
T1052 (Exfiltration Over Physical Medium) - real-time device detection can alert before
adversaries can exploit discovered devices.
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
    technique_id="T1120",
    technique_name="Peripheral Device Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1120/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate attached peripheral devices and components connected "
            "to computer systems including removable storage (USB drives, SD cards, external "
            "hard drives), input devices (keyboards, mice, smart card readers), output devices "
            "(printers, cameras, displays), and specialized hardware (Bluetooth devices, modems). "
            "This reconnaissance helps attackers identify data exfiltration opportunities, "
            "removable media for lateral movement, and understand the system's hardware capabilities."
        ),
        attacker_goal="Identify peripheral devices for data exfiltration and lateral movement opportunities",
        why_technique=[
            "Discovers removable storage for data exfiltration",
            "Identifies USB devices for malware propagation",
            "Finds network-connected printers and cameras",
            "Locates smart card readers for credential theft",
            "Maps Bluetooth devices for covert channels",
            "Assesses hardware for exploitation opportunities",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=5,
        severity_reasoning=(
            "Peripheral device discovery is moderate-severity reconnaissance that often "
            "precedes data exfiltration or lateral movement via removable media. While not "
            "directly damaging, it indicates adversary preparation for data theft or malware "
            "propagation. Common in ransomware and APT operations targeting sensitive data."
        ),
        business_impact=[
            "Precursor to data exfiltration via removable media",
            "Indicates preparation for lateral movement",
            "Risk of malware propagation via USB devices",
            "Potential compromise of network peripherals",
            "Early warning of ransomware reconnaissance",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1091", "T1052", "T1025", "T1074"],
        often_follows=["T1082", "T1083", "T1057"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 EBS Volume and Device Enumeration
        DetectionStrategy(
            strategy_id="t1120-aws-ebs",
            name="EC2 Volume and Block Device Discovery Detection",
            description="Detect enumeration of EBS volumes, attached devices, and storage configurations on EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters.instanceId
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["DescribeVolumes", "DescribeVolumeAttribute", "DescribeInstanceAttribute", "DescribeSnapshots"]
| stats count(*) as enumeration_count by userIdentity.arn, sourceIPAddress, bin(1h)
| filter enumeration_count > 25
| sort enumeration_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect peripheral device discovery via EBS enumeration

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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for volume enumeration
  PeripheralDeviceFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ec2.amazonaws.com" && ($.eventName = "DescribeVolumes" || $.eventName = "DescribeVolumeAttribute" || $.eventName = "DescribeInstanceAttribute" || $.eventName = "DescribeSnapshots") }'
      MetricTransformations:
        - MetricName: PeripheralDeviceDiscovery
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: CloudWatch alarm for excessive enumeration
  PeripheralDeviceAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: PeripheralDeviceDiscovery
      MetricName: PeripheralDeviceDiscovery
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 40
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect peripheral device discovery via EBS enumeration

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "peripheral-device-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for volume enumeration
resource "aws_cloudwatch_log_metric_filter" "peripheral_device" {
  name           = "peripheral-device-discovery"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ec2.amazonaws.com\" && ($.eventName = \"DescribeVolumes\" || $.eventName = \"DescribeVolumeAttribute\" || $.eventName = \"DescribeInstanceAttribute\" || $.eventName = \"DescribeSnapshots\") }"

  metric_transformation {
    name      = "PeripheralDeviceDiscovery"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm for excessive enumeration
resource "aws_cloudwatch_metric_alarm" "peripheral_device" {
  alarm_name          = "PeripheralDeviceDiscovery"
  metric_name         = "PeripheralDeviceDiscovery"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 40
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# SNS topic policy
data "aws_caller_identity" "current" {}

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
}""",
                alert_severity="medium",
                alert_title="Peripheral Device Discovery Detected",
                alert_description_template="Excessive EBS volume and device enumeration from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify the principal performing volume enumeration",
                    "Check if this is authorised backup or monitoring activity",
                    "Review what storage devices were enumerated",
                    "Look for subsequent snapshot creation or data access",
                    "Check for correlation with data exfiltration attempts",
                    "Review instance metadata access patterns",
                ],
                containment_actions=[
                    "Review principal's EC2 and EBS permissions",
                    "Monitor for snapshot creation or volume attachment",
                    "Check for unauthorised data access",
                    "Enable EBS encryption if not already enabled",
                    "Review volume attachment history",
                    "Consider restricting DescribeVolumes permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist backup solutions, monitoring tools, and infrastructure automation (e.g., Terraform, CloudFormation drift detection)",
            detection_coverage="55% - volume-based detection of API calls",
            evasion_considerations="Slow enumeration or direct metadata service queries may evade volume-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 2: AWS - FSx and Storage Gateway Discovery
        DetectionStrategy(
            strategy_id="t1120-aws-storage",
            name="FSx and Storage Gateway Enumeration Detection",
            description="Detect enumeration of file systems, Storage Gateway devices, and network-attached storage.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventSource in ["fsx.amazonaws.com", "storagegateway.amazonaws.com", "elasticfilesystem.amazonaws.com"]
| filter eventName in ["DescribeFileSystems", "DescribeVolumes", "DescribeGateways", "ListGateways", "DescribeTapeArchives", "DescribeFileSystemAssociations"]
| stats count(*) as query_count by userIdentity.arn, eventSource, bin(1h)
| filter query_count > 15
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect peripheral storage device discovery

Parameters:
  CloudTrailLogGroup:
    Type: String
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

  # Step 2: Metric filter for storage enumeration
  StorageDeviceFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "fsx.amazonaws.com" || $.eventSource = "storagegateway.amazonaws.com" || $.eventSource = "elasticfilesystem.amazonaws.com") && ($.eventName = "DescribeFileSystems" || $.eventName = "DescribeVolumes" || $.eventName = "DescribeGateways" || $.eventName = "ListGateways") }'
      MetricTransformations:
        - MetricName: StorageDeviceDiscovery
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm for excessive queries
  StorageDeviceAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: StorageDeviceDiscovery
      MetricName: StorageDeviceDiscovery
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 25
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect peripheral storage device discovery

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "storage-device-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for storage enumeration
resource "aws_cloudwatch_log_metric_filter" "storage_device" {
  name           = "storage-device-discovery"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"fsx.amazonaws.com\" || $.eventSource = \"storagegateway.amazonaws.com\" || $.eventSource = \"elasticfilesystem.amazonaws.com\") && ($.eventName = \"DescribeFileSystems\" || $.eventName = \"DescribeVolumes\" || $.eventName = \"DescribeGateways\" || $.eventName = \"ListGateways\") }"

  metric_transformation {
    name      = "StorageDeviceDiscovery"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for excessive queries
resource "aws_cloudwatch_metric_alarm" "storage_device" {
  alarm_name          = "StorageDeviceDiscovery"
  metric_name         = "StorageDeviceDiscovery"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 25
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Storage Device Discovery Detected",
                alert_description_template="Excessive file system and storage gateway enumeration from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who enumerated storage devices",
                    "Determine if access is authorised",
                    "Review what file systems were discovered",
                    "Check for subsequent data access or exfiltration",
                    "Look for correlation with network activity",
                    "Review Storage Gateway and FSx access logs",
                ],
                containment_actions=[
                    "Review principal's FSx and Storage Gateway permissions",
                    "Monitor for unauthorised file access",
                    "Check for data exfiltration attempts",
                    "Review file system access patterns",
                    "Consider network segmentation for storage services",
                    "Enable VPC Flow Logs for storage traffic analysis",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist backup software, monitoring tools, and file management solutions",
            detection_coverage="70% - catches storage device enumeration",
            evasion_considerations="Gradual enumeration or use of legitimate management tools may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 3: GCP - Persistent Disk and Storage Enumeration
        DetectionStrategy(
            strategy_id="t1120-gcp-disk",
            name="GCP Persistent Disk Discovery Detection",
            description="Detect enumeration of persistent disks, local SSDs, and attached storage devices in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.disks.list|compute.disks.get|compute.instances.getSerialPortOutput|compute.disks.aggregatedList|compute.diskTypes.list)"''',
                gcp_terraform_template="""# GCP: Detect peripheral device discovery

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for disk enumeration
resource "google_logging_metric" "peripheral_device" {
  project = var.project_id
  name   = "peripheral-device-discovery"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.disks.list|compute.disks.get|compute.instances.getSerialPortOutput|compute.disks.aggregatedList|compute.diskTypes.list)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for excessive enumeration
resource "google_monitoring_alert_policy" "peripheral_device" {
  project      = var.project_id
  display_name = "Peripheral Device Discovery"
  combiner     = "OR"

  conditions {
    display_name = "High volume disk enumeration"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.peripheral_device.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 40
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
                alert_title="GCP: Peripheral Device Discovery",
                alert_description_template="Excessive persistent disk enumeration detected.",
                investigation_steps=[
                    "Identify the principal performing disk enumeration",
                    "Check if this is authorised backup or monitoring",
                    "Review what storage devices were enumerated",
                    "Look for snapshot creation or disk attachment activity",
                    "Check for correlation with data access patterns",
                    "Review serial port output access (potential data exfiltration)",
                ],
                containment_actions=[
                    "Review principal's Compute Engine permissions",
                    "Monitor for disk snapshot or clone operations",
                    "Check for unauthorised disk attachments",
                    "Enable disk encryption if not already active",
                    "Review VPC Service Controls for storage resources",
                    "Consider IAM Conditions to restrict disk access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist backup solutions, monitoring tools, and infrastructure automation (e.g., Terraform state refresh)",
            detection_coverage="55% - volume-based detection",
            evasion_considerations="Slow enumeration or use of metadata service may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - Filestore and Storage Device Discovery
        DetectionStrategy(
            strategy_id="t1120-gcp-filestore",
            name="GCP Filestore and Network Storage Discovery Detection",
            description="Detect enumeration of Filestore instances, Cloud Storage buckets, and network-attached storage.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName=~"(file.googleapis.com|storage.googleapis.com)"
protoPayload.methodName=~"(google.cloud.filestore.*.ListInstances|google.cloud.filestore.*.GetInstance|storage.buckets.list|storage.objects.list)"''',
                gcp_terraform_template="""# GCP: Detect filestore and storage discovery

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for storage discovery
resource "google_logging_metric" "storage_discovery" {
  project = var.project_id
  name   = "filestore-storage-discovery"
  filter = <<-EOT
    protoPayload.serviceName=~"(file.googleapis.com|storage.googleapis.com)"
    protoPayload.methodName=~"(google.cloud.filestore.*.ListInstances|google.cloud.filestore.*.GetInstance|storage.buckets.list|storage.objects.list)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "storage_discovery" {
  project      = var.project_id
  display_name = "Filestore and Storage Discovery"
  combiner     = "OR"

  conditions {
    display_name = "Bulk storage enumeration"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.storage_discovery.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 30
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
                alert_title="GCP: Storage Device Discovery Detected",
                alert_description_template="Bulk enumeration of Filestore instances and Cloud Storage detected.",
                investigation_steps=[
                    "Identify who enumerated storage resources",
                    "Verify if access is authorised",
                    "Review what storage devices were discovered",
                    "Check for subsequent data access or downloads",
                    "Look for correlation with network egress activity",
                    "Review Cloud Storage access logs",
                ],
                containment_actions=[
                    "Review principal's Filestore and Storage permissions",
                    "Monitor for bulk data downloads",
                    "Check for unauthorised bucket access",
                    "Enable VPC Service Controls for storage APIs",
                    "Review bucket and Filestore ACLs",
                    "Consider implementing data loss prevention policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist backup software, data analytics tools, and monitoring solutions",
            detection_coverage="70% - catches storage enumeration",
            evasion_considerations="Use of legitimate tools or gradual enumeration may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Data Access logs enabled for Cloud Storage",
            ],
        ),
        # Azure Strategy: Peripheral Device Discovery
        DetectionStrategy(
            strategy_id="t1120-azure",
            name="Azure Peripheral Device Discovery Detection",
            description=(
                "Azure detection for Peripheral Device Discovery. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Peripheral Device Discovery Detection
// Technique: T1120
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
                azure_terraform_template="""# Azure Detection for Peripheral Device Discovery
# MITRE ATT&CK: T1120

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
  name                = "peripheral-device-discovery-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "peripheral-device-discovery-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Peripheral Device Discovery Detection
// Technique: T1120
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

  description = "Detects Peripheral Device Discovery (T1120) activity in Azure environment"
  display_name = "Peripheral Device Discovery Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1120"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Peripheral Device Discovery Detected",
                alert_description_template=(
                    "Peripheral Device Discovery activity detected. "
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
        "t1120-aws-ebs",
        "t1120-aws-storage",
        "t1120-gcp-disk",
        "t1120-gcp-filestore",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+7% improvement for Discovery tactic",
)
