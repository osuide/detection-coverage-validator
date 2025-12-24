"""
T1082 - System Information Discovery

Adversaries gather detailed operating system and hardware information including
version, patches, architecture, and configuration to inform follow-on actions.
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
    technique_id="T1082",
    technique_name="System Information Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1082/",
    threat_context=ThreatContext(
        description=(
            "Adversaries collect detailed operating system and hardware information "
            "including version, patches, hotfixes, service packs, architecture, and "
            "configuration details. This reconnaissance shapes follow-on behaviours, "
            "including whether the adversary fully infects the target or selects "
            "appropriate exploits and payloads."
        ),
        attacker_goal="Gather system details to inform exploitation and persistence strategies",
        why_technique=[
            "Identifies OS version and patch level",
            "Determines system architecture (32/64-bit)",
            "Reveals hardware capabilities and resources",
            "Helps select compatible payloads",
            "Informs privilege escalation tactics",
            "Essential for targeted exploitation",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Cloud Instance Profiling",
                year=2024,
                description="Adversaries enumerate EC2/GCE metadata and system information to select appropriate malware variants",
                reference_url="https://unit42.paloaltonetworks.com/2025-cloud-security-alert-trends/",
            ),
            Campaign(
                name="Container Environment Fingerprinting",
                year=2024,
                description="Attackers probe container environments to identify escape opportunities and host system details",
                reference_url="https://www.datadoghq.com/state-of-cloud-security/",
            ),
        ],
        prevalence="very_common",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "System information discovery is low-impact reconnaissance but indicates "
            "active adversary presence. Typically occurs early in attack lifecycle and "
            "precedes more damaging actions. Important early warning signal."
        ),
        business_impact=[
            "Indicates active reconnaissance phase",
            "Precursor to targeted exploitation",
            "Early detection opportunity",
            "May reveal vulnerable systems",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1059", "T1203", "T1068", "T1105"],
        often_follows=["T1078.004", "T1190", "T1566"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 Metadata Service Access
        DetectionStrategy(
            strategy_id="t1082-aws-metadata",
            name="EC2 Instance Metadata Service Access Detection",
            description="Detect unusual access to EC2 instance metadata service from compute resources.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["DescribeInstances", "DescribeInstanceAttribute", "DescribeInstanceTypes"]
| stats count(*) as query_count by userIdentity.arn, sourceIPAddress, bin(1h)
| filter query_count > 30
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect system information discovery via EC2 API calls

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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for instance enumeration
  SystemInfoFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ec2.amazonaws.com" && ($.eventName = "DescribeInstances" || $.eventName = "DescribeInstanceAttribute" || $.eventName = "DescribeInstanceTypes") }'
      MetricTransformations:
        - MetricName: SystemInfoDiscovery
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: CloudWatch alarm for excessive queries
  SystemInfoAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SystemInformationDiscovery
      MetricName: SystemInfoDiscovery
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect system information discovery via EC2 API

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "system-info-discovery-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for instance enumeration
resource "aws_cloudwatch_log_metric_filter" "system_info" {
  name           = "system-info-discovery"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ec2.amazonaws.com\" && ($.eventName = \"DescribeInstances\" || $.eventName = \"DescribeInstanceAttribute\" || $.eventName = \"DescribeInstanceTypes\") }"

  metric_transformation {
    name      = "SystemInfoDiscovery"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm for excessive queries
resource "aws_cloudwatch_metric_alarm" "system_info" {
  alarm_name          = "SystemInformationDiscovery"
  metric_name         = "SystemInfoDiscovery"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="low",
                alert_title="System Information Discovery Detected",
                alert_description_template="Excessive EC2 instance enumeration from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify the principal performing enumeration",
                    "Check if this is authorised monitoring or scanning",
                    "Review what system information was accessed",
                    "Look for follow-on exploitation attempts",
                    "Check instance metadata service logs",
                ],
                containment_actions=[
                    "Review principal's permissions and legitimacy",
                    "Monitor for suspicious command execution",
                    "Check for exploit attempts or malware",
                    "Consider restricting describe permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist monitoring tools, auto-scaling, and infrastructure automation",
            detection_coverage="60% - volume-based detection of API calls",
            evasion_considerations="Slow enumeration or direct metadata service access evades",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 2: AWS - Systems Manager Inventory
        DetectionStrategy(
            strategy_id="t1082-aws-ssm",
            name="Systems Manager Inventory Access Detection",
            description="Detect access to SSM inventory data which contains detailed system information.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventSource = "ssm.amazonaws.com"
| filter eventName in ["GetInventory", "DescribeInstanceInformation", "ListInventoryEntries"]
| stats count(*) as query_count by userIdentity.arn, bin(1h)
| filter query_count > 20
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect system information access via SSM

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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for SSM inventory access
  SSMInventoryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ssm.amazonaws.com" && ($.eventName = "GetInventory" || $.eventName = "DescribeInstanceInformation") }'
      MetricTransformations:
        - MetricName: SSMInventoryAccess
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm for excessive access
  SSMInventoryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SSMInventoryAccess
      MetricName: SSMInventoryAccess
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 30
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect SSM inventory access

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "ssm-inventory-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for SSM inventory access
resource "aws_cloudwatch_log_metric_filter" "ssm_inventory" {
  name           = "ssm-inventory-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ssm.amazonaws.com\" && ($.eventName = \"GetInventory\" || $.eventName = \"DescribeInstanceInformation\") }"

  metric_transformation {
    name      = "SSMInventoryAccess"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for excessive access
resource "aws_cloudwatch_metric_alarm" "ssm_inventory" {
  alarm_name          = "SSMInventoryAccess"
  metric_name         = "SSMInventoryAccess"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 30
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="SSM Inventory Access Detected",
                alert_description_template="Bulk access to Systems Manager inventory from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who accessed SSM inventory",
                    "Determine if access is authorised",
                    "Review what system details were retrieved",
                    "Check for correlation with other suspicious activity",
                ],
                containment_actions=[
                    "Review principal's SSM permissions",
                    "Monitor for follow-on command execution",
                    "Check for lateral movement attempts",
                    "Audit SSM Run Command history",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist patch management and inventory tools",
            detection_coverage="75% - catches bulk inventory access",
            evasion_considerations="Gradual access or use of compromised legitimate tools evades",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch", "SSM enabled"],
        ),
        # Strategy 3: GCP - Compute Instance Metadata Enumeration
        DetectionStrategy(
            strategy_id="t1082-gcp-compute",
            name="GCP Compute Instance Discovery Detection",
            description="Detect enumeration of GCP compute instances and their attributes.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.instances.get|compute.instances.list|compute.zones.list|compute.machineTypes.list)"''',
                gcp_terraform_template="""# GCP: Detect system information discovery

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

# Step 2: Log-based metric for instance enumeration
resource "google_logging_metric" "system_info" {
  name   = "system-information-discovery"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.instances.get|compute.instances.list|compute.zones.list|compute.machineTypes.list)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for excessive queries
resource "google_monitoring_alert_policy" "system_info" {
  display_name = "System Information Discovery"
  combiner     = "OR"

  conditions {
    display_name = "High volume instance queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.system_info.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="low",
                alert_title="GCP: System Information Discovery",
                alert_description_template="Excessive compute instance enumeration detected.",
                investigation_steps=[
                    "Identify the principal performing enumeration",
                    "Check if this is authorised monitoring",
                    "Review what instance details were accessed",
                    "Look for suspicious follow-on activity",
                    "Check metadata server access logs",
                ],
                containment_actions=[
                    "Review principal's permissions",
                    "Monitor for command execution on instances",
                    "Check for exploitation attempts",
                    "Consider IAM Conditions to restrict access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist monitoring tools and auto-scaling services",
            detection_coverage="60% - volume-based detection",
            evasion_considerations="Slow enumeration or direct metadata access evades",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - OS Config Inventory
        DetectionStrategy(
            strategy_id="t1082-gcp-osconfig",
            name="GCP OS Config Inventory Access Detection",
            description="Detect access to OS Config inventory containing detailed system information.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(osconfig.*.Inventory|osconfig.*.PatchJob)"
protoPayload.serviceName="osconfig.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect OS Config inventory access

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

# Step 2: Log-based metric for inventory access
resource "google_logging_metric" "os_inventory" {
  name   = "os-config-inventory-access"
  filter = <<-EOT
    protoPayload.methodName=~"(osconfig.*.Inventory|osconfig.*.PatchJob)"
    protoPayload.serviceName="osconfig.googleapis.com"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "os_inventory" {
  display_name = "OS Config Inventory Access"
  combiner     = "OR"

  conditions {
    display_name = "Bulk inventory access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.os_inventory.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 30
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: OS Inventory Access Detected",
                alert_description_template="Bulk access to OS Config inventory detected.",
                investigation_steps=[
                    "Identify who accessed OS inventory",
                    "Verify if access is authorised",
                    "Review what system details were retrieved",
                    "Check for correlated suspicious activity",
                ],
                containment_actions=[
                    "Review principal's permissions",
                    "Monitor for command execution",
                    "Check for lateral movement",
                    "Audit recent OS Config activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist patch management tools",
            detection_coverage="75% - catches inventory access",
            evasion_considerations="Use of legitimate tools or gradual access evades",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled", "OS Config API enabled"],
        ),
    ],
    recommended_order=[
        "t1082-aws-metadata",
        "t1082-aws-ssm",
        "t1082-gcp-compute",
        "t1082-gcp-osconfig",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+8% improvement for Discovery tactic",
)
