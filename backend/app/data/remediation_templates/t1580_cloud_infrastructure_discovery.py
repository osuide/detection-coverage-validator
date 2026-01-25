"""
T1580 - Cloud Infrastructure Discovery

Adversaries enumerate cloud resources (EC2, VPCs, databases, etc.)
to understand the environment and identify targets for further exploitation.
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
    technique_id="T1580",
    technique_name="Cloud Infrastructure Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1580/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate cloud infrastructure including compute instances, "
            "databases, VPCs, and other resources. This reconnaissance helps identify "
            "valuable targets and understand network topology."
        ),
        attacker_goal="Map cloud infrastructure to identify targets and attack paths",
        why_technique=[
            "Identifies valuable compute resources",
            "Reveals database and storage locations",
            "Maps network topology and VPCs",
            "Finds exposed services",
            "Required for targeted attacks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=5,
        severity_reasoning=(
            "Discovery with moderate impact. Indicates active reconnaissance. "
            "Typically precedes data theft or resource abuse."
        ),
        business_impact=[
            "Reveals infrastructure layout",
            "Identifies data storage locations",
            "Enables targeted attacks",
            "Early warning opportunity",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1530", "T1537", "T1496.001"],
        often_follows=["T1078.004", "T1087.004"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: GuardDuty Reconnaissance Detection (Recommended)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1580-aws-guardduty",
            name="AWS GuardDuty Reconnaissance Detection",
            description=(
                "Leverage GuardDuty to detect reconnaissance activities including "
                "port scanning and unusual API activity patterns. "
                "See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Recon:EC2/PortProbeEMRUnprotectedPort",
                    "Recon:EC2/PortProbeUnprotectedPort",
                    "Recon:EC2/Portscan",
                    "Discovery:IAMUser/AnomalousBehavior",
                ],
                terraform_template="""# AWS GuardDuty Reconnaissance Detection
# Detects: Port scanning, unusual API patterns, anomalous discovery
# See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html

variable "alert_email" {
  type        = string
  description = "Email for reconnaissance security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "recon_alerts" {
  name              = "guardduty-recon-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.recon_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 3: Route reconnaissance findings to SNS
resource "aws_cloudwatch_event_rule" "recon_findings" {
  name        = "guardduty-recon-findings"
  description = "Detect reconnaissance and discovery activity"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Recon:EC2/" },
        { prefix = "Discovery:" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "recon-findings-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.recon_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.recon_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      findingType = "$.detail.type"
      severity    = "$.detail.severity"
      accountId   = "$.account"
      region      = "$.region"
    }
    input_template = <<-EOF
      "GuardDuty Reconnaissance Alert"
      "Type: <findingType>"
      "Severity: <severity>"
      "Account: <accountId>"
      "Region: <region>"
      "Action: Investigate potential attacker reconnaissance activity"
    EOF
  }
}

resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.recon_findings.arn
        }
      }
    }]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.recon_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.recon_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.recon_findings.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Reconnaissance Activity Detected",
                alert_description_template=(
                    "GuardDuty detected reconnaissance activity: {type}. "
                    "This indicates an attacker is mapping your infrastructure."
                ),
                investigation_steps=[
                    "Review the specific GuardDuty finding for context",
                    "Identify the source of reconnaissance (internal/external)",
                    "Check for compromised EC2 instances",
                    "Review recent IAM activity for the affected resources",
                    "Look for follow-on attack activity",
                ],
                containment_actions=[
                    "Block source IPs at security groups/NACLs",
                    "Isolate any compromised instances",
                    "Review and tighten security group rules",
                    "Enable VPC Flow Logs for detailed analysis",
                    "Consider enabling AWS Network Firewall",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty's ML reduces false positives. "
                "Suppress findings for authorised vulnerability scanners. "
                "Use trusted IP lists for known security tools."
            ),
            detection_coverage="85% - ML-based detection of recon patterns",
            evasion_considerations="Slow/distributed scanning may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "GuardDuty: ~$4/GB VPC Flow Logs analysed. "
                "See: https://aws.amazon.com/guardduty/pricing/"
            ),
            prerequisites=["GuardDuty enabled", "VPC Flow Logs (for Recon findings)"],
        ),
        # =====================================================================
        # STRATEGY 2: AWS - EC2/VPC Enumeration (CloudWatch)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1580-aws-infra",
            name="AWS Infrastructure Enumeration Detection",
            description="Detect bulk describe/list operations across AWS services.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, eventSource
| filter eventName like /Describe|List/
| filter eventSource in ["ec2.amazonaws.com", "rds.amazonaws.com", "elasticache.amazonaws.com"]
| stats count(*) as enum_count by userIdentity.arn, bin(1h)
| filter enum_count > 50
| sort enum_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect cloud infrastructure enumeration

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

  # Step 2: Metric filter
  InfraEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "DescribeInstances" || $.eventName = "DescribeVpcs" || $.eventName = "DescribeDBInstances") }'
      MetricTransformations:
        - MetricName: InfraEnumeration
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  InfraEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: InfraEnumeration
      MetricName: InfraEnumeration
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect cloud infrastructure enumeration

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "infra-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "infra_enum" {
  name           = "infra-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"DescribeInstances\" || $.eventName = \"DescribeVpcs\" || $.eventName = \"DescribeDBInstances\") }"

  metric_transformation {
    name      = "InfraEnumeration"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "infra_enum" {
  alarm_name          = "InfraEnumeration"
  metric_name         = "InfraEnumeration"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Infrastructure Enumeration Detected",
                alert_description_template="High volume of infrastructure discovery calls from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who is enumerating infrastructure",
                    "Check if this is authorised scanning",
                    "Review what resources were discovered",
                    "Look for follow-on attack activity",
                ],
                containment_actions=[
                    "Review user's permissions",
                    "Monitor for resource access",
                    "Consider restricting describe permissions",
                    "Audit recent activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist automation, CSPM, and monitoring tools",
            detection_coverage="70% - volume-based",
            evasion_considerations="Slow enumeration evades thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 2: GCP - Compute/Resource Enumeration
        DetectionStrategy(
            strategy_id="t1580-gcp-infra",
            name="GCP Infrastructure Enumeration Detection",
            description="Detect bulk list operations across GCP services.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(compute.instances.list|compute.networks.list|cloudsql.instances.list|compute.zones.list)"''',
                gcp_terraform_template="""# GCP: Detect infrastructure enumeration

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

# Step 2: Log-based metric
resource "google_logging_metric" "infra_enum" {
  project = var.project_id
  name   = "infrastructure-enumeration"
  filter = <<-EOT
    protoPayload.methodName=~"(compute.instances.list|compute.networks.list|cloudsql.instances.list)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "infra_enum" {
  project      = var.project_id
  display_name = "Infrastructure Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "High volume list operations"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.infra_enum.name}\""
      duration        = "300s"
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
                alert_severity="medium",
                alert_title="GCP: Infrastructure Enumeration",
                alert_description_template="High volume of infrastructure discovery calls.",
                investigation_steps=[
                    "Identify the enumerating principal",
                    "Check if authorised scanning",
                    "Review resources discovered",
                    "Look for follow-on attacks",
                ],
                containment_actions=[
                    "Review principal permissions",
                    "Monitor resource access",
                    "Consider IAM Conditions",
                    "Audit recent activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist monitoring and CSPM tools",
            detection_coverage="70% - volume-based",
            evasion_considerations="Slow enumeration evades",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Cloud Infrastructure Discovery
        DetectionStrategy(
            strategy_id="t1580-azure",
            name="Azure Cloud Infrastructure Discovery Detection",
            description=(
                "Monitor cloud infrastructure discovery. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Cloud Infrastructure Discovery Detection
// Technique: T1580
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.Resources/subscriptions/resources/read"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| project
    TimeGenerated,
    SubscriptionId,
    ResourceGroup,
    Resource,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    Properties
| order by TimeGenerated desc""",
                azure_activity_operations=[
                    "Microsoft.Resources/subscriptions/resources/read"
                ],
                azure_terraform_template="""# Azure Detection for Cloud Infrastructure Discovery
# MITRE ATT&CK: T1580

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
  name                = "cloud-infrastructure-discovery-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "cloud-infrastructure-discovery-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Cloud Infrastructure Discovery Detection
// Technique: T1580
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.Resources/subscriptions/resources/read"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| project
    TimeGenerated,
    SubscriptionId,
    ResourceGroup,
    Resource,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    Properties
| order by TimeGenerated desc
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

  description = "Detects Cloud Infrastructure Discovery (T1580) activity in Azure environment"
  display_name = "Cloud Infrastructure Discovery Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1580"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Cloud Infrastructure Discovery Detected",
                alert_description_template=(
                    "Cloud Infrastructure Discovery activity detected. "
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
        "t1580-aws-guardduty",
        "t1580-aws-infra",
        "t1580-gcp-infra",
    ],
    total_effort_hours=2.5,
    coverage_improvement="+10% improvement for Discovery tactic",
)
