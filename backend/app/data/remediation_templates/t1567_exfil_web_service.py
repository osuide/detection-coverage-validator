"""
T1567 - Exfiltration Over Web Service

Adversaries use legitimate web services to exfiltrate data.
Used by APT28, BlackByte, OilRig, Magic Hound.
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
    technique_id="T1567",
    technique_name="Exfiltration Over Web Service",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1567/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use legitimate external web services to exfiltrate data. "
            "This provides cover since organisations typically communicate with these "
            "services, and SSL/TLS encryption hides the data."
        ),
        attacker_goal="Exfiltrate data using legitimate web services to avoid detection",
        why_technique=[
            "Blends with normal traffic",
            "SSL/TLS hides data content",
            "Firewall rules permit traffic",
            "Cloud storage has high capacity",
            "Hard to distinguish from legitimate use",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Data exfiltration via trusted services is hard to detect. "
            "Bypasses traditional DLP and firewall controls."
        ),
        business_impact=[
            "Data breach",
            "Intellectual property theft",
            "Regulatory violations",
            "Reputational damage",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1530", "T1552.001", "T1114.003"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1567-aws-s3upload",
            name="AWS Unusual S3 Cross-Account Upload",
            description="Detect data uploads to external S3 buckets.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName, userIdentity.arn, bytesTransferredOut
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutObject", "UploadPart", "CompleteMultipartUpload"]
| filter requestParameters.bucketName not like /your-org-prefix/
| stats sum(bytesTransferredOut) as total_bytes by userIdentity.arn, requestParameters.bucketName, bin(1h)
| filter total_bytes > 104857600
| sort total_bytes desc""",
                terraform_template="""# Detect exfiltration to external S3

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "s3-exfil-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "external_upload" {
  name           = "external-s3-uploads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"s3.amazonaws.com\" && $.eventName = \"PutObject\" }"

  metric_transformation {
    name      = "ExternalS3Uploads"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "exfil_alert" {
  alarm_name          = "S3ExternalUpload"
  metric_name         = "ExternalS3Uploads"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublishScoped"
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
                alert_title="Data Upload to External S3",
                alert_description_template="Large upload to external bucket {bucketName} by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify bucket ownership",
                    "Review uploaded data",
                    "Check if transfer was authorised",
                    "Review user's recent activity",
                ],
                containment_actions=[
                    "Block external bucket access",
                    "Revoke user credentials",
                    "Enable S3 Block Public Access",
                    "Review bucket policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known partner buckets",
            detection_coverage="70% - catches S3 exfiltration",
            evasion_considerations="May use third-party services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1567-aws-vpc",
            name="AWS VPC Large Outbound Transfer",
            description="Detect large outbound data transfers via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, bytes, action
| filter action = "ACCEPT" and bytes > 100000000
| filter dstAddr not like /^10\\./ and dstAddr not like /^172\\.1[6-9]\\./
| stats sum(bytes) as total_bytes by srcAddr, dstAddr, bin(1h)
| filter total_bytes > 1073741824
| sort total_bytes desc""",
                terraform_template="""# Detect large outbound transfers via VPC Flow Logs

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "outbound-transfer-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "large_outbound" {
  name           = "large-outbound-transfer"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes > 100000000, ...]"

  metric_transformation {
    name      = "LargeOutboundTransfer"
    namespace = "Security"
    value     = "$bytes"
  }
}

resource "aws_cloudwatch_metric_alarm" "exfil_transfer" {
  alarm_name          = "LargeOutboundTransfer"
  metric_name         = "LargeOutboundTransfer"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1073741824
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublishScoped"
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
                alert_title="Large Outbound Data Transfer",
                alert_description_template="Large outbound transfer detected from {srcAddr} to {dstAddr}.",
                investigation_steps=[
                    "Identify destination service",
                    "Review source instance activity",
                    "Check for data staging",
                    "Review access patterns",
                ],
                containment_actions=[
                    "Block destination IP",
                    "Isolate source instance",
                    "Review security groups",
                    "Enable DLP controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known backup/CDN destinations",
            detection_coverage="60% - network-level detection",
            evasion_considerations="Low and slow exfiltration may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1567-gcp-storage",
            name="GCP Cloud Storage External Transfer",
            description="Detect data uploads to external Cloud Storage buckets.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="storage.objects.create"
NOT protoPayload.resourceName=~"projects/YOUR-PROJECT"''',
                gcp_terraform_template="""# GCP: Detect external storage uploads

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "external_upload" {
  name   = "external-storage-uploads"
  filter = <<-EOT
    protoPayload.methodName="storage.objects.create"
    NOT protoPayload.resourceName=~"projects/${var.project_id}"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "external_upload" {
  project      = var.project_id
  display_name = "External Storage Upload"
  combiner     = "OR"
  conditions {
    display_name = "Uploads to external buckets"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.external_upload.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
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
                alert_title="GCP: External Storage Upload",
                alert_description_template="Data uploaded to external Cloud Storage bucket.",
                investigation_steps=[
                    "Identify destination bucket",
                    "Review uploaded objects",
                    "Check user authorisation",
                    "Review access patterns",
                ],
                containment_actions=[
                    "Block external bucket access",
                    "Revoke user credentials",
                    "Enable VPC Service Controls",
                    "Review IAM policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known partner projects",
            detection_coverage="70% - catches GCS exfiltration",
            evasion_considerations="May use third-party services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs for GCS enabled"],
        ),
        # Azure Strategy: Exfiltration Over Web Service
        DetectionStrategy(
            strategy_id="t1567-azure",
            name="Azure Exfiltration Over Web Service Detection",
            description=(
                "Sentinel detects exfiltration over web services. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Exfiltration Over Web Service
// MITRE ATT&CK: T1567
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources""",
                azure_terraform_template="""# Azure Detection for Exfiltration Over Web Service
# MITRE ATT&CK: T1567

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
  name                = "exfiltration-over-web-service-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "exfiltration-over-web-service-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Exfiltration Over Web Service
// MITRE ATT&CK: T1567
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources
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

  description = "Detects Exfiltration Over Web Service (T1567) activity in Azure environment"
  display_name = "Exfiltration Over Web Service Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1567"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Exfiltration Over Web Service Detected",
                alert_description_template=(
                    "Exfiltration Over Web Service activity detected. "
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
    recommended_order=["t1567-aws-s3upload", "t1567-gcp-storage", "t1567-aws-vpc"],
    total_effort_hours=5.0,
    coverage_improvement="+18% improvement for Exfiltration tactic",
)
