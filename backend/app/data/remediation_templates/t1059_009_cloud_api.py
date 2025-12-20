"""
T1059.009 - Command and Scripting Interpreter: Cloud API

Adversaries use cloud APIs to execute commands and manage resources.
Used by APT29, Storm-0501, TeamTNT.
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
    technique_id="T1059.009",
    technique_name="Command and Scripting Interpreter: Cloud API",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1059/009/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit cloud APIs to execute commands across cloud environments. "
            "Using CLIs, cloud shells, PowerShell modules, and SDKs, attackers can control "
            "compute, storage, IAM, and security policies."
        ),
        attacker_goal="Execute commands via cloud APIs using compromised credentials",
        why_technique=[
            "Broad access to cloud resources",
            "Programmatic control over infrastructure",
            "Can modify security settings",
            "Enables automated attacks",
            "Hard to distinguish from legitimate admin",
        ],
        known_threat_actors=["APT29", "Storm-0501", "TeamTNT"],
        recent_campaigns=[
            Campaign(
                name="APT29 Microsoft Graph API",
                year=2024,
                description="Leveraged Microsoft Graph API across Azure and M365 environments",
                reference_url="https://attack.mitre.org/groups/G0016/",
            ),
            Campaign(
                name="TeamTNT AWS CLI Enumeration",
                year=2024,
                description="Employed AWS CLI to enumerate cloud environments with stolen credentials",
                reference_url="https://attack.mitre.org/groups/G0139/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Cloud APIs provide extensive control over infrastructure. "
            "Compromised API access can lead to full environment takeover."
        ),
        business_impact=[
            "Infrastructure modification",
            "Data exfiltration",
            "Resource hijacking",
            "Security control bypass",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1530", "T1496.001", "T1562.008"],
        often_follows=["T1078.004", "T1552.005"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1059009-aws-cli",
            name="AWS CLI/SDK Anomaly Detection",
            description="Detect unusual AWS CLI or SDK usage patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, userAgent, eventName, sourceIPAddress
| filter userAgent like /aws-cli|boto|sdk/
| stats count(*) as api_calls by userIdentity.arn, userAgent, bin(1h)
| filter api_calls > 100
| sort api_calls desc""",
                terraform_template="""# Detect unusual CLI/SDK usage

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "cli-anomaly-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "cli_usage" {
  name           = "cli-sdk-usage"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.userAgent = \"*aws-cli*\" || $.userAgent = \"*boto*\" }"

  metric_transformation {
    name      = "CLIUsage"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "high_cli" {
  alarm_name          = "HighCLIUsage"
  metric_name         = "CLIUsage"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 500
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="High CLI/SDK API Usage",
                alert_description_template="Unusual volume of CLI/SDK API calls from {userIdentity.arn}.",
                investigation_steps=[
                    "Review API calls made",
                    "Check source IP location",
                    "Verify user identity",
                    "Check for enumeration patterns",
                ],
                containment_actions=[
                    "Rotate affected credentials",
                    "Review IAM permissions",
                    "Block suspicious IPs",
                    "Enable MFA enforcement",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal CLI usage for automation",
            detection_coverage="70% - catches high-volume abuse",
            evasion_considerations="Low and slow attacks may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1059009-aws-enum",
            name="AWS Enumeration Pattern Detection",
            description="Detect reconnaissance patterns via cloud API.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter eventName like /^(List|Describe|Get)/
| stats count(*) as enum_calls, count_distinct(eventName) as unique_apis by userIdentity.arn, bin(15m)
| filter unique_apis > 20
| sort unique_apis desc""",
                terraform_template="""# Detect enumeration patterns

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "enum-pattern-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "enum_calls" {
  name           = "enumeration-calls"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"List*\" || $.eventName = \"Describe*\" || $.eventName = \"Get*\" }"

  metric_transformation {
    name      = "EnumerationCalls"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "enum_alert" {
  alarm_name          = "EnumerationPattern"
  metric_name         = "EnumerationCalls"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 200
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Cloud API Enumeration Detected",
                alert_description_template="Enumeration pattern detected from {userIdentity.arn} - {unique_apis} unique APIs.",
                investigation_steps=[
                    "Review enumerated services",
                    "Check credential source",
                    "Review user agent string",
                    "Look for follow-up actions",
                ],
                containment_actions=[
                    "Revoke credentials",
                    "Review accessed data",
                    "Block source IP",
                    "Enable additional monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known automation tools",
            detection_coverage="80% - catches enumeration",
            evasion_considerations="Slow enumeration may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1059009-gcp-api",
            name="GCP Cloud API Anomaly Detection",
            description="Detect unusual GCP API usage patterns.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.authenticationInfo.principalEmail:*
protoPayload.methodName=~"(list|get|describe)"''',
                gcp_terraform_template="""# GCP: Detect API anomalies

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "api_usage" {
  name   = "cloud-api-anomaly"
  filter = <<-EOT
    protoPayload.methodName=~"list|get|describe"
    protoPayload.authenticationInfo.principalEmail:*
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "api_alert" {
  display_name = "Cloud API Anomaly"
  combiner     = "OR"
  conditions {
    display_name = "High API usage"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.api_usage.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 500
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: API Anomaly Detected",
                alert_description_template="Unusual GCP API usage pattern detected.",
                investigation_steps=[
                    "Review API methods called",
                    "Check principal identity",
                    "Review accessed resources",
                    "Check for enumeration",
                ],
                containment_actions=[
                    "Revoke service account keys",
                    "Review IAM bindings",
                    "Enable VPC Service Controls",
                    "Block suspicious IPs",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal API patterns",
            detection_coverage="70% - catches enumeration",
            evasion_considerations="May blend with normal usage",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1059009-aws-enum", "t1059009-aws-cli", "t1059009-gcp-api"],
    total_effort_hours=5.0,
    coverage_improvement="+15% improvement for Execution tactic",
)
