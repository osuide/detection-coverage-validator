"""
T1114.003 - Email Collection: Email Forwarding Rule

Adversaries create email forwarding rules to monitor victims and exfiltrate data.
Used by LAPSUS$, Scattered Spider, Kimsuky, Silent Librarian.
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
    technique_id="T1114.003",
    technique_name="Email Collection: Email Forwarding Rule",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1114/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries create email forwarding rules to monitor victims and collect "
            "sensitive data. Rules persist even after credential resets. Can be hidden "
            "using MAPI or created at tenant level."
        ),
        attacker_goal="Maintain persistent email access via forwarding rules",
        why_technique=[
            "Persists after password reset",
            "Silent data exfiltration",
            "Can forward all org email",
            "Hidden rules evade detection",
            "Captures MFA codes and alerts",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Persistent access that survives credential resets. "
            "Can capture all organisation email. Hard to detect."
        ),
        business_impact=[
            "Email data exfiltration",
            "Persistent monitoring",
            "Security alert bypass",
            "Compliance violations",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1530"],
        often_follows=["T1078.004", "T1621"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1114003-aws-ses",
            name="AWS SES/WorkMail Forwarding Detection",
            description="Detect email forwarding configuration changes.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventSource = "workmail.amazonaws.com" or eventSource = "ses.amazonaws.com"
| filter eventName like /Forward|Rule|Redirect/
| sort @timestamp desc""",
                terraform_template="""# Detect email forwarding changes

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "email-forward-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "email_forward" {
  name           = "email-forwarding-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"workmail.amazonaws.com\" && $.eventName = \"*Rule*\" }"

  metric_transformation {
    name      = "EmailForwardingChanges"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "email_forward" {
  alarm_name          = "EmailForwardingChange"
  metric_name         = "EmailForwardingChanges"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Email Forwarding Rule Created",
                alert_description_template="Email forwarding configuration changed by {userIdentity.arn}.",
                investigation_steps=[
                    "Review the forwarding rule",
                    "Check destination address",
                    "Verify rule was authorised",
                    "Check for other rules",
                ],
                containment_actions=[
                    "Delete unauthorised rules",
                    "Reset affected credentials",
                    "Review all forwarding rules",
                    "Block external forwarding",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Forwarding rules are infrequent",
            detection_coverage="90% - catches API-based rules",
            evasion_considerations="Hidden MAPI rules may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled for WorkMail/SES"],
        ),
        DetectionStrategy(
            strategy_id="t1114003-gcp-workspace",
            name="Google Workspace Forwarding Detection",
            description="Detect email forwarding rule creation in Workspace.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"gmail.users.settings.forwardingAddresses"
OR protoPayload.serviceName="admin.googleapis.com" AND protoPayload.methodName=~"CHANGE_EMAIL_SETTINGS"''',
                gcp_terraform_template="""# GCP: Detect Workspace email forwarding

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "email_forward" {
  name   = "email-forwarding-rules"
  filter = <<-EOT
    protoPayload.methodName=~"gmail.*forward|CHANGE_EMAIL_SETTINGS"
    OR protoPayload.serviceName="admin.googleapis.com"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "email_forward" {
  display_name = "Email Forwarding Rule"
  combiner     = "OR"
  conditions {
    display_name = "Forwarding rule created"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.email_forward.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Email Forwarding Rule Created",
                alert_description_template="Email forwarding rule was created or modified.",
                investigation_steps=[
                    "Review the forwarding rule",
                    "Check destination",
                    "Verify authorisation",
                    "Check user's other settings",
                ],
                containment_actions=[
                    "Delete unauthorised rules",
                    "Reset credentials",
                    "Review all user rules",
                    "Disable external forwarding org-wide",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Forwarding is typically rare",
            detection_coverage="85% - catches Workspace rules",
            evasion_considerations="Some rules may be hidden",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Workspace audit logs enabled"],
        ),
    ],
    recommended_order=["t1114003-aws-ses", "t1114003-gcp-workspace"],
    total_effort_hours=2.5,
    coverage_improvement="+15% improvement for Collection tactic",
)
