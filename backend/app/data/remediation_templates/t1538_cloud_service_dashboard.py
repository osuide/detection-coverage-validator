"""
T1538 - Cloud Service Dashboard

Adversaries use cloud dashboards for reconnaissance without API calls.
Used by Scattered Spider.
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
    technique_id="T1538",
    technique_name="Cloud Service Dashboard",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1538/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit stolen credentials to access cloud service dashboards "
            "and extract operational intelligence. This enables reconnaissance of services, "
            "resources, and features without direct API requests."
        ),
        attacker_goal="Discover cloud resources and configurations via web dashboards",
        why_technique=[
            "Visual overview of resources",
            "May show more than API access",
            "No API calls to detect",
            "Easy navigation of services",
            "Browser-based access blends in",
        ],
        known_threat_actors=["Scattered Spider"],
        recent_campaigns=[
            Campaign(
                name="Scattered Spider AWS Dashboard Recon",
                year=2024,
                description="Abused AWS Systems Manager Inventory to identify targets prior to lateral movement",
                reference_url="https://attack.mitre.org/groups/G1015/",
            )
        ],
        prevalence="moderate",
        trend="stable",
        severity_score=5,
        severity_reasoning=(
            "Discovery technique that precedes more impactful attacks. "
            "Provides attacker with environment understanding."
        ),
        business_impact=[
            "Environment reconnaissance",
            "Attack planning enablement",
            "Resource discovery",
            "Configuration exposure",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1530", "T1021.007", "T1059.009"],
        often_follows=["T1078.004", "T1110"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1538-aws-console",
            name="AWS Console Access Anomaly Detection",
            description="Detect unusual AWS console access patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, sourceIPAddress, eventName, userAgent
| filter eventSource = "signin.amazonaws.com"
| filter eventName = "ConsoleLogin"
| stats count(*) as logins by userIdentity.arn, sourceIPAddress, bin(1d)
| sort logins desc""",
                terraform_template="""# Detect unusual console access

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "console-access-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "console_login" {
  name = "console-login-detection"
  event_pattern = jsonencode({
    source      = ["aws.signin"]
    detail-type = ["AWS Console Sign In via CloudTrail"]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.console_login.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="AWS Console Login Detected",
                alert_description_template="Console login by {userIdentity.arn} from {sourceIPAddress}.",
                investigation_steps=[
                    "Verify login was authorised",
                    "Check source IP geolocation",
                    "Review subsequent console activity",
                    "Check for unusual navigation patterns",
                ],
                containment_actions=[
                    "Force session logout",
                    "Reset user credentials",
                    "Enable MFA if not set",
                    "Review IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Filter known admin users and IPs",
            detection_coverage="60% - catches console logins",
            evasion_considerations="Cannot distinguish legitimate from malicious browsing",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1538-aws-ssm",
            name="AWS Systems Manager Dashboard Access",
            description="Detect SSM inventory and dashboard access.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, sourceIPAddress
| filter eventSource = "ssm.amazonaws.com"
| filter eventName like /^(Describe|List|Get)/
| stats count(*) as ssm_calls by userIdentity.arn, bin(1h)
| filter ssm_calls > 20
| sort ssm_calls desc""",
                terraform_template="""# Detect SSM dashboard reconnaissance

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ssm-recon-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "ssm_recon" {
  name           = "ssm-reconnaissance"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ssm.amazonaws.com\" && ($.eventName = \"Describe*\" || $.eventName = \"List*\") }"

  metric_transformation {
    name      = "SSMReconnaissance"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ssm_recon" {
  alarm_name          = "SSMReconnaissance"
  metric_name         = "SSMReconnaissance"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 30
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="SSM Dashboard Reconnaissance",
                alert_description_template="Heavy SSM inventory access by {userIdentity.arn}.",
                investigation_steps=[
                    "Review SSM queries made",
                    "Check target instances",
                    "Verify user authorisation",
                    "Look for lateral movement",
                ],
                containment_actions=[
                    "Restrict SSM permissions",
                    "Review user access",
                    "Enable session logging",
                    "Audit managed instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal SSM admin activity",
            detection_coverage="75% - catches SSM recon",
            evasion_considerations="May blend with normal admin",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1538-gcp-console",
            name="GCP Console Access Anomaly Detection",
            description="Detect unusual GCP console access patterns.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName=~"(GetProject|ListProjects|GetIamPolicy)"
protoPayload.authenticationInfo.principalEmail:*""",
                gcp_terraform_template="""# GCP: Detect console reconnaissance

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "console_recon" {
  name   = "console-reconnaissance"
  filter = <<-EOT
    protoPayload.methodName=~"GetProject|ListProjects|GetIamPolicy|ListInstances"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "console_recon" {
  display_name = "Console Reconnaissance"
  combiner     = "OR"
  conditions {
    display_name = "High dashboard activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.console_recon.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Console Reconnaissance",
                alert_description_template="Unusual console activity detected.",
                investigation_steps=[
                    "Review accessed resources",
                    "Check principal identity",
                    "Verify access was authorised",
                    "Look for follow-up actions",
                ],
                containment_actions=[
                    "Revoke user session",
                    "Review IAM permissions",
                    "Enable 2FA if not set",
                    "Audit project access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal console patterns",
            detection_coverage="65% - catches console recon",
            evasion_considerations="Hard to distinguish from legitimate browsing",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1538-aws-ssm", "t1538-aws-console", "t1538-gcp-console"],
    total_effort_hours=3.0,
    coverage_improvement="+10% improvement for Discovery tactic",
)
