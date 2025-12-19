"""
T1021.007 - Remote Services: Cloud Services

Adversaries use valid cloud credentials to move laterally via cloud services.
Used by APT29, Scattered Spider, Storm-0501.
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
    technique_id="T1021.007",
    technique_name="Remote Services: Cloud Services",
    tactic_ids=["TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1021/007/",

    threat_context=ThreatContext(
        description=(
            "Adversaries exploit synchronised or federated user identities to access "
            "cloud services using valid accounts. They authenticate via web consoles, "
            "CLI tools, or access tokens to move laterally within cloud environments."
        ),
        attacker_goal="Move laterally using valid cloud credentials and federated identities",
        why_technique=[
            "Federated identities span environments",
            "Single credential unlocks multiple services",
            "Appears as legitimate user activity",
            "CLI tools provide broad access",
            "OAuth tokens persist after password change"
        ],
        known_threat_actors=["APT29", "Scattered Spider", "Storm-0501"],
        recent_campaigns=[
            Campaign(
                name="APT29 Office 365 Lateral Movement",
                year=2024,
                description="Leveraged compromised high-privileged on-premises accounts synced to Office 365",
                reference_url="https://attack.mitre.org/groups/G0016/"
            ),
            Campaign(
                name="Scattered Spider Cloud Access",
                year=2024,
                description="Used compromised Azure credentials and leveraged pre-existing AWS EC2 instances",
                reference_url="https://attack.mitre.org/groups/G1015/"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Enables lateral movement across cloud services using legitimate credentials. "
            "Hard to distinguish from normal user activity."
        ),
        business_impact=[
            "Cross-cloud lateral movement",
            "Data access across services",
            "Privilege escalation risk",
            "Difficult attribution"
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1530", "T1552.005"],
        often_follows=["T1078.004", "T1110"]
    ),

    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1021007-aws-unusual",
            name="AWS Unusual Console/CLI Access",
            description="Detect unusual cloud service access patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn, sourceIPAddress, userAgent, eventName
| filter eventSource in ["signin.amazonaws.com", "sts.amazonaws.com"]
| filter eventName in ["ConsoleLogin", "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"]
| stats count(*) as access_count by userIdentity.arn, sourceIPAddress, bin(1h)
| filter access_count > 1
| sort @timestamp desc''',
                terraform_template='''# Detect unusual cloud service access

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "cloud-lateral-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "unusual_access" {
  name           = "unusual-cloud-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"AssumeRole*\" || $.eventName = \"ConsoleLogin\" }"

  metric_transformation {
    name      = "UnusualCloudAccess"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "lateral_movement" {
  alarm_name          = "CloudLateralMovement"
  metric_name         = "UnusualCloudAccess"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}''',
                alert_severity="high",
                alert_title="Unusual Cloud Service Access",
                alert_description_template="Multiple cloud service access events from {userIdentity.arn}.",
                investigation_steps=[
                    "Review source IP and user agent",
                    "Check if access is from expected location",
                    "Review subsequent API calls",
                    "Check for federated identity abuse"
                ],
                containment_actions=[
                    "Revoke active sessions",
                    "Rotate credentials",
                    "Review role trust policies",
                    "Check for persistence mechanisms"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal user access patterns",
            detection_coverage="75% - catches role assumptions",
            evasion_considerations="May use legitimate user patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1021007-aws-federation",
            name="AWS Federated Access Detection",
            description="Detect federated identity access via SAML/OIDC.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.sts"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"]
                    }
                },
                terraform_template='''# Detect federated identity access

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "federated-access-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "federated" {
  name = "federated-access"
  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"] }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.federated.name
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
}''',
                alert_severity="medium",
                alert_title="Federated Identity Access",
                alert_description_template="Federated access via {eventName} to role {requestParameters.roleArn}.",
                investigation_steps=[
                    "Verify identity provider is trusted",
                    "Check user identity in SAML assertion",
                    "Review accessed resources",
                    "Check for unusual timing"
                ],
                containment_actions=[
                    "Revoke federation trust if compromised",
                    "Review IdP logs",
                    "Update role trust policies",
                    "Enable MFA requirements"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter known IdP sources",
            detection_coverage="90% - catches federated access",
            evasion_considerations="Cannot evade if CloudTrail enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "STS logging enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1021007-gcp-lateral",
            name="GCP Cross-Project Access Detection",
            description="Detect access to multiple GCP projects.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.authenticationInfo.principalEmail:*
protoPayload.methodName=~"(CreateServiceAccountKey|SignBlob|GenerateAccessToken)"
OR protoPayload.serviceName="iamcredentials.googleapis.com"''',
                gcp_terraform_template='''# GCP: Detect lateral movement via cloud services

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "lateral_access" {
  name   = "cloud-lateral-movement"
  filter = <<-EOT
    protoPayload.serviceName="iamcredentials.googleapis.com"
    OR protoPayload.methodName=~"CreateServiceAccountKey|GenerateAccessToken"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "lateral_access" {
  display_name = "Cloud Lateral Movement"
  combiner     = "OR"
  conditions {
    display_name = "Service account token generation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.lateral_access.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}''',
                alert_severity="high",
                alert_title="GCP: Lateral Movement Detected",
                alert_description_template="Cross-project or service account access detected.",
                investigation_steps=[
                    "Review principal identity",
                    "Check accessed projects",
                    "Review token generation events",
                    "Check for unusual patterns"
                ],
                containment_actions=[
                    "Revoke service account keys",
                    "Review IAM bindings",
                    "Enable VPC Service Controls",
                    "Review access logs"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal cross-project access",
            detection_coverage="80% - catches token generation",
            evasion_considerations="May use legitimate patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"]
        )
    ],

    recommended_order=["t1021007-aws-federation", "t1021007-aws-unusual", "t1021007-gcp-lateral"],
    total_effort_hours=4.0,
    coverage_improvement="+15% improvement for Lateral Movement tactic"
)
