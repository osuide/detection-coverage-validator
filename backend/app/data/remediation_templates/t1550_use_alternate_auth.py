"""
T1550 - Use Alternate Authentication Material

Adversaries use stolen authentication artefacts to bypass access controls.
Used by APT29 (SAML token forging), FoggyWeb.
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
    technique_id="T1550",
    technique_name="Use Alternate Authentication Material",
    tactic_ids=["TA0005", "TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1550/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage stolen authentication artefacts like password hashes, "
            "Kerberos tickets, OAuth tokens, and SAML assertions to bypass authentication. "
            "In cloud environments, this includes stolen access tokens and session cookies."
        ),
        attacker_goal="Bypass authentication using stolen tokens, cookies, or credentials",
        why_technique=[
            "Bypasses MFA requirements",
            "Tokens persist after password change",
            "Forged SAML grants broad access",
            "Session cookies avoid re-authentication",
            "Hard to distinguish from legitimate use",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Critical technique that bypasses MFA. Forged SAML tokens grant "
            "persistent access across cloud services."
        ),
        business_impact=[
            "MFA bypass",
            "Persistent unauthorised access",
            "Broad cloud service access",
            "Difficult detection",
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1021.007", "T1530"],
        often_follows=["T1552.001", "T1552.005", "T1528"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1550-aws-token",
            name="AWS Token Reuse Detection",
            description="Detect access token usage from unusual locations or patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, userIdentity.accessKeyId, sourceIPAddress, eventName
| filter userIdentity.type = "IAMUser" or userIdentity.type = "AssumedRole"
| stats count(*) as api_calls, count_distinct(sourceIPAddress) as unique_ips by userIdentity.accessKeyId, bin(1h)
| filter unique_ips > 3
| sort unique_ips desc""",
                terraform_template="""# Detect token reuse from multiple locations

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "token-reuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Use CloudWatch Insights for complex queries
# Alert on GuardDuty finding for impossible travel
resource "aws_cloudwatch_event_rule" "impossible_travel" {
  name = "impossible-travel-detection"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" },
        { prefix = "InitialAccess:IAMUser/AnomalousBehavior" }
      ]
    }
  })
}

# DLQ for failed events
resource "aws_sqs_queue" "dlq" {
  name                      = "impossible-travel-detection-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "dlq" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.impossible_travel.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.impossible_travel.name
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.impossible_travel.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Possible Token Reuse Detected",
                alert_description_template="Access key {accessKeyId} used from multiple IPs.",
                investigation_steps=[
                    "Review IP locations for impossible travel",
                    "Check if token was compromised",
                    "Review API calls made",
                    "Check for credential theft indicators",
                ],
                containment_actions=[
                    "Rotate access keys immediately",
                    "Revoke active sessions",
                    "Review IAM user activity",
                    "Enable MFA if not set",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude VPN exit nodes and mobile users",
            detection_coverage="75% - catches multi-location reuse",
            evasion_considerations="Attacker may use same IP range",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1550-aws-sts",
            name="AWS STS Token Anomaly Detection",
            description="Detect unusual STS token usage patterns.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                ],
                terraform_template="""# Enable GuardDuty for token anomaly detection

variable "alert_email" { type = string }

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_sns_topic" "alerts" {
  name = "guardduty-token-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "token_anomaly" {
  name = "guardduty-token-anomaly"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" },
        { prefix = "CredentialAccess:IAMUser/AnomalousBehavior" }
      ]
    }
  })
}

# DLQ for token anomaly detection
resource "aws_sqs_queue" "token_dlq" {
  name                      = "token-anomaly-detection-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "token_dlq" {
  queue_url = aws_sqs_queue.token_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.token_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.token_anomaly.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.token_anomaly.name
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.token_dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

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
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.token_anomaly.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="AWS Credential Exfiltration Detected",
                alert_description_template="GuardDuty detected credential theft: {type}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Identify compromised credential",
                    "Review all API calls from credential",
                    "Check source of exfiltration",
                ],
                containment_actions=[
                    "Rotate compromised credentials",
                    "Revoke all active sessions",
                    "Block source IP if applicable",
                    "Review instance for compromise",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty has built-in ML tuning",
            detection_coverage="90% - ML-based detection",
            evasion_considerations="Novel patterns may evade initial detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-30",
            prerequisites=["GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1550-gcp-token",
            name="GCP Token Anomaly Detection",
            description="Detect unusual service account token usage.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.authenticationInfo.serviceAccountDelegationInfo:*
OR protoPayload.authenticationInfo.principalSubject=~"serviceAccount:"''',
                gcp_terraform_template="""# GCP: Detect token anomalies

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Monitor for service account token usage from unusual sources
resource "google_logging_metric" "token_usage" {
  name   = "sa-token-anomaly"
  filter = <<-EOT
    protoPayload.authenticationInfo.serviceAccountDelegationInfo:*
    OR protoPayload.authenticationInfo.principalSubject=~"serviceAccount:"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "token_alert" {
  display_name = "Service Account Token Anomaly"
  combiner     = "OR"
  conditions {
    display_name = "Unusual SA token usage"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.token_usage.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Token Anomaly Detected",
                alert_description_template="Unusual service account token usage detected.",
                investigation_steps=[
                    "Review token delegation chain",
                    "Check source of API calls",
                    "Review accessed resources",
                    "Check for impossible travel",
                ],
                containment_actions=[
                    "Delete compromised SA keys",
                    "Disable service account",
                    "Review IAM bindings",
                    "Check for persistence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal SA usage patterns",
            detection_coverage="75% - catches token delegation abuse",
            evasion_considerations="May use legitimate delegation paths",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1550-aws-sts", "t1550-aws-token", "t1550-gcp-token"],
    total_effort_hours=4.0,
    coverage_improvement="+20% improvement for Defense Evasion and Lateral Movement tactics",
)
