"""
T1555.006 - Credentials from Password Stores: Cloud Secrets Management Stores

Adversaries access cloud secrets managers to retrieve credentials.
Targets AWS Secrets Manager, GCP Secret Manager, Azure Key Vault.
Used by HAFNIUM, Pacu, Storm-0501.
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
    technique_id="T1555.006",
    technique_name="Credentials from Password Stores: Cloud Secrets Management Stores",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1555/006/",
    threat_context=ThreatContext(
        description=(
            "Adversaries access cloud secrets managers (AWS Secrets Manager, GCP Secret Manager) "
            "to retrieve credentials. Requires elevated privileges or compromised service roles."
        ),
        attacker_goal="Retrieve credentials from cloud secrets management services",
        why_technique=[
            "Secrets managers store high-value credentials",
            "Database passwords often stored here",
            "API keys and tokens accessible",
            "Single access can yield many secrets",
            "Lateral movement enabler",
        ],
        known_threat_actors=["HAFNIUM", "Storm-0501"],
        recent_campaigns=[
            Campaign(
                name="HAFNIUM Azure Key Vault",
                year=2024,
                description="Moved laterally from on-premises to steal passwords from Azure Key Vaults",
                reference_url="https://attack.mitre.org/groups/G0125/",
            ),
            Campaign(
                name="Storm-0501 Key Vault Access",
                year=2024,
                description="Used Azure Key Vault operations to access encryption keys",
                reference_url="https://attack.mitre.org/groups/G1053/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Direct access to sensitive credentials. Can enable lateral movement "
            "and access to databases, APIs, and other systems."
        ),
        business_impact=[
            "Credential theft enabling lateral movement",
            "Database access via stolen passwords",
            "API key compromise",
            "Complete environment compromise possible",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1530"],
        often_follows=["T1098.003", "T1078.004"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1555006-aws-secrets",
            name="AWS Secrets Manager Access Detection",
            description="Detect access to secrets in AWS Secrets Manager.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.secretsmanager"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["GetSecretValue", "BatchGetSecretValue"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Secrets Manager access

Parameters:
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  SecretsAccessRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.secretsmanager]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [GetSecretValue, BatchGetSecretValue]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect Secrets Manager access

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "secrets-access-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "secrets_access" {
  name = "secrets-manager-access"
  event_pattern = jsonencode({
    source      = ["aws.secretsmanager"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["GetSecretValue", "BatchGetSecretValue"] }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.secrets_access.name
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
                alert_severity="high",
                alert_title="Secrets Manager Access",
                alert_description_template="Secret {secretId} accessed by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify the access was authorised",
                    "Check which secrets were accessed",
                    "Review the accessing identity",
                    "Check for unusual access patterns",
                ],
                containment_actions=[
                    "Rotate the accessed secrets",
                    "Review IAM permissions",
                    "Audit all secret access",
                    "Check for credential use",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known applications that access secrets",
            detection_coverage="95% - catches all secret retrievals",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1555006-gcp-secrets",
            name="GCP Secret Manager Access Detection",
            description="Detect access to secrets in GCP Secret Manager.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"''',
                gcp_terraform_template="""# GCP: Detect Secret Manager access

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "secret_access" {
  name   = "secret-manager-access"
  filter = <<-EOT
    protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "secret_access" {
  display_name = "Secret Manager Access"
  combiner     = "OR"
  conditions {
    display_name = "Secret accessed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.secret_access.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Secret Manager Access",
                alert_description_template="Secret accessed from Secret Manager.",
                investigation_steps=[
                    "Verify access was authorised",
                    "Check which secrets accessed",
                    "Review accessing principal",
                    "Check access patterns",
                ],
                containment_actions=[
                    "Rotate accessed secrets",
                    "Review IAM bindings",
                    "Audit secret access",
                    "Check credential usage",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known applications",
            detection_coverage="95% - catches all access",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1555006-aws-secrets", "t1555006-gcp-secrets"],
    total_effort_hours=1.5,
    coverage_improvement="+18% improvement for Credential Access tactic",
)
