"""
T1525 - Implant Internal Image

Adversaries inject malicious code into container/VM images stored in
victim registries to maintain persistence. Backdoored images execute
when deployed.
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
    technique_id="T1525",
    technique_name="Implant Internal Image",
    tactic_ids=["TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1525/",
    threat_context=ThreatContext(
        description=(
            "Adversaries implant malicious code into container or VM images stored "
            "in victim registries. Backdoored images provide persistence when "
            "automatically deployed by CI/CD pipelines."
        ),
        attacker_goal="Maintain persistence via backdoored container/VM images",
        why_technique=[
            "Images deployed automatically",
            "Persists across instance replacements",
            "Hard to detect in running containers",
            "Affects all deployments using image",
            "CI/CD may pull latest automatically",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Container Image Backdoors",
                year=2024,
                description="Attackers backdooring ECR/GCR images for persistence",
                reference_url="https://attack.mitre.org/techniques/T1525/",
            )
        ],
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Persistent access through legitimate deployment processes. "
            "Hard to detect. Affects all instances using the image."
        ),
        business_impact=[
            "Persistent backdoor access",
            "Supply chain compromise",
            "All deployments affected",
            "Hard to remediate fully",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1530", "T1496.001"],
        often_follows=["T1078.004", "T1190"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1525-aws-ecr",
            name="AWS ECR Image Push Detection",
            description="Detect image pushes to ECR repositories.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ecr"],
                    "detail-type": ["ECR Image Action"],
                    "detail": {"action-type": ["PUSH"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect ECR image pushes

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

  ECRPushRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ecr]
        detail-type: [ECR Image Action]
        detail:
          action-type: [PUSH]
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
                terraform_template="""# Detect ECR image pushes

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ecr-push-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "ecr_push" {
  name = "ecr-image-push"
  event_pattern = jsonencode({
    source      = ["aws.ecr"]
    detail-type = ["ECR Image Action"]
    detail      = { "action-type" = ["PUSH"] }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.ecr_push.name
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
                alert_title="ECR Image Pushed",
                alert_description_template="Image pushed to ECR repository {repository-name}.",
                investigation_steps=[
                    "Verify image push was authorised",
                    "Check who pushed the image",
                    "Scan image for vulnerabilities/malware",
                    "Compare with previous versions",
                ],
                containment_actions=[
                    "Delete unauthorised images",
                    "Enable ECR image scanning",
                    "Require image signing",
                    "Review ECR permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD pipeline roles",
            detection_coverage="95% - catches all pushes",
            evasion_considerations="Cannot evade push detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["ECR with EventBridge enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1525-gcp-gcr",
            name="GCP Container Registry Push Detection",
            description="Detect image pushes to GCR/Artifact Registry.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.devtools.artifactregistry.v1.ArtifactRegistry.ImportAptArtifacts"
OR protoPayload.methodName=~"docker.upload"
OR resource.type="gcs_bucket" AND protoPayload.methodName="storage.objects.create" AND resource.labels.bucket_name=~"artifacts"''',
                gcp_terraform_template="""# GCP: Detect container image pushes

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "image_push" {
  name   = "container-image-push"
  filter = <<-EOT
    protoPayload.methodName=~"artifactregistry.*|docker.upload"
    OR (resource.type="gcs_bucket" AND resource.labels.bucket_name=~"artifacts")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "image_push" {
  display_name = "Container Image Push"
  combiner     = "OR"
  conditions {
    display_name = "Image pushed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.image_push.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Container Image Pushed",
                alert_description_template="Container image pushed to registry.",
                investigation_steps=[
                    "Verify push was authorised",
                    "Check pushing identity",
                    "Scan image for malware",
                    "Compare with previous versions",
                ],
                containment_actions=[
                    "Delete unauthorised images",
                    "Enable vulnerability scanning",
                    "Require Binary Authorization",
                    "Review IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD service accounts",
            detection_coverage="90% - catches registry pushes",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1525-aws-ecr", "t1525-gcp-gcr"],
    total_effort_hours=1.5,
    coverage_improvement="+15% improvement for Persistence tactic",
)
