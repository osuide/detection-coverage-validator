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
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
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
        # =====================================================================
        # STRATEGY 1: AWS ECR Image Scan Findings (Recommended)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1525-aws-ecr-scan",
            name="AWS ECR Image Scan Vulnerability Detection",
            description=(
                "Detect vulnerabilities and malware in container images using ECR "
                "native scanning or Amazon Inspector. Triggers on scan completion. "
                "See: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ecr"],
                    "detail-type": ["ECR Image Scan"],
                    "detail": {"scan-status": ["COMPLETE"]},
                },
                terraform_template="""# AWS ECR Image Scanning with Inspector
# Detects: Vulnerabilities and malware in container images
# See: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html

variable "alert_email" {
  type        = string
  description = "Email for image security alerts"
}

variable "ecr_repository_name" {
  type        = string
  description = "ECR repository name to enable scanning"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "image_scan_alerts" {
  name              = "ecr-image-scan-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.image_scan_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Enable enhanced scanning with Inspector
resource "aws_ecr_registry_scanning_configuration" "enhanced" {
  scan_type = "ENHANCED"

  rule {
    scan_frequency = "SCAN_ON_PUSH"
    repository_filter {
      filter      = "*"
      filter_type = "WILDCARD"
    }
  }
}

# Step 3: EventBridge rule for scan findings
resource "aws_cloudwatch_event_rule" "image_scan_findings" {
  name        = "ecr-image-scan-findings"
  description = "Detect vulnerabilities in container images"

  event_pattern = jsonencode({
    source      = ["aws.ecr"]
    detail-type = ["ECR Image Scan"]
    detail = {
      scan-status        = ["COMPLETE"]
      finding-severity-counts = {
        CRITICAL = [{ exists = true }]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.image_scan_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.image_scan_alerts.arn

  input_transformer {
    input_paths = {
      repository = "$.detail.repository-name"
      tag        = "$.detail.image-tags[0]"
      critical   = "$.detail.finding-severity-counts.CRITICAL"
      high       = "$.detail.finding-severity-counts.HIGH"
    }
    input_template = <<-EOF
      "ECR Image Scan Alert - Critical Vulnerabilities Found"
      "Repository: <repository>"
      "Tag: <tag>"
      "Critical: <critical>, High: <high>"
      "Action: Do NOT deploy this image until vulnerabilities are remediated"
    EOF
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.image_scan_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.image_scan_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

# Step 4: Lambda to block deployment of vulnerable images (optional)
resource "aws_lambda_function" "block_vulnerable_deploy" {
  function_name = "block-vulnerable-image-deploy"
  runtime       = "python3.11"
  handler       = "index.handler"
  role          = aws_iam_role.lambda_role.arn
  timeout       = 30

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      CRITICAL_THRESHOLD = "0"
      HIGH_THRESHOLD     = "5"
    }
  }
}""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect vulnerabilities in ECR container images

Parameters:
  AlertEmail:
    Type: String
    Description: Email for image security alerts

Resources:
  # Step 1: Create SNS topic with encryption
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: ecr-image-scan-alerts
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for critical findings
  ImageScanRule:
    Type: AWS::Events::Rule
    Properties:
      Name: ecr-critical-vulnerabilities
      Description: Alert on critical vulnerabilities in container images
      EventPattern:
        source:
          - aws.ecr
        detail-type:
          - ECR Image Scan
        detail:
          scan-status:
            - COMPLETE
          finding-severity-counts:
            CRITICAL:
              - exists: true
      Targets:
        - Id: AlertTopic
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                alert_severity="critical",
                alert_title="ECR Image Scan: Critical Vulnerabilities Found",
                alert_description_template=(
                    "Container image {repository-name}:{image-tag} contains critical "
                    "vulnerabilities. Do not deploy until remediated."
                ),
                investigation_steps=[
                    "Review the specific CVEs found in the scan",
                    "Check if base image needs updating",
                    "Identify which packages are vulnerable",
                    "Check if patches are available",
                    "Review if image is already deployed",
                ],
                containment_actions=[
                    "Block deployment of vulnerable images",
                    "Update base images to patched versions",
                    "Implement admission controllers to prevent deployment",
                    "Roll back any deployments using this image",
                    "Enable Binary Authorisation patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Some vulnerabilities may not be exploitable in context. "
                "Use vulnerability exception lists for accepted risks. "
                "Focus on CRITICAL and HIGH severity."
            ),
            detection_coverage="95% - scans all pushed images",
            evasion_considerations="Zero-day vulnerabilities not in databases",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "Enhanced scanning: $0.11 per image. "
                "See: https://aws.amazon.com/ecr/pricing/"
            ),
            prerequisites=[
                "ECR repository",
                "Inspector enabled (for enhanced scanning)",
            ],
        ),
        # =====================================================================
        # STRATEGY 2: AWS ECR Image Push Detection
        # =====================================================================
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
      KmsMasterKeyId: alias/aws/sns
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
  kms_master_key_id = "alias/aws/sns"
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
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
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
    recommended_order=[
        "t1525-aws-ecr-scan",
        "t1525-aws-ecr",
        "t1525-gcp-gcr",
    ],
    total_effort_hours=2.0,
    coverage_improvement="+15% improvement for Persistence tactic",
)
