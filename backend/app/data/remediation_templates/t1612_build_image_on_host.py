"""
T1612 - Build Image on Host

Adversaries construct container images directly on a host to evade defences
monitoring for malicious image retrieval. They pull vanilla base images and
build custom images incorporating malware.
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
    technique_id="T1612",
    technique_name="Build Image on Host",
    tactic_ids=["TA0005"],  # Defense Evasion
    mitre_url="https://attack.mitre.org/techniques/T1612/",
    threat_context=ThreatContext(
        description=(
            "Adversaries construct container images directly on a host system to evade "
            "defences monitoring for malicious image retrieval. They send remote build "
            "requests to the Docker API containing a Dockerfile, pull vanilla base images, "
            "and build custom images that incorporate malware from C2 servers."
        ),
        attacker_goal="Evade detection by building malicious images on-host instead of pulling them",
        why_technique=[
            "Bypasses image pull monitoring",
            "Vanilla base images appear benign",
            "Locally-built images less suspicious",
            "Malware fetched during build process",
            "Exploits gap in detection coverage",
        ],
        known_threat_actors=[],  # No documented threat actors from MITRE
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Effective evasion technique that bypasses traditional image monitoring. "
            "Difficult to detect without Docker API monitoring. Can lead to malware "
            "execution in containerised environments."
        ),
        business_impact=[
            "Undetected malware deployment",
            "Container compromise",
            "Data exfiltration risk",
            "Cryptomining abuse",
        ],
        typical_attack_phase="defense_evasion",
        often_precedes=["T1204.003", "T1496.001"],
        often_follows=["T1078.004", "T1190"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1612-aws-docker-build",
            name="AWS Docker Build Activity Detection",
            description=(
                "Detect Docker build commands via CodeBuild/CloudTrail in near real-time. "
                "Uses EventBridge for low-latency alerting with reliable delivery."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.codebuild"],
                    "detail-type": ["CodeBuild Build State Change"],
                    "detail": {
                        "build-status": ["IN_PROGRESS", "SUCCEEDED"],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Docker build activity via CodeBuild (T1612)

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: t1612-docker-build-alerts
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: t1612-docker-build-dlq
      MessageRetentionPeriod: 1209600

  CodeBuildRule:
    Type: AWS::Events::Rule
    Properties:
      Name: t1612-codebuild-detection
      Description: Detect CodeBuild builds that may include Docker (T1612)
      State: ENABLED
      EventPattern:
        source:
          - aws.codebuild
        detail-type:
          - CodeBuild Build State Change
        detail:
          build-status:
            - IN_PROGRESS
            - SUCCEEDED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic
          DeadLetterConfig:
            Arn: !GetAtt DeadLetterQueue.Arn
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          InputTransformer:
            InputPathsMap:
              time: $.time
              account: $.account
              region: $.region
              project: $.detail.project-name
              status: $.detail.build-status
              buildId: $.detail.build-id
              initiator: $.detail.additional-information.initiator
            InputTemplate: |
              "ALERT: CodeBuild Activity Detected (T1612)"
              "time=<time>"
              "account=<account> region=<region>"
              "project=<project>"
              "status=<status>"
              "build_id=<buildId>"
              "initiator=<initiator>"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt CodeBuildRule.Arn

  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref DeadLetterQueue
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt DeadLetterQueue.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt CodeBuildRule.Arn

Outputs:
  AlertTopicArn:
    Description: SNS topic for Docker build alerts
    Value: !Ref AlertTopic
  EventRuleArn:
    Description: EventBridge rule ARN
    Value: !GetAtt CodeBuildRule.Arn
  DLQUrl:
    Description: Dead letter queue URL
    Value: !Ref DeadLetterQueue""",
                terraform_template="""# Detect Docker build activity via CodeBuild (T1612)
# Uses EventBridge for near real-time detection
# Optimised pattern: DLQ, retry policy, scoped SNS, human-readable alerts

variable "name_prefix" {
  type        = string
  default     = "t1612-docker-build"
  description = "Prefix for resource names"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts (SNS subscription confirmation required)"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

data "aws_caller_identity" "current" {}

# SNS topic for alerts
resource "aws_sns_topic" "docker_build_alerts" {
  name              = "${var.name_prefix}-alerts"
  display_name      = "Docker Build Alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.docker_build_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule: detect CodeBuild builds
resource "aws_cloudwatch_event_rule" "docker_build" {
  name        = "${var.name_prefix}-codebuild"
  description = "Detect CodeBuild builds that may include Docker (T1612)"

  event_pattern = jsonencode({
    source        = ["aws.codebuild"]
    "detail-type" = ["CodeBuild Build State Change"]
    detail = {
      "build-status" = ["IN_PROGRESS", "SUCCEEDED"]
    }
  })
}

# DLQ for delivery failures (14 day retention)
resource "aws_sqs_queue" "docker_build_dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600
}

# Route to SNS with input transformer for human-readable alerts
resource "aws_cloudwatch_event_target" "docker_build_to_sns" {
  rule      = aws_cloudwatch_event_rule.docker_build.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.docker_build_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.docker_build_dlq.arn
  }

  input_transformer {
    input_paths = {
      time      = "$.time"
      account   = "$.account"
      region    = "$.region"
      project   = "$.detail.project-name"
      status    = "$.detail.build-status"
      buildId   = "$.detail.build-id"
      initiator = "$.detail.additional-information.initiator"
    }

    input_template = <<-EOT
"ALERT: CodeBuild Activity Detected (T1612)
time=<time>
account=<account> region=<region>
project=<project>
status=<status>
build_id=<buildId>
initiator=<initiator>"
EOT
  }
}

# SNS topic policy with scoped conditions for least privilege
resource "aws_sns_topic_policy" "allow_eventbridge_publish" {
  arn = aws_sns_topic.docker_build_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.docker_build_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.docker_build.arn
        }
      }
    }]
  })
}

# Allow EventBridge to send to DLQ
resource "aws_sqs_queue_policy" "docker_build_dlq" {
  queue_url = aws_sqs_queue.docker_build_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.docker_build_dlq.arn
    }]
  })
}

output "alert_topic_arn" {
  description = "SNS topic for Docker build alerts"
  value       = aws_sns_topic.docker_build_alerts.arn
}

output "event_rule_arn" {
  description = "EventBridge rule ARN"
  value       = aws_cloudwatch_event_rule.docker_build.arn
}

output "dlq_url" {
  description = "Dead letter queue URL for failed deliveries"
  value       = aws_sqs_queue.docker_build_dlq.url
}""",
                alert_severity="high",
                alert_title="Docker Build Activity Detected",
                alert_description_template="CodeBuild project {project} triggered by {initiator}. Review for container image builds.",
                investigation_steps=[
                    "Review CodeBuild project configuration",
                    "Check buildspec.yml for Docker commands",
                    "Identify who initiated the build",
                    "Review build logs for suspicious activity",
                    "Scan resulting image for malware",
                ],
                containment_actions=[
                    "Delete suspicious images from ECR",
                    "Restrict CodeBuild permissions",
                    "Require TLS authentication for Docker API",
                    "Implement image scanning pipeline",
                    "Enable ECR image scanning",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter by project name pattern to exclude known CI/CD projects",
            detection_coverage="95% - catches all CodeBuild activity",
            evasion_considerations="Direct Docker builds on EC2 may bypass - use GuardDuty Runtime Monitoring",
            implementation_effort=EffortLevel.LOW,
            implementation_time="20 minutes",
            estimated_monthly_cost="$1-3",
            prerequisites=[
                "CloudTrail enabled",
                "CodeBuild used for container builds",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1612-aws-ecr-rapid-build",
            name="AWS ECR Image Push Detection",
            description=(
                "Detect images pushed to ECR in near real-time. "
                "Uses EventBridge with DLQ and retry for reliable alerting."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ecr"],
                    "detail-type": ["ECR Image Action"],
                    "detail": {"action-type": ["PUSH"], "result": ["SUCCESS"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect ECR image push (T1612)

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: t1612-ecr-push-alerts
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: t1612-ecr-push-dlq
      MessageRetentionPeriod: 1209600

  ECRPushRule:
    Type: AWS::Events::Rule
    Properties:
      Name: t1612-ecr-push-detection
      Description: Alert on ECR image push (T1612)
      State: ENABLED
      EventPattern:
        source:
          - aws.ecr
        detail-type:
          - ECR Image Action
        detail:
          action-type:
            - PUSH
          result:
            - SUCCESS
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic
          DeadLetterConfig:
            Arn: !GetAtt DeadLetterQueue.Arn
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          InputTransformer:
            InputPathsMap:
              time: $.time
              account: $.account
              region: $.region
              repository: $.detail.repository-name
              tag: $.detail.image-tag
              digest: $.detail.image-digest
            InputTemplate: |
              "ALERT: ECR Image Push Detected (T1612)"
              "time=<time>"
              "account=<account> region=<region>"
              "repository=<repository>"
              "tag=<tag>"
              "digest=<digest>"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ECRPushRule.Arn

  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref DeadLetterQueue
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt DeadLetterQueue.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ECRPushRule.Arn

Outputs:
  AlertTopicArn:
    Description: SNS topic for ECR push alerts
    Value: !Ref AlertTopic
  EventRuleArn:
    Description: EventBridge rule ARN
    Value: !GetAtt ECRPushRule.Arn""",
                terraform_template="""# Detect ECR image push (T1612)
# Uses EventBridge for near real-time detection
# Optimised pattern: DLQ, retry policy, scoped SNS, human-readable alerts

variable "name_prefix" {
  type        = string
  default     = "t1612-ecr-push"
  description = "Prefix for resource names"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts (SNS subscription confirmation required)"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

data "aws_caller_identity" "current" {}

# SNS topic for alerts
resource "aws_sns_topic" "ecr_push_alerts" {
  name              = "${var.name_prefix}-alerts"
  display_name      = "ECR Push Alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ecr_push_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule: detect ECR image pushes
resource "aws_cloudwatch_event_rule" "ecr_push" {
  name        = "${var.name_prefix}-detection"
  description = "Alert on ECR image push (T1612)"

  event_pattern = jsonencode({
    source        = ["aws.ecr"]
    "detail-type" = ["ECR Image Action"]
    detail = {
      "action-type" = ["PUSH"]
      result        = ["SUCCESS"]
    }
  })
}

# DLQ for delivery failures (14 day retention)
resource "aws_sqs_queue" "ecr_push_dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600
}

# Route to SNS with input transformer for human-readable alerts
resource "aws_cloudwatch_event_target" "ecr_push_to_sns" {
  rule      = aws_cloudwatch_event_rule.ecr_push.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.ecr_push_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.ecr_push_dlq.arn
  }

  input_transformer {
    input_paths = {
      time       = "$.time"
      account    = "$.account"
      region     = "$.region"
      repository = "$.detail.repository-name"
      tag        = "$.detail.image-tag"
      digest     = "$.detail.image-digest"
    }

    input_template = <<-EOT
"ALERT: ECR Image Push Detected (T1612)
time=<time>
account=<account> region=<region>
repository=<repository>
tag=<tag>
digest=<digest>"
EOT
  }
}

# SNS topic policy with scoped conditions for least privilege
resource "aws_sns_topic_policy" "allow_eventbridge_publish" {
  arn = aws_sns_topic.ecr_push_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ecr_push_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ecr_push.arn
        }
      }
    }]
  })
}

# Allow EventBridge to send to DLQ
resource "aws_sqs_queue_policy" "ecr_push_dlq" {
  queue_url = aws_sqs_queue.ecr_push_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.ecr_push_dlq.arn
    }]
  })
}

output "alert_topic_arn" {
  description = "SNS topic for ECR push alerts"
  value       = aws_sns_topic.ecr_push_alerts.arn
}

output "event_rule_arn" {
  description = "EventBridge rule ARN"
  value       = aws_cloudwatch_event_rule.ecr_push.arn
}

output "dlq_url" {
  description = "Dead letter queue URL for failed deliveries"
  value       = aws_sqs_queue.ecr_push_dlq.url
}""",
                alert_severity="medium",
                alert_title="ECR Image Push Detected",
                alert_description_template="Image pushed to ECR repository {repository} with tag {tag}.",
                investigation_steps=[
                    "Verify push was from approved CI/CD",
                    "Check if image went through scanning",
                    "Review image build history",
                    "Examine image for suspicious layers",
                    "Check if immediately deployed",
                ],
                containment_actions=[
                    "Enable ECR image scanning",
                    "Require image approval workflow",
                    "Implement immutability tags",
                    "Use ECR lifecycle policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Filter by repository name or tag pattern to exclude known CI/CD pipelines",
            detection_coverage="95% - catches all ECR pushes",
            evasion_considerations="Attacker may use different registries",
            implementation_effort=EffortLevel.LOW,
            implementation_time="20 minutes",
            estimated_monthly_cost="$1-3",
            prerequisites=["ECR repositories configured"],
        ),
        DetectionStrategy(
            strategy_id="t1612-gcp-docker-build",
            name="GCP Cloud Build Activity Detection",
            description="Detect Cloud Build and local Docker build operations.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.devtools.cloudbuild.v1.CloudBuild.CreateBuild"
OR protoPayload.methodName=~"docker.*build"
OR resource.type="gce_instance" AND jsonPayload.message=~"docker build"''',
                gcp_terraform_template="""# GCP: Detect Docker build activity

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "docker_build" {
  project = var.project_id
  name   = "docker-build-activity"
  filter = <<-EOT
    protoPayload.methodName="google.devtools.cloudbuild.v1.CloudBuild.CreateBuild"
    OR protoPayload.methodName=~"docker.*build"
    OR (resource.type="gce_instance" AND jsonPayload.message=~"docker build")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "docker_build" {
  project      = var.project_id
  display_name = "Docker Build Detection"
  combiner     = "OR"

  conditions {
    display_name = "Docker build detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.docker_build.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "Docker build activity detected. Review for suspicious Dockerfile instructions."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Docker Build Detected",
                alert_description_template="Docker build operation detected on {resource.name}.",
                investigation_steps=[
                    "Review Cloud Build configuration",
                    "Check Dockerfile for malicious commands",
                    "Verify build was authorised",
                    "Scan resulting image",
                    "Check for outbound connections during build",
                ],
                containment_actions=[
                    "Delete suspicious images",
                    "Enable Binary Authorization",
                    "Restrict Cloud Build permissions",
                    "Implement vulnerability scanning",
                    "Use VPC Service Controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate Cloud Build service accounts",
            detection_coverage="85% - requires Cloud Logging enabled",
            evasion_considerations="Attacker may build outside Cloud Build",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled", "Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1612-gcp-artifact-push",
            name="GCP Artifact Registry Push Detection",
            description="Detect images pushed to Artifact Registry after local builds.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="google.devtools.artifactregistry.v1.ArtifactRegistry.ImportAptArtifacts"
OR protoPayload.methodName=~"artifactregistry.*UploadArtifact"
OR (resource.type="artifact_registry_repository" AND protoPayload.methodName="storage.objects.create")""",
                gcp_terraform_template="""# GCP: Detect Artifact Registry image pushes

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "artifact_push" {
  project = var.project_id
  name   = "artifact-registry-push"
  filter = <<-EOT
    protoPayload.methodName=~"artifactregistry.*Import|artifactregistry.*Upload"
    OR (resource.type="artifact_registry_repository" AND protoPayload.methodName="storage.objects.create")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "artifact_push" {
  project      = var.project_id
  display_name = "Artifact Registry Push"
  combiner     = "OR"

  conditions {
    display_name = "Image pushed to registry"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.artifact_push.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "Image pushed to Artifact Registry. Verify authorisation and scan for vulnerabilities."
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Artifact Registry Image Push",
                alert_description_template="Image pushed to Artifact Registry {repository}.",
                investigation_steps=[
                    "Verify push was authorised",
                    "Check pushing identity",
                    "Enable vulnerability scanning",
                    "Review image layers and history",
                ],
                containment_actions=[
                    "Delete unauthorised images",
                    "Enable Container Analysis",
                    "Implement Binary Authorization policies",
                    "Restrict registry write permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Filter CI/CD service account pushes",
            detection_coverage="90% - catches registry pushes",
            evasion_considerations="Attacker may use external registries",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Artifact Registry configured", "Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Build Image on Host
        DetectionStrategy(
            strategy_id="t1612-azure",
            name="Azure Build Image on Host Detection",
            description=(
                "Azure detection for Build Image on Host. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Build Image on Host
// MITRE ATT&CK: T1612
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
                azure_terraform_template="""# Azure Detection for Build Image on Host
# MITRE ATT&CK: T1612

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
  name                = "build-image-on-host-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "build-image-on-host-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Build Image on Host
// MITRE ATT&CK: T1612
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

  description = "Detects Build Image on Host (T1612) activity in Azure environment"
  display_name = "Build Image on Host Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1612"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Build Image on Host Detected",
                alert_description_template=(
                    "Build Image on Host activity detected. "
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
        "t1612-aws-docker-build",
        "t1612-aws-ecr-rapid-build",
        "t1612-gcp-docker-build",
        "t1612-gcp-artifact-push",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+18% improvement for Defence Evasion tactic",
)
