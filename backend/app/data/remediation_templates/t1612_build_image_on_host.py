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
            description="Detect Docker build commands and suspicious Dockerfile instructions on EC2/ECS.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @message like /docker build/
| filter @message like /RUN curl|RUN wget|RUN nc|ADD http/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious Docker build activity

Parameters:
  LogGroupName:
    Type: String
    Description: CloudWatch log group for Docker logs
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

  DockerBuildFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: '[time, request_id, event_type = *build*, ...]'
      MetricTransformations:
        - MetricName: DockerBuildCount
          MetricNamespace: Security/Container
          MetricValue: "1"

  DockerBuildAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousDockerBuild
      MetricName: DockerBuildCount
      Namespace: Security/Container
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious Docker build activity

variable "log_group_name" {
  type        = string
  description = "CloudWatch log group for Docker logs"
}
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "docker-build-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "docker_build" {
  name           = "docker-build-activity"
  log_group_name = var.log_group_name
  pattern        = "[time, request_id, event_type = *build*, ...]"

  metric_transformation {
    name      = "DockerBuildCount"
    namespace = "Security/Container"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "docker_build" {
  alarm_name          = "suspicious-docker-build"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DockerBuildCount"
  namespace           = "Security/Container"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on Docker build activity"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious Docker Build Detected",
                alert_description_template="Docker build with suspicious instructions detected on {instance_id}.",
                investigation_steps=[
                    "Review Dockerfile contents",
                    "Check for malicious RUN/ADD/COPY commands",
                    "Identify who initiated the build",
                    "Examine network connections during build",
                    "Scan resulting image for malware",
                ],
                containment_actions=[
                    "Delete suspicious images",
                    "Block Docker API access from internet",
                    "Require TLS authentication for Docker API",
                    "Implement image scanning pipeline",
                    "Restrict Docker socket access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate CI/CD build processes",
            detection_coverage="80% - requires Docker logging enabled",
            evasion_considerations="Attacker may use obfuscated Dockerfiles or multi-stage builds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Docker daemon logging to CloudWatch",
                "Container Insights enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1612-aws-ecr-rapid-build",
            name="AWS Rapid Build-Push Detection",
            description="Detect images built and immediately deployed without approval process.",
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
Description: Detect rapid image build and push

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
      Description: Alert on ECR image push
      EventPattern:
        source: [aws.ecr]
        detail-type: [ECR Image Action]
        detail:
          action-type: [PUSH]
          result: [SUCCESS]
      State: ENABLED
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
                terraform_template="""# Detect rapid image build and push

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ecr-rapid-push-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "ecr_push" {
  name        = "ecr-image-push-detection"
  description = "Alert on ECR image push"

  event_pattern = jsonencode({
    source      = ["aws.ecr"]
    detail-type = ["ECR Image Action"]
    detail = {
      action-type = ["PUSH"]
      result      = ["SUCCESS"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ecr_push.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn
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
                alert_title="ECR Image Push After Build",
                alert_description_template="Image pushed to ECR repository {repository-name} by {identity}.",
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
            false_positive_tuning="Filter legitimate CI/CD service roles and tag conventions",
            detection_coverage="90% - catches all ECR pushes",
            evasion_considerations="Attacker may use different registries or slow down timing",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["ECR repositories configured", "EventBridge enabled"],
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

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "docker_build" {
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

  notification_channels = [google_monitoring_notification_channel.email.id]

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

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "artifact_push" {
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

  notification_channels = [google_monitoring_notification_channel.email.id]

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
