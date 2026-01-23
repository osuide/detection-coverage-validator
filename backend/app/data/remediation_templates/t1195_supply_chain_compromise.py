"""
T1195 - Supply Chain Compromise

Adversaries manipulate products or delivery mechanisms prior to receipt by end consumers
to enable data or system compromise. Used by Ember Bear, OilRig, Sandworm Team.
Includes software dependencies, software supply chain, and hardware supply chain compromise.
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
    technique_id="T1195",
    technique_name="Supply Chain Compromise",
    tactic_ids=["TA0001"],
    mitre_url="https://attack.mitre.org/techniques/T1195/",
    threat_context=ThreatContext(
        description=(
            "Adversaries manipulate products or delivery mechanisms before they reach end consumers "
            "to enable data or system compromise. This can occur at multiple stages including development "
            "tools, source code repositories, software dependencies, software updates, system images, "
            "and hardware components. Supply chain compromises provide adversaries with initial access "
            "to multiple targets through a single compromise point."
        ),
        attacker_goal="Gain initial access to multiple targets via compromised supply chain components",
        why_technique=[
            "Single compromise affects multiple downstream targets",
            "Difficult to detect compromised legitimate software",
            "Bypasses traditional security controls",
            "Leverages trusted distribution channels",
            "Provides persistent access across deployments",
            "Automated deployment systems propagate malicious code",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="uncommon",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Highly impactful due to widespread distribution through trusted channels. "
            "Single compromise can affect thousands of organisations. Difficult to detect "
            "and remediate. Often provides persistent access across system rebuilds."
        ),
        business_impact=[
            "Widespread compromise across customer base",
            "Reputational damage if you're the compromised vendor",
            "Data breach across multiple systems",
            "Supply chain trust erosion",
            "Compliance violations and regulatory scrutiny",
            "Difficult and costly remediation",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1078.004", "T1530", "T1552.005", "T1525", "T1098"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1195-aws-lambda-layer",
            name="AWS Lambda Layer and Dependency Monitoring",
            description="Detect unauthorised Lambda layer modifications and suspicious dependency changes that could indicate supply chain compromise.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.lambda"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "PublishLayerVersion",
                            "DeleteLayerVersion",
                            "AddLayerVersionPermission",
                            "RemoveLayerVersionPermission",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda layer modifications for supply chain monitoring (T1195)

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Supply Chain Security Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for Lambda layer changes
  LambdaLayerRule:
    Type: AWS::Events::Rule
    Properties:
      Name: t1195-lambda-layer-monitoring
      Description: Detect Lambda layer modifications
      EventPattern:
        source: [aws.lambda]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PublishLayerVersion
            - DeleteLayerVersion
            - AddLayerVersionPermission
            - RemoveLayerVersionPermission
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref AlertTopic

  # Step 3: CloudWatch metric for function updates
  FunctionUpdateFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "UpdateFunctionCode" || $.eventName = "UpdateFunctionConfiguration") && $.requestParameters.packageType = "Image" }'
      MetricTransformations:
        - MetricName: LambdaImageUpdates
          MetricNamespace: Security/T1195
          MetricValue: "1"

  FunctionUpdateAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1195-Lambda-Image-Updates
      AlarmDescription: Detect Lambda function updates using container images
      MetricName: LambdaImageUpdates
      Namespace: Security/T1195
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt LambdaLayerRule.Arn
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# AWS: Detect Lambda layer and dependency changes (T1195)

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "supply_chain_alerts" {
  name         = "t1195-supply-chain-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Supply Chain Security Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.supply_chain_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for Lambda layer changes
resource "aws_cloudwatch_event_rule" "lambda_layer" {
  name        = "t1195-lambda-layer-monitoring"
  description = "Detect Lambda layer modifications"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PublishLayerVersion",
        "DeleteLayerVersion",
        "AddLayerVersionPermission",
        "RemoveLayerVersionPermission"
      ]
    }
  })
}

# DLQ for failed EventBridge deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "t1195-lambda-layer-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "dlq_policy" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.lambda_layer.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.lambda_layer.name
  target_id = "LambdaLayerSNSTarget"
  arn       = aws_sns_topic.supply_chain_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

# Step 3: Monitor Lambda function image updates
resource "aws_cloudwatch_log_metric_filter" "function_updates" {
  name           = "lambda-image-updates"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"UpdateFunctionCode\" || $.eventName = \"UpdateFunctionConfiguration\") && $.requestParameters.packageType = \"Image\" }"

  metric_transformation {
    name      = "LambdaImageUpdates"
    namespace = "Security/T1195"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "image_updates" {
  alarm_name          = "T1195-Lambda-Image-Updates"
  alarm_description   = "Detect Lambda function updates using container images"
  metric_name         = "LambdaImageUpdates"
  namespace           = "Security/T1195"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.supply_chain_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.supply_chain_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = ["events.amazonaws.com", "cloudwatch.amazonaws.com"]
      }
      Action   = "sns:Publish"
      Resource = aws_sns_topic.supply_chain_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Supply Chain: Lambda Layer or Dependency Modified",
                alert_description_template=(
                    "Lambda layer modification detected: {eventName} by {userIdentity.principalId}. "
                    "Layer: {requestParameters.layerName}. Version: {responseElements.version}."
                ),
                investigation_steps=[
                    "Identify who published or modified the Lambda layer",
                    "Review layer contents for malicious code or backdoors",
                    "Check all functions using the modified layer",
                    "Verify layer source and build provenance",
                    "Compare layer hash against known-good baseline",
                    "Review deployment pipeline for compromise indicators",
                    "Check for similar modifications across other layers",
                    "Scan layer dependencies for known vulnerabilities",
                ],
                containment_actions=[
                    "Delete unauthorised layer versions immediately",
                    "Revert functions to previous known-good layer versions",
                    "Enable Lambda function code signing",
                    "Implement layer version pinning in deployments",
                    "Require approval workflow for layer publications",
                    "Enable AWS Signer for code signing enforcement",
                    "Review and rotate any credentials in affected functions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD pipeline roles and service accounts; filter expected deployment times",
            detection_coverage="85% - covers Lambda layer supply chain vectors",
            evasion_considerations="Attackers may use compromised CI/CD credentials to appear legitimate",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15 depending on Lambda activity",
            prerequisites=["CloudTrail enabled", "Lambda functions in use"],
        ),
        DetectionStrategy(
            strategy_id="t1195-aws-ecr-integrity",
            name="AWS ECR Container Image Integrity Monitoring",
            description="Detect unauthorised container image pushes and integrity violations in ECR repositories.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ecr"],
                    "detail-type": ["ECR Image Action"],
                    "detail": {
                        "action-type": ["PUSH", "DELETE"],
                        "result": ["SUCCESS"],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor ECR for supply chain compromise indicators (T1195)

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for image pushes
  ECRImageRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ecr]
        detail-type: [ECR Image Action]
        detail:
          action-type: [PUSH, DELETE]
          result: [SUCCESS]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Enable ECR image scanning
  ScanOnPushConfig:
    Type: AWS::ECR::RegistryScanningConfiguration
    Properties:
      ScanType: ENHANCED
      Rules:
        - RepositoryFilters:
            - Filter: "*"
              FilterType: WILDCARD
          ScanFrequency: SCAN_ON_PUSH

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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ECRImageRule.Arn""",
                terraform_template="""# AWS: Monitor ECR image integrity (T1195)

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "ecr_alerts" {
  name = "t1195-ecr-supply-chain-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ecr_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for ECR image actions
resource "aws_cloudwatch_event_rule" "ecr_image" {
  name = "t1195-ecr-image-monitoring"

  event_pattern = jsonencode({
    source      = ["aws.ecr"]
    detail-type = ["ECR Image Action"]
    detail = {
      action-type = ["PUSH", "DELETE"]
      result      = ["SUCCESS"]
    }
  })
}

# DLQ for failed EventBridge deliveries (ECR)
resource "aws_sqs_queue" "ecr_dlq" {
  name                      = "t1195-ecr-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "ecr_dlq_policy" {
  queue_url = aws_sqs_queue.ecr_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.ecr_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ecr_image.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ecr_image.name
  target_id = "ECRImageSNSTarget"
  arn       = aws_sns_topic.ecr_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.ecr_dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

# Step 3: Enable enhanced ECR scanning
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

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.ecr_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ecr_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ecr_image.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Supply Chain: ECR Image Push Detected",
                alert_description_template=(
                    "Container image {detail.action-type} to ECR repository {detail.repository-name}. "
                    "Image tag: {detail.image-tag}. Principal: {userIdentity.principalId}."
                ),
                investigation_steps=[
                    "Verify image push was authorised and expected",
                    "Review ECR image scan results for vulnerabilities",
                    "Check image provenance and build attestation",
                    "Compare image layers against known-good baseline",
                    "Verify pushing principal is legitimate CI/CD system",
                    "Review image for backdoors or malicious code",
                    "Check all deployments using the image",
                    "Validate image signing status if enabled",
                ],
                containment_actions=[
                    "Delete unauthorised or suspicious images",
                    "Enable ECR image tag immutability",
                    "Require image signing with AWS Signer",
                    "Implement lifecycle policies to retain only signed images",
                    "Restrict ECR push permissions to CI/CD roles only",
                    "Enable ECR replication to backup trusted images",
                    "Quarantine affected container deployments",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist CI/CD pipeline identities; filter expected deployment windows",
            detection_coverage="95% - comprehensive ECR activity monitoring",
            evasion_considerations="Cannot evade if EventBridge is enabled; attackers may use compromised CI/CD credentials",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$2-10 depending on image activity",
            prerequisites=["ECR repositories in use", "EventBridge enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1195-aws-codebuild",
            name="AWS CodeBuild and CodePipeline Compromise Detection",
            description="Monitor build environments for unauthorised modifications that could inject malicious code.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, eventName, userIdentity.principalId, requestParameters.projectName, requestParameters.source.location
| filter eventSource = "codebuild.amazonaws.com"
| filter eventName in ["UpdateProject", "CreateProject", "BatchGetProjects"]
| filter requestParameters.source.location not like /github\.com\/your-org/
| stats count(*) as modifications by userIdentity.principalId, requestParameters.projectName, bin(1h)
| filter modifications > 0
| sort @timestamp desc""",
                terraform_template="""# AWS: Monitor CodeBuild for supply chain compromise (T1195)

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

variable "allowed_source_patterns" {
  type        = list(string)
  description = "Allowed source repository patterns"
  default     = ["github.com/your-org/*"]
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "codebuild_alerts" {
  name = "t1195-codebuild-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.codebuild_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Detect CodeBuild project modifications
resource "aws_cloudwatch_log_metric_filter" "codebuild_changes" {
  name           = "codebuild-project-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"codebuild.amazonaws.com\" && ($.eventName = \"UpdateProject\" || $.eventName = \"CreateProject\") }"

  metric_transformation {
    name      = "CodeBuildModifications"
    namespace = "Security/T1195"
    value     = "1"
  }
}

# Step 3: Alert on unauthorised build changes
resource "aws_cloudwatch_metric_alarm" "codebuild_compromise" {
  alarm_name          = "T1195-CodeBuild-Compromise"
  alarm_description   = "Unauthorised CodeBuild project modification detected"
  metric_name         = "CodeBuildModifications"
  namespace           = "Security/T1195"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.codebuild_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.codebuild_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.codebuild_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Supply Chain: CodeBuild Project Modified",
                alert_description_template=(
                    "CodeBuild project {projectName} modified by {userIdentity.principalId}. "
                    "Source location: {source.location}. Change count: {modifications}."
                ),
                investigation_steps=[
                    "Identify who modified the CodeBuild project",
                    "Review buildspec.yml changes for malicious commands",
                    "Check source repository location changes",
                    "Verify environment variable modifications",
                    "Review build artifacts for backdoors",
                    "Check privileged mode and service role changes",
                    "Audit all builds executed since modification",
                    "Review CloudWatch Logs for build process anomalies",
                ],
                containment_actions=[
                    "Revert CodeBuild project to known-good configuration",
                    "Disable compromised build projects immediately",
                    "Quarantine all artifacts from suspicious builds",
                    "Rotate service role credentials",
                    "Enable build project version control",
                    "Require approval for buildspec changes",
                    "Implement CodeBuild project immutability controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised DevOps team members and deployment automation",
            detection_coverage="80% - covers build pipeline compromise vectors",
            evasion_considerations="Sophisticated attackers may make subtle buildspec changes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-1.5 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled",
                "CodeBuild in use",
                "CloudTrail logs in CloudWatch",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1195-gcp-artifact-registry",
            name="GCP Artifact Registry Supply Chain Monitoring",
            description="Detect unauthorised container and package repository activities indicating supply chain compromise.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="artifact_registry"
(protoPayload.methodName=~"google.devtools.artifactregistry.v1.ArtifactRegistry.CreateRepository"
OR protoPayload.methodName=~"google.devtools.artifactregistry.v1.ArtifactRegistry.UpdateRepository"
OR protoPayload.methodName=~"google.devtools.artifactregistry.v1.ArtifactRegistry.ImportAptArtifacts"
OR protoPayload.methodName=~"google.devtools.artifactregistry.v1.ArtifactRegistry.UploadAptArtifact"
OR protoPayload.methodName=~"docker.upload")
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Monitor Artifact Registry for supply chain compromise (T1195)

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Supply Chain Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for artifact uploads
resource "google_logging_metric" "artifact_uploads" {
  project = var.project_id
  name    = "t1195-artifact-registry-activity"

  filter = <<-EOT
    resource.type="artifact_registry"
    (protoPayload.methodName=~"google.devtools.artifactregistry.v1.ArtifactRegistry.*"
    OR protoPayload.methodName=~"docker.upload")
    severity>=WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Create alert policy for suspicious artifact activity
resource "google_monitoring_alert_policy" "artifact_alert" {
  project      = var.project_id
  display_name = "T1195: Artifact Registry Supply Chain Activity"
  combiner     = "OR"

  conditions {
    display_name = "Unauthorised artifact upload or modification"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.artifact_uploads.name}\" AND resource.type=\"artifact_registry\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "604800s"  # 7 days
  }

  documentation {
    content   = "Artifact Registry activity detected that may indicate supply chain compromise. Investigate immediately."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Artifact Registry Supply Chain Activity",
                alert_description_template=(
                    "Artifact Registry activity: {methodName} by {principalEmail}. "
                    "Repository: {resource.labels.repository_id}. Location: {resource.labels.location}."
                ),
                investigation_steps=[
                    "Identify who uploaded or modified the artifact",
                    "Review artifact contents for malicious code",
                    "Check Binary Authorization policies and attestations",
                    "Verify artifact source and build provenance",
                    "Scan artifact for vulnerabilities using Container Analysis",
                    "Review all deployments using the artifact",
                    "Check repository IAM permissions for unauthorised access",
                    "Compare artifact hash against known-good baseline",
                ],
                containment_actions=[
                    "Delete unauthorised artifacts immediately",
                    "Enable Binary Authorization for GKE deployments",
                    "Require signed attestations for all deployments",
                    "Implement VPC Service Controls around Artifact Registry",
                    "Restrict repository write access to CI/CD service accounts",
                    "Enable vulnerability scanning for all repositories",
                    "Quarantine workloads using suspicious artifacts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD service accounts; filter expected deployment schedules",
            detection_coverage="90% - comprehensive Artifact Registry monitoring",
            evasion_considerations="Attackers may use compromised service accounts to appear legitimate",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-1.5 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["Cloud Audit Logs enabled", "Artifact Registry in use"],
        ),
        DetectionStrategy(
            strategy_id="t1195-gcp-cloud-build",
            name="GCP Cloud Build Pipeline Integrity Monitoring",
            description="Monitor Cloud Build for unauthorised build configuration changes and suspicious build activities.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="cloud_build"
(protoPayload.methodName=~"google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger"
OR protoPayload.methodName=~"google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger"
OR protoPayload.methodName=~"google.devtools.cloudbuild.v1.CloudBuild.RunBuildTrigger")
OR (resource.type="build"
    jsonPayload.status=~"SUCCESS|FAILURE"
    jsonPayload.source.repoSource.repoName!~"github_your-org.*")""",
                gcp_terraform_template="""# GCP: Monitor Cloud Build for supply chain compromise (T1195)

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "allowed_repo_pattern" {
  type        = string
  description = "Allowed repository pattern (regex)"
  default     = "github_your-org.*"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Cloud Build Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log metric for build trigger changes
resource "google_logging_metric" "build_trigger_changes" {
  project = var.project_id
  name    = "t1195-cloud-build-trigger-changes"

  filter = <<-EOT
    resource.type="cloud_build"
    (protoPayload.methodName=~"google.devtools.cloudbuild.v1.CloudBuild.CreateBuildTrigger"
    OR protoPayload.methodName=~"google.devtools.cloudbuild.v1.CloudBuild.UpdateBuildTrigger")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert on build trigger modifications
resource "google_monitoring_alert_policy" "build_compromise" {
  project      = var.project_id
  display_name = "T1195: Cloud Build Configuration Change"
  combiner     = "OR"

  conditions {
    display_name = "Build trigger modified"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.build_trigger_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "604800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Cloud Build trigger configuration changed. Review for unauthorised modifications that could indicate supply chain compromise."
    mime_type = "text/markdown"
  }
}

# Log metric for suspicious build sources
resource "google_logging_metric" "suspicious_builds" {
  project = var.project_id
  name    = "t1195-suspicious-build-sources"

  filter = <<-EOT
    resource.type="build"
    jsonPayload.status=~"SUCCESS|FAILURE"
    jsonPayload.source.repoSource.repoName!~"${var.allowed_repo_pattern}"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert on builds from unexpected sources
resource "google_monitoring_alert_policy" "suspicious_source" {
  project      = var.project_id
  display_name = "T1195: Build from Unexpected Source"
  combiner     = "OR"

  conditions {
    display_name = "Build from non-authorised repository"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_builds.name}\""
      duration        = "60s"
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
}""",
                alert_severity="critical",
                alert_title="GCP: Cloud Build Configuration Compromised",
                alert_description_template=(
                    "Cloud Build modification: {methodName} by {principalEmail}. "
                    "Trigger: {request.trigger.name}. Source: {source.repoSource.repoName}."
                ),
                investigation_steps=[
                    "Identify who modified the build trigger",
                    "Review cloudbuild.yaml changes for malicious steps",
                    "Check source repository configuration changes",
                    "Verify substitution variable modifications",
                    "Review service account permissions changes",
                    "Audit all builds executed since modification",
                    "Check build artifacts for backdoors or malware",
                    "Review build logs for unusual commands or network activity",
                ],
                containment_actions=[
                    "Revert build trigger to known-good configuration",
                    "Disable compromised build triggers immediately",
                    "Delete suspicious build artifacts from repositories",
                    "Rotate service account keys used by builds",
                    "Enable Binary Authorization for deployments",
                    "Require manual approval for build trigger changes",
                    "Implement Cloud Build trigger versioning",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised DevOps team members; filter expected repository patterns",
            detection_coverage="85% - covers build pipeline compromise",
            evasion_considerations="Subtle cloudbuild.yaml changes may be difficult to detect",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled", "Cloud Build in use"],
        ),
        DetectionStrategy(
            strategy_id="t1195-gcp-gcr-integrity",
            name="GCP Container Registry Image Verification",
            description="Monitor GCR for unauthorised image pushes and integrity violations (legacy GCR support).",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gcs_bucket"
resource.labels.bucket_name=~".*artifacts.*gcr.io"
protoPayload.methodName="storage.objects.create"
protoPayload.resourceName=~".*/manifests/.*"
severity>=NOTICE""",
                gcp_terraform_template="""# GCP: Monitor GCR image uploads (T1195 - legacy GCR)

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s3" {
  project      = var.project_id
  display_name = "GCR Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log metric for GCR image pushes
resource "google_logging_metric" "gcr_pushes" {
  project = var.project_id
  name    = "t1195-gcr-image-pushes"

  filter = <<-EOT
    resource.type="gcs_bucket"
    resource.labels.bucket_name=~".*artifacts.*gcr.io"
    protoPayload.methodName="storage.objects.create"
    protoPayload.resourceName=~".*/manifests/.*"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert on GCR image pushes
resource "google_monitoring_alert_policy" "gcr_activity" {
  project      = var.project_id
  display_name = "T1195: GCR Image Push Detected"
  combiner     = "OR"

  conditions {
    display_name = "Container image pushed to GCR"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcr_pushes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s3.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Container image pushed to GCR. Verify authorisation and scan for vulnerabilities. Consider migrating to Artifact Registry for enhanced security features."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: GCR Image Upload Detected",
                alert_description_template=(
                    "Container image pushed to GCR by {principalEmail}. "
                    "Bucket: {resource.labels.bucket_name}. Image: {resourceName}."
                ),
                investigation_steps=[
                    "Identify who pushed the container image",
                    "Verify push was authorised and expected",
                    "Scan image using Container Analysis API",
                    "Check image layers for suspicious content",
                    "Verify pushing identity is legitimate CI/CD",
                    "Review all deployments using the image",
                    "Compare image digest against known-good baseline",
                    "Consider migrating to Artifact Registry for better controls",
                ],
                containment_actions=[
                    "Delete unauthorised images from GCR",
                    "Enable Binary Authorization to prevent deployment",
                    "Migrate to Artifact Registry for enhanced security",
                    "Restrict GCS bucket permissions on GCR storage",
                    "Implement image signing requirements",
                    "Enable vulnerability scanning via Container Analysis",
                    "Quarantine pods using suspicious images",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist CI/CD service accounts; consider migrating to Artifact Registry",
            detection_coverage="80% - covers GCR image uploads",
            evasion_considerations="GCR uses GCS bucket events which cannot be easily evaded",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes - 1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Audit Logs enabled", "GCR in use (legacy)"],
        ),
        # Azure Strategy: Supply Chain Compromise
        DetectionStrategy(
            strategy_id="t1195-azure",
            name="Azure Supply Chain Compromise Detection",
            description=(
                "Azure detection for Supply Chain Compromise. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Supply Chain Compromise (T1195)
# Microsoft Defender detects Supply Chain Compromise activity

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
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1195-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1195"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (
                    "Suspicious activity detected",
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Supply Chain Compromise activity"
  display_name = "Defender: Supply Chain Compromise"
  enabled      = true
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Supply Chain Compromise Detected",
                alert_description_template=(
                    "Supply Chain Compromise activity detected. "
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
        "t1195-aws-ecr-integrity",
        "t1195-gcp-artifact-registry",
        "t1195-aws-codebuild",
        "t1195-gcp-cloud-build",
        "t1195-aws-lambda-layer",
        "t1195-gcp-gcr-integrity",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+30% improvement for Initial Access tactic",
)
