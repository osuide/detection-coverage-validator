"""
T1587 - Develop Capabilities

Adversaries develop their own tools and capabilities rather than acquiring them
externally, including creating malware, exploits, and self-signed certificates.
Used by Contagious Interview, Kimsuky, Moonstone Sleet.
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
    technique_id="T1587",
    technique_name="Develop Capabilities",
    tactic_ids=["TA0042"],
    mitre_url="https://attack.mitre.org/techniques/T1587/",
    threat_context=ThreatContext(
        description=(
            "Adversaries develop their own tools and capabilities rather than acquiring them "
            "externally. This in-house development includes creating malware, exploits, code "
            "signing certificates, and digital certificates to support operations across multiple "
            "lifecycle phases. Development may involve contracting external developers whilst "
            "maintaining control over requirements and exclusivity."
        ),
        attacker_goal="Create custom tools and capabilities for tailored attacks",
        why_technique=[
            "Evades signature-based detection",
            "Enables custom functionality",
            "Maintains operational security",
            "Reduces attribution risk",
            "Provides exclusive capabilities",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Pre-compromise technique occurring outside organisational visibility. "
            "Custom-developed capabilities enable targeted attacks whilst evading "
            "traditional defences. Severity reflects the sophistication of threats "
            "using custom tooling."
        ),
        business_impact=[
            "Sophisticated targeted attacks",
            "Reduced detection capability",
            "Extended dwell time",
            "Supply chain compromise risk",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1566.001", "T1204.002", "T1195.002", "T1608.001"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1587-aws-guardduty",
            name="AWS GuardDuty Malware Detection",
            description="Detect suspicious files and malware characteristics in AWS environment.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, service.action.actionType, resource.s3BucketDetails.name, severity
| filter service.serviceName = "guardduty"
| filter (type like /Malware/ or type like /Trojan/ or type like /Backdoor/)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect malware and suspicious files via GuardDuty

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: GuardDuty Malware Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # GuardDuty should be enabled in your account
  # This EventBridge rule catches malware findings
  MalwareFindingRule:
    Type: AWS::Events::Rule
    Properties:
      Name: GuardDuty-Malware-Detection
      Description: Alert on malware findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: Execution:S3/MaliciousFile
            - prefix: Trojan
            - prefix: Backdoor
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: MalwareAlertTarget""",
                terraform_template="""# Detect malware and suspicious files via GuardDuty

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name         = "guardduty-malware-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "GuardDuty Malware Alerts"

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
            Resource: !Ref AlertTopic
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# GuardDuty should be enabled in your account
# This EventBridge rule catches malware findings
resource "aws_cloudwatch_event_rule" "malware_finding" {
  name        = "guardduty-malware-detection"
  description = "Alert on malware findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Object:S3/MaliciousFile" },
        { prefix = "Trojan" },
        { prefix = "Backdoor" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-malware-dlq"
  message_retention_seconds = 1209600  # 14 days
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.malware_finding.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "malware_alert" {
  rule      = aws_cloudwatch_event_rule.malware_finding.name
  target_id = "MalwareAlertTarget"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Allow EventBridge to publish to SNS
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.malware_finding.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Malware Detected in AWS Environment",
                alert_description_template="GuardDuty detected malware or suspicious files: {finding_type}",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Analyse file hashes and signatures",
                    "Check for compiler artifacts or debugging symbols",
                    "Review S3 bucket access logs",
                    "Identify file origin and upload source",
                    "Check for related findings or indicators",
                ],
                containment_actions=[
                    "Quarantine affected S3 objects",
                    "Block malicious IPs at security group level",
                    "Rotate exposed credentials",
                    "Review IAM policies for compromised accounts",
                    "Enable GuardDuty malware protection if not active",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses threat intelligence feeds with low false positive rates",
            detection_coverage="50% - detects known malware patterns and signatures",
            evasion_considerations="Custom-developed malware may evade signature detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-20",
            prerequisites=["GuardDuty enabled", "S3 malware protection enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1587-aws-s3-suspicious",
            name="S3 Suspicious File Upload Detection",
            description="Detect suspicious file uploads that may contain malware or exploits.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, requestParameters.bucketName, requestParameters.key, userIdentity.principalId
| filter eventName = "PutObject"
| filter (requestParameters.key like /\\.exe$/ or requestParameters.key like /\\.dll$/
         or requestParameters.key like /\\.scr$/ or requestParameters.key like /\\.vbs$/
         or requestParameters.key like /\\.ps1$/ or requestParameters.key like /\\.bat$/)
| stats count(*) as uploads by userIdentity.principalId, requestParameters.bucketName
| filter uploads > 10
| sort uploads desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious file uploads to S3

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: S3 Suspicious Upload Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  SuspiciousUploadFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "PutObject") && ($.requestParameters.key = "*.exe" || $.requestParameters.key = "*.dll" || $.requestParameters.key = "*.ps1") }'
      MetricTransformations:
        - MetricName: SuspiciousS3Uploads
          MetricNamespace: Security
          MetricValue: "1"

  SuspiciousUploadAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighSuspiciousS3Uploads
      MetricName: SuspiciousS3Uploads
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious file uploads to S3

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name         = "s3-suspicious-upload-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "S3 Suspicious Upload Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "suspicious_uploads" {
  name           = "suspicious-s3-uploads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"PutObject\") && ($.requestParameters.key = \"*.exe\" || $.requestParameters.key = \"*.dll\" || $.requestParameters.key = \"*.ps1\") }"

  metric_transformation {
    name      = "SuspiciousS3Uploads"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "suspicious_uploads_alarm" {
  alarm_name          = "HighSuspiciousS3Uploads"
  metric_name         = "SuspiciousS3Uploads"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious File Uploads to S3",
                alert_description_template="High volume of executable file uploads by {principalId}",
                investigation_steps=[
                    "Review uploaded file types and patterns",
                    "Check user identity and access patterns",
                    "Analyse file hashes against threat intelligence",
                    "Review bucket policies and permissions",
                    "Check for automated upload patterns",
                ],
                containment_actions=[
                    "Enable S3 Object Lock on sensitive buckets",
                    "Review and restrict bucket policies",
                    "Enable GuardDuty S3 protection",
                    "Implement bucket encryption",
                    "Review IAM permissions for uploading principals",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust file extensions and thresholds based on legitimate software distribution needs",
            detection_coverage="40% - file extension-based detection",
            evasion_considerations="Adversaries may use compressed files or alternate extensions",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$3-10",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "CloudTrail logs in CloudWatch",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1587-gcp-artifact",
            name="GCP Artifact Registry Suspicious Uploads",
            description="Detect suspicious container image or package uploads in Artifact Registry.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="artifact_registry_repository"
protoPayload.methodName=~"CreatePackage|UploadArtifact"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect suspicious Artifact Registry uploads

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "artifact_uploads" {
  name   = "suspicious-artifact-uploads"
  filter = <<-EOT
    resource.type="artifact_registry_repository"
    protoPayload.methodName=~"CreatePackage|UploadArtifact"
    severity="NOTICE"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "artifact_upload_alert" {
  display_name = "Suspicious Artifact Uploads"
  combiner     = "OR"
  conditions {
    display_name = "High upload rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.artifact_uploads.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "604800s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Suspicious Artifact Registry Activity",
                alert_description_template="High volume of package uploads detected in Artifact Registry",
                investigation_steps=[
                    "Review uploaded package details",
                    "Check authentication method and identity",
                    "Analyse package contents and dependencies",
                    "Review repository access logs",
                    "Check for malicious package patterns",
                ],
                containment_actions=[
                    "Review repository IAM permissions",
                    "Enable Binary Authorization",
                    "Implement package scanning",
                    "Review artifact retention policies",
                    "Delete suspicious packages",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude CI/CD service accounts and adjust threshold for your deployment frequency",
            detection_coverage="45% - detects high-volume uploads",
            evasion_considerations="Low-volume targeted uploads may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-25",
            prerequisites=["Artifact Registry enabled", "Audit logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1587-gcp-code-build",
            name="GCP Cloud Build Suspicious Activity",
            description="Detect suspicious Cloud Build activities that may indicate malware compilation.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="cloud_build"
protoPayload.methodName="google.devtools.cloudbuild.v1.CloudBuild.CreateBuild"
(protoPayload.request.steps.args=~"gcc|g\\+\\+|make|cmake|cargo|go build"
 OR protoPayload.request.steps.name=~"compiler|builder")""",
                gcp_terraform_template="""# GCP: Detect suspicious build activities

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "suspicious_builds" {
  name   = "suspicious-cloud-builds"
  filter = <<-EOT
    resource.type="cloud_build"
    protoPayload.methodName="google.devtools.cloudbuild.v1.CloudBuild.CreateBuild"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_repo"
      value_type  = "STRING"
      description = "Source repository"
    }
  }
  label_extractors = {
    source_repo = "EXTRACT(protoPayload.request.source.repoSource.repoName)"
  }
}

resource "google_monitoring_alert_policy" "build_alert" {
  display_name = "Suspicious Cloud Build Activity"
  combiner     = "OR"
  conditions {
    display_name = "High build rate from unknown sources"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_builds.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 15
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Suspicious Cloud Build Activity",
                alert_description_template="Unusual compilation activity detected in Cloud Build",
                investigation_steps=[
                    "Review build configurations and source",
                    "Check build trigger authenticity",
                    "Analyse compiled artifacts",
                    "Review build service account permissions",
                    "Check for obfuscation or packing tools",
                ],
                containment_actions=[
                    "Review Cloud Build IAM permissions",
                    "Restrict build trigger sources",
                    "Enable build approval requirements",
                    "Implement artifact scanning",
                    "Review and delete suspicious builds",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Exclude legitimate CI/CD pipelines and adjust threshold based on normal build frequency",
            detection_coverage="35% - detects compilation activities",
            evasion_considerations="External compilation environments outside GCP will not be detected",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Build enabled", "Audit logging enabled"],
        ),
    ],
    recommended_order=[
        "t1587-aws-guardduty",
        "t1587-gcp-artifact",
        "t1587-aws-s3-suspicious",
        "t1587-gcp-code-build",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+15% improvement for Resource Development tactic",
)
