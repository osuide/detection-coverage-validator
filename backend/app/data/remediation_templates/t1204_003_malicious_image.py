"""
T1204.003 - User Execution: Malicious Image

Adversaries deploy backdoored container/VM images from public repositories.
Users unknowingly run malicious instances. Used by TeamTNT.
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
    technique_id="T1204.003",
    technique_name="User Execution: Malicious Image",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1204/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries deploy backdoored container or VM images to public repositories. "
            "Users unknowingly download and deploy these images, bypassing initial access defenses."
        ),
        attacker_goal="Execute malicious code via trojanised container/VM images",
        why_technique=[
            "Users trust public repositories",
            "Images run with system privileges",
            "Hard to detect backdoors",
            "Deceptive naming tricks users",
            "Bypasses perimeter defenses",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Execution via trusted-looking images. Hard to detect. "
            "Can lead to cryptomining or data theft."
        ),
        business_impact=[
            "Malware execution",
            "Cryptomining abuse",
            "Data exfiltration",
            "Credential theft",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1496.001", "T1530"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1204003-aws-public",
            name="AWS Public Image Usage Detection",
            description="Detect EC2 instances launched from non-approved public AMIs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.imageId, userIdentity.arn
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "RunInstances"
| filter requestParameters.imageId not like /^ami-[a-z0-9]+/ or requestParameters.imageId not like /approved/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect usage of unapproved AMIs

Parameters:
  CloudTrailLogGroup:
    Type: String
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

  PublicAMIFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "RunInstances" }'
      MetricTransformations:
        - MetricName: InstanceLaunches
          MetricNamespace: Security
          MetricValue: "1"

  AMIAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: InstanceLaunchAlert
      MetricName: InstanceLaunches
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect usage of unapproved images

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "image-usage-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_caller_identity" "current" {}

# Use Config rule to check approved AMIs
resource "aws_config_config_rule" "approved_amis" {
  name = "approved-amis-by-id"
  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_ID"
  }
  input_parameters = jsonencode({
    amiIds = "ami-xxxxxxxx,ami-yyyyyyyy"  # Your approved AMIs
  })
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
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
                alert_severity="high",
                alert_title="Unapproved Image Used",
                alert_description_template="Instance launched from potentially unapproved image {imageId}.",
                investigation_steps=[
                    "Verify image is from approved source",
                    "Check image for malware",
                    "Review who launched the instance",
                    "Check instance behaviour",
                ],
                containment_actions=[
                    "Terminate suspicious instances",
                    "Block unapproved AMIs via SCP",
                    "Require AMI approval process",
                    "Scan running containers",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Maintain approved image list",
            detection_coverage="70% - requires image whitelist",
            evasion_considerations="Attacker may use similar names",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["Approved AMI list maintained"],
        ),
        DetectionStrategy(
            strategy_id="t1204003-gcp-public",
            name="GCP Public Image Usage Detection",
            description="Detect VMs launched from non-approved public images.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="compute.instances.insert"
protoPayload.request.disks.initializeParams.sourceImage!~"projects/YOUR-PROJECT"''',
                gcp_terraform_template="""# GCP: Detect usage of unapproved images

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "external_image" {
  name   = "external-image-usage"
  filter = <<-EOT
    protoPayload.methodName="compute.instances.insert"
    NOT protoPayload.request.disks.initializeParams.sourceImage=~"projects/${var.project_id}"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "external_image" {
  project      = var.project_id
  display_name = "External Image Usage"
  combiner     = "OR"
  conditions {
    display_name = "Non-approved image used"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.external_image.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Unapproved Image Used",
                alert_description_template="VM launched from external image.",
                investigation_steps=[
                    "Verify image source",
                    "Check for malware",
                    "Review launcher",
                    "Check VM behaviour",
                ],
                containment_actions=[
                    "Delete suspicious VMs",
                    "Use org policies for images",
                    "Enable Binary Authorization",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Maintain approved image projects",
            detection_coverage="70% - requires image policy",
            evasion_considerations="Similar naming",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1204003-aws-public", "t1204003-gcp-public"],
    total_effort_hours=4.0,
    coverage_improvement="+12% improvement for Execution tactic",
)
