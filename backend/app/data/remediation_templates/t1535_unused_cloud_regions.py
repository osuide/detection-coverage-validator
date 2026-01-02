"""
T1535 - Unused/Unsupported Cloud Regions

Adversaries create resources in underutilised cloud regions to evade detection.
Regions without monitoring are attractive for cryptomining and other abuse.
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
    technique_id="T1535",
    technique_name="Unused/Unsupported Cloud Regions",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1535/",
    threat_context=ThreatContext(
        description=(
            "Adversaries create resources in underutilised geographic cloud regions "
            "where organisations don't typically operate or monitor. These regions "
            "may lack advanced detection capabilities."
        ),
        attacker_goal="Evade detection by using unmonitored cloud regions",
        why_technique=[
            "Unused regions often lack monitoring",
            "Detection tools may not cover all regions",
            "Security teams focus on primary regions",
            "Billing alerts may not be region-specific",
            "Enables cryptomining without detection",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=6,
        severity_reasoning=(
            "Defence evasion technique. Can lead to significant costs and "
            "undetected malicious activity in regions without monitoring."
        ),
        business_impact=[
            "Unexpected cloud costs",
            "Undetected malicious activity",
            "Resource abuse",
            "Compliance gaps in unused regions",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1496.001", "T1578.002"],
        often_follows=["T1078.004"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1535-aws-unusedregion",
            name="AWS Unused Region Activity Detection",
            description="Detect resource creation in regions not typically used.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, awsRegion, eventName, userIdentity.arn
| filter eventName like /Create|Run|Launch/
| filter awsRegion not in ["eu-west-1", "eu-west-2", "us-east-1"]
| stats count(*) as activity by awsRegion
| sort activity desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect activity in unused regions

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String
  AllowedRegions:
    Type: CommaDelimitedList
    Default: "eu-west-1,eu-west-2,us-east-1"

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  UnusedRegionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "RunInstances" || $.eventName = "CreateBucket" }'
      MetricTransformations:
        - MetricName: UnusedRegionActivity
          MetricNamespace: Security
          MetricValue: "1"

  UnusedRegionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusedRegionActivity
      MetricName: UnusedRegionActivity
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect activity in unused AWS regions

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }
variable "allowed_regions" {
  type    = list(string)
  default = ["eu-west-1", "eu-west-2", "us-east-1"]
}

resource "aws_sns_topic" "alerts" {
  name = "unused-region-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Deploy EventBridge rule in each unused region
# This detects any EC2/resource creation

resource "aws_cloudwatch_event_rule" "unused_region" {
  name = "unused-region-activity"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["RunInstances"] }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "unused-region-dlq"
  message_retention_seconds = 1209600
}

data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sqs_queue.dlq.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.unused_region.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.unused_region.name
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
            "aws:SourceArn" = aws_cloudwatch_event_rule.unused_region.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Activity in Unused Region",
                alert_description_template="Resource created in region {awsRegion} which is not normally used.",
                investigation_steps=[
                    "Verify if the region should have activity",
                    "Check what resources were created",
                    "Review who initiated the activity",
                    "Check for cryptomining indicators",
                ],
                containment_actions=[
                    "Terminate resources in unused regions",
                    "Use SCPs to deny actions in unused regions",
                    "Enable GuardDuty in all regions",
                    "Set up billing alerts per region",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Define allowed regions for your organisation",
            detection_coverage="90% - catches creation in unusual regions",
            evasion_considerations="Attacker may use allowed regions",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled in all regions"],
        ),
        DetectionStrategy(
            strategy_id="t1535-gcp-unusedregion",
            name="GCP Unused Region Activity Detection",
            description="Detect resource creation in regions not typically used.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"compute.instances.insert"
resource.labels.zone!~"europe-west2|us-central1"''',
                gcp_terraform_template="""# GCP: Detect activity in unused regions

variable "project_id" { type = string }
variable "alert_email" { type = string }
variable "allowed_regions" {
  type    = list(string)
  default = ["europe-west2", "us-central1"]
}

resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "unused_region" {
  project = var.project_id
  name   = "unused-region-activity"
  filter = <<-EOT
    protoPayload.methodName="compute.instances.insert"
    NOT resource.labels.zone=~"${join("|", var.allowed_regions)}"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "unused_region" {
  project      = var.project_id
  display_name = "Unused Region Activity"
  combiner     = "OR"
  conditions {
    display_name = "Activity in unused region"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.unused_region.name}\""
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
                alert_title="GCP: Activity in Unused Region",
                alert_description_template="Resource created in region not normally used.",
                investigation_steps=[
                    "Verify if region should have activity",
                    "Check what resources were created",
                    "Review who initiated activity",
                    "Check for cryptomining",
                ],
                containment_actions=[
                    "Delete resources in unused regions",
                    "Set organisation policy constraints",
                    "Enable SCC in all regions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Define allowed regions",
            detection_coverage="90% - catches unusual regions",
            evasion_considerations="Attacker may use allowed regions",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1535-aws-unusedregion", "t1535-gcp-unusedregion"],
    total_effort_hours=3.0,
    coverage_improvement="+12% improvement for Defence Evasion tactic",
)
