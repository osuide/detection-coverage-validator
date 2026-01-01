"""
T1489 - Service Stop

Adversaries stop or disable services to inhibit response or enable ransomware.
Used by Wizard Spider, Conti, LockBit, RobbinHood, Lazarus Group.
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
    technique_id="T1489",
    technique_name="Service Stop",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1489/",
    threat_context=ThreatContext(
        description=(
            "Adversaries stop or disable services to render them unavailable. "
            "In cloud, this includes stopping EC2 instances, disabling Lambda functions, "
            "or stopping ECS/GKE services to facilitate destruction or encryption."
        ),
        attacker_goal="Stop critical services to enable ransomware or cause disruption",
        why_technique=[
            "Enables data encryption without locks",
            "Prevents incident response",
            "Maximises business disruption",
            "Stops backup services",
            "Disables security tools",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=9,
        severity_reasoning=(
            "Critical impact technique used before ransomware deployment. "
            "Stops security and backup services to maximise damage."
        ),
        business_impact=[
            "Service unavailability",
            "Enables ransomware encryption",
            "Backup service disruption",
            "Extended recovery time",
        ],
        typical_attack_phase="impact",
        often_precedes=["T1486", "T1485"],
        often_follows=["T1078.004", "T1021.007"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1489-aws-stop",
            name="AWS Service Stop Detection",
            description="Detect stopping of EC2 instances, Lambda functions, and ECS services.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2", "aws.lambda", "aws.ecs"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "StopInstances",
                            "TerminateInstances",
                            "DeleteFunction",
                            "UpdateFunctionConfiguration",
                            "StopTask",
                            "DeleteService",
                            "UpdateService",
                        ]
                    },
                },
                terraform_template="""# Detect cloud service stops

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "service-stop-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed event deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "service-stop-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_cloudwatch_event_rule" "service_stop" {
  name = "cloud-service-stop"
  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.lambda", "aws.ecs"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "StopInstances", "TerminateInstances",
        "DeleteFunction", "StopTask", "DeleteService"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.service_stop.name
  arn  = aws_sns_topic.alerts.arn

  # Retry policy: 8 attempts over 1 hour
  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age      = 3600
  }

  # Dead letter queue for failed deliveries
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.service_stop.arn
        }
      }
    }]
  })
}

# Allow EventBridge to send failed events to DLQ
resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Cloud Service Stopped",
                alert_description_template="Service stopped: {eventName} by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify stop was authorised",
                    "Check for bulk service stops",
                    "Review user's recent activity",
                    "Check for ransomware indicators",
                ],
                containment_actions=[
                    "Restart critical services",
                    "Isolate compromised identity",
                    "Review all recent stops",
                    "Activate incident response",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude scheduled maintenance windows",
            detection_coverage="90% - catches API-based stops",
            evasion_considerations="Cannot evade if CloudTrail enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1489-aws-bulk",
            name="AWS Bulk Service Stop Detection",
            description="Detect bulk stopping of services indicating ransomware.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventSource in ["ec2.amazonaws.com", "lambda.amazonaws.com", "ecs.amazonaws.com"]
| filter eventName in ["StopInstances", "TerminateInstances", "DeleteFunction", "StopTask"]
| stats count(*) as stop_count by userIdentity.arn, bin(15m)
| filter stop_count > 5
| sort stop_count desc""",
                terraform_template="""# Detect bulk service stops

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "bulk-stop-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "bulk_stop" {
  name           = "bulk-service-stops"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"StopInstances\" || $.eventName = \"TerminateInstances\" || $.eventName = \"DeleteFunction\" }"

  metric_transformation {
    name      = "ServiceStops"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "bulk_stop" {
  alarm_name          = "BulkServiceStop"
  metric_name         = "ServiceStops"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Bulk Service Stop - Possible Ransomware",
                alert_description_template="Multiple services stopped by {userIdentity.arn} in short time.",
                investigation_steps=[
                    "Immediately investigate as ransomware",
                    "Check for data encryption",
                    "Review all affected services",
                    "Activate IR playbook",
                ],
                containment_actions=[
                    "Isolate affected accounts",
                    "Revoke compromised credentials",
                    "Enable recovery procedures",
                    "Engage incident response team",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Bulk stops are rare outside maintenance",
            detection_coverage="95% - catches bulk stops",
            evasion_considerations="Attacker may slow down stops",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1489-gcp-stop",
            name="GCP Service Stop Detection",
            description="Detect stopping of GCE instances, Cloud Functions, and GKE workloads.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(instances.stop|instances.delete|functions.delete|deployments.delete)"
OR protoPayload.serviceName="container.googleapis.com" AND protoPayload.methodName=~"delete"''',
                gcp_terraform_template="""# GCP: Detect service stops

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "service_stop" {
  name   = "cloud-service-stops"
  filter = <<-EOT
    protoPayload.methodName=~"instances.stop|instances.delete|functions.delete"
    OR protoPayload.serviceName="container.googleapis.com"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "service_stop" {
  display_name = "Service Stop Alert"
  combiner     = "OR"
  conditions {
    display_name = "Multiple service stops"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.service_stop.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="critical",
                alert_title="GCP: Service Stops Detected",
                alert_description_template="Cloud services being stopped or deleted.",
                investigation_steps=[
                    "Verify stops are authorised",
                    "Check for bulk operations",
                    "Review actor identity",
                    "Check for ransomware",
                ],
                containment_actions=[
                    "Restart critical services",
                    "Isolate compromised accounts",
                    "Review all recent operations",
                    "Activate incident response",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude scheduled maintenance",
            detection_coverage="90% - catches API-based stops",
            evasion_considerations="Cannot evade audit logs",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1489-aws-bulk", "t1489-aws-stop", "t1489-gcp-stop"],
    total_effort_hours=3.0,
    coverage_improvement="+20% improvement for Impact tactic",
)
