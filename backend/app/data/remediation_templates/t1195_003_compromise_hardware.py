"""
T1195.003 - Supply Chain Compromise: Compromise Hardware Supply Chain

Adversaries manipulate hardware components or firmware in products before they
reach consumers. Backdoored servers, network devices, or peripherals provide
persistent access with system-level control.
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
    technique_id="T1195.003",
    technique_name="Supply Chain Compromise: Compromise Hardware Supply Chain",
    tactic_ids=["TA0001"],
    mitre_url="https://attack.mitre.org/techniques/T1195/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries manipulate hardware components or firmware in servers, "
            "network devices, workstations, or peripherals before they reach end "
            "users. Backdoored hardware provides persistent, system-level access that "
            "is difficult to detect through traditional security monitoring."
        ),
        attacker_goal="Gain persistent system-level access via compromised hardware supply chain",
        why_technique=[
            "Extremely difficult to detect",
            "Survives OS reinstallation",
            "System-level privileges",
            "Affects all cloud instances using hardware",
            "Bypasses software security controls",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="rare",
        trend="stable",
        severity_score=10,
        severity_reasoning=(
            "Highest severity due to difficulty of detection, persistence across "
            "system rebuilds, system-level access, and potential for widespread impact. "
            "Compromised firmware survives traditional remediation efforts."
        ),
        business_impact=[
            "Persistent system compromise",
            "Complete system control",
            "Difficult remediation",
            "Potential fleet-wide impact",
            "Loss of hardware trust",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1078.004", "T1552.005", "T1530", "T1098"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1195.003-aws-boot",
            name="AWS EC2 Boot Integrity Monitoring",
            description="Detect anomalous boot behaviour and firmware changes in EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, instance_id, @message
| filter @message like /boot|firmware|UEFI|BIOS|TPM/
| filter @message like /fail|error|anomaly|unexpected|modified/
| stats count(*) as anomalies by instance_id, bin(1h)
| filter anomalies > 0
| sort anomalies desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 boot integrity issues and firmware anomalies

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Boot Integrity Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for boot anomalies
  BootAnomalyFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: /aws/ec2/system
      FilterPattern: '[timestamp, instance, level=ERROR*, msg="*boot*" || msg="*firmware*" || msg="*UEFI*"]'
      MetricTransformations:
        - MetricName: BootIntegrityFailures
          MetricNamespace: Security
          MetricValue: "1"

  # CloudWatch alarm
  BootIntegrityAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EC2-Boot-Integrity-Failure
      AlarmDescription: Detect EC2 boot or firmware integrity issues
      MetricName: BootIntegrityFailures
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect EC2 boot integrity and firmware anomalies

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "boot_alerts" {
  name         = "ec2-boot-integrity-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Boot Integrity Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.boot_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for boot anomalies
resource "aws_cloudwatch_log_metric_filter" "boot_anomaly" {
  name           = "boot-integrity-failures"
  log_group_name = "/aws/ec2/system"
  pattern        = "[timestamp, instance, level=ERROR*, msg=\"*boot*\" || msg=\"*firmware*\" || msg=\"*UEFI*\"]"

  metric_transformation {
    name      = "BootIntegrityFailures"
    namespace = "Security"
    value     = "1"
  }
}

# CloudWatch alarm for boot integrity
resource "aws_cloudwatch_metric_alarm" "boot_integrity" {
  alarm_name          = "EC2-Boot-Integrity-Failure"
  alarm_description   = "Detect EC2 boot or firmware integrity issues"
  metric_name         = "BootIntegrityFailures"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.boot_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="EC2 Boot Integrity Failure Detected",
                alert_description_template="Boot integrity or firmware anomaly detected on instance {instance_id}.",
                investigation_steps=[
                    "Immediately isolate affected instance",
                    "Review instance boot logs and system logs",
                    "Check firmware version against known-good baseline",
                    "Verify instance AMI integrity and provenance",
                    "Compare with other instances from same hardware batch",
                    "Review AWS Systems Manager inventory data",
                    "Check for unexpected hardware changes",
                    "Consult AWS Support for hardware verification",
                ],
                containment_actions=[
                    "Quarantine affected instance immediately",
                    "Stop instance and create forensic snapshot",
                    "Do NOT restart - preserve evidence",
                    "Identify all instances from same hardware batch",
                    "Deploy replacement instances from verified AMIs",
                    "Enable EC2 Instance Connect Endpoint for secure access",
                    "Report to AWS Security if hardware compromise suspected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal boot patterns; exclude planned firmware updates",
            detection_coverage="40% - requires comprehensive logging",
            evasion_considerations="Sophisticated firmware backdoors may avoid log generation",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["EC2 system logs enabled", "CloudWatch Logs configured"],
        ),
        DetectionStrategy(
            strategy_id="t1195.003-aws-nitro",
            name="AWS Nitro System Attestation",
            description="Monitor Nitro Enclave attestation for hardware integrity verification.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["EC2 Instance State-change Notification"],
                    "detail": {"state": ["running"]},
                },
                terraform_template="""# AWS: Monitor Nitro attestation and hardware verification

variable "alert_email" {
  type        = string
  description = "Email for attestation alerts"
}

# SNS topic for Nitro attestation alerts
resource "aws_sns_topic" "nitro_alerts" {
  name = "nitro-attestation-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.nitro_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for instance state changes
resource "aws_cloudwatch_event_rule" "instance_launch" {
  name        = "ec2-instance-launch-verification"
  description = "Trigger hardware verification on instance launch"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["EC2 Instance State-change Notification"]
    detail = {
      state = ["running"]
    }
  })
}

# Lambda function to verify Nitro attestation
resource "aws_lambda_function" "verify_attestation" {
  filename         = "verify_nitro_attestation.zip"
  function_name    = "verify-nitro-attestation"
  role            = aws_iam_role.lambda_role.arn
  handler         = "index.handler"
  runtime         = "python3.11"
  timeout         = 60

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.nitro_alerts.arn
    }
  }
}

# DLQ for failed EventBridge deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "nitro-attestation-dlq"
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.instance_launch.arn
        }
      }
    }]
  })
}

# EventBridge target
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.instance_launch.name
  target_id = "VerifyAttestation"
  arn       = aws_lambda_function.verify_attestation.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account = "$.account"
      region  = "$.region"
      time    = "$.time"
      source  = "$.source"
      detail  = "$.detail"
    }

    input_template = <<-EOT
"Security Alert
Time: <time>
Account: <account>
Region: <region>
Source: <source>
Action: Review event details and investigate"
EOT
  }

}

# Allow EventBridge to publish to SNS
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.nitro_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.nitro_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.instance_launch.arn
        }
      }
    }]
  })
}

# Lambda execution role
resource "aws_iam_role" "lambda_role" {
  name = "nitro-attestation-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# Lambda permissions
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.verify_attestation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.instance_launch.arn
}""",
                alert_severity="critical",
                alert_title="Nitro Attestation Verification Failure",
                alert_description_template="Hardware attestation failed for instance {instance_id}.",
                investigation_steps=[
                    "Review Nitro Enclave attestation document",
                    "Verify PCR (Platform Configuration Register) values",
                    "Compare against known-good attestation baseline",
                    "Check instance metadata for hardware details",
                    "Review instance placement and availability zone",
                    "Verify instance type supports Nitro attestation",
                ],
                containment_actions=[
                    "Terminate instance immediately",
                    "Launch replacement from verified AMI",
                    "Document attestation failure details",
                    "Report to AWS Security team",
                    "Review all instances in same placement group",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Requires proper Nitro attestation baseline configuration",
            detection_coverage="85% - for Nitro-based instances only",
            evasion_considerations="Only works with Nitro System instances",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4-6 hours",
            estimated_monthly_cost="$15-40",
            prerequisites=["EC2 Nitro instances", "Lambda execution permissions"],
        ),
        DetectionStrategy(
            strategy_id="t1195.003-gcp-shielded",
            name="GCP Shielded VM Integrity Monitoring",
            description="Monitor Shielded VM integrity validation and boot measurements.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.insert"
OR protoPayload.methodName="beta.compute.instances.start"
OR logName=~"logs/serialconsole"
AND (jsonPayload.message=~".*integrity.*fail.*"
OR jsonPayload.message=~".*boot.*verif.*fail.*"
OR jsonPayload.message=~".*TPM.*fail.*"
OR jsonPayload.message=~".*secure.*boot.*fail.*")""",
                gcp_terraform_template="""# GCP: Monitor Shielded VM integrity and boot verification

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Boot Integrity Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for boot integrity failures
resource "google_logging_metric" "boot_integrity" {
  project = var.project_id
  name    = "shielded-vm-integrity-failures"

  filter = <<-EOT
    resource.type="gce_instance"
    (logName=~"logs/serialconsole" OR logName=~"logs/syslog")
    AND (
      jsonPayload.message=~".*integrity.*fail.*"
      OR jsonPayload.message=~".*boot.*verif.*fail.*"
      OR jsonPayload.message=~".*TPM.*fail.*"
      OR jsonPayload.message=~".*secure.*boot.*fail.*"
      OR jsonPayload.message=~".*UEFI.*fail.*"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Alert policy for integrity failures
resource "google_monitoring_alert_policy" "boot_integrity_alert" {
  project      = var.project_id
  display_name = "Shielded VM Boot Integrity Failure"
  combiner     = "OR"

  conditions {
    display_name = "Boot integrity check failed"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.boot_integrity.name}\" AND resource.type=\"gce_instance\""
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
    content   = "Shielded VM boot integrity verification failed. Investigate immediately for potential hardware compromise."
    mime_type = "text/markdown"
  }
}

# Log-based metric for vTPM attestation
resource "google_logging_metric" "vtpm_attestation" {
  project = var.project_id
  name    = "vtpm-attestation-failures"

  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~".*compute.*"
    AND jsonPayload.event=~".*attestation.*"
    AND jsonPayload.status="FAIL"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert for vTPM attestation failures
resource "google_monitoring_alert_policy" "vtpm_alert" {
  project      = var.project_id
  display_name = "vTPM Attestation Failure"
  combiner     = "OR"

  conditions {
    display_name = "vTPM attestation check failed"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.vtpm_attestation.name}\""
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
}""",
                alert_severity="critical",
                alert_title="GCP: Shielded VM Integrity Failure",
                alert_description_template="Boot integrity or vTPM verification failed for instance {instance_name}.",
                investigation_steps=[
                    "Review Shielded VM integrity validation logs",
                    "Check vTPM measurements against baseline",
                    "Verify Secure Boot configuration",
                    "Review instance boot sequence logs",
                    "Compare with other instances from same image",
                    "Check for firmware update history",
                    "Verify image provenance and checksum",
                ],
                containment_actions=[
                    "Stop instance immediately",
                    "Create forensic disk snapshot",
                    "Do not delete - preserve for investigation",
                    "Launch replacement from verified image",
                    "Enable Shielded VM on all instances",
                    "Review all instances from same image source",
                    "Report to Google Cloud Security if hardware suspected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Baseline Shielded VM measurements; exclude planned updates",
            detection_coverage="80% - for Shielded VM instances",
            evasion_considerations="Sophisticated firmware may avoid measurement changes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Shielded VM enabled", "Serial console logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1195.003-gcp-integrity",
            name="GCP Instance Integrity Verification",
            description="Monitor instance creation and verify hardware integrity baseline.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.insert"
AND operation.first=true""",
                gcp_terraform_template="""# GCP: Verify instance integrity on creation

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Instance Integrity Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log sink for instance creation
resource "google_logging_project_sink" "instance_creation" {
  project     = var.project_id
  name        = "instance-creation-verification"
  destination = "pubsub.googleapis.com/projects/${var.project_id}/topics/instance-verification"

  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="v1.compute.instances.insert"
    AND operation.first=true
  EOT

  unique_writer_identity = true
}

# Pub/Sub topic for verification workflow
resource "google_pubsub_topic" "verification" {
  project = var.project_id
  name    = "instance-verification"
}

# Pub/Sub subscription
resource "google_pubsub_subscription" "verification_sub" {
  project = var.project_id
  name    = "instance-verification-sub"
  topic   = google_pubsub_topic.verification.name

  ack_deadline_seconds = 60
}

# Grant log sink permission to publish
resource "google_pubsub_topic_iam_binding" "log_sink" {
  project = var.project_id
  topic   = google_pubsub_topic.verification.name
  role    = "roles/pubsub.publisher"
  members = [google_logging_project_sink.instance_creation.writer_identity]
}""",
                alert_severity="high",
                alert_title="GCP: New Instance Requires Integrity Verification",
                alert_description_template="New instance {instance_name} created - verify hardware integrity.",
                investigation_steps=[
                    "Verify Shielded VM is enabled",
                    "Check vTPM measurements",
                    "Review instance creation logs",
                    "Verify image source and integrity",
                    "Check instance zone and hardware platform",
                    "Compare with security baseline",
                ],
                containment_actions=[
                    "Require Shielded VM for all instances",
                    "Enable Confidential Computing where possible",
                    "Implement organisation policy for Shielded VM",
                    "Document hardware verification process",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist automated deployment service accounts",
            detection_coverage="100% - all instance creation events",
            evasion_considerations="Cannot evade instance creation logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1195.003-aws-nitro",
        "t1195.003-gcp-shielded",
        "t1195.003-aws-boot",
        "t1195.003-gcp-integrity",
    ],
    total_effort_hours=12.0,
    coverage_improvement="+25% improvement for Initial Access tactic",
)
