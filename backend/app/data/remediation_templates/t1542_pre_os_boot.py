"""
T1542 - Pre-OS Boot

Adversaries exploit Pre-OS Boot mechanisms to establish persistence below the
operating system layer by compromising firmware (BIOS/UEFI), bootkits, or
component firmware. Detections focus on cloud infrastructure boot integrity.
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
    technique_id="T1542",
    technique_name="Pre-OS Boot",
    tactic_ids=["TA0005", "TA0003"],  # Defense Evasion, Persistence
    mitre_url="https://attack.mitre.org/techniques/T1542/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit Pre-OS Boot mechanisms to establish persistence "
            "below the operating system layer. They overwrite firmware data in BIOS "
            "or UEFI during the boot process, deploy bootkits, or compromise component "
            "firmware. Malware at this level is extremely difficult to detect since it "
            "executes before the OS loads and survives OS reinstallation."
        ),
        attacker_goal="Gain persistent, OS-independent access via firmware-level compromise",
        why_technique=[
            "Executes before OS and security tools load",
            "Survives OS reinstallation and disk reformatting",
            "Extremely difficult to detect and remove",
            "System-level privileges from boot",
            "Bypasses host-based security defences",
            "Enables long-term persistent access",
        ],
        known_threat_actors=[
            "APT28 (Fancy Bear)",
            "APT41 (Winnti/Double Dragon)",
            "Winnti Umbrella Groups",
            "MosaicRegressor operators",
            "Nation-state actors",
        ],
        recent_campaigns=[
            Campaign(
                name="MoonBounce UEFI Implant",
                year=2022,
                description="APT41 deployed advanced UEFI firmware implant for espionage",
                reference_url="https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/",
            ),
            Campaign(
                name="BlackLotus UEFI Bootkit",
                year=2023,
                description="First public bootkit bypassing UEFI Secure Boot on Windows 11",
                reference_url="https://www.bleepingcomputer.com/news/security/blacklotus-bootkit-bypasses-uefi-secure-boot-on-patched-windows-11/",
            ),
            Campaign(
                name="LoJax UEFI Rootkit",
                year=2018,
                description="APT28 deployed first discovered UEFI rootkit targeting government institutions",
                reference_url="https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/",
            ),
            Campaign(
                name="Bootkitty Linux UEFI Bootkit",
                year=2024,
                description="First UEFI bootkit targeting Linux systems (proof-of-concept)",
                reference_url="https://www.welivesecurity.com/en/eset-research/bootkitty-analyzing-first-uefi-bootkit-linux/",
            ),
        ],
        prevalence="rare",
        trend="increasing",
        severity_score=10,
        severity_reasoning=(
            "Maximum severity due to extreme difficulty of detection, persistence "
            "across OS reinstallation, system-level access, and ability to disable "
            "all OS-level security controls. Firmware-level compromise represents the "
            "highest level of system compromise and is nearly impossible to remediate "
            "without hardware replacement or firmware reflashing."
        ),
        business_impact=[
            "Complete system compromise",
            "Persistent espionage capability",
            "Extremely difficult remediation",
            "Potential fleet-wide impact",
            "Loss of hardware/firmware trust",
            "Regulatory compliance violations",
            "Total control over boot process",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1078.004", "T1552.005", "T1562.001", "T1070"],
        often_follows=["T1190", "T1068", "T1078"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1542-aws-nitro",
            name="AWS Nitro System Boot Integrity Monitoring",
            description="Monitor Nitro Enclave attestation and boot integrity for EC2 instances.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["EC2 Instance State-change Notification"],
                    "detail": {"state": ["running"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor EC2 boot integrity and Nitro attestation

Parameters:
  AlertEmail:
    Type: String
    Description: Email for boot integrity alerts

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Boot Integrity Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # EventBridge rule for instance launches
  InstanceLaunchRule:
    Type: AWS::Events::Rule
    Properties:
      Name: ec2-boot-verification
      Description: Verify boot integrity on instance launch
      EventPattern:
        source: [aws.ec2]
        detail-type: [EC2 Instance State-change Notification]
        detail:
          state: [running]
      Targets:
        - Id: VerifyBoot
          Arn: !GetAtt VerificationLambda.Arn

  # Lambda to verify boot integrity
  VerificationLambda:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: verify-boot-integrity
      Runtime: python3.11
      Handler: index.handler
      Timeout: 60
      Role: !GetAtt LambdaRole.Arn
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref AlertTopic
      Code:
        ZipFile: |
          import json
          import boto3
          import os

          def handler(event, context):
              # Verify Nitro attestation and boot integrity
              instance_id = event['detail']['instance-id']
              sns = boto3.client('sns')

              # Check boot integrity (implementation depends on logging)
              # Alert on anomalies
              sns.publish(
                  TopicArn=os.environ['SNS_TOPIC_ARN'],
                  Subject='EC2 Boot Verification Required',
                  Message=f'Instance {instance_id} launched - verify boot integrity'
              )

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: BootVerification
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - ec2:DescribeInstances
                  - sns:Publish
                Resource: '*'

  LambdaPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref VerificationLambda
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt InstanceLaunchRule.Arn""",
                terraform_template="""# AWS: Monitor EC2 boot integrity and Nitro attestation

variable "alert_email" {
  type        = string
  description = "Email for boot integrity alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "boot_alerts" {
  name         = "ec2-boot-integrity-alerts"
  display_name = "Boot Integrity Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.boot_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for instance state changes
resource "aws_cloudwatch_event_rule" "instance_launch" {
  name        = "ec2-boot-verification"
  description = "Verify boot integrity on instance launch"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["EC2 Instance State-change Notification"]
    detail = {
      state = ["running"]
    }
  })
}

# Lambda function to verify boot integrity
resource "aws_lambda_function" "verify_boot" {
  filename         = "verify_boot_integrity.zip"
  function_name    = "verify-boot-integrity"
  role            = aws_iam_role.lambda_role.arn
  handler         = "index.handler"
  runtime         = "python3.11"
  timeout         = 60

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.boot_alerts.arn
    }
  }
}

# EventBridge target
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.instance_launch.name
  target_id = "VerifyBoot"
  arn       = aws_lambda_function.verify_boot.arn
}

# Lambda execution role
resource "aws_iam_role" "lambda_role" {
  name = "boot-verification-lambda-role"

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

# Lambda policy for boot verification
resource "aws_iam_role_policy" "lambda_policy" {
  name = "boot-verification-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach managed policy for Lambda execution
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.verify_boot.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.instance_launch.arn
}""",
                alert_severity="critical",
                alert_title="EC2 Instance Boot Verification Required",
                alert_description_template="Instance {instance-id} launched - verify Nitro attestation and boot integrity.",
                investigation_steps=[
                    "Review Nitro Enclave attestation document if available",
                    "Verify Platform Configuration Register (PCR) values",
                    "Check instance boot logs for anomalies",
                    "Compare firmware version against known-good baseline",
                    "Verify AMI integrity and source",
                    "Review instance metadata and hardware details",
                    "Check for unexpected firmware modifications",
                    "Consult AWS Support for hardware verification if suspicious",
                ],
                containment_actions=[
                    "Immediately isolate suspicious instance",
                    "Stop instance and create forensic snapshot",
                    "Launch replacement from verified AMI",
                    "Enable Nitro Enclaves where possible",
                    "Implement boot integrity monitoring",
                    "Review all instances from same hardware batch",
                    "Report suspected firmware compromise to AWS Security",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal boot patterns; whitelist authorised AMIs",
            detection_coverage="60% - limited visibility into firmware-level activity",
            evasion_considerations="Sophisticated firmware backdoors may operate without logging",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4-6 hours",
            estimated_monthly_cost="$20-50",
            prerequisites=["Nitro-based EC2 instances", "CloudWatch Logs configured"],
        ),
        DetectionStrategy(
            strategy_id="t1542-aws-boot-logs",
            name="AWS EC2 Boot Anomaly Detection",
            description="Detect boot failures, firmware errors, and integrity issues via system logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, instance_id, @message
| filter @message like /boot|firmware|UEFI|BIOS|TPM|secure.boot/
| filter @message like /fail|error|anomaly|unexpected|modified|corrupt|invalid/
| stats count(*) as anomalies by instance_id, bin(1h)
| filter anomalies > 0
| sort anomalies desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 boot anomalies and firmware integrity issues

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Boot Anomaly Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for boot anomalies
  BootAnomalyFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: /aws/ec2/system
      FilterPattern: '[timestamp, instance, level, msg="*boot*fail*" || msg="*firmware*error*" || msg="*UEFI*fail*"]'
      MetricTransformations:
        - MetricName: BootAnomalies
          MetricNamespace: Security
          MetricValue: "1"
          DefaultValue: 0

  # CloudWatch alarm for boot anomalies
  BootAnomalyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EC2-Boot-Anomaly-Detected
      AlarmDescription: Detect EC2 boot failures and firmware anomalies
      MetricName: BootAnomalies
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect EC2 boot anomalies and firmware issues

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "boot_anomaly_alerts" {
  name         = "ec2-boot-anomaly-alerts"
  display_name = "Boot Anomaly Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.boot_anomaly_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for boot anomalies
resource "aws_cloudwatch_log_metric_filter" "boot_anomaly" {
  name           = "boot-anomalies"
  log_group_name = "/aws/ec2/system"
  pattern        = "[timestamp, instance, level, msg=\"*boot*fail*\" || msg=\"*firmware*error*\" || msg=\"*UEFI*fail*\" || msg=\"*TPM*fail*\"]"

  metric_transformation {
    name          = "BootAnomalies"
    namespace     = "Security"
    value         = "1"
    default_value = 0
  }
}

# CloudWatch alarm for boot anomalies
resource "aws_cloudwatch_metric_alarm" "boot_anomaly" {
  alarm_name          = "EC2-Boot-Anomaly-Detected"
  alarm_description   = "Detect EC2 boot failures and firmware anomalies"
  metric_name         = "BootAnomalies"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.boot_anomaly_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="critical",
                alert_title="EC2 Boot Anomaly Detected",
                alert_description_template="Boot failure or firmware anomaly detected on instance {instance_id}.",
                investigation_steps=[
                    "Review complete system boot logs",
                    "Check for firmware modification timestamps",
                    "Verify UEFI/BIOS version against baseline",
                    "Examine boot sequence for irregularities",
                    "Compare with other instances from same AMI",
                    "Check AWS Systems Manager inventory",
                    "Review recent instance modifications",
                    "Investigate any unexpected reboots",
                ],
                containment_actions=[
                    "Quarantine affected instance immediately",
                    "Stop instance and preserve state",
                    "Create forensic snapshot before any changes",
                    "Deploy replacement from verified AMI",
                    "Enable enhanced boot logging",
                    "Implement firmware integrity monitoring",
                    "Review fleet for similar anomalies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude planned firmware updates; baseline normal boot patterns",
            detection_coverage="40% - depends on comprehensive system logging",
            evasion_considerations="Advanced bootkits may suppress error logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["EC2 system logs enabled", "CloudWatch Logs configured"],
        ),
        DetectionStrategy(
            strategy_id="t1542-gcp-shielded",
            name="GCP Shielded VM Integrity Monitoring",
            description="Monitor Shielded VM integrity validation and vTPM attestation.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(protoPayload.methodName="v1.compute.instances.insert"
OR protoPayload.methodName="beta.compute.instances.start"
OR logName=~"logs/serialconsole"
OR logName=~"logs/syslog")
AND (
  jsonPayload.message=~".*integrity.*fail.*"
  OR jsonPayload.message=~".*boot.*verif.*fail.*"
  OR jsonPayload.message=~".*TPM.*fail.*"
  OR jsonPayload.message=~".*secure.*boot.*fail.*"
  OR jsonPayload.message=~".*UEFI.*fail.*"
  OR jsonPayload.message=~".*firmware.*error.*"
)""",
                gcp_terraform_template="""# GCP: Monitor Shielded VM boot integrity and vTPM attestation

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
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
  name    = "shielded-vm-boot-integrity-failures"

  filter = <<-EOT
    resource.type="gce_instance"
    (logName=~"logs/serialconsole" OR logName=~"logs/syslog")
    AND (
      jsonPayload.message=~".*integrity.*fail.*"
      OR jsonPayload.message=~".*boot.*verif.*fail.*"
      OR jsonPayload.message=~".*TPM.*fail.*"
      OR jsonPayload.message=~".*secure.*boot.*fail.*"
      OR jsonPayload.message=~".*UEFI.*fail.*"
      OR jsonPayload.message=~".*firmware.*error.*"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Alert policy for boot integrity failures
resource "google_monitoring_alert_policy" "boot_integrity_alert" {
  project      = var.project_id
  display_name = "Shielded VM Boot Integrity Failure"
  combiner     = "OR"

  conditions {
    display_name = "Boot integrity verification failed"

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

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "604800s"  # 7 days
  }

  documentation {
    content   = "Shielded VM boot integrity or vTPM verification failed. Investigate immediately for potential firmware compromise."
    mime_type = "text/markdown"
  }
}

# Log-based metric for vTPM attestation failures
resource "google_logging_metric" "vtpm_attestation" {
  project = var.project_id
  name    = "vtpm-attestation-failures"

  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~".*compute.*"
    AND (
      jsonPayload.event=~".*attestation.*"
      OR protoPayload.status.message=~".*attestation.*fail.*"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert policy for vTPM attestation failures
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

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "vTPM attestation failed. This may indicate firmware-level compromise or tampering."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Shielded VM Boot Integrity Failure",
                alert_description_template="Boot integrity or vTPM verification failed for instance {instance_name}.",
                investigation_steps=[
                    "Review Shielded VM integrity validation logs",
                    "Check vTPM measurements against baseline",
                    "Verify Secure Boot configuration status",
                    "Review instance boot sequence and system logs",
                    "Compare with other instances from same image",
                    "Check firmware update and modification history",
                    "Verify image source integrity and provenance",
                    "Review instance metadata for anomalies",
                ],
                containment_actions=[
                    "Stop instance immediately",
                    "Create forensic disk snapshot",
                    "Preserve instance for investigation",
                    "Launch replacement from verified image",
                    "Enable Shielded VM on all instances",
                    "Implement Confidential Computing where applicable",
                    "Review all instances from same image source",
                    "Report to Google Cloud Security if hardware suspected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Baseline Shielded VM measurements; exclude authorised firmware updates",
            detection_coverage="80% - for Shielded VM instances with vTPM",
            evasion_considerations="Advanced firmware implants may manipulate measurements",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Shielded VM enabled", "Serial console logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1542-gcp-instance-launch",
            name="GCP Instance Launch Boot Verification",
            description="Monitor instance creation and verify boot integrity baseline.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(protoPayload.methodName="v1.compute.instances.insert"
OR protoPayload.methodName="beta.compute.instances.start")
AND operation.first=true""",
                gcp_terraform_template="""# GCP: Monitor instance launch and verify boot integrity

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Instance Boot Verification Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for instance creation
resource "google_logging_metric" "instance_launch" {
  project = var.project_id
  name    = "instance-launch-boot-verification"

  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName="v1.compute.instances.insert"
    OR protoPayload.methodName="beta.compute.instances.start")
    AND operation.first=true
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Alert policy for instance launches
resource "google_monitoring_alert_policy" "instance_launch_alert" {
  project      = var.project_id
  display_name = "Instance Launch - Boot Verification Required"
  combiner     = "OR"

  conditions {
    display_name = "New instance requires boot verification"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.instance_launch.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "New instance created or started. Verify Shielded VM settings and boot integrity baseline."
    mime_type = "text/markdown"
  }
}

# Log sink for instance creation events
resource "google_logging_project_sink" "instance_creation" {
  project     = var.project_id
  name        = "instance-boot-verification-sink"
  destination = "pubsub.googleapis.com/projects/${var.project_id}/topics/instance-boot-verification"

  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName="v1.compute.instances.insert"
    OR protoPayload.methodName="beta.compute.instances.start")
    AND operation.first=true
  EOT

  unique_writer_identity = true
}

# Pub/Sub topic for verification workflow
resource "google_pubsub_topic" "verification" {
  project = var.project_id
  name    = "instance-boot-verification"
}

# Grant log sink permission to publish
resource "google_pubsub_topic_iam_binding" "log_sink" {
  project = var.project_id
  topic   = google_pubsub_topic.verification.name
  role    = "roles/pubsub.publisher"
  members = [google_logging_project_sink.instance_creation.writer_identity]
}""",
                alert_severity="high",
                alert_title="GCP: Instance Launch - Boot Verification Required",
                alert_description_template="Instance {instance_name} created/started - verify boot integrity and Shielded VM settings.",
                investigation_steps=[
                    "Verify Shielded VM is enabled on instance",
                    "Check vTPM and integrity monitoring status",
                    "Review instance creation audit logs",
                    "Verify image source and integrity hash",
                    "Check instance zone and machine type",
                    "Review Secure Boot configuration",
                    "Compare boot baseline with expected values",
                ],
                containment_actions=[
                    "Enforce Shielded VM on all new instances",
                    "Enable Confidential Computing where supported",
                    "Implement organisation policy requiring Shielded VM",
                    "Enable automatic OS patch management",
                    "Document boot integrity verification process",
                    "Create golden image baselines with verified boot configs",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised deployment service accounts; baseline normal instance creation",
            detection_coverage="100% - all instance creation and start events",
            evasion_considerations="Cannot evade instance creation logging in GCP",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1542-aws-nitro",
        "t1542-gcp-shielded",
        "t1542-aws-boot-logs",
        "t1542-gcp-instance-launch",
    ],
    total_effort_hours=14.0,
    coverage_improvement="+30% improvement for Defense Evasion and Persistence tactics",
)
