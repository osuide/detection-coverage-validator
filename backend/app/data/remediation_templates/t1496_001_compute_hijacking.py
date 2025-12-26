"""
T1496.001 - Resource Hijacking: Compute Hijacking

Adversaries abuse system resources for cryptocurrency mining.
Used by TeamTNT, Kinsing, APT41, and Blue Mockingbird.
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
    technique_id="T1496.001",
    technique_name="Resource Hijacking: Compute Hijacking",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1496/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse compute resources for cryptocurrency mining. "
            "Targets servers, cloud infrastructure, and containers due to "
            "their computational capacity. Uses tools like XMRig."
        ),
        attacker_goal="Abuse compute resources for cryptocurrency mining",
        why_technique=[
            "Monetises compromised infrastructure",
            "Cloud resources scale easily",
            "Victim pays electricity/compute costs",
            "XMRig and similar tools readily available",
            "Containers and serverless also targeted",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Direct financial impact through compute costs. "
            "Indicates compromised infrastructure. May affect system performance."
        ),
        business_impact=[
            "Significant cloud cost increases",
            "Degraded system performance",
            "Indicates broader compromise",
            "Potential compliance issues",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1578.002", "T1535"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1496001-aws-cpu",
            name="AWS High CPU Utilisation Detection",
            description="Detect sustained high CPU indicative of cryptomining.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""# Use CloudWatch Metrics for EC2 CPU monitoring
# CPUUtilization > 90% for extended periods indicates mining""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect cryptomining via high CPU

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

  HighCPUAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: PotentialCryptomining
      MetricName: CPUUtilization
      Namespace: AWS/EC2
      Statistic: Average
      Period: 300
      Threshold: 90
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 12
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]
      Dimensions:
        - Name: InstanceId
          Value: "*"''',
                terraform_template="""# Detect cryptomining via high CPU

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "cryptomining-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Per-instance alarm (create for each critical instance)
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "PotentialCryptomining"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  period              = 300
  threshold           = 90
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 12  # 1 hour sustained
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Potential Cryptomining Detected",
                alert_description_template="Instance {instanceId} sustained >90% CPU for 1+ hour.",
                investigation_steps=[
                    "Check running processes on instance",
                    "Look for xmrig, minerd, or similar",
                    "Review network connections to mining pools",
                    "Check for unauthorised containers",
                ],
                containment_actions=[
                    "Terminate malicious processes",
                    "Isolate or terminate instance",
                    "Review instance launch origin",
                    "Scan for backdoors",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known compute-intensive workloads",
            detection_coverage="70% - catches obvious mining",
            evasion_considerations="Throttled mining may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudWatch detailed monitoring"],
        ),
        DetectionStrategy(
            strategy_id="t1496001-aws-guardduty",
            name="GuardDuty Cryptomining Detection",
            description="Use GuardDuty to detect cryptomining activity.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                    "CryptoCurrency:EC2/BitcoinTool.B",
                    "Impact:EC2/BitcoinDomainRequest.Reputation",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty cryptomining detection

Parameters:
  AlertEmail:
    Type: String

Resources:
  Detector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: guardduty-crypto-alerts-dlq
      MessageRetentionPeriod: 1209600

  CryptoMiningRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "CryptoCurrency:"
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          DeadLetterConfig:
            Arn: !GetAtt DeadLetterQueue.Arn
          InputTransformer:
            InputPathsMap:
              account: $.account
              region: $.region
              time: $.time
              type: $.detail.type
              severity: $.detail.severity
              instanceId: $.detail.resource.instanceDetails.instanceId
            InputTemplate: |
              "CRITICAL: Cryptomining Detected (T1496.001)"
              "Time: <time>"
              "Account: <account> | Region: <region>"
              "Finding Type: <type>"
              "Severity: <severity>"
              "Instance: <instanceId>"
              "Action: Terminate instance and investigate"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
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
                aws:SourceArn: !GetAtt CryptoMiningRule.Arn

  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref DeadLetterQueue
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt DeadLetterQueue.Arn""",
                terraform_template="""# GuardDuty cryptomining detection

variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_sns_topic" "alerts" {
  name              = "guardduty-crypto-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-crypto-alerts-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_rule" "crypto" {
  name = "guardduty-cryptomining"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "CryptoCurrency:" }]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.crypto.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      instanceId = "$.detail.resource.instanceDetails.instanceId"
    }

    input_template = <<-EOT
"CRITICAL: Cryptomining Detected (T1496.001)
Time: <time>
Account: <account> | Region: <region>
Finding Type: <type>
Severity: <severity>
Instance: <instanceId>
Action: Terminate instance and investigate"
EOT
  }
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.crypto.arn
        }
      }
    }]
  })
}

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
                alert_severity="high",
                alert_title="GuardDuty: Cryptomining Detected",
                alert_description_template="Cryptocurrency mining activity detected on {resource}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Identify affected resources",
                    "Check DNS queries to mining pools",
                    "Review instance/container for malware",
                ],
                containment_actions=[
                    "Terminate affected resources",
                    "Block mining pool domains",
                    "Review access logs",
                    "Rotate compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty has low false positive rate for crypto",
            detection_coverage="90% - excellent for known mining",
            evasion_considerations="Novel miners may evade initially",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4/million events",
            prerequisites=["GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1496001-gcp-cpu",
            name="GCP High CPU/Cryptomining Detection",
            description="Detect cryptomining via CPU metrics and SCC findings.",
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                scc_finding_categories=["MALWARE: CRYPTOMINING_POOL_COMMUNICATION"],
                gcp_terraform_template="""# GCP: Detect cryptomining

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# CPU-based detection
resource "google_monitoring_alert_policy" "high_cpu" {
  display_name = "Potential Cryptomining - High CPU"
  combiner     = "OR"
  conditions {
    display_name = "Sustained high CPU"
    condition_threshold {
      filter          = "metric.type=\"compute.googleapis.com/instance/cpu/utilization\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.9
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}

# SCC integration - enable Event Threat Detection for cryptomining
# This detects mining pool communication automatically""",
                alert_severity="high",
                alert_title="GCP: Cryptomining Detected",
                alert_description_template="Cryptocurrency mining activity detected.",
                investigation_steps=[
                    "Review SCC finding details",
                    "Check VM processes",
                    "Review network connections",
                    "Check container images",
                ],
                containment_actions=[
                    "Stop affected VMs",
                    "Block mining pool IPs",
                    "Review IAM permissions",
                    "Scan for backdoors",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="SCC has low false positive rate",
            detection_coverage="85% - excellent detection",
            evasion_considerations="Novel miners may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-20",
            prerequisites=["Security Command Center enabled"],
        ),
    ],
    recommended_order=[
        "t1496001-aws-guardduty",
        "t1496001-gcp-cpu",
        "t1496001-aws-cpu",
    ],
    total_effort_hours=2.0,
    coverage_improvement="+20% improvement for Impact tactic",
)
