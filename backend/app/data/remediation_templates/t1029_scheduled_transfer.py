"""
T1029 - Scheduled Transfer

Adversaries schedule data exfiltration during specific times or intervals to blend malicious
traffic with normal activity patterns. This technique works alongside other exfiltration methods.
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
    technique_id="T1029",
    technique_name="Scheduled Transfer",
    tactic_ids=["TA0010"],  # Exfiltration
    mitre_url="https://attack.mitre.org/techniques/T1029/",
    threat_context=ThreatContext(
        description=(
            "Adversaries schedule data exfiltration during specific times or intervals to blend "
            "malicious traffic with normal activity patterns. In cloud environments, this involves "
            "using scheduled tasks, Lambda functions, Cloud Functions, cron jobs, or EventBridge rules "
            "to automate recurring data transfers to external destinations at predictable times. "
            "Common patterns include exfiltration during business hours to blend with legitimate traffic, "
            "or during night-time when security monitoring may be reduced. Attackers configure intervals "
            "ranging from every few minutes to specific business hours (e.g., 9-5, Monday-Friday) to "
            "avoid detection whilst maintaining persistent access to stolen data."
        ),
        attacker_goal="Exfiltrate data at scheduled intervals to blend with normal traffic patterns and maintain persistent theft",
        why_technique=[
            "Blends exfiltration with legitimate scheduled workflows",
            "Reduces detection likelihood through predictable timing",
            "Enables continuous data theft without manual intervention",
            "Mimics normal business operations and backup schedules",
            "Exploits reduced monitoring during specific time windows",
            "Maintains persistent access for ongoing data collection",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Scheduled transfer is a sophisticated evasion technique that significantly increases the "
            "difficulty of detecting ongoing data exfiltration. By mimicking legitimate scheduled operations "
            "and blending with normal business traffic, attackers can maintain persistent data theft over "
            "extended periods. The technique's effectiveness in avoiding anomaly-based detection systems and "
            "exploiting predictable monitoring gaps makes it particularly dangerous for sustained intellectual "
            "property theft and compliance violations. High severity due to potential for long-term undetected "
            "data loss."
        ),
        business_impact=[
            "Sustained intellectual property and sensitive data theft",
            "Extended breach periods leading to significant data loss",
            "Compliance violations from ongoing unauthorised data access",
            "Increased cloud egress costs from recurring transfers",
            "Reputational damage from sophisticated attack exposure",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1074", "T1560", "T1020", "T1048"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Recurring Network Transfer Pattern Detection
        DetectionStrategy(
            strategy_id="t1029-aws-recurring-transfer",
            name="AWS Recurring Network Transfer Pattern Detection",
            description="Detect recurring network transfers at scheduled intervals that may indicate scheduled data exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, bytes, packets
| filter action = "ACCEPT" and bytes > 1048576
| stats sum(bytes) as total_bytes, count(*) as transfer_count by srcAddr, dstAddr, bin(1h)
| stats count(*) as recurring_patterns, avg(total_bytes) as avg_bytes by srcAddr, dstAddr
| filter recurring_patterns >= 3
| sort recurring_patterns desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect recurring scheduled data transfers indicating exfiltration

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  VPCFlowLogGroup:
    Type: String
    Description: CloudWatch Log Group for VPC Flow Logs

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Scheduled Transfer Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for recurring transfers
  RecurringTransferFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes > 1000000, ...]'
      MetricTransformations:
        - MetricName: RecurringDataTransfers
          MetricNamespace: Security/Exfiltration
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: CloudWatch alarm for recurring patterns
  RecurringTransferAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Scheduled-Transfer-Pattern-Detected
      AlarmDescription: Recurring data transfer pattern detected
      MetricName: RecurringDataTransfers
      Namespace: Security/Exfiltration
      Statistic: Sum
      Period: 300
      Threshold: 10485760
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 3
      DatapointsToAlarm: 3
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  # Step 4: SNS topic policy (scoped)
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId

Outputs:
  AlertTopicArn:
    Value: !Ref AlertTopic
    Description: SNS Topic ARN for scheduled transfer alerts""",
                terraform_template="""# Detect recurring scheduled data transfers

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "scheduled_transfer_alerts" {
  name         = "scheduled-transfer-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Scheduled Transfer Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.scheduled_transfer_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for recurring transfers
resource "aws_cloudwatch_log_metric_filter" "recurring_transfer" {
  name           = "recurring-data-transfers"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes > 1000000, ...]"

  metric_transformation {
    name      = "RecurringDataTransfers"
    namespace = "Security/Exfiltration"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: CloudWatch alarm for recurring patterns
resource "aws_cloudwatch_metric_alarm" "recurring_transfer" {
  alarm_name          = "Scheduled-Transfer-Pattern-Detected"
  alarm_description   = "Recurring data transfer pattern detected"
  metric_name         = "RecurringDataTransfers"
  namespace           = "Security/Exfiltration"
  statistic           = "Sum"
  period              = 300
  threshold           = 10485760
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.scheduled_transfer_alerts.arn]
}

# Step 4: SNS topic policy (scoped)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.scheduled_transfer_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.scheduled_transfer_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

output "alert_topic_arn" {
  value       = aws_sns_topic.scheduled_transfer_alerts.arn
  description = "SNS Topic ARN for scheduled transfer alerts"
}""",
                alert_severity="high",
                alert_title="Recurring Scheduled Transfer Pattern Detected",
                alert_description_template="Recurring data transfers detected from {srcAddr} to {dstAddr}: {recurring_patterns} occurrences with average {avg_bytes} bytes per hour.",
                investigation_steps=[
                    "Identify source instance and verify legitimacy",
                    "Examine transfer timing patterns (hourly, daily, business hours)",
                    "Review destination IP addresses and domain ownership",
                    "Check for correlation with scheduled tasks or cron jobs",
                    "Analyse transferred data volume consistency",
                    "Review CloudTrail for associated API activities",
                    "Verify against known backup schedules and ETL jobs",
                ],
                containment_actions=[
                    "Isolate source instance from network",
                    "Disable suspicious scheduled tasks or Lambda functions",
                    "Revoke credentials for compromised identities",
                    "Block destination IP addresses at security group level",
                    "Review and restrict VPC egress rules",
                    "Enable enhanced VPC Flow Log monitoring",
                    "Implement network segmentation to limit data access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup schedules, ETL pipelines, and data synchronisation jobs. Adjust byte thresholds based on legitimate transfer volumes.",
            detection_coverage="75% - catches regularly scheduled transfer patterns",
            evasion_considerations="Irregular scheduling, variable transfer sizes, or randomised intervals may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$8-15",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs Insights"],
        ),
        # Strategy 2: AWS - Scheduled Task and EventBridge Rule Monitoring
        DetectionStrategy(
            strategy_id="t1029-aws-scheduled-task",
            name="AWS Scheduled Task Creation and Execution Monitoring",
            description="Monitor creation and execution of EventBridge rules, Lambda functions, and ECS scheduled tasks that may facilitate scheduled exfiltration.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.events", "aws.lambda", "aws.ecs"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "PutRule",
                            "PutTargets",
                            "CreateFunction20150331",
                            "UpdateFunctionCode20150331v2",
                            "RegisterTaskDefinition",
                            "CreateScheduledTask",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor scheduled task creation for potential exfiltration automation

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Scheduled Task Monitoring
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for scheduled task creation
  ScheduledTaskRule:
    Type: AWS::Events::Rule
    Properties:
      Name: scheduled-task-creation-monitoring
      Description: Monitor creation of scheduled tasks and rules
      EventPattern:
        source: [aws.events, aws.lambda, aws.ecs]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PutRule
            - PutTargets
            - CreateFunction20150331
            - UpdateFunctionCode20150331v2
            - RegisterTaskDefinition
      State: ENABLED
      Targets:
        - Id: AlertTarget
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
              eventName: $.detail.eventName
              user: $.detail.userIdentity.arn
              schedule: $.detail.requestParameters.scheduleExpression
            InputTemplate: |
              "Scheduled Task Alert (T1029)
              time=<time> account=<account> region=<region>
              event=<eventName> user=<user>
              schedule=<schedule>
              Action: Verify scheduled task legitimacy"

  # Step 3: Dead letter queue
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: scheduled-task-dlq
      MessageRetentionPeriod: 1209600

  # Step 4: SNS topic policy (scoped)
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublish
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ScheduledTaskRule.Arn

Outputs:
  RuleArn:
    Value: !GetAtt ScheduledTaskRule.Arn
    Description: EventBridge Rule ARN""",
                terraform_template="""# Monitor scheduled task creation for exfiltration

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "scheduled_task_alerts" {
  name         = "scheduled-task-monitoring"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Scheduled Task Monitoring"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.scheduled_task_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for scheduled task creation
resource "aws_cloudwatch_event_rule" "scheduled_task" {
  name        = "scheduled-task-creation-monitoring"
  description = "Monitor creation of scheduled tasks and rules"

  event_pattern = jsonencode({
    source      = ["aws.events", "aws.lambda", "aws.ecs"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutRule",
        "PutTargets",
        "CreateFunction20150331",
        "UpdateFunctionCode20150331v2",
        "RegisterTaskDefinition"
      ]
    }
  })
}

# Step 3: Dead letter queue
resource "aws_sqs_queue" "dlq" {
  name                      = "scheduled-task-dlq"
  message_retention_seconds = 1209600
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
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
      values   = [aws_cloudwatch_event_rule.scheduled_task.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.scheduled_task.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.scheduled_task_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      account   = "$.account"
      region    = "$.region"
      time      = "$.time"
      eventName = "$.detail.eventName"
      user      = "$.detail.userIdentity.arn"
      schedule  = "$.detail.requestParameters.scheduleExpression"
    }
    input_template = <<-EOT
"Scheduled Task Alert (T1029)
time=<time> account=<account> region=<region>
event=<eventName> user=<user>
schedule=<schedule>
Action: Verify scheduled task legitimacy"
EOT
  }
}

# Step 4: SNS topic policy (scoped)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.scheduled_task_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.scheduled_task_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.scheduled_task.arn
        }
      }
    }]
  })
}

output "rule_arn" {
  value       = aws_cloudwatch_event_rule.scheduled_task.arn
  description = "EventBridge Rule ARN"
}""",
                alert_severity="medium",
                alert_title="Scheduled Task or Rule Created",
                alert_description_template="Scheduled task created: {eventName} by {userIdentity.arn}. Rule: {requestParameters.name}, Schedule: {requestParameters.scheduleExpression}",
                investigation_steps=[
                    "Review the schedule expression and timing pattern",
                    "Identify who created the scheduled task or rule",
                    "Examine the target Lambda function, ECS task, or service",
                    "Check IAM permissions of the target execution role",
                    "Review code or configuration for external network calls",
                    "Verify business justification for the automation",
                    "Check for similar patterns across the environment",
                ],
                containment_actions=[
                    "Disable suspicious EventBridge rules immediately",
                    "Delete unauthorised Lambda functions or ECS tasks",
                    "Review and restrict events:PutRule permissions",
                    "Implement approval workflows for scheduled tasks",
                    "Enable code signing for Lambda functions",
                    "Review all existing scheduled rules and tasks",
                    "Configure VPC endpoints to restrict external access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised CI/CD pipelines, infrastructure automation tools, and known operational schedules. Focus on rules with unusual timing patterns or external targets.",
            detection_coverage="80% - catches scheduled task creation",
            evasion_considerations="Attackers may modify existing legitimate tasks or use irregular schedules to avoid pattern detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with management events"],
        ),
        # Strategy 3: AWS - Time-Based S3 Upload Pattern Detection
        DetectionStrategy(
            strategy_id="t1029-aws-s3-timing",
            name="AWS Time-Based S3 Upload Pattern Detection",
            description="Detect S3 uploads occurring at regular intervals or specific time windows that may indicate scheduled exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, requestParameters.bucketName, requestParameters.key, hour(@timestamp) as upload_hour
| filter eventName in ["PutObject", "CopyObject", "CompleteMultipartUpload"]
| stats count(*) as upload_count, sum(requestParameters.contentLength) as total_bytes by userIdentity.arn, requestParameters.bucketName, upload_hour
| filter upload_count > 20
| sort upload_hour, upload_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect time-based S3 upload patterns for scheduled exfiltration

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: S3 Time-Based Upload Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for S3 upload monitoring
  S3TimingRule:
    Type: AWS::Events::Rule
    Properties:
      Name: s3-time-based-upload-detection
      Description: Detect scheduled S3 upload patterns
      EventPattern:
        source: [aws.s3]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PutObject
            - CopyObject
            - CompleteMultipartUpload
      State: ENABLED
      Targets:
        - Id: AlertTarget
          Arn: !Ref AlertTopic

  # Step 3: SNS topic policy
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
                aws:SourceArn: !GetAtt S3TimingRule.Arn

Outputs:
  AlertTopicArn:
    Value: !Ref AlertTopic""",
                terraform_template="""# Detect time-based S3 upload patterns

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "s3_timing_alerts" {
  name         = "s3-time-based-upload-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "S3 Time-Based Upload Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.s3_timing_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for S3 upload monitoring
resource "aws_cloudwatch_event_rule" "s3_timing" {
  name        = "s3-time-based-upload-detection"
  description = "Detect scheduled S3 upload patterns"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutObject",
        "CopyObject",
        "CompleteMultipartUpload"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.s3_timing.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.s3_timing_alerts.arn
}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.s3_timing_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.s3_timing_alerts.arn
    }]
  })
}

output "alert_topic_arn" {
  value       = aws_sns_topic.s3_timing_alerts.arn
  description = "SNS Topic ARN for S3 timing alerts"
}""",
                alert_severity="high",
                alert_title="Time-Based S3 Upload Pattern Detected",
                alert_description_template="Scheduled S3 uploads detected from {userIdentity.arn} to bucket {bucketName} during hour {upload_hour}: {upload_count} uploads, {total_bytes} bytes",
                investigation_steps=[
                    "Analyse upload timing patterns (hourly, daily, specific business hours)",
                    "Identify the source identity and verify legitimacy",
                    "Review uploaded objects and their content types",
                    "Check bucket ownership, location, and access policies",
                    "Examine whether uploads correlate with scheduled jobs",
                    "Review IAM role session duration and assume role patterns",
                    "Check for encryption and data classification of uploaded objects",
                ],
                containment_actions=[
                    "Revoke credentials for suspicious identities",
                    "Enable S3 Block Public Access on affected buckets",
                    "Implement bucket policies restricting upload times",
                    "Enable S3 Object Lock to prevent unauthorised deletion",
                    "Review and restrict s3:PutObject permissions",
                    "Enable S3 Access Logging and Object-level logging",
                    "Configure S3 event notifications for real-time monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup schedules, application logging, and data pipeline jobs. Analyse historical patterns to establish normal upload timing.",
            detection_coverage="70% - catches time-based S3 exfiltration patterns",
            evasion_considerations="Variable timing, small file uploads, or randomised schedules may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$8-12",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "S3 bucket logging",
            ],
        ),
        # Strategy 4: GCP - Recurring Cloud Storage Transfer Detection
        DetectionStrategy(
            strategy_id="t1029-gcp-recurring-transfer",
            name="GCP Recurring Cloud Storage Transfer Pattern Detection",
            description="Detect recurring Cloud Storage uploads at scheduled intervals that may indicate scheduled data exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
protoPayload.serviceName="storage.googleapis.com"
| extract timestamp, hour from @timestamp
| stats count() as upload_count, sum(protoPayload.response.size) as total_bytes
  by protoPayload.authenticationInfo.principalEmail, resource.labels.bucket_name, hour
| upload_count > 10""",
                gcp_terraform_template="""# GCP: Detect recurring scheduled Cloud Storage transfers

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Scheduled Transfer Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for recurring GCS uploads
resource "google_logging_metric" "recurring_gcs_upload" {
  name   = "recurring-gcs-uploads"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.create"
    protoPayload.serviceName="storage.googleapis.com"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "bucket_name"
      value_type  = "STRING"
      description = "Cloud Storage bucket name"
    }
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "Principal performing the upload"
    }
  }

  label_extractors = {
    "bucket_name"     = "EXTRACT(resource.labels.bucket_name)"
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for recurring upload patterns
resource "google_monitoring_alert_policy" "recurring_upload_alert" {
  display_name = "Scheduled Transfer Pattern Detected"
  combiner     = "OR"

  conditions {
    display_name = "Recurring Cloud Storage uploads at regular intervals"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.recurring_gcs_upload.name}\" resource.type=\"gcs_bucket\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period     = "3600s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.bucket_name", "metric.label.principal_email"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content   = "Recurring Cloud Storage upload pattern detected. Investigate for potential scheduled data exfiltration."
    mime_type = "text/markdown"
  }
}

output "alert_policy_name" {
  value       = google_monitoring_alert_policy.recurring_upload_alert.name
  description = "Alert policy name for recurring transfers"
}""",
                alert_severity="high",
                alert_title="GCP: Recurring Scheduled Transfer Pattern Detected",
                alert_description_template="Recurring uploads detected to bucket {bucket_name} by {principal_email}: {upload_count} uploads during hour {hour}",
                investigation_steps=[
                    "Identify the service account or user performing uploads",
                    "Analyse upload timing patterns and intervals",
                    "Review uploaded object names, sizes, and metadata",
                    "Check bucket location, storage class, and access controls",
                    "Verify against known scheduled workflows or backup jobs",
                    "Review Cloud Audit Logs for correlated activities",
                    "Examine service account key creation and usage patterns",
                ],
                containment_actions=[
                    "Revoke compromised service account keys immediately",
                    "Disable suspicious Cloud Scheduler jobs or Cloud Functions",
                    "Implement bucket IAM policies restricting uploads",
                    "Enable uniform bucket-level access",
                    "Review and restrict storage.objects.create permissions",
                    "Configure VPC Service Controls to limit data egress",
                    "Enable Object Versioning for forensic recovery",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup systems, data pipelines, and application logging patterns. Adjust thresholds based on legitimate upload frequencies.",
            detection_coverage="75% - catches regularly scheduled transfer patterns",
            evasion_considerations="Irregular scheduling or variable upload volumes may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-18",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Cloud Storage data access logs",
            ],
        ),
        # Strategy 5: GCP - Cloud Scheduler and Function Monitoring
        DetectionStrategy(
            strategy_id="t1029-gcp-scheduler",
            name="GCP Cloud Scheduler and Function Creation Monitoring",
            description="Monitor creation of Cloud Scheduler jobs and Cloud Functions that may facilitate scheduled exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type=("cloud_scheduler_job" OR "cloud_function")
(protoPayload.methodName="google.cloud.scheduler.v1.CloudScheduler.CreateJob" OR
 protoPayload.methodName="google.cloud.scheduler.v1.CloudScheduler.UpdateJob" OR
 protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CreateFunction" OR
 protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.UpdateFunction")
(protoPayload.serviceName="cloudscheduler.googleapis.com" OR
 protoPayload.serviceName="cloudfunctions.googleapis.com")""",
                gcp_terraform_template="""# GCP: Monitor Cloud Scheduler and Function creation

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Scheduled Task Monitoring"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for scheduler and function changes
resource "google_logging_metric" "scheduled_task_changes" {
  name   = "scheduled-task-modifications"
  filter = <<-EOT
    (resource.type="cloud_scheduler_job" OR resource.type="cloud_function")
    (protoPayload.serviceName="cloudscheduler.googleapis.com" OR
     protoPayload.serviceName="cloudfunctions.googleapis.com")
    (protoPayload.methodName:"CreateJob" OR
     protoPayload.methodName:"UpdateJob" OR
     protoPayload.methodName:"CreateFunction" OR
     protoPayload.methodName:"UpdateFunction")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "method_name"
      value_type  = "STRING"
      description = "API method called"
    }
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User or service account"
    }
  }

  label_extractors = {
    "method_name"     = "EXTRACT(protoPayload.methodName)"
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for scheduled task creation
resource "google_monitoring_alert_policy" "scheduled_task_alert" {
  display_name = "Cloud Scheduler or Function Modified"
  combiner     = "OR"

  conditions {
    display_name = "Scheduled automation created or modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.scheduled_task_changes.name}\""
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
    auto_close = "3600s"
  }

  documentation {
    content   = "Cloud Scheduler job or Cloud Function created/modified. Review for potential scheduled exfiltration automation."
    mime_type = "text/markdown"
  }
}

output "alert_policy_name" {
  value       = google_monitoring_alert_policy.scheduled_task_alert.name
  description = "Alert policy name"
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Scheduler Job or Function Modified",
                alert_description_template="Scheduled task modified: {method_name} by {principal_email}. Resource: {resource_name}",
                investigation_steps=[
                    "Review the schedule configuration and timing pattern",
                    "Identify who created or modified the scheduler job or function",
                    "Examine the target Cloud Function, HTTP endpoint, or Pub/Sub topic",
                    "Check service account permissions and IAM bindings",
                    "Review function source code for external network calls",
                    "Verify business justification for the automation",
                    "Check for similar patterns across projects",
                ],
                containment_actions=[
                    "Pause or delete suspicious Cloud Scheduler jobs",
                    "Disable unauthorised Cloud Functions",
                    "Review and restrict cloudscheduler.jobs.create permissions",
                    "Implement organisation policy constraints on automation",
                    "Review all existing scheduled jobs and functions",
                    "Configure VPC Service Controls to restrict egress",
                    "Enable function source code repository tracking",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised CI/CD systems, infrastructure automation, and known operational schedules. Focus on functions with unusual timing or external targets.",
            detection_coverage="80% - catches scheduled task creation",
            evasion_considerations="Attackers may modify existing legitimate tasks or use Cloud Run jobs instead",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-18",
            prerequisites=[
                "Cloud Audit Logs enabled for Cloud Scheduler and Cloud Functions"
            ],
        ),
        # Strategy 6: GCP - VPC Flow Log Time-Based Pattern Detection
        DetectionStrategy(
            strategy_id="t1029-gcp-vpc-timing",
            name="GCP VPC Flow Log Time-Based Transfer Detection",
            description="Detect network transfers occurring at regular time intervals via VPC Flow Logs analysis.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName:"vpc_flows"
jsonPayload.bytes_sent > 1048576
| extract hour from timestamp
| stats count() as transfer_count, sum(jsonPayload.bytes_sent) as total_bytes
  by jsonPayload.connection.src_ip, jsonPayload.connection.dest_ip, hour
| transfer_count > 5""",
                gcp_terraform_template="""# GCP: Detect time-based network transfer patterns

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Network Transfer Timing Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for time-based transfers
resource "google_logging_metric" "timed_transfers" {
  name   = "time-based-network-transfers"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName:"vpc_flows"
    jsonPayload.bytes_sent > 1048576
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "src_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
    labels {
      key         = "dest_ip"
      value_type  = "STRING"
      description = "Destination IP address"
    }
  }

  label_extractors = {
    "src_ip"  = "EXTRACT(jsonPayload.connection.src_ip)"
    "dest_ip" = "EXTRACT(jsonPayload.connection.dest_ip)"
  }
}

# Step 3: Alert policy for recurring transfer patterns
resource "google_monitoring_alert_policy" "timed_transfer_alert" {
  display_name = "Time-Based Transfer Pattern Detected"
  combiner     = "OR"

  conditions {
    display_name = "Recurring network transfers at scheduled intervals"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.timed_transfers.name}\" resource.type=\"gce_subnetwork\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period     = "3600s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.src_ip", "metric.label.dest_ip"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content   = "Recurring network transfer pattern detected in VPC Flow Logs. Potential scheduled data exfiltration."
    mime_type = "text/markdown"
  }
}

output "alert_policy_name" {
  value       = google_monitoring_alert_policy.timed_transfer_alert.name
  description = "Alert policy name for timed transfers"
}""",
                alert_severity="high",
                alert_title="GCP: Time-Based Network Transfer Pattern Detected",
                alert_description_template="Recurring network transfers detected from {src_ip} to {dest_ip}: {transfer_count} transfers during hour {hour}",
                investigation_steps=[
                    "Identify source and destination instances or workloads",
                    "Analyse transfer timing patterns and intervals",
                    "Review destination IP ownership and geolocation",
                    "Check for correlation with scheduled jobs or cron tasks",
                    "Examine firewall rules and network policies",
                    "Verify against known backup schedules and data pipelines",
                    "Review Cloud Audit Logs for related API activities",
                ],
                containment_actions=[
                    "Isolate source instance from network",
                    "Block destination IPs via VPC firewall rules",
                    "Disable suspicious scheduled workloads",
                    "Review and restrict egress firewall rules",
                    "Implement VPC Service Controls for perimeter security",
                    "Enable Private Google Access to restrict external egress",
                    "Configure Cloud NAT logs for enhanced visibility",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup destinations, CDN endpoints, and data synchronisation targets. Adjust byte thresholds based on normal traffic patterns.",
            detection_coverage="70% - catches time-based network exfiltration patterns",
            evasion_considerations="Variable timing, small transfer sizes, or randomised destinations may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$12-20",
            prerequisites=["VPC Flow Logs enabled on subnets", "Cloud Logging enabled"],
        ),
    ],
    recommended_order=[
        "t1029-aws-recurring-transfer",
        "t1029-gcp-recurring-transfer",
        "t1029-aws-scheduled-task",
        "t1029-gcp-scheduler",
        "t1029-aws-s3-timing",
        "t1029-gcp-vpc-timing",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+22% improvement for Exfiltration tactic detection",
)
