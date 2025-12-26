"""
T1070 - Indicator Removal

Adversaries remove or modify artefacts generated on cloud systems to conceal evidence
of compromise, including deletion of logs, command histories, and other defensive indicators.
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
    technique_id="T1070",
    technique_name="Indicator Removal",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1070/",
    threat_context=ThreatContext(
        description=(
            "Adversaries remove or modify artefacts to conceal evidence of compromise. "
            "In cloud environments, this includes deleting CloudTrail logs, clearing bash history "
            "on instances, removing scheduled tasks, deleting container logs, and tampering with "
            "audit configurations to interfere with event collection and detection."
        ),
        attacker_goal="Remove evidence of malicious activity to evade detection and hinder incident response",
        why_technique=[
            "Eliminates audit trail of attacker actions in cloud environment",
            "Makes forensic investigation extremely difficult",
            "Hides lateral movement and privilege escalation activities",
            "Can be executed with a single API call in many cases",
            "Often performed before exfiltration or destructive actions",
            "May go unnoticed without proper monitoring controls",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Indicator removal is a critical red flag suggesting active compromise. "
            "When logs are deleted, defenders lose visibility into the attacker's actions, "
            "making incident response nearly impossible. This technique often precedes "
            "data exfiltration or ransomware deployment. The ease of execution in cloud "
            "environments makes it particularly dangerous."
        ),
        business_impact=[
            "Loss of audit trail for compliance and regulatory requirements",
            "Inability to conduct thorough incident investigation",
            "Potential regulatory violations and fines",
            "Extended dwell time for attackers without detection",
            "Compromised forensic evidence for legal proceedings",
            "Reduced ability to prevent future similar attacks",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1530", "T1537", "T1485", "T1486"],
        often_follows=["T1078.004", "T1098", "T1136.003"],
    ),
    detection_strategies=[
        # AWS GuardDuty Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1070-aws-guardduty",
            name="AWS GuardDuty Anomaly Detection",
            description=(
                "AWS GuardDuty detects defence evasion and indicator removal. DefenseEvasion:IAMUser/AnomalousBehavior identifies anomalous calls to APIs like DeleteFlowLogs, StopLogging, or DisableAlarmActions. Stealth:IAMUser/CloudTrailLoggingDisabled fires when CloudTrail is disabled."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "DefenseEvasion:IAMUser/AnomalousBehavior",
                    "Stealth:IAMUser/CloudTrailLoggingDisabled",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for T1070

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty-T1070-Alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for GuardDuty findings
  GuardDutyRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Capture GuardDuty findings for T1070
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "DefenseEvasion:IAMUser/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# GuardDuty alerts for T1070

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: SNS Topic
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "guardduty-t1070-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for findings
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-t1070"
  description = "Capture GuardDuty findings for T1070"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "DefenseEvasion:IAMUser/" }]
    }
  })
}

# Step 3: Target with DLQ and retry
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-t1070-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Step 4: SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty.arn }
      }
    }]
  })
}""",
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML baselines; tune suppression rules for known benign patterns",
            detection_coverage="70% - detects anomalous behaviour but may miss attacks that blend with normal activity",
            evasion_considerations="Disabling logging during low-activity periods, using legitimate admin accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events",
            prerequisites=[
                "AWS GuardDuty enabled",
                "CloudTrail logging active",
            ],
        ),
        # Strategy 1: AWS - CloudTrail Log File Deletion
        DetectionStrategy(
            strategy_id="t1070-aws-cloudtrail-deletion",
            name="CloudTrail Log File Deletion Detection",
            description="Detect attempts to delete CloudTrail log files from S3 buckets.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["DeleteObject", "DeleteObjects"],
                        "requestParameters": {"bucketName": [{"exists": True}]},
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect CloudTrail log file deletion attempts

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  CloudTrailBucketName:
    Type: String
    Description: Name of the CloudTrail S3 bucket to monitor

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: CloudTrail Log Deletion Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Dead Letter Queue for failed deliveries
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: cloudtrail-log-deletion-alerts-dlq
      MessageRetentionPeriod: 1209600

  # Step 3: EventBridge rule for CloudTrail log deletion
  CloudTrailLogDeletionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1070-CloudTrailLogDeletion
      Description: Alert on CloudTrail log file deletion attempts
      EventPattern:
        source: [aws.s3]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - DeleteObject
            - DeleteObjects
          requestParameters:
            bucketName: [!Ref CloudTrailBucketName]
      State: ENABLED
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
              bucketName: $.detail.requestParameters.bucketName
              objectKey: $.detail.requestParameters.key
              userArn: $.detail.userIdentity.arn
            InputTemplate: |
              "CRITICAL: CloudTrail Log Deletion Alert (T1070)"
              "Time: <time>"
              "Account: <account> | Region: <region>"
              "Bucket: <bucketName>"
              "Object: <objectKey>"
              "User: <userArn>"
              "Action: Evidence tampering detected - investigate immediately"

  # Step 4: SNS topic policy
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
                aws:SourceArn: !GetAtt CloudTrailLogDeletionRule.Arn

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
                terraform_template="""# Detect CloudTrail log file deletion attempts

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "cloudtrail_bucket_name" {
  type        = string
  description = "Name of the CloudTrail S3 bucket to monitor"
}

data "aws_caller_identity" "current" {}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "cloudtrail_log_deletion_alerts" {
  name              = "cloudtrail-log-deletion-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name      = "CloudTrail Log Deletion Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cloudtrail_log_deletion_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Dead Letter Queue for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "cloudtrail-log-deletion-alerts-dlq"
  message_retention_seconds = 1209600
}

# Step 3: EventBridge rule for CloudTrail log deletion
resource "aws_cloudwatch_event_rule" "cloudtrail_log_deletion" {
  name        = "T1070-CloudTrailLogDeletion"
  description = "Alert on CloudTrail log file deletion attempts"
  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["DeleteObject", "DeleteObjects"]
      requestParameters = {
        bucketName = [var.cloudtrail_bucket_name]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_log_deletion.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.cloudtrail_log_deletion_alerts.arn

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
      bucketName = "$.detail.requestParameters.bucketName"
      objectKey  = "$.detail.requestParameters.key"
      userArn    = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CRITICAL: CloudTrail Log Deletion Alert (T1070)
Time: <time>
Account: <account> | Region: <region>
Bucket: <bucketName>
Object: <objectKey>
User: <userArn>
Action: Evidence tampering detected - investigate immediately"
EOT
  }
}

# Step 4: SNS topic policy with scoped conditions
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.cloudtrail_log_deletion_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.cloudtrail_log_deletion_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.cloudtrail_log_deletion.arn
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
                alert_severity="critical",
                alert_title="CloudTrail Log Files Deleted",
                alert_description_template="CloudTrail log files were deleted from bucket {bucketName}. This indicates potential evidence tampering.",
                investigation_steps=[
                    "Identify the IAM principal that deleted the log files",
                    "Check what time range of logs was deleted",
                    "Review remaining CloudTrail events before deletion occurred",
                    "Check for concurrent suspicious activities",
                    "Verify if CloudTrail log file validation is enabled",
                    "Examine other S3 access patterns from the same principal",
                ],
                containment_actions=[
                    "Enable S3 Object Lock on CloudTrail bucket to prevent deletion",
                    "Revoke credentials of the principal that deleted logs",
                    "Enable MFA Delete on CloudTrail S3 bucket",
                    "Implement SCPs to prevent CloudTrail log deletion",
                    "Configure CloudTrail to send logs to a separate security account",
                    "Enable S3 versioning to recover deleted objects",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate log rotation should use lifecycle policies, not manual deletion",
            detection_coverage="95% - catches all S3 delete operations on CloudTrail bucket",
            evasion_considerations="Attackers may disable CloudTrail entirely rather than delete logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "CloudTrail logging to S3"],
        ),
        # Strategy 2: AWS - Instance Command History Clearing
        DetectionStrategy(
            strategy_id="t1070-aws-bash-history",
            name="Detect Bash History Clearing on EC2 Instances",
            description="Monitor for commands that clear bash history or modify audit logs on EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, commandLine
| filter @message like /history -c|rm.*bash_history|unset HISTFILE|shred.*bash_history|cat.*null.*bash_history|truncate.*bash_history/
| stats count() as occurrences by instanceId, commandLine, bin(5m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect bash history clearing on EC2 instances

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing EC2 instance command logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for history clearing
  HistoryClearFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, command="*history -c*" || command="*rm*bash_history*" || command="*unset HISTFILE*"]'
      MetricTransformations:
        - MetricName: BashHistoryClearing
          MetricNamespace: Security/T1070
          MetricValue: "1"

  # Step 3: Create alarm
  HistoryClearAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1070-BashHistoryClearing
      AlarmDescription: Bash history clearing detected on EC2 instance
      MetricName: BashHistoryClearing
      Namespace: Security/T1070
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect bash history clearing on EC2 instances

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing EC2 instance command logs"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "history_clear_alerts" {
  name = "bash-history-clearing-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.history_clear_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for history clearing
resource "aws_cloudwatch_log_metric_filter" "bash_history_clear" {
  name           = "bash-history-clearing"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, command=\"*history -c*\" || command=\"*rm*bash_history*\" || command=\"*unset HISTFILE*\"]"

  metric_transformation {
    name      = "BashHistoryClearing"
    namespace = "Security/T1070"
    value     = "1"
  }
}

# Step 3: Create alarm
resource "aws_cloudwatch_metric_alarm" "history_clear" {
  alarm_name          = "T1070-BashHistoryClearing"
  alarm_description   = "Bash history clearing detected on EC2 instance"
  metric_name         = "BashHistoryClearing"
  namespace           = "Security/T1070"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.history_clear_alerts.arn]
}""",
                alert_severity="high",
                alert_description_template="Bash history clearing detected on instance {instance_id}. Command: {command_line}",
                alert_title="Bash History Clearing Detected",
                investigation_steps=[
                    "Identify which user executed the history clearing command",
                    "Review remaining audit logs from auditd if enabled",
                    "Check CloudTrail for API calls from the instance role",
                    "Examine process execution timeline before history was cleared",
                    "Look for other anti-forensic activities on the instance",
                    "Check for signs of lateral movement or data exfiltration",
                ],
                containment_actions=[
                    "Enable auditd logging with tamper-proof configuration",
                    "Configure CloudWatch agent to stream bash history in real-time",
                    "Isolate the instance from the network",
                    "Create forensic snapshot before further investigation",
                    "Review and rotate instance IAM role credentials",
                    "Implement read-only audit logging with separate storage",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="History clearing is rarely legitimate; investigate all occurrences",
            detection_coverage="75% - requires CloudWatch agent with command logging",
            evasion_considerations="Attackers may disable logging before clearing history",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudWatch Agent installed",
                "Command execution logging enabled",
            ],
        ),
        # Strategy 3: AWS - Container Log Tampering
        DetectionStrategy(
            strategy_id="t1070-aws-container-logs",
            name="Detect Container Log Deletion in ECS/EKS",
            description="Monitor for deletion of container logs or log streams in CloudWatch.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.logs"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["DeleteLogGroup", "DeleteLogStream"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect container log deletion in CloudWatch

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for log deletion
  LogDeletionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1070-ContainerLogDeletion
      Description: Detect container log deletion
      EventPattern:
        source: [aws.logs]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - DeleteLogGroup
            - DeleteLogStream
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
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
                terraform_template="""# Detect container log deletion in CloudWatch

variable "alert_email" {
  type = string
}

data "aws_caller_identity" "current" {}

# Step 1: SNS topic
resource "aws_sns_topic" "log_deletion_alerts" {
  name              = "container-log-deletion-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.log_deletion_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Dead Letter Queue for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "container-log-deletion-alerts-dlq"
  message_retention_seconds = 1209600
}

# Step 3: EventBridge rule for log deletion
resource "aws_cloudwatch_event_rule" "log_deletion" {
  name        = "T1070-ContainerLogDeletion"
  description = "Detect container log deletion"
  event_pattern = jsonencode({
    source        = ["aws.logs"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["DeleteLogGroup", "DeleteLogStream"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.log_deletion.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.log_deletion_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      account      = "$.account"
      region       = "$.region"
      time         = "$.time"
      logGroupName = "$.detail.requestParameters.logGroupName"
      userArn      = "$.detail.userIdentity.arn"
      eventName    = "$.detail.eventName"
    }

    input_template = <<-EOT
"Container Log Deletion Alert (T1070)
Time: <time>
Account: <account> | Region: <region>
Event: <eventName>
Log Group: <logGroupName>
User: <userArn>
Action: Evidence tampering detected - investigate immediately"
EOT
  }
}

# Step 4: Topic policy with scoped conditions
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.log_deletion_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.log_deletion_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.log_deletion.arn
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
                alert_title="Container Log Deletion Detected",
                alert_description_template="CloudWatch log group or stream deleted: {logGroupName}. This may indicate evidence tampering.",
                investigation_steps=[
                    "Identify the IAM principal that deleted the logs",
                    "Determine which containers or services were logging to the deleted group",
                    "Check if logs were exported to S3 before deletion",
                    "Review CloudTrail for other suspicious activities by the same principal",
                    "Check for concurrent container or pod deletions",
                    "Examine remaining logs for signs of compromise",
                ],
                containment_actions=[
                    "Implement CloudWatch log retention policies to prevent deletion",
                    "Enable log exports to S3 with Object Lock",
                    "Revoke credentials of the principal that deleted logs",
                    "Implement SCPs to restrict log deletion permissions",
                    "Configure log groups with retention policies",
                    "Use cross-account log aggregation for tamper-proof logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised log cleanup automation with approval workflows",
            detection_coverage="95% - catches all CloudWatch log deletion events",
            evasion_considerations="Attackers may delete containers entirely rather than just logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 4: GCP - Audit Log Deletion Detection
        DetectionStrategy(
            strategy_id="t1070-gcp-log-deletion",
            name="GCP: Detect Audit Log and Log Sink Deletion",
            description="Monitor for deletion or modification of GCP audit logs and log sinks.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="logging.googleapis.com"
protoPayload.methodName=~"DeleteSink|DeleteLog|UpdateSink"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect audit log and log sink deletion

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for log deletion
resource "google_logging_metric" "log_deletion" {
  project = var.project_id
  name    = "audit-log-deletion-attempts"
  filter  = <<-EOT
    protoPayload.serviceName="logging.googleapis.com"
    protoPayload.methodName=~"DeleteSink|DeleteLog|UpdateSink"
    severity="NOTICE"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "method_name"
      value_type  = "STRING"
      description = "Method that was called"
    }
  }

  label_extractors = {
    method_name = "EXTRACT(protoPayload.methodName)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "log_deletion" {
  project      = var.project_id
  display_name = "T1070: Audit Log Deletion Detected"
  combiner     = "OR"
  conditions {
    display_name = "Log deletion or modification"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.log_deletion.name}\" resource.type=\"global\""
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
    auto_close = "1800s"
  }
  documentation {
    content   = "Audit log deletion or sink modification detected. This may indicate evidence tampering. Investigate immediately."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Audit Log Deletion Detected",
                alert_description_template="GCP audit log or sink was deleted/modified. Method: {method_name}. Investigate for evidence tampering.",
                investigation_steps=[
                    "Identify the principal that deleted or modified the logs",
                    "Check which log sink or log was affected",
                    "Review remaining audit logs for the principal's recent activities",
                    "Verify if logs were exported to Cloud Storage before deletion",
                    "Check for concurrent suspicious API calls",
                    "Review IAM permissions granted to the principal",
                ],
                containment_actions=[
                    "Restore deleted log sinks from configuration backups",
                    "Enable organisation-level log sinks that cannot be deleted at project level",
                    "Revoke credentials of the principal that deleted logs",
                    "Implement organisation policies to prevent log deletion",
                    "Configure log retention with locked buckets in Cloud Storage",
                    "Use VPC Service Controls to restrict Logging API access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist approved infrastructure-as-code deployments",
            detection_coverage="95% - catches all logging API modification calls",
            evasion_considerations="Attackers with organisation admin can modify organisation-level logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - Instance Command History Clearing
        DetectionStrategy(
            strategy_id="t1070-gcp-bash-history",
            name="GCP: Detect Command History Clearing on GCE Instances",
            description="Monitor for commands that clear bash history or modify audit logs on GCE instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(textPayload=~"history -c|rm.*bash_history|unset HISTFILE|shred.*bash_history|truncate.*bash_history"
OR jsonPayload.message=~"history -c|rm.*bash_history")""",
                gcp_terraform_template="""# GCP: Detect command history clearing on GCE instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for history clearing
resource "google_logging_metric" "history_clearing" {
  project = var.project_id
  name    = "bash-history-clearing"
  filter  = <<-EOT
    resource.type="gce_instance"
    (textPayload=~"history -c|rm.*bash_history|unset HISTFILE|shred.*bash_history|truncate.*bash_history"
    OR jsonPayload.message=~"history -c|rm.*bash_history")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where history was cleared"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "history_clearing" {
  project      = var.project_id
  display_name = "T1070: Bash History Clearing Detected"
  combiner     = "OR"
  conditions {
    display_name = "History clearing detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.history_clearing.name}\" resource.type=\"gce_instance\""
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
    auto_close = "1800s"
  }
  documentation {
    content   = "Bash history clearing detected on GCE instance. This may indicate evidence tampering. Investigate immediately."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Bash History Clearing Detected",
                alert_description_template="Bash history clearing detected on GCE instance {instance_id}. This indicates potential evidence tampering.",
                investigation_steps=[
                    "Identify which user cleared the bash history",
                    "Review Cloud Logging for other activities from the same instance",
                    "Check the instance's service account recent API calls",
                    "Examine OS Login audit logs if enabled",
                    "Look for signs of lateral movement or privilege escalation",
                    "Check VPC Flow Logs for suspicious network connections",
                ],
                containment_actions=[
                    "Enable OS Login with 2FA for enhanced audit logging",
                    "Configure Ops Agent to stream command logs to Cloud Logging",
                    "Stop the instance to preserve evidence",
                    "Create disk snapshot for forensic analysis",
                    "Revoke the instance's service account credentials",
                    "Implement organisation policy requiring OS Login",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="History clearing is rarely legitimate; investigate all occurrences",
            detection_coverage="70% - requires Ops Agent with command logging",
            evasion_considerations="Attackers may disable Ops Agent before clearing history",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=[
                "Ops Agent installed on GCE instances",
                "Cloud Logging API enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1070-aws-cloudtrail-deletion",
        "t1070-gcp-log-deletion",
        "t1070-aws-container-logs",
        "t1070-aws-bash-history",
        "t1070-gcp-bash-history",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+35% improvement for Defence Evasion tactic",
)
