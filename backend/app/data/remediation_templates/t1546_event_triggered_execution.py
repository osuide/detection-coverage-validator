"""
T1546 - Event Triggered Execution

Adversaries establish persistence and escalate privileges by exploiting system
mechanisms that execute code based on specific events (logons, cloud events, etc.).
Used by KV Botnet, Pacu, UPSTYLE, and XCSSET malware.
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
    technique_id="T1546",
    technique_name="Event Triggered Execution",
    tactic_ids=["TA0003", "TA0004"],  # Persistence, Privilege Escalation
    mitre_url="https://attack.mitre.org/techniques/T1546/",
    threat_context=ThreatContext(
        description=(
            "Adversaries establish persistence and escalate privileges by exploiting "
            "system mechanisms that trigger code execution based on specific events. "
            "These mechanisms monitor activities like logons, application execution, "
            "and cloud events, then automatically execute associated code. In cloud "
            "environments, attackers abuse event-driven architectures like Lambda "
            "triggers, EventBridge rules, and Cloud Functions to maintain persistence "
            "and execute malicious code under elevated service account privileges."
        ),
        attacker_goal="Establish persistence through event-triggered execution",
        why_technique=[
            "Automatic execution without user interaction",
            "Often runs with elevated privileges (SYSTEM, service accounts)",
            "Difficult to detect among legitimate event triggers",
            "Survives system reboots and credential rotation",
            "Can be triggered by routine cloud operations",
            "Provides both persistence and privilege escalation",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Event-triggered execution provides both persistence and privilege escalation. "
            "Execution often occurs under elevated privileges (SYSTEM or service accounts), "
            "making it particularly dangerous. In cloud environments, malicious event "
            "triggers can respond to routine operations like user creation or file uploads, "
            "providing attackers with persistent access that survives credential rotation."
        ),
        business_impact=[
            "Persistent unauthorised access",
            "Privilege escalation via service accounts",
            "Data exfiltration through event triggers",
            "Resource abuse (cryptomining, spam)",
            "Backdoor access survives remediation attempts",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1078.004", "T1098.001", "T1530"],
        often_follows=["T1078.004", "T1098.003", "T1648"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Lambda Event Source Mapping
        DetectionStrategy(
            strategy_id="t1546-aws-lambda-triggers",
            name="AWS Lambda Event Trigger Creation Detection",
            description="Detect creation of new Lambda event source mappings and triggers.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.lambda"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateEventSourceMapping",
                            "UpdateEventSourceMapping",
                            "CreateEventSourceMapping20150331",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda event trigger creation

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

  # Dead Letter Queue for failed event deliveries (14-day retention)
  AlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: lambda-trigger-alert-dlq
      MessageRetentionPeriod: 1209600

  # Step 2: EventBridge rule for Lambda trigger creation
  LambdaTriggerRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.lambda]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateEventSourceMapping
            - UpdateEventSourceMapping
            - CreateEventSourceMapping20150331
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt AlertDLQ.Arn

  # Step 3: Allow EventBridge to publish to SNS
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
                aws:SourceArn: !GetAtt LambdaTriggerRule.Arn

  # Allow EventBridge to send failed events to DLQ
  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [!Ref AlertDLQ]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt AlertDLQ.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt LambdaTriggerRule.Arn""",
                terraform_template="""# Detect Lambda event trigger creation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "lambda-trigger-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed event deliveries (14-day retention)
resource "aws_sqs_queue" "alert_dlq" {
  name                      = "lambda-trigger-alert-dlq"
  message_retention_seconds = 1209600
}

# Step 2: EventBridge rule for Lambda trigger creation
resource "aws_cloudwatch_event_rule" "lambda_trigger" {
  name = "lambda-event-trigger-creation"
  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateEventSourceMapping",
        "UpdateEventSourceMapping",
        "CreateEventSourceMapping20150331"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.lambda_trigger.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age_in_seconds      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.alert_dlq.arn
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

# Step 3: Allow EventBridge to publish to SNS
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.lambda_trigger.arn
        }
      }
    }]
  })
}

# Allow EventBridge to send failed events to DLQ
resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.alert_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.alert_dlq.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Lambda Event Trigger Created",
                alert_description_template="New Lambda event source mapping created for function {functionName} by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify event source mapping was authorised",
                    "Review the Lambda function code",
                    "Check IAM role attached to function",
                    "Identify event source (S3, DynamoDB, etc.)",
                    "Review function execution history",
                    "Check for concurrent suspicious IAM activity",
                ],
                containment_actions=[
                    "Delete unauthorised event source mappings",
                    "Review and restrict Lambda creation permissions",
                    "Audit Lambda function IAM roles",
                    "Disable suspicious Lambda functions",
                    "Enable Lambda code signing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD pipelines and authorised automation tools",
            detection_coverage="95% - catches all event source mapping creation",
            evasion_considerations="Cannot evade creation detection, but attackers may use existing legitimate triggers",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - EventBridge Rule Creation
        DetectionStrategy(
            strategy_id="t1546-aws-eventbridge",
            name="AWS EventBridge Rule Creation Detection",
            description="Detect creation or modification of EventBridge rules that could trigger malicious code.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.events"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["PutRule", "PutTargets", "CreateEventBus"]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EventBridge rule creation

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

  # Dead Letter Queue for failed event deliveries (14-day retention)
  AlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: eventbridge-rule-alert-dlq
      MessageRetentionPeriod: 1209600

  # Step 2: EventBridge rule for rule creation
  EventBridgeModRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.events]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PutRule
            - PutTargets
            - CreateEventBus
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt AlertDLQ.Arn

  # Step 3: Allow EventBridge to publish to SNS
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
                aws:SourceArn: !GetAtt EventBridgeModRule.Arn

  # Allow EventBridge to send failed events to DLQ
  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [!Ref AlertDLQ]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt AlertDLQ.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt EventBridgeModRule.Arn""",
                terraform_template="""# Detect EventBridge rule creation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "eventbridge-rule-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed event deliveries (14-day retention)
resource "aws_sqs_queue" "alert_dlq" {
  name                      = "eventbridge-rule-alert-dlq"
  message_retention_seconds = 1209600
}

# Step 2: EventBridge rule for rule creation
resource "aws_cloudwatch_event_rule" "eventbridge_mod" {
  name = "eventbridge-rule-creation"
  event_pattern = jsonencode({
    source      = ["aws.events"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutRule",
        "PutTargets",
        "CreateEventBus"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.eventbridge_mod.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age_in_seconds      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.alert_dlq.arn
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

# Step 3: Allow EventBridge to publish to SNS
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.eventbridge_mod.arn
        }
      }
    }]
  })
}

# Allow EventBridge to send failed events to DLQ
resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.alert_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.alert_dlq.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="EventBridge Rule Created or Modified",
                alert_description_template="EventBridge rule {ruleName} was created or modified by {userIdentity.arn}.",
                investigation_steps=[
                    "Review the rule pattern and targets",
                    "Verify rule creation was authorised",
                    "Check what the rule triggers (Lambda, Step Functions, etc.)",
                    "Review execution history of targets",
                    "Check for patterns matching IAM events or sensitive operations",
                    "Look for rules with overly broad patterns",
                ],
                containment_actions=[
                    "Disable unauthorised EventBridge rules",
                    "Delete malicious rule targets",
                    "Review permissions for EventBridge management",
                    "Audit target Lambda functions or Step Functions",
                    "Enable EventBridge schema validation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist infrastructure automation and CI/CD tools. Focus on rules targeting IAM or security events.",
            detection_coverage="95% - catches all rule creation",
            evasion_considerations="High false positive rate requires tuning. Attackers may use subtle event patterns.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - S3 Event Notification Configuration
        DetectionStrategy(
            strategy_id="t1546-aws-s3-events",
            name="AWS S3 Event Notification Detection",
            description="Detect configuration of S3 event notifications that trigger Lambda functions.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["PutBucketNotificationConfiguration"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 event notification configuration

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

  # Dead Letter Queue for failed event deliveries (14-day retention)
  AlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: s3-event-notification-alert-dlq
      MessageRetentionPeriod: 1209600

  # Step 2: EventBridge rule for S3 notification config
  S3NotificationRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.s3]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [PutBucketNotificationConfiguration]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt AlertDLQ.Arn

  # Step 3: Allow EventBridge to publish to SNS
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
                aws:SourceArn: !GetAtt S3NotificationRule.Arn

  # Allow EventBridge to send failed events to DLQ
  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [!Ref AlertDLQ]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt AlertDLQ.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt S3NotificationRule.Arn""",
                terraform_template="""# Detect S3 event notification configuration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "s3-event-notification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed event deliveries (14-day retention)
resource "aws_sqs_queue" "alert_dlq" {
  name                      = "s3-event-notification-alert-dlq"
  message_retention_seconds = 1209600
}

# Step 2: EventBridge rule for S3 notification config
resource "aws_cloudwatch_event_rule" "s3_notification" {
  name = "s3-event-notification-config"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutBucketNotificationConfiguration"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.s3_notification.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age_in_seconds      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.alert_dlq.arn
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

# Step 3: Allow EventBridge to publish to SNS
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.s3_notification.arn
        }
      }
    }]
  })
}

# Allow EventBridge to send failed events to DLQ
resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.alert_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.alert_dlq.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="S3 Event Notification Configured",
                alert_description_template="S3 bucket {bucketName} event notification configured by {userIdentity.arn}.",
                investigation_steps=[
                    "Review notification configuration details",
                    "Check which Lambda/SNS/SQS receives events",
                    "Verify the bucket contains sensitive data",
                    "Review Lambda function code if applicable",
                    "Check for CloudFormation upload triggers (Pacu technique)",
                    "Review recent S3 bucket policy changes",
                ],
                containment_actions=[
                    "Remove unauthorised bucket notifications",
                    "Review and restrict s3:PutBucketNotification permissions",
                    "Audit Lambda functions triggered by S3 events",
                    "Enable S3 bucket versioning and MFA delete",
                    "Review bucket policies for unauthorised access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known data processing pipelines and ETL jobs",
            detection_coverage="95% - catches all notification configuration changes",
            evasion_considerations="Pacu specifically uses this technique. Legitimate use is common for data pipelines.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled with S3 data events"],
        ),
        # Strategy 4: GCP - Cloud Functions Event Triggers
        DetectionStrategy(
            strategy_id="t1546-gcp-function-triggers",
            name="GCP Cloud Functions Event Trigger Detection",
            description="Detect creation of Cloud Functions with event triggers.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName=~"CloudFunctionsService.CreateFunction|FunctionService.CreateFunction"
protoPayload.request.eventTrigger:*""",
                gcp_terraform_template="""# GCP: Detect Cloud Functions with event triggers

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for event-triggered functions
resource "google_logging_metric" "function_trigger" {
  project = var.project_id
  name   = "cloud-functions-event-triggers"
  filter = <<-EOT
    protoPayload.methodName=~"CloudFunctionsService.CreateFunction|FunctionService.CreateFunction"
    protoPayload.request.eventTrigger:*
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "function_trigger" {
  project      = var.project_id
  display_name = "Cloud Function Event Trigger Created"
  combiner     = "OR"

  conditions {
    display_name = "Event-triggered function created"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_trigger.name}\""
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
                alert_severity="medium",
                alert_title="GCP: Cloud Function with Event Trigger Created",
                alert_description_template="Cloud Function with event trigger was created.",
                investigation_steps=[
                    "Review function source code",
                    "Check event trigger configuration",
                    "Verify service account permissions",
                    "Review what events trigger the function",
                    "Check for triggers on IAM, storage, or Pub/Sub events",
                    "Audit recent function executions",
                ],
                containment_actions=[
                    "Delete unauthorised functions",
                    "Remove event triggers from suspicious functions",
                    "Review Cloud Functions deployment permissions",
                    "Audit service account IAM bindings",
                    "Enable VPC Service Controls for Functions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD pipelines and known serverless applications",
            detection_coverage="95% - catches all event-triggered function creation",
            evasion_considerations="Cannot evade creation detection. Attackers may use subtle trigger configurations.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - Pub/Sub Subscription Creation
        DetectionStrategy(
            strategy_id="t1546-gcp-pubsub",
            name="GCP Pub/Sub Subscription Creation Detection",
            description="Detect creation of Pub/Sub subscriptions that push to endpoints.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="google.pubsub.v1.Subscriber.CreateSubscription"
protoPayload.request.pushConfig:*""",
                gcp_terraform_template="""# GCP: Detect Pub/Sub push subscription creation

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for push subscriptions
resource "google_logging_metric" "pubsub_push" {
  project = var.project_id
  name   = "pubsub-push-subscription-creation"
  filter = <<-EOT
    protoPayload.methodName="google.pubsub.v1.Subscriber.CreateSubscription"
    protoPayload.request.pushConfig:*
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "pubsub_push" {
  project      = var.project_id
  display_name = "Pub/Sub Push Subscription Created"
  combiner     = "OR"

  conditions {
    display_name = "Push subscription created"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.pubsub_push.name}\""
      duration        = "0s"
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
                alert_severity="medium",
                alert_title="GCP: Pub/Sub Push Subscription Created",
                alert_description_template="Pub/Sub push subscription was created.",
                investigation_steps=[
                    "Review push endpoint configuration",
                    "Verify subscription was authorised",
                    "Check what topic the subscription monitors",
                    "Review push endpoint authentication",
                    "Audit service account permissions",
                    "Check for subscriptions to admin activity topics",
                ],
                containment_actions=[
                    "Delete unauthorised subscriptions",
                    "Review Pub/Sub IAM permissions",
                    "Verify push endpoint legitimacy",
                    "Enable authentication for push endpoints",
                    "Audit topic publishing permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known event-driven applications and integration platforms",
            detection_coverage="90% - catches push subscription creation",
            evasion_considerations="Pull subscriptions are not detected by this rule",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 6: AWS - CloudWatch Logs Subscription Filters
        DetectionStrategy(
            strategy_id="t1546-aws-logs-subscription",
            name="AWS CloudWatch Logs Subscription Filter Detection",
            description="Detect creation of CloudWatch Logs subscription filters that stream logs to Lambda.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.logs"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["PutSubscriptionFilter"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect CloudWatch Logs subscription filter creation

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

  # Dead Letter Queue for failed event deliveries (14-day retention)
  AlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: logs-subscription-alert-dlq
      MessageRetentionPeriod: 1209600

  # Step 2: EventBridge rule for subscription filter
  LogsSubscriptionRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.logs]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [PutSubscriptionFilter]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt AlertDLQ.Arn

  # Step 3: Allow EventBridge to publish to SNS
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
                aws:SourceArn: !GetAtt LogsSubscriptionRule.Arn

  # Allow EventBridge to send failed events to DLQ
  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [!Ref AlertDLQ]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt AlertDLQ.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt LogsSubscriptionRule.Arn""",
                terraform_template="""# Detect CloudWatch Logs subscription filter creation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "logs-subscription-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed event deliveries (14-day retention)
resource "aws_sqs_queue" "alert_dlq" {
  name                      = "logs-subscription-alert-dlq"
  message_retention_seconds = 1209600
}

# Step 2: EventBridge rule for subscription filter
resource "aws_cloudwatch_event_rule" "logs_subscription" {
  name = "logs-subscription-filter-creation"
  event_pattern = jsonencode({
    source      = ["aws.logs"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutSubscriptionFilter"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.logs_subscription.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age_in_seconds      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.alert_dlq.arn
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

# Step 3: Allow EventBridge to publish to SNS
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.logs_subscription.arn
        }
      }
    }]
  })
}

# Allow EventBridge to send failed events to DLQ
resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.alert_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.alert_dlq.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="CloudWatch Logs Subscription Filter Created",
                alert_description_template="Subscription filter created for log group {logGroupName} by {userIdentity.arn}.",
                investigation_steps=[
                    "Review filter pattern and destination",
                    "Check destination Lambda function code",
                    "Verify subscription was authorised",
                    "Review what logs are being filtered",
                    "Check for filters on security-related log groups",
                    "Audit Lambda function execution history",
                ],
                containment_actions=[
                    "Delete unauthorised subscription filters",
                    "Review logs:PutSubscriptionFilter permissions",
                    "Audit destination Lambda functions",
                    "Enable log group encryption",
                    "Review Lambda function IAM roles",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known log processing and SIEM integrations",
            detection_coverage="95% - catches all subscription filter creation",
            evasion_considerations="Legitimate use is less common than other event triggers",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Azure Strategy: Event Triggered Execution
        DetectionStrategy(
            strategy_id="t1546-azure",
            name="Azure Event Triggered Execution Detection",
            description=(
                "Azure detection for Event Triggered Execution. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Event Triggered Execution (T1546)
# Microsoft Defender detects Event Triggered Execution activity

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
  name                = "defender-t1546-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1546"
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

  description = "Microsoft Defender detects Event Triggered Execution activity"
  display_name = "Defender: Event Triggered Execution"
  enabled      = true
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Event Triggered Execution Detected",
                alert_description_template=(
                    "Event Triggered Execution activity detected. "
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
        "t1546-aws-lambda-triggers",
        "t1546-aws-s3-events",
        "t1546-gcp-function-triggers",
        "t1546-aws-eventbridge",
        "t1546-gcp-pubsub",
        "t1546-aws-logs-subscription",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+20% improvement for Persistence and Privilege Escalation tactics",
)
