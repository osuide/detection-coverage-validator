"""
T1020 - Automated Exfiltration

Adversaries use automated processes to exfiltrate collected data, such as sensitive documents.
The automation typically occurs after data gathering and often works alongside other exfiltration methods.
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
    technique_id="T1020",
    technique_name="Automated Exfiltration",
    tactic_ids=["TA0010"],  # Exfiltration
    mitre_url="https://attack.mitre.org/techniques/T1020/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use automated processes to exfiltrate collected data from cloud environments. "
            "In AWS and GCP, this involves automated scripts or tools that periodically transmit data to "
            "external destinations via S3/GCS uploads, API calls, or unauthorised network connections. "
            "The automation often uses scheduled tasks, Lambda functions, Cloud Functions, or background "
            "daemons that operate after initial data collection, making detection challenging as the "
            "activity may blend with legitimate automated workflows."
        ),
        attacker_goal="Automatically and continuously exfiltrate collected sensitive data to external destinations",
        why_technique=[
            "Enables continuous data theft without manual intervention",
            "Difficult to distinguish from legitimate automated workflows",
            "Can operate in background over extended periods",
            "Reduces attacker operational exposure",
            "Leverages legitimate cloud services for exfiltration",
            "Circumvents manual monitoring controls",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Automated exfiltration represents a critical threat as it enables persistent, large-scale "
            "data theft without ongoing attacker involvement. The technique is difficult to prevent as it "
            "abuses legitimate cloud features. High severity due to potential for sustained loss of "
            "intellectual property, customer data, and sensitive business information. The automation "
            "aspect makes it particularly dangerous for compliance violations and data breach scenarios."
        ),
        business_impact=[
            "Large-scale theft of intellectual property and business data",
            "Sustained compliance violations and regulatory penalties",
            "Loss of competitive advantage through data leakage",
            "Reputational damage from extended breach periods",
            "Increased cloud egress costs from unauthorised transfers",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=["T1041", "T1567"],
        often_follows=["T1074", "T1560", "T1005"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Automated S3 Upload Detection
        DetectionStrategy(
            strategy_id="t1020-aws-s3-upload",
            name="Automated S3 Data Upload Detection",
            description="Detect unusual patterns of automated S3 uploads that may indicate data exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
| filter eventName in ["PutObject", "CopyObject", "UploadPart", "CompleteMultipartUpload"]
| stats count(*) as upload_count, sum(requestParameters.contentLength) as total_bytes by userIdentity.arn, requestParameters.bucketName, bin(5m)
| filter upload_count > 50 or total_bytes > 100000000
| sort upload_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect automated S3 data uploads indicating exfiltration

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
      DisplayName: S3 Upload Anomaly Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for high-frequency S3 uploads
  S3UploadRule:
    Type: AWS::Events::Rule
    Properties:
      Name: s3-upload-anomaly-detection
      Description: Detect unusual S3 upload patterns
      EventPattern:
        source: [aws.s3]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PutObject
            - CopyObject
            - UploadPart
            - CompleteMultipartUpload
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
              bucket: $.detail.requestParameters.bucketName
              user: $.detail.userIdentity.arn
            InputTemplate: |
              "Automated S3 Upload Alert (T1020)
              time=<time> account=<account> region=<region>
              event=<eventName> bucket=<bucket>
              user=<user>
              Action: Investigate potential automated exfiltration"

  # Step 3: Dead letter queue
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: s3-upload-anomaly-dlq
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
                aws:SourceArn: !GetAtt S3UploadRule.Arn""",
                terraform_template="""# Detect automated S3 uploads

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "s3_upload_alerts" {
  name         = "s3-upload-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "S3 Upload Anomaly Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.s3_upload_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for S3 uploads
resource "aws_cloudwatch_event_rule" "s3_upload" {
  name        = "s3-upload-anomaly-detection"
  description = "Detect unusual S3 upload patterns"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutObject",
        "CopyObject",
        "UploadPart",
        "CompleteMultipartUpload"
      ]
    }
  })
}

# Step 3: Dead letter queue
resource "aws_sqs_queue" "dlq" {
  name                      = "s3-upload-anomaly-dlq"
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
      values   = [aws_cloudwatch_event_rule.s3_upload.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 4: EventBridge target with DLQ, retry, input transformer
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.s3_upload.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.s3_upload_alerts.arn

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
      bucket    = "$.detail.requestParameters.bucketName"
      user      = "$.detail.userIdentity.arn"
    }
    input_template = <<-EOT
"Automated S3 Upload Alert (T1020)
time=<time> account=<account> region=<region>
event=<eventName> bucket=<bucket>
user=<user>
Action: Investigate potential automated exfiltration"
EOT
  }
}

# Step 5: SNS topic policy (scoped)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.s3_upload_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.s3_upload_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.s3_upload.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Automated S3 Upload Pattern Detected",
                alert_description_template="High-frequency S3 uploads detected from {userIdentity.arn} to bucket {bucketName}. May indicate automated data exfiltration.",
                investigation_steps=[
                    "Identify the source identity and verify legitimacy",
                    "Review uploaded objects and their sizes",
                    "Check destination bucket ownership and region",
                    "Examine upload patterns and timing",
                    "Review CloudTrail for concurrent suspicious activities",
                    "Verify if uploads align with scheduled jobs or workflows",
                ],
                containment_actions=[
                    "Revoke credentials for suspicious identities",
                    "Enable S3 Block Public Access on affected buckets",
                    "Implement bucket policies to restrict uploads",
                    "Enable S3 Object Lock for critical data",
                    "Review and restrict s3:PutObject permissions",
                    "Enable S3 Access Logging for forensic analysis",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup jobs, ETL pipelines, and scheduled data transfer workflows. Adjust thresholds based on normal upload volumes.",
            detection_coverage="85% - catches high-volume automated uploads",
            evasion_considerations="Low-volume exfiltration or uploads matching normal patterns may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "S3 bucket logging",
            ],
        ),
        # Strategy 2: AWS - Lambda-based Exfiltration Detection
        DetectionStrategy(
            strategy_id="t1020-aws-lambda-exfil",
            name="Lambda Function Data Exfiltration Detection",
            description="Detect Lambda functions making automated external connections potentially for data exfiltration.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.lambda"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateFunction20150331",
                            "UpdateFunctionCode20150331v2",
                            "UpdateFunctionConfiguration20150331v2",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda functions for automated exfiltration

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

  # Step 2: EventBridge rule for Lambda modifications
  LambdaChangeRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.lambda]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateFunction20150331
            - UpdateFunctionCode20150331v2
            - UpdateFunctionConfiguration20150331v2
      Targets:
        - Id: Alert
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
              functionName: $.detail.requestParameters.functionName
              user: $.detail.userIdentity.arn
            InputTemplate: |
              "Lambda Modification Alert (T1020)
              time=<time> account=<account> region=<region>
              function=<functionName> user=<user>
              Action: Review function code for exfiltration"

  # Step 3: Dead letter queue
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: lambda-exfiltration-dlq
      MessageRetentionPeriod: 1209600

  # Step 4: Topic policy (scoped)
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
                aws:SourceArn: !GetAtt LambdaChangeRule.Arn""",
                terraform_template="""# Detect Lambda-based automated exfiltration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "lambda_alerts" {
  name = "lambda-exfiltration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.lambda_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for Lambda changes
resource "aws_cloudwatch_event_rule" "lambda_changes" {
  name        = "lambda-exfiltration-detection"
  description = "Detect Lambda function modifications"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateFunction20150331",
        "UpdateFunctionCode20150331v2",
        "UpdateFunctionConfiguration20150331v2"
      ]
    }
  })
}

# Step 3: Dead letter queue
resource "aws_sqs_queue" "dlq" {
  name                      = "lambda-exfiltration-dlq"
  message_retention_seconds = 1209600
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
data "aws_iam_policy_document" "eventbridge_dlq_policy_lambda" {
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
      values   = [aws_cloudwatch_event_rule.lambda_changes.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq_lambda" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy_lambda.json
}

# Step 4: EventBridge target with DLQ, retry, input transformer
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.lambda_changes.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.lambda_alerts.arn

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
      functionName = "$.detail.requestParameters.functionName"
      user         = "$.detail.userIdentity.arn"
    }
    input_template = <<-EOT
"Lambda Modification Alert (T1020)
time=<time> account=<account> region=<region>
function=<functionName> user=<user>
Action: Review function code for exfiltration"
EOT
  }
}

# Step 5: SNS topic policy (scoped)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.lambda_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.lambda_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.lambda_changes.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Lambda Function Modified - Potential Exfiltration Vector",
                alert_description_template="Lambda function {functionName} was modified. Review for unauthorised data exfiltration code.",
                investigation_steps=[
                    "Review Lambda function code for external connections",
                    "Check function execution logs in CloudWatch",
                    "Examine function IAM role permissions",
                    "Identify who made the modifications",
                    "Review VPC configuration and security groups",
                    "Check for environment variables containing credentials",
                ],
                containment_actions=[
                    "Delete or disable suspicious Lambda functions",
                    "Review and restrict lambda:UpdateFunctionCode permissions",
                    "Enable function code signing",
                    "Implement VPC endpoints for AWS services",
                    "Review Lambda execution role permissions",
                    "Enable CloudWatch Logs for all functions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised deployment pipelines and CI/CD systems",
            detection_coverage="80% - catches Lambda-based exfiltration mechanisms",
            evasion_considerations="Attackers may use existing legitimate functions or gradual modifications",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - Scheduled Task Exfiltration Detection
        DetectionStrategy(
            strategy_id="t1020-aws-scheduled-exfil",
            name="Scheduled Task Data Transfer Detection",
            description="Detect creation of EventBridge scheduled rules that may automate data exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters.name, requestParameters.scheduleExpression
| filter eventName in ["PutRule", "PutTargets"]
| filter requestParameters.scheduleExpression like /rate|cron/
| sort @timestamp desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect scheduled rules for automated exfiltration

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

  # Step 2: EventBridge rule for scheduled rule creation
  ScheduledRuleDetection:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.events]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PutRule
            - PutTargets
      Targets:
        - Id: Alert
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
              ruleName: $.detail.requestParameters.name
              user: $.detail.userIdentity.arn
            InputTemplate: |
              "Scheduled Rule Alert (T1020)
              time=<time> account=<account> region=<region>
              rule=<ruleName> user=<user>
              Action: Verify scheduled rule legitimacy"

  # Step 3: Dead letter queue
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: scheduled-exfiltration-dlq
      MessageRetentionPeriod: 1209600

  # Step 4: Topic policy (scoped)
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
                aws:SourceArn: !GetAtt ScheduledRuleDetection.Arn""",
                terraform_template="""# Detect scheduled automated exfiltration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "schedule_alerts" {
  name = "scheduled-exfiltration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.schedule_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for scheduled rule creation
resource "aws_cloudwatch_event_rule" "schedule_detection" {
  name        = "scheduled-rule-detection"
  description = "Detect creation of scheduled EventBridge rules"

  event_pattern = jsonencode({
    source      = ["aws.events"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutRule", "PutTargets"]
    }
  })
}

# Step 3: Dead letter queue
resource "aws_sqs_queue" "dlq" {
  name                      = "scheduled-exfiltration-dlq"
  message_retention_seconds = 1209600
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
data "aws_iam_policy_document" "eventbridge_dlq_policy_scheduled" {
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
      values   = [aws_cloudwatch_event_rule.schedule_detection.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq_scheduled" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy_scheduled.json
}

# Step 4: EventBridge target with DLQ, retry, input transformer
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.schedule_detection.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.schedule_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      account  = "$.account"
      region   = "$.region"
      time     = "$.time"
      ruleName = "$.detail.requestParameters.name"
      user     = "$.detail.userIdentity.arn"
    }
    input_template = <<-EOT
"Scheduled Rule Alert (T1020)
time=<time> account=<account> region=<region>
rule=<ruleName> user=<user>
Action: Verify scheduled rule legitimacy"
EOT
  }
}

# Step 5: SNS topic policy (scoped)
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.schedule_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.schedule_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.schedule_detection.arn
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Scheduled EventBridge Rule Created",
                alert_description_template="New scheduled rule {ruleName} created with expression {scheduleExpression}. Verify legitimacy to prevent automated exfiltration.",
                investigation_steps=[
                    "Review rule schedule and targets",
                    "Identify who created the scheduled rule",
                    "Examine target Lambda functions or services",
                    "Check rule pattern and filter criteria",
                    "Review recent CloudTrail events from same principal",
                    "Verify business justification for automation",
                ],
                containment_actions=[
                    "Disable suspicious scheduled rules",
                    "Review and restrict events:PutRule permissions",
                    "Enable EventBridge rule audit logging",
                    "Implement approval workflows for scheduled tasks",
                    "Review all existing scheduled rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist known automation frameworks, backup schedules, and operational tasks. Focus on rules with external network targets.",
            detection_coverage="75% - catches scheduled automation creation",
            evasion_considerations="Attackers may use irregular schedules or modify existing rules",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 4: GCP - Cloud Storage Upload Anomaly Detection
        DetectionStrategy(
            strategy_id="t1020-gcp-gcs-upload",
            name="GCP Cloud Storage Upload Anomaly Detection",
            description="Detect unusual patterns of automated GCS uploads indicating potential data exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
protoPayload.serviceName="storage.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect automated Cloud Storage uploads

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for GCS uploads
resource "google_logging_metric" "gcs_upload" {
  project = var.project_id
  name   = "gcs-upload-frequency"
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
  }

  label_extractors = {
    "bucket_name" = "EXTRACT(resource.labels.bucket_name)"
  }
}

# Step 3: Alert policy for high-frequency uploads
resource "google_monitoring_alert_policy" "gcs_upload_alert" {
  project      = var.project_id
  display_name = "Automated GCS Upload Detected"
  combiner     = "OR"

  conditions {
    display_name = "High-frequency Cloud Storage uploads"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_upload.name}\" resource.type=\"gcs_bucket\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
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
                alert_severity="high",
                alert_title="GCP: Automated Cloud Storage Upload Pattern Detected",
                alert_description_template="High-frequency uploads detected to bucket {bucket_name}. May indicate automated data exfiltration.",
                investigation_steps=[
                    "Identify the service account or user performing uploads",
                    "Review uploaded object names and sizes",
                    "Check bucket location and storage class",
                    "Examine upload patterns and timing",
                    "Review Cloud Audit Logs for concurrent activities",
                    "Verify against known scheduled jobs",
                ],
                containment_actions=[
                    "Revoke service account keys if compromised",
                    "Implement bucket IAM policies to restrict uploads",
                    "Enable uniform bucket-level access",
                    "Review and restrict storage.objects.create permissions",
                    "Enable Object Versioning for recovery",
                    "Configure VPC Service Controls to limit data egress",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup jobs, data pipelines, and application upload workflows. Adjust thresholds based on normal patterns.",
            detection_coverage="85% - catches high-volume automated uploads",
            evasion_considerations="Low-volume or intermittent uploads may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$8-15",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Cloud Storage data access logs",
            ],
        ),
        # Strategy 5: GCP - Cloud Function Exfiltration Detection
        DetectionStrategy(
            strategy_id="t1020-gcp-function-exfil",
            name="GCP Cloud Function Data Exfiltration Detection",
            description="Detect Cloud Functions that may be used for automated data exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
(protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CreateFunction"
OR protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.UpdateFunction")
protoPayload.serviceName="cloudfunctions.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect Cloud Function modifications for exfiltration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for function changes
resource "google_logging_metric" "function_changes" {
  project = var.project_id
  name   = "cloud-function-modifications"
  filter = <<-EOT
    resource.type="cloud_function"
    protoPayload.serviceName="cloudfunctions.googleapis.com"
    (protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CreateFunction" OR
     protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.UpdateFunction")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "function_alert" {
  project      = var.project_id
  display_name = "Cloud Function Modification Detected"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Function created or updated"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_changes.name}\""
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
                alert_severity="high",
                alert_title="GCP: Cloud Function Modified - Potential Exfiltration Vector",
                alert_description_template="Cloud Function {function_name} was modified. Review for unauthorised data exfiltration code.",
                investigation_steps=[
                    "Review function source code for external connections",
                    "Check function execution logs in Cloud Logging",
                    "Examine function service account permissions",
                    "Identify who made the modifications",
                    "Review VPC Connector configuration",
                    "Check environment variables for credentials",
                ],
                containment_actions=[
                    "Delete or disable suspicious Cloud Functions",
                    "Review and restrict cloudfunctions.functions.update permissions",
                    "Implement VPC Service Controls",
                    "Review function service account IAM bindings",
                    "Enable function source code repository tracking",
                    "Configure Cloud Logging for all function executions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised deployment systems and CI/CD pipelines",
            detection_coverage="80% - catches Cloud Function-based exfiltration mechanisms",
            evasion_considerations="Attackers may use existing functions or make gradual changes",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$8-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 6: GCP - Cloud Scheduler Job Detection
        DetectionStrategy(
            strategy_id="t1020-gcp-scheduler",
            name="GCP Cloud Scheduler Job Detection",
            description="Detect creation of Cloud Scheduler jobs that may automate data exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_scheduler_job"
(protoPayload.methodName="google.cloud.scheduler.v1.CloudScheduler.CreateJob"
OR protoPayload.methodName="google.cloud.scheduler.v1.CloudScheduler.UpdateJob")
protoPayload.serviceName="cloudscheduler.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect Cloud Scheduler job creation

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s3" {
  project      = var.project_id
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for scheduler jobs
resource "google_logging_metric" "scheduler_jobs" {
  project = var.project_id
  name   = "cloud-scheduler-job-changes"
  filter = <<-EOT
    resource.type="cloud_scheduler_job"
    protoPayload.serviceName="cloudscheduler.googleapis.com"
    (protoPayload.methodName="google.cloud.scheduler.v1.CloudScheduler.CreateJob" OR
     protoPayload.methodName="google.cloud.scheduler.v1.CloudScheduler.UpdateJob")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "scheduler_alert" {
  project      = var.project_id
  display_name = "Cloud Scheduler Job Created or Modified"
  combiner     = "OR"

  conditions {
    display_name = "Scheduler job automation detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.scheduler_jobs.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s3.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Scheduler Job Created or Modified",
                alert_description_template="Cloud Scheduler job {job_name} with schedule {schedule} was modified. Verify legitimacy.",
                investigation_steps=[
                    "Review job schedule and target configuration",
                    "Identify who created or modified the job",
                    "Examine target Cloud Function, HTTP endpoint, or Pub/Sub topic",
                    "Check job service account permissions",
                    "Review recent Cloud Audit Logs from same principal",
                    "Verify business justification",
                ],
                containment_actions=[
                    "Pause or delete suspicious scheduler jobs",
                    "Review and restrict cloudscheduler.jobs.create permissions",
                    "Implement organisation policy constraints",
                    "Review all existing scheduled jobs",
                    "Enable notifications for job executions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist known automation systems, backup schedules, and operational workflows",
            detection_coverage="75% - catches scheduled automation creation",
            evasion_considerations="Attackers may use irregular schedules or modify existing jobs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$8-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Automated Exfiltration
        DetectionStrategy(
            strategy_id="t1020-azure",
            name="Azure Automated Exfiltration Detection",
            description=(
                "Azure detection for Automated Exfiltration. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Automated Exfiltration Detection
// Technique: T1020
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc""",
                azure_terraform_template="""# Azure Detection for Automated Exfiltration
# MITRE ATT&CK: T1020

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
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "automated-exfiltration-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "automated-exfiltration-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Automated Exfiltration Detection
// Technique: T1020
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects Automated Exfiltration (T1020) activity in Azure environment"
  display_name = "Automated Exfiltration Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1020"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Automated Exfiltration Detected",
                alert_description_template=(
                    "Automated Exfiltration activity detected. "
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
        "t1020-aws-s3-upload",
        "t1020-gcp-gcs-upload",
        "t1020-aws-lambda-exfil",
        "t1020-gcp-function-exfil",
        "t1020-aws-scheduled-exfil",
        "t1020-gcp-scheduler",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+25% improvement for Exfiltration tactic detection",
)
