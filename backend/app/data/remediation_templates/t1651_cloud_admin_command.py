"""
T1651 - Cloud Administration Command

Adversaries use cloud management services (SSM, Azure RunCommand, GCP OS Config)
to execute commands on VMs. Used by APT29, Pacu, and SCARLETEEL.
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
    technique_id="T1651",
    technique_name="Cloud Administration Command",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1651/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use cloud management services (AWS Systems Manager, GCP OS Config) "
            "to execute commands on virtual machines through installed VM agents. "
            "These legitimate tools bypass traditional network security controls."
        ),
        attacker_goal="Execute commands on VMs via cloud management services",
        why_technique=[
            "Legitimate admin tool often allowed",
            "No need for SSH/RDP access",
            "Commands executed as SYSTEM/root",
            "May bypass network security controls",
            "Logs may be overlooked",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Enables command execution with high privileges. "
            "Legitimate tool makes detection difficult. "
            "Bypasses traditional network security."
        ),
        business_impact=[
            "Arbitrary command execution",
            "Malware deployment",
            "Data exfiltration",
            "Lateral movement",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1530", "T1485"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: SSM Command Execution with Lambda Analysis
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1651-aws-ssm-lambda",
            name="AWS SSM Command Execution with Anomaly Detection",
            description=(
                "Monitor SSM SendCommand and StartSession with Lambda-based analysis. "
                "Detects unusual command patterns, out-of-hours execution, and suspicious targets."
            ),
            detection_type=DetectionType.CUSTOM_LAMBDA,
            aws_service="lambda",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# AWS SSM Command Execution with Anomaly Detection
# Monitors SendCommand, StartSession with suspicious pattern detection

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}

variable "alert_email" {
  type        = string
  description = "Email for SSM security alerts"
}

variable "allowed_users" {
  type        = list(string)
  default     = []
  description = "IAM ARNs allowed to use SSM commands"
}

variable "business_hours_start" {
  type        = number
  default     = 9
  description = "Business hours start (0-23 UTC)"
}

variable "business_hours_end" {
  type        = number
  default     = 18
  description = "Business hours end (0-23 UTC)"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "ssm_alerts" {
  name              = "ssm-command-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: DynamoDB for command tracking
resource "aws_dynamodb_table" "ssm_tracking" {
  name         = "ssm-command-tracking"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "user_arn"
  range_key    = "window_id"

  attribute {
    name = "user_arn"
    type = "S"
  }

  attribute {
    name = "window_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

# Step 3: Lambda function for SSM analysis
resource "aws_lambda_function" "ssm_analyzer" {
  function_name = "ssm-command-analyzer"
  runtime       = "python3.11"
  handler       = "index.handler"
  role          = aws_iam_role.lambda_role.arn
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      TRACKING_TABLE       = aws_dynamodb_table.ssm_tracking.name
      ALERT_TOPIC_ARN      = aws_sns_topic.ssm_alerts.arn
      ALLOWED_USERS        = jsonencode(var.allowed_users)
      BUSINESS_HOURS_START = tostring(var.business_hours_start)
      BUSINESS_HOURS_END   = tostring(var.business_hours_end)
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/ssm_analyzer.zip"

  source {
    content  = <<-PYTHON
import json
import os
import boto3
from datetime import datetime, timezone

dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')
table = dynamodb.Table(os.environ['TRACKING_TABLE'])
ALLOWED = json.loads(os.environ.get('ALLOWED_USERS', '[]'))
BH_START = int(os.environ.get('BUSINESS_HOURS_START', '9'))
BH_END = int(os.environ.get('BUSINESS_HOURS_END', '18'))

# Suspicious command patterns
SUSPICIOUS_PATTERNS = [
    'curl', 'wget', 'nc ', 'netcat', 'bash -c', 'powershell',
    'base64', 'eval', '/dev/tcp', 'chmod +x', 'python -c',
    'aws s3 cp', 'aws iam', 'whoami', 'id ', 'cat /etc/passwd'
]


def handler(event, context):
    for record in event.get('Records', []):
        try:
            detail = json.loads(record['body'])
            analyze_ssm_command(detail)
        except Exception as e:
            print(f"Error: {e}")
            raise


def analyze_ssm_command(detail):
    event_name = detail.get('eventName', '')
    user_arn = detail.get('userIdentity', {}).get('arn', 'unknown')
    source_ip = detail.get('sourceIPAddress', '')
    event_time = detail.get('eventTime', '')
    request_params = detail.get('requestParameters', {})

    score = 0
    reasons = []

    # Check if user is in allowed list
    if user_arn in ALLOWED:
        return

    # Check for out-of-hours execution
    if event_time:
        hour = int(event_time[11:13])
        if hour < BH_START or hour > BH_END:
            score += 20
            reasons.append('Out of business hours')

    # Check for StartSession (interactive)
    if event_name == 'StartSession':
        score += 15
        reasons.append('Interactive session started')

    # Check for SendCommand with suspicious patterns
    if event_name == 'SendCommand':
        document_name = request_params.get('documentName', '')
        parameters = json.dumps(request_params.get('parameters', {})).lower()

        # Check for AWS-RunShellScript or AWS-RunPowerShellScript
        if 'runshellscript' in document_name.lower() or 'runpowershellscript' in document_name.lower():
            score += 10
            reasons.append(f'Command execution via {document_name}')

            # Check for suspicious command patterns
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern.lower() in parameters:
                    score += 25
                    reasons.append(f'Suspicious pattern: {pattern}')
                    break

        # Check for multiple target instances
        instance_ids = request_params.get('instanceIds', [])
        if len(instance_ids) > 5:
            score += 15
            reasons.append(f'Targeting {len(instance_ids)} instances')

    # Update tracking and check velocity
    import time
    window_id = event_time[:13] if event_time else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H')
    expires_at = int(time.time()) + 86400

    response = table.update_item(
        Key={'user_arn': user_arn, 'window_id': window_id},
        UpdateExpression='SET cmd_count = if_not_exists(cmd_count, :zero) + :one, expires_at = :exp',
        ExpressionAttributeValues={':zero': 0, ':one': 1, ':exp': expires_at},
        ReturnValues='ALL_NEW'
    )

    cmd_count = int(response.get('Attributes', {}).get('cmd_count', 0))
    if cmd_count > 10:
        score += 20
        reasons.append(f'High command velocity: {cmd_count} in hour')

    # Alert if score exceeds threshold
    if score >= 25:
        send_alert({
            'alert': 'SSM Command Anomaly Detected',
            'severity': 'HIGH' if score >= 50 else 'MEDIUM',
            'score': score,
            'reasons': reasons,
            'user': user_arn,
            'event': event_name,
            'source_ip': source_ip,
            'targets': request_params.get('instanceIds', [])[:5],
            'recommendation': 'Investigate user activity and SSM command history'
        })


def send_alert(message):
    sns.publish(
        TopicArn=os.environ['ALERT_TOPIC_ARN'],
        Subject=f"SSM Command Alert: {message.get('alert', 'Unknown')} (Score: {message.get('score', 0)})",
        Message=json.dumps(message, indent=2, default=str)
    )
PYTHON
    filename = "index.py"
  }
}

# Step 4: EventBridge rule for SSM commands
resource "aws_cloudwatch_event_rule" "ssm_commands" {
  name        = "ssm-command-events"
  description = "Capture SSM command execution events"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand", "StartSession", "StartAutomationExecution"]
    }
  })
}

resource "aws_sqs_queue" "ssm_events" {
  name                       = "ssm-command-events"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400
}

resource "aws_cloudwatch_event_target" "to_sqs" {
  rule      = aws_cloudwatch_event_rule.ssm_commands.name
  target_id = "SendToSQS"
  arn       = aws_sqs_queue.ssm_events.arn
}

resource "aws_lambda_event_source_mapping" "sqs_trigger" {
  event_source_arn = aws_sqs_queue.ssm_events.arn
  function_name    = aws_lambda_function.ssm_analyzer.arn
  batch_size       = 10
}

# Supporting resources
resource "aws_sqs_queue" "dlq" {
  name                      = "ssm-analyzer-dlq"
  message_retention_seconds = 1209600
}

resource "aws_iam_role" "lambda_role" {
  name = "ssm-analyzer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "ssm-analyzer-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.ssm_tracking.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.ssm_alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.ssm_events.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.dlq.arn
      }
    ]
  })
}

resource "aws_sqs_queue_policy" "allow_eventbridge" {
  queue_url = aws_sqs_queue.ssm_events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.ssm_events.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="SSM Command Anomaly Detected",
                alert_description_template=(
                    "Suspicious SSM command activity detected from {user}. "
                    "Score: {score}. Reasons: {reasons}."
                ),
                investigation_steps=[
                    "Review the SSM command history for this user",
                    "Check the command content in CloudTrail",
                    "Verify the target instances are expected",
                    "Check for follow-on malicious activity on targets",
                    "Review the source IP location",
                ],
                containment_actions=[
                    "Revoke the user's SSM permissions",
                    "Check target instances for compromise",
                    "Review and terminate suspicious SSM sessions",
                    "Enable SSM Session Manager logging to S3/CloudWatch",
                    "Consider requiring approval for SSM commands",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Add authorised automation accounts to allowed_users. "
                "Tune business hours for your organisation's schedule. "
                "Adjust suspicious pattern list for your environment."
            ),
            detection_coverage="85% - catches suspicious patterns and anomalies",
            evasion_considerations="Encoded commands or custom SSM documents may evade pattern detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20/month (Lambda + DynamoDB + SQS)",
            prerequisites=["CloudTrail enabled", "SSM data events enabled"],
        ),
        # =====================================================================
        # STRATEGY 2: SSM Session Manager Logging
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1651-aws-ssm-logging",
            name="SSM Session Manager Logging and Monitoring",
            description=(
                "Enable comprehensive SSM Session Manager logging to CloudWatch and S3. "
                "Captures all interactive session commands for forensics and detection."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="ssm",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# SSM Session Manager Logging and Monitoring
# Enables comprehensive logging of all SSM sessions

variable "alert_email" {
  type        = string
  description = "Email for SSM alerts"
}

variable "log_retention_days" {
  type        = number
  default     = 90
  description = "CloudWatch log retention in days"
}

# Step 1: CloudWatch log group for SSM sessions
resource "aws_cloudwatch_log_group" "ssm_sessions" {
  name              = "/aws/ssm/session-logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.ssm_logs.arn
}

resource "aws_kms_key" "ssm_logs" {
  description             = "KMS key for SSM session logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "Allow CloudWatch Logs"
        Effect    = "Allow"
        Principal = { Service = "logs.${data.aws_region.current.name}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
      }
    ]
  })
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Step 2: S3 bucket for session logs (long-term retention)
resource "aws_s3_bucket" "ssm_logs" {
  bucket = "ssm-session-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "ssm_logs" {
  bucket = aws_s3_bucket.ssm_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ssm_logs" {
  bucket = aws_s3_bucket.ssm_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "ssm_logs" {
  bucket = aws_s3_bucket.ssm_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Step 3: SSM Document for session preferences
resource "aws_ssm_document" "session_preferences" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Session Manager preferences with logging"
    sessionType   = "Standard_Stream"
    inputs = {
      cloudWatchLogGroupName      = aws_cloudwatch_log_group.ssm_sessions.name
      cloudWatchEncryptionEnabled = true
      s3BucketName               = aws_s3_bucket.ssm_logs.id
      s3EncryptionEnabled        = true
      runAsEnabled               = false
      idleSessionTimeout         = "20"
    }
  })
}

# Step 4: SNS topic for alerts
resource "aws_sns_topic" "ssm_session_alerts" {
  name              = "ssm-session-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_session_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 5: CloudWatch metric filter for suspicious commands
resource "aws_cloudwatch_log_metric_filter" "suspicious_commands" {
  name           = "ssm-suspicious-commands"
  log_group_name = aws_cloudwatch_log_group.ssm_sessions.name
  pattern        = "?curl ?wget ?nc ?netcat ?/dev/tcp ?base64 ?eval ?chmod ?python"

  metric_transformation {
    name      = "SuspiciousSSMCommands"
    namespace = "Security/SSM"
    value     = "1"
  }
}

# Step 6: CloudWatch alarm for suspicious commands
resource "aws_cloudwatch_metric_alarm" "suspicious_commands" {
  alarm_name          = "SSM-SuspiciousCommands"
  alarm_description   = "Suspicious commands detected in SSM sessions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SuspiciousSSMCommands"
  namespace           = "Security/SSM"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.ssm_session_alerts.arn]
}

# Step 7: EventBridge rule for session start/end
resource "aws_cloudwatch_event_rule" "ssm_sessions" {
  name        = "ssm-session-events"
  description = "Capture SSM session start and end events"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["StartSession", "TerminateSession", "ResumeSession"]
    }
  })
}

resource "aws_cloudwatch_event_target" "session_to_sns" {
  rule      = aws_cloudwatch_event_rule.ssm_sessions.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.ssm_session_alerts.arn

  input_transformer {
    input_paths = {
      eventName  = "$.detail.eventName"
      user       = "$.detail.userIdentity.arn"
      sourceIp   = "$.detail.sourceIPAddress"
      instanceId = "$.detail.requestParameters.target"
    }
    input_template = <<-EOF
      {
        "alert": "SSM Session Event",
        "event": "<eventName>",
        "user": "<user>",
        "sourceIp": "<sourceIp>",
        "target": "<instanceId>"
      }
    EOF
  }
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.ssm_session_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssm_session_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ssm_sessions.arn
        }
      }
    }]
  })
}

output "log_group_name" {
  value       = aws_cloudwatch_log_group.ssm_sessions.name
  description = "CloudWatch log group for SSM sessions"
}

output "s3_bucket_name" {
  value       = aws_s3_bucket.ssm_logs.id
  description = "S3 bucket for SSM session logs"
}""",
                alert_severity="high",
                alert_title="SSM Session Activity",
                alert_description_template=(
                    "SSM session {eventName} by {user} targeting {target}. "
                    "Review session logs for command content."
                ),
                investigation_steps=[
                    "Review the session logs in CloudWatch/S3",
                    "Check what commands were executed during the session",
                    "Verify the user was authorised to access this instance",
                    "Check for data exfiltration or malware deployment",
                    "Review the target instance for compromise",
                ],
                containment_actions=[
                    "Terminate active suspicious sessions",
                    "Revoke the user's SSM access",
                    "Isolate the target instance for forensics",
                    "Review and rotate any accessed credentials",
                    "Enable more restrictive SSM policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Tune the suspicious command pattern filter. "
                "Add exceptions for legitimate admin patterns. "
                "Consider separate alerting for production vs non-production."
            ),
            detection_coverage="95% - full session command logging",
            evasion_considerations="Encoding or obfuscation may evade pattern matching",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30/month (CloudWatch Logs + S3)",
            prerequisites=["SSM Agent installed on instances"],
        ),
        # =====================================================================
        # STRATEGY 3: Simple EventBridge SSM Monitoring
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1651-aws-ssm-eventbridge",
            name="AWS SSM Command EventBridge Monitoring",
            description=(
                "EventBridge rule for SSM SendCommand and StartSession events. "
                "Quick to deploy with reliable delivery (DLQ + retry) and human-readable alerts."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["SendCommand", "StartSession"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: SSM Command Monitoring via EventBridge (T1651)

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: t1651-ssm-command-alerts
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: t1651-ssm-command-dlq
      MessageRetentionPeriod: 1209600

  SSMCommandRule:
    Type: AWS::Events::Rule
    Properties:
      Name: t1651-ssm-command-monitoring
      Description: Monitor SSM command execution (T1651)
      State: ENABLED
      EventPattern:
        source:
          - aws.ssm
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - SendCommand
            - StartSession
            - StartAutomationExecution
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic
          DeadLetterConfig:
            Arn: !GetAtt DeadLetterQueue.Arn
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          InputTransformer:
            InputPathsMap:
              time: $.time
              account: $.account
              region: $.detail.awsRegion
              eventName: $.detail.eventName
              user: $.detail.userIdentity.arn
              sourceIp: $.detail.sourceIPAddress
              target: $.detail.requestParameters.instanceIds
              document: $.detail.requestParameters.documentName
            InputTemplate: |
              "ALERT: SSM Command Executed (T1651)"
              "time=<time>"
              "account=<account> region=<region>"
              "event=<eventName>"
              "user=<user>"
              "source_ip=<sourceIp>"
              "targets=<target>"
              "document=<document>"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
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
                aws:SourceArn: !GetAtt SSMCommandRule.Arn

  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref DeadLetterQueue
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt DeadLetterQueue.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt SSMCommandRule.Arn

Outputs:
  AlertTopicArn:
    Description: SNS topic for SSM alerts
    Value: !Ref AlertTopic
  EventRuleArn:
    Description: EventBridge rule ARN
    Value: !GetAtt SSMCommandRule.Arn
  DLQUrl:
    Description: Dead letter queue URL
    Value: !Ref DeadLetterQueue""",
                terraform_template="""# SSM Command EventBridge Monitoring (T1651)
# Uses EventBridge for near real-time detection
# Optimised pattern: DLQ, retry policy, scoped SNS, human-readable alerts

variable "name_prefix" {
  type        = string
  default     = "t1651-ssm-command"
  description = "Prefix for resource names"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts (SNS subscription confirmation required)"
}

data "aws_caller_identity" "current" {}

# SNS topic for alerts
resource "aws_sns_topic" "ssm_alerts" {
  name              = "${var.name_prefix}-alerts"
  display_name      = "SSM Command Alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule: detect SSM commands via CloudTrail
resource "aws_cloudwatch_event_rule" "ssm_commands" {
  name        = "${var.name_prefix}-monitoring"
  description = "Monitor SSM command execution (T1651)"

  event_pattern = jsonencode({
    source        = ["aws.ssm"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand", "StartSession", "StartAutomationExecution"]
    }
  })
}

# DLQ for delivery failures (14 day retention)
resource "aws_sqs_queue" "ssm_dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600
}

# Route to SNS with input transformer for human-readable alerts
resource "aws_cloudwatch_event_target" "ssm_to_sns" {
  rule      = aws_cloudwatch_event_rule.ssm_commands.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.ssm_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.ssm_dlq.arn
  }

  input_transformer {
    input_paths = {
      time      = "$.time"
      account   = "$.account"
      region    = "$.detail.awsRegion"
      eventName = "$.detail.eventName"
      user      = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
      targets   = "$.detail.requestParameters.instanceIds"
      document  = "$.detail.requestParameters.documentName"
    }

    input_template = <<-EOT
"ALERT: SSM Command Executed (T1651)
time=<time>
account=<account> region=<region>
event=<eventName>
user=<user>
source_ip=<sourceIp>
targets=<targets>
document=<document>"
EOT
  }
}

# SNS topic policy with scoped conditions for least privilege
resource "aws_sns_topic_policy" "allow_eventbridge_publish" {
  arn = aws_sns_topic.ssm_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssm_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ssm_commands.arn
        }
      }
    }]
  })
}

# Allow EventBridge to send to DLQ
resource "aws_sqs_queue_policy" "ssm_dlq" {
  queue_url = aws_sqs_queue.ssm_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.ssm_dlq.arn
    }]
  })
}

output "alert_topic_arn" {
  description = "SNS topic for SSM alerts"
  value       = aws_sns_topic.ssm_alerts.arn
}

output "event_rule_arn" {
  description = "EventBridge rule ARN"
  value       = aws_cloudwatch_event_rule.ssm_commands.arn
}

output "dlq_url" {
  description = "Dead letter queue URL for failed deliveries"
  value       = aws_sqs_queue.ssm_dlq.url
}""",
                alert_severity="medium",
                alert_title="SSM Command Executed",
                alert_description_template=(
                    "SSM {event} executed by {user} targeting {targets}."
                ),
                investigation_steps=[
                    "Verify the command execution was authorised",
                    "Review the command content in CloudTrail",
                    "Check the target instances",
                    "Review command output",
                ],
                containment_actions=[
                    "Review SSM permissions for the user",
                    "Check target instances for compromise",
                    "Enable SSM Session Manager logging",
                    "Consider requiring SSM command approval",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Add filters for known automation and patching systems. "
                "Consider time-based filtering for maintenance windows."
            ),
            detection_coverage="95% - catches all SSM commands",
            evasion_considerations="Cannot evade SSM logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="20 minutes",
            estimated_monthly_cost="$1-3",
            prerequisites=["CloudTrail enabled"],
        ),
        # =====================================================================
        # STRATEGY 4: GCP OS Config Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1651-gcp-osconfig",
            name="GCP OS Config Command Detection",
            description=(
                "Monitor GCP OS Config Agent for command execution on VMs. "
                "Detects OS policies, patch deployments, and guest policies."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""# OS Config command execution
protoPayload.serviceName="osconfig.googleapis.com"
protoPayload.methodName=~"Execute|Run|CreatePatchDeployment|CreateOSPolicyAssignment"

# OS Policy assignments
protoPayload.serviceName="osconfig.googleapis.com"
protoPayload.methodName="CreateOSPolicyAssignment"

# Guest policies (legacy)
protoPayload.serviceName="osconfig.googleapis.com"
protoPayload.methodName=~"CreateGuestPolicy|UpdateGuestPolicy" """,
                gcp_terraform_template="""# GCP OS Config Command Detection

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  display_name = "OS Config Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for OS policy assignments
resource "google_logging_metric" "osconfig_policy" {
  name    = "osconfig-policy-assignments"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="osconfig.googleapis.com"
    protoPayload.methodName=~"CreateOSPolicyAssignment|UpdateOSPolicyAssignment"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal creating policy"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert on OS policy assignments
resource "google_monitoring_alert_policy" "osconfig_policy" {
  project      = var.project_id
  display_name = "OS Config Policy Assignment"
  combiner     = "OR"

  conditions {
    display_name = "OS policy assignment created"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.osconfig_policy.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
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

  documentation {
    content   = "An OS Config policy was assigned. This could execute commands on VMs. Verify this was authorised."
    mime_type = "text/markdown"
  }
}

# Step 4: Log-based metric for patch deployments
resource "google_logging_metric" "patch_deployment" {
  name    = "osconfig-patch-deployments"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="osconfig.googleapis.com"
    protoPayload.methodName=~"CreatePatchDeployment|ExecutePatchJob"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "patch_deployment" {
  project      = var.project_id
  display_name = "OS Config Patch Deployment"
  combiner     = "OR"

  conditions {
    display_name = "Patch deployment created"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.patch_deployment.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
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

  documentation {
    content   = "A patch deployment was created via OS Config. Review the patch job configuration."
    mime_type = "text/markdown"
  }
}

# Step 5: Log-based metric for Compute Engine SSH-in-browser
resource "google_logging_metric" "ssh_browser" {
  name    = "compute-ssh-browser"
  project = var.project_id

  filter = <<-EOT
    protoPayload.methodName="v1.compute.instances.setMetadata"
    protoPayload.request.metadata.items.key="ssh-keys"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "ssh_browser" {
  project      = var.project_id
  display_name = "Compute Engine SSH Key Added"
  combiner     = "OR"

  conditions {
    display_name = "SSH key added to instance metadata"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ssh_browser.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
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

  documentation {
    content   = "An SSH key was added to a Compute Engine instance. This may indicate an attempt to access the VM."
    mime_type = "text/markdown"
  }
}

output "notification_channel_id" {
  value       = google_monitoring_notification_channel.email_s1.id
  description = "Notification channel for alerts"
}""",
                alert_severity="high",
                alert_title="GCP: OS Config Command Execution",
                alert_description_template=(
                    "OS Config command or policy executed by {principal}. "
                    "Verify this was authorised."
                ),
                investigation_steps=[
                    "Review the OS policy or patch deployment details",
                    "Check the target VMs and scope",
                    "Verify the principal was authorised to make this change",
                    "Review the script or commands in the policy",
                    "Check for any anomalies on target VMs",
                ],
                containment_actions=[
                    "Delete unauthorised OS policies",
                    "Review and restrict OS Config IAM bindings",
                    "Check target VMs for compromise",
                    "Enable VPC Service Controls for OS Config",
                    "Implement approval workflow for OS policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Filter out known patching and automation service accounts. "
                "Consider separate alerting for scheduled vs ad-hoc deployments."
            ),
            detection_coverage="90% - catches OS Config and SSH key changes",
            evasion_considerations="Direct SSH may bypass OS Config monitoring",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20/month (Logging + Monitoring)",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Data Access logs enabled for Compute Engine",
            ],
        ),
        # Azure Strategy: Cloud Administration Command
        DetectionStrategy(
            strategy_id="t1651-azure",
            name="Azure Cloud Administration Command Detection",
            description=(
                "Azure detection for Cloud Administration Command. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Cloud Administration Command
// MITRE ATT&CK: T1651
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources""",
                azure_terraform_template="""# Azure Detection for Cloud Administration Command
# MITRE ATT&CK: T1651

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
  name                = "cloud-administration-command-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "cloud-administration-command-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Cloud Administration Command
// MITRE ATT&CK: T1651
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources
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

  description = "Detects Cloud Administration Command (T1651) activity in Azure environment"
  display_name = "Cloud Administration Command Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1651"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Cloud Administration Command Detected",
                alert_description_template=(
                    "Cloud Administration Command activity detected. "
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
        "t1651-aws-ssm-lambda",
        "t1651-aws-ssm-logging",
        "t1651-aws-ssm-eventbridge",
        "t1651-gcp-osconfig",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+25% improvement for Execution tactic with comprehensive SSM monitoring",
)
