"""
T1059.009 - Command and Scripting Interpreter: Cloud API

Adversaries use cloud APIs to execute commands and manage resources.
Used by APT29, Storm-0501, TeamTNT.
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
    technique_id="T1059.009",
    technique_name="Command and Scripting Interpreter: Cloud API",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1059/009/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit cloud APIs to execute commands across cloud environments. "
            "Using CLIs, cloud shells, PowerShell modules, and SDKs, attackers can control "
            "compute, storage, IAM, and security policies."
        ),
        attacker_goal="Execute commands via cloud APIs using compromised credentials",
        why_technique=[
            "Broad access to cloud resources",
            "Programmatic control over infrastructure",
            "Can modify security settings",
            "Enables automated attacks",
            "Hard to distinguish from legitimate admin",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Cloud APIs provide extensive control over infrastructure. "
            "Compromised API access can lead to full environment takeover."
        ),
        business_impact=[
            "Infrastructure modification",
            "Data exfiltration",
            "Resource hijacking",
            "Security control bypass",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1530", "T1496.001", "T1562.008"],
        often_follows=["T1078.004", "T1552.005"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: GuardDuty ML-Based Anomaly Detection (Recommended First)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1059009-aws-guardduty",
            name="AWS GuardDuty API Reconnaissance Detection",
            description=(
                "Leverage GuardDuty's ML-based detection for unusual API activity patterns. "
                "GuardDuty analyses CloudTrail events to detect reconnaissance and discovery "
                "behaviour indicative of compromised credentials exploring your environment."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  GuardDuty API Reconnaissance Detection
  Detects: Discovery:IAMUser/AnomalousBehavior, Recon:IAMUser/MaliciousIPCaller
  See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS Topic for GuardDuty API reconnaissance findings
  ApiReconAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: guardduty-api-recon-alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref ApiReconAlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # EventBridge rule for Discovery and Reconnaissance findings
  ApiReconEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-api-reconnaissance
      Description: Detect API reconnaissance patterns via GuardDuty
      State: ENABLED
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Discovery:IAMUser/"
            - prefix: "Recon:IAMUser/"
            - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
            - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS
      Targets:
        - Id: SendToSNS
          Arn: !Ref ApiReconAlertTopic
          InputTransformer:
            InputPathsMap:
              findingType: $.detail.type
              severity: $.detail.severity
              principal: $.detail.resource.accessKeyDetails.userName
              sourceIp: $.detail.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4
              apiName: $.detail.service.action.awsApiCallAction.api
              accountId: $.account
            InputTemplate: |
              "GuardDuty API Reconnaissance Alert"
              "Type: <findingType>"
              "Severity: <severity>"
              "Principal: <principal>"
              "Source IP: <sourceIp>"
              "API: <apiName>"
              "Account: <accountId>"

  # Enable GuardDuty if not already enabled
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      DataSources:
        S3Logs:
          Enable: true

Outputs:
  AlertTopicArn:
    Description: SNS topic for API reconnaissance alerts
    Value: !Ref ApiReconAlertTopic""",
                terraform_template="""# AWS GuardDuty API Reconnaissance Detection

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref ApiReconAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref ApiReconAlertTopic
# Detects: Discovery:IAMUser/AnomalousBehavior, Recon:IAMUser/MaliciousIPCaller
# See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create encrypted SNS topic for alerts
resource "aws_sns_topic" "api_recon_alerts" {
  name              = "guardduty-api-recon-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.api_recon_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Enable GuardDuty detector
resource "aws_guardduty_detector" "main" {
  enable = true
  datasources {
    s3_logs {
      enable = true
    }
  }
}

# Step 3: Route Discovery and Recon findings to SNS
resource "aws_cloudwatch_event_rule" "api_recon" {
  name        = "guardduty-api-reconnaissance"
  description = "Detect API reconnaissance patterns via GuardDuty"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Discovery:IAMUser/" },
        { prefix = "Recon:IAMUser/" },
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS"
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "api-recon-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.api_recon.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.api_recon_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      findingType = "$.detail.type"
      severity    = "$.detail.severity"
      principal   = "$.detail.resource.accessKeyDetails.userName"
      sourceIp    = "$.detail.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4"
      apiName     = "$.detail.service.action.awsApiCallAction.api"
      accountId   = "$.account"
    }
    input_template = <<-EOF
      "GuardDuty API Reconnaissance Alert"
      "Type: <findingType>"
      "Severity: <severity>"
      "Principal: <principal>"
      "Source IP: <sourceIp>"
      "API: <apiName>"
      "Account: <accountId>"
    EOF
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.api_recon_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.api_recon_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.api_recon.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: API Reconnaissance Activity Detected",
                alert_description_template=(
                    "GuardDuty has detected API reconnaissance activity: {type}. "
                    "Principal {principal} made unusual discovery/enumeration API calls from {sourceIp}."
                ),
                investigation_steps=[
                    "Review the specific GuardDuty finding in the console for full context",
                    "Identify all APIs called by this principal in the time window",
                    "Check if the source IP is associated with legitimate access",
                    "Review CloudTrail for the complete session activity",
                    "Determine if this is a compromised credential or insider threat",
                ],
                containment_actions=[
                    "Immediately rotate the affected access keys or credentials",
                    "Add the source IP to a deny list in AWS WAF or security groups",
                    "Apply a restrictive inline policy to the IAM user/role",
                    "Enable MFA if not already required",
                    "Consider temporarily disabling the principal until investigation completes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty's ML learns baseline behaviour over 7-14 days. "
                "Use trusted IP lists for known automation servers. "
                "Archive findings for expected reconnaissance tools (security scanners, inventory tools)."
            ),
            detection_coverage="85% - GuardDuty ML detects anomalous API patterns across all services",
            evasion_considerations=(
                "Very slow enumeration may blend into baseline. "
                "Using compromised credentials from expected source IPs is harder to detect."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "$4-5 per million CloudTrail events analysed. "
                "Typical small account: $10-30/month. "
                "See: https://aws.amazon.com/guardduty/pricing/"
            ),
            prerequisites=["AWS account with CloudTrail enabled (default)"],
        ),
        # =====================================================================
        # STRATEGY 2: Lambda-Based API Anomaly Scoring
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1059009-aws-lambda-scoring",
            name="Lambda-Based API Reconnaissance Scoring",
            description=(
                "Custom Lambda function that scores API call patterns for reconnaissance indicators. "
                "Tracks per-principal API diversity, velocity, and sensitive operation sequences. "
                "Uses DynamoDB to maintain behavioural baselines per principal."
            ),
            detection_type=DetectionType.CUSTOM_LAMBDA,
            aws_service="lambda",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# Lambda-Based API Reconnaissance Scorer
# Detects enumeration via API call pattern analysis
# Scoring: unique_apis * 2 + velocity_score + sensitive_api_score

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
  description = "Email for security alerts"
}

variable "threshold_score" {
  type        = number
  default     = 50
  description = "Alert threshold score (default 50)"
}

variable "allowed_principals" {
  type        = list(string)
  default     = []
  description = "Principal ARNs to exclude from alerting"
}

# Step 1: DynamoDB table for per-principal API tracking
resource "aws_dynamodb_table" "api_baseline" {
  name         = "api-recon-baseline"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_arn"
  range_key    = "window_id"

  attribute {
    name = "principal_arn"
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

  point_in_time_recovery {
    enabled = true
  }
}

# Step 2: Lambda function for scoring
resource "aws_lambda_function" "api_scorer" {
  function_name = "api-recon-scorer"
  runtime       = "python3.11"
  handler       = "index.handler"
  role          = aws_iam_role.lambda_role.arn
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      BASELINE_TABLE     = aws_dynamodb_table.api_baseline.name
      ALERT_TOPIC_ARN    = aws_sns_topic.alerts.arn
      THRESHOLD_SCORE    = tostring(var.threshold_score)
      ALLOWED_PRINCIPALS = jsonencode(var.allowed_principals)
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/api_scorer.zip"

  source {
    content  = <<-PYTHON
import json
import os
import boto3
from datetime import datetime, timezone
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')
baseline_table = dynamodb.Table(os.environ['BASELINE_TABLE'])
THRESHOLD = int(os.environ.get('THRESHOLD_SCORE', '50'))
ALLOWED = json.loads(os.environ.get('ALLOWED_PRINCIPALS', '[]'))

# High-value reconnaissance APIs
SENSITIVE_APIS = {
    'ListUsers', 'ListRoles', 'ListPolicies', 'GetUser', 'GetRole',
    'ListAccessKeys', 'ListAttachedUserPolicies', 'ListAttachedRolePolicies',
    'ListBuckets', 'ListSecrets', 'DescribeInstances', 'DescribeSecurityGroups',
    'DescribeVpcs', 'DescribeSubnets', 'GetCallerIdentity', 'ListKeys',
    'DescribeDBInstances', 'ListFunctions', 'ListTables', 'DescribeClusters'
}

# Discovery/enumeration prefixes
ENUM_PREFIXES = ('List', 'Describe', 'Get', 'Search', 'Scan')


def handler(event, context):
    for record in event.get('Records', []):
        try:
            detail = json.loads(record['body'])
            process_api_call(detail)
        except Exception as e:
            print(f"Error processing record: {e}")
            raise


def process_api_call(detail):
    principal_arn = detail.get('userIdentity', {}).get('arn', 'unknown')
    event_name = detail.get('eventName', '')
    source_ip = detail.get('sourceIPAddress', '')
    user_agent = detail.get('userAgent', '')
    event_time = detail.get('eventTime', '')

    # Skip allowed principals
    if principal_arn in ALLOWED:
        return

    # Get 15-minute window ID
    window_id = event_time[:15] if event_time else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M')

    # Update baseline and get current window stats
    stats = update_baseline(principal_arn, window_id, event_name, source_ip, user_agent)

    # Calculate risk score
    score = calculate_score(stats, event_name)

    if score >= THRESHOLD:
        send_alert(principal_arn, stats, score, source_ip, user_agent)


def update_baseline(principal_arn, window_id, event_name, source_ip, user_agent):
    # Update DynamoDB with current API call and return window statistics.
    import time
    expires_at = int(time.time()) + 86400 * 7  # 7 day TTL

    response = baseline_table.update_item(
        Key={'principal_arn': principal_arn, 'window_id': window_id},
        UpdateExpression='''
            SET api_calls = if_not_exists(api_calls, :zero) + :one,
                unique_apis = if_not_exists(unique_apis, :empty_set),
                source_ips = if_not_exists(source_ips, :empty_set),
                user_agents = if_not_exists(user_agents, :empty_set),
                expires_at = :expires
            ADD unique_apis :api_set,
                source_ips :ip_set,
                user_agents :ua_set
        ''',
        ExpressionAttributeValues={
            ':zero': 0,
            ':one': 1,
            ':empty_set': set(),
            ':api_set': {event_name},
            ':ip_set': {source_ip} if source_ip else set(),
            ':ua_set': {user_agent[:100]} if user_agent else set(),
            ':expires': expires_at
        },
        ReturnValues='ALL_NEW'
    )

    item = response.get('Attributes', {})
    return {
        'api_calls': int(item.get('api_calls', 0)),
        'unique_apis': len(item.get('unique_apis', set())),
        'apis': list(item.get('unique_apis', set())),
        'source_ips': len(item.get('source_ips', set())),
        'user_agents': len(item.get('user_agents', set()))
    }


def calculate_score(stats, current_api):
    # Calculate reconnaissance risk score.
    score = 0

    # Unique API diversity (major indicator)
    unique_apis = stats['unique_apis']
    if unique_apis > 20:
        score += 30
    elif unique_apis > 10:
        score += 20
    elif unique_apis > 5:
        score += 10

    # API call velocity
    api_calls = stats['api_calls']
    if api_calls > 100:
        score += 20
    elif api_calls > 50:
        score += 10

    # Sensitive API access
    sensitive_count = sum(1 for api in stats.get('apis', []) if api in SENSITIVE_APIS)
    score += sensitive_count * 3

    # Enumeration pattern (List/Describe heavy)
    enum_count = sum(1 for api in stats.get('apis', []) if api.startswith(ENUM_PREFIXES))
    if enum_count > stats['unique_apis'] * 0.7:
        score += 15

    # Multiple source IPs (lateral movement indicator)
    if stats['source_ips'] > 2:
        score += 10

    # Multiple user agents (different tools)
    if stats['user_agents'] > 2:
        score += 5

    return score


def send_alert(principal_arn, stats, score, source_ip, user_agent):
    # Send high-scoring reconnaissance alert.
    message = {
        'alert': 'API Reconnaissance Detected',
        'principal': principal_arn,
        'score': score,
        'threshold': THRESHOLD,
        'source_ip': source_ip,
        'user_agent': user_agent[:100],
        'stats': {
            'api_calls': stats['api_calls'],
            'unique_apis': stats['unique_apis'],
            'sample_apis': stats.get('apis', [])[:10]
        },
        'recommendation': 'Investigate principal activity and consider credential rotation'
    }

    sns.publish(
        TopicArn=os.environ['ALERT_TOPIC_ARN'],
        Subject=f'API Recon Alert: Score {score} from {principal_arn.split("/")[-1]}',
        Message=json.dumps(message, indent=2, default=str)
    )
PYTHON
    filename = "index.py"
  }
}

# Step 3: EventBridge rule to capture CloudTrail API calls
resource "aws_cloudwatch_event_rule" "api_calls" {
  name        = "capture-api-calls-for-scoring"
  description = "Route CloudTrail API calls to Lambda scorer"

  event_pattern = jsonencode({
    source      = ["aws.iam", "aws.s3", "aws.ec2", "aws.lambda", "aws.rds",
                   "aws.secretsmanager", "aws.kms", "aws.dynamodb", "aws.ecs"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        { prefix = "List" },
        { prefix = "Describe" },
        { prefix = "Get" }
      ]
    }
  })
}

resource "aws_sqs_queue" "api_events" {
  name                       = "api-recon-events"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400
}

resource "aws_cloudwatch_event_target" "to_sqs" {
  rule      = aws_cloudwatch_event_rule.api_calls.name
  target_id = "SendToSQS"
  arn       = aws_sqs_queue.api_events.arn
}

resource "aws_lambda_event_source_mapping" "sqs_trigger" {
  event_source_arn = aws_sqs_queue.api_events.arn
  function_name    = aws_lambda_function.api_scorer.arn
  batch_size       = 10
}

# Supporting resources
resource "aws_sns_topic" "alerts" {
  name              = "api-recon-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sqs_queue" "dlq" {
  name                      = "api-recon-scorer-dlq"
  message_retention_seconds = 1209600
}

resource "aws_iam_role" "lambda_role" {
  name = "api-recon-scorer-role"

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
  name = "api-recon-scorer-policy"
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
        Resource = aws_dynamodb_table.api_baseline.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.api_events.arn
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
  queue_url = aws_sqs_queue.api_events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.api_events.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="API Reconnaissance Pattern Detected",
                alert_description_template=(
                    "Principal {principal} has a reconnaissance risk score of {score}. "
                    "Observed {unique_apis} unique APIs across {api_calls} calls in the time window."
                ),
                investigation_steps=[
                    "Review the specific APIs called by this principal",
                    "Check if the activity matches expected automation or admin work",
                    "Identify the source IP and user agent for attribution",
                    "Look for follow-on actions after the reconnaissance phase",
                    "Correlate with any authentication anomalies",
                ],
                containment_actions=[
                    "Rotate the affected credentials immediately",
                    "Apply a deny-all inline policy to contain the principal",
                    "Block the source IP at the network level",
                    "Review and potentially roll back any changes made",
                    "Preserve CloudTrail logs for forensics",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Tune threshold_score based on your environment (start at 50). "
                "Add automation service accounts to allowed_principals. "
                "Consider increasing threshold for accounts with heavy admin activity."
            ),
            detection_coverage="75% - catches structured enumeration patterns",
            evasion_considerations=(
                "Very slow enumeration across multiple sessions may evade. "
                "Using legitimate admin user agents helps blend in."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost=(
                "Lambda: $0.20 per million requests. "
                "DynamoDB: ~$1-5/month for typical usage. "
                "SQS: $0.40 per million requests. "
                "Total: $5-20/month for typical account."
            ),
            prerequisites=[
                "CloudTrail enabled (for EventBridge)",
                "IAM permissions to create Lambda, DynamoDB, SQS, SNS",
            ],
        ),
        # =====================================================================
        # STRATEGY 3: CloudShell Session Monitoring
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1059009-aws-cloudshell",
            name="AWS CloudShell Session Monitoring",
            description=(
                "Monitor CloudShell usage patterns for potential abuse. CloudShell provides "
                "a browser-based shell with pre-configured AWS CLI access. Adversaries may "
                "use it to avoid logging from their own infrastructure."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="cloudshell",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# AWS CloudShell Session Monitoring
# Detects CloudShell usage and correlates with sensitive API calls
# CloudShell events appear in CloudTrail as cloudshell.amazonaws.com

variable "alert_email" {
  type        = string
  description = "Email for CloudShell alerts"
}

variable "allowed_users" {
  type        = list(string)
  default     = []
  description = "IAM usernames allowed to use CloudShell"
}

# Step 1: Encrypted SNS topic for alerts
resource "aws_sns_topic" "cloudshell_alerts" {
  name              = "cloudshell-security-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cloudshell_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for CloudShell environment creation
resource "aws_cloudwatch_event_rule" "cloudshell_create" {
  name        = "cloudshell-environment-created"
  description = "Detect when CloudShell environments are created"

  event_pattern = jsonencode({
    source      = ["aws.cloudshell"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudshell.amazonaws.com"]
      eventName   = ["CreateEnvironment", "StartEnvironment"]
    }
  })
}

resource "aws_cloudwatch_event_target" "cloudshell_to_sns" {
  rule      = aws_cloudwatch_event_rule.cloudshell_create.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cloudshell_alerts.arn

  input_transformer {
    input_paths = {
      user      = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
      eventTime = "$.detail.eventTime"
      eventName = "$.detail.eventName"
      region    = "$.detail.awsRegion"
    }
    input_template = <<-EOF
      {
        "alert": "CloudShell Session Started",
        "user": "<user>",
        "sourceIp": "<sourceIp>",
        "region": "<region>",
        "eventTime": "<eventTime>",
        "action": "<eventName>",
        "recommendation": "Review user's CloudShell activity for reconnaissance or data access"
      }
    EOF
  }
}

# Step 3: Monitor sensitive APIs called from CloudShell
resource "aws_cloudwatch_event_rule" "cloudshell_sensitive_apis" {
  name        = "cloudshell-sensitive-api-calls"
  description = "Detect sensitive APIs called via CloudShell"

  event_pattern = jsonencode({
    source      = ["aws.iam", "aws.s3", "aws.secretsmanager", "aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userAgent = [{ prefix = "CloudShell" }]
      eventName = [
        "CreateAccessKey", "CreateUser", "CreateRole",
        "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy",
        "GetSecretValue", "GetObject", "CreateGrant", "Decrypt"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sensitive_to_sns" {
  rule      = aws_cloudwatch_event_rule.cloudshell_sensitive_apis.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cloudshell_alerts.arn

  input_transformer {
    input_paths = {
      user      = "$.detail.userIdentity.arn"
      eventName = "$.detail.eventName"
      sourceIp  = "$.detail.sourceIPAddress"
      resource  = "$.detail.requestParameters"
    }
    input_template = <<-EOF
      {
        "alert": "SENSITIVE API via CloudShell",
        "severity": "HIGH",
        "user": "<user>",
        "api": "<eventName>",
        "sourceIp": "<sourceIp>",
        "requestParams": "<resource>",
        "recommendation": "Immediately investigate this activity"
      }
    EOF
  }
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.cloudshell_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.cloudshell_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = [
            aws_cloudwatch_event_rule.cloudshell_create.arn,
            aws_cloudwatch_event_rule.cloudshell_sensitive_apis.arn
          ]
        }
      }
    }]
  })
}

output "alert_topic_arn" {
  value       = aws_sns_topic.cloudshell_alerts.arn
  description = "SNS topic for CloudShell alerts"
}""",
                alert_severity="medium",
                alert_title="CloudShell Session Activity Detected",
                alert_description_template=(
                    "CloudShell session started by {user} from {sourceIp}. "
                    "Monitor for reconnaissance or sensitive data access."
                ),
                investigation_steps=[
                    "Verify the user is authorised to use CloudShell",
                    "Review all API calls made during the CloudShell session",
                    "Check for data access (S3 GetObject, Secrets GetSecretValue)",
                    "Look for persistence attempts (IAM CreateAccessKey, CreateUser)",
                    "Correlate with authentication events for the same user",
                ],
                containment_actions=[
                    "Disable CloudShell access via SCP if organisation-wide abuse",
                    "Rotate any credentials accessed during the session",
                    "Review and revert any IAM changes made",
                    "Consider requiring MFA for CloudShell access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "CloudShell is legitimately used by developers and admins. "
                "Focus alerting on sensitive API patterns rather than all CloudShell use. "
                "Maintain an allowed_users list for expected CloudShell users."
            ),
            detection_coverage="80% - catches CloudShell-based attacks",
            evasion_considerations="Attacker could use regular CLI instead of CloudShell to avoid this detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10/month (EventBridge + SNS)",
            prerequisites=["CloudTrail enabled for data events"],
        ),
        # =====================================================================
        # STRATEGY 4: GCP Cloud Shell and API Anomaly Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1059009-gcp-cloudshell",
            name="GCP Cloud Shell and API Anomaly Detection",
            description=(
                "Monitor GCP Cloud Shell usage and API call patterns for reconnaissance. "
                "Cloud Shell provides a browser-based terminal with gcloud CLI pre-configured. "
                "Uses Cloud Audit Logs to detect unusual activity."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""# Cloud Shell session monitoring
resource.type="cloudshell.googleapis.com"
protoPayload.methodName=~"CreateEnvironment|StartEnvironment"

# API enumeration detection
protoPayload.methodName=~"(list|get|describe)"
protoPayload.authenticationInfo.principalEmail:*
severity>=INFO""",
                gcp_terraform_template="""# GCP Cloud Shell and API Anomaly Detection
# Monitors Cloud Shell usage and API enumeration patterns

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
  display_name = "Security Alerts - API Anomaly"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for Cloud Shell usage
resource "google_logging_metric" "cloudshell_usage" {
  name    = "cloudshell-session-starts"
  project = var.project_id

  filter = <<-EOT
    resource.type="cloudshell.googleapis.com"
    protoPayload.methodName=~"CreateEnvironment|StartEnvironment"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "User who started Cloud Shell"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert on Cloud Shell usage
resource "google_monitoring_alert_policy" "cloudshell_alert" {
  project      = var.project_id
  display_name = "Cloud Shell Session Started"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Shell session detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cloudshell_usage.name}\" resource.type=\"global\""
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
    content   = "Cloud Shell session started. Review user activity for reconnaissance."
    mime_type = "text/markdown"
  }
}

# Step 4: Log-based metric for API enumeration
resource "google_logging_metric" "api_enumeration" {
  name    = "api-enumeration-calls"
  project = var.project_id

  filter = <<-EOT
    protoPayload.methodName=~"list|List|get|Get|describe|Describe"
    protoPayload.authenticationInfo.principalEmail:*
    severity>=INFO
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "User making API calls"
    }
    labels {
      key         = "method"
      value_type  = "STRING"
      description = "API method called"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "method"    = "EXTRACT(protoPayload.methodName)"
  }
}

# Step 5: Alert on high API enumeration volume
resource "google_monitoring_alert_policy" "api_enum_alert" {
  project      = var.project_id
  display_name = "API Enumeration Pattern Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume of List/Get/Describe APIs"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.api_enumeration.name}\" resource.type=\"global\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 200

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_COUNT"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.principal"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "3600s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "High volume of enumeration API calls detected. Investigate for potential reconnaissance."
    mime_type = "text/markdown"
  }
}

# Step 6: Log-based metric for sensitive API access
resource "google_logging_metric" "sensitive_api_calls" {
  name    = "sensitive-api-calls"
  project = var.project_id

  filter = <<-EOT
    protoPayload.methodName=~"CreateServiceAccountKey|SetIamPolicy|CreateRole|accessSecrets"
    protoPayload.authenticationInfo.principalEmail:*
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "sensitive_api_alert" {
  project      = var.project_id
  display_name = "Sensitive GCP API Call"
  combiner     = "OR"

  conditions {
    display_name = "Sensitive API called"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sensitive_api_calls.name}\" resource.type=\"global\""
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
    content   = "Sensitive API called. Immediately investigate for potential compromise."
    mime_type = "text/markdown"
  }
}

output "notification_channel_id" {
  value       = google_monitoring_notification_channel.email_s1.id
  description = "Notification channel for alerts"
}""",
                alert_severity="high",
                alert_title="GCP API Reconnaissance or Cloud Shell Activity Detected",
                alert_description_template=(
                    "Unusual API activity detected from {principal}. "
                    "Review for reconnaissance or privilege escalation attempts."
                ),
                investigation_steps=[
                    "Review the principal's recent API calls in Cloud Audit Logs",
                    "Check if Cloud Shell was used (may indicate interactive session)",
                    "Look for sensitive API calls (CreateServiceAccountKey, SetIamPolicy)",
                    "Verify the activity matches expected behaviour for this principal",
                    "Check for any resources created or modified",
                ],
                containment_actions=[
                    "Revoke the service account key if compromised",
                    "Remove IAM bindings for the principal",
                    "Apply VPC Service Controls to limit access",
                    "Enable additional audit logging for the affected resources",
                    "Consider disabling the service account temporarily",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Tune enumeration threshold based on your environment's normal activity. "
                "Exclude known automation service accounts from alerting. "
                "Consider separate thresholds for human users vs service accounts."
            ),
            detection_coverage="70% - catches enumeration and Cloud Shell usage",
            evasion_considerations="Slow enumeration may stay below thresholds. Service account key abuse from expected locations.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost=(
                "Cloud Logging: Free tier covers 50GB/month. "
                "Monitoring: Free for first 100 alert policies. "
                "Typical cost: $10-30/month."
            ),
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Admin Activity logs enabled (on by default)",
                "Data Access logs enabled for sensitive services",
            ],
        ),
        # =====================================================================
        # STRATEGY 5: CloudWatch Logs Insights Query (Legacy/Simple)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1059009-aws-cli",
            name="AWS CLI/SDK Anomaly Detection (CloudWatch Query)",
            description="Detect unusual AWS CLI or SDK usage patterns via CloudWatch Logs Insights.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, userAgent, eventName, sourceIPAddress
| filter userAgent like /aws-cli|boto|sdk/
| stats count(*) as api_calls, count_distinct(eventName) as unique_apis by userIdentity.arn, userAgent, bin(1h)
| filter api_calls > 100 or unique_apis > 20
| sort api_calls desc""",
                terraform_template="""# Detect unusual CLI/SDK usage via CloudWatch metric filters
# Simple approach for environments without GuardDuty

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "cli_alerts" {
  name              = "cli-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cli_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for CLI/SDK usage
resource "aws_cloudwatch_log_metric_filter" "cli_usage" {
  name           = "cli-sdk-usage"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.userAgent = \"*aws-cli*\" || $.userAgent = \"*boto*\" || $.userAgent = \"*sdk*\" }"

  metric_transformation {
    name      = "CLIUsageCount"
    namespace = "Security/APIMonitoring"
    value     = "1"
    dimensions = {
      UserARN = "$.userIdentity.arn"
    }
  }
}

# Step 3: Alarm for high CLI usage
resource "aws_cloudwatch_metric_alarm" "high_cli_usage" {
  alarm_name          = "HighCLISDKUsage"
  alarm_description   = "High volume of CLI/SDK API calls detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CLIUsageCount"
  namespace           = "Security/APIMonitoring"
  period              = 300
  statistic           = "Sum"
  threshold           = 500
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.cli_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="medium",
                alert_title="High CLI/SDK API Usage",
                alert_description_template="Unusual volume of CLI/SDK API calls from {userIdentity.arn}.",
                investigation_steps=[
                    "Review API calls made by the principal",
                    "Check source IP location",
                    "Verify user identity is legitimate",
                    "Check for enumeration patterns",
                ],
                containment_actions=[
                    "Rotate affected credentials",
                    "Review IAM permissions",
                    "Block suspicious IPs",
                    "Enable MFA enforcement",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal CLI usage for automation and adjust threshold",
            detection_coverage="60% - catches high-volume abuse only",
            evasion_considerations="Low and slow attacks may evade threshold-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15/month (CloudWatch Logs + Alarms)",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
    ],
    recommended_order=[
        "t1059009-aws-guardduty",
        "t1059009-aws-cloudshell",
        "t1059009-aws-lambda-scoring",
        "t1059009-gcp-cloudshell",
        "t1059009-aws-cli",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+20% improvement for Execution tactic with multi-layered detection",
)
