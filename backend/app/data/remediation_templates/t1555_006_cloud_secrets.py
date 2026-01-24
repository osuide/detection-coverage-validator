"""
T1555.006 - Credentials from Password Stores: Cloud Secrets Management Stores

Adversaries access cloud secrets managers to retrieve credentials.
Targets AWS Secrets Manager, SSM Parameter Store, GCP Secret Manager.
Used by HAFNIUM, Pacu, Storm-0501.
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
    technique_id="T1555.006",
    technique_name="Credentials from Password Stores: Cloud Secrets Management Stores",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1555/006/",
    threat_context=ThreatContext(
        description=(
            "Adversaries access cloud secrets managers (AWS Secrets Manager, SSM Parameter Store, "
            "GCP Secret Manager) to retrieve credentials. Requires elevated privileges or "
            "compromised service roles. Often targeted after initial access is established."
        ),
        attacker_goal="Retrieve credentials from cloud secrets management services",
        why_technique=[
            "Secrets managers store high-value credentials",
            "Database passwords often stored here",
            "API keys and tokens accessible",
            "Single access can yield many secrets",
            "Lateral movement enabler",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Direct access to sensitive credentials. Can enable lateral movement "
            "and access to databases, APIs, and other systems."
        ),
        business_impact=[
            "Credential theft enabling lateral movement",
            "Database access via stolen passwords",
            "API key compromise",
            "Complete environment compromise possible",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1530"],
        often_follows=["T1098.003", "T1078.004"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: GuardDuty Credential Access Detection (Recommended)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1555006-aws-guardduty",
            name="AWS GuardDuty Secrets Manager Anomaly Detection",
            description=(
                "Leverage GuardDuty's ML-based detection for anomalous Secrets Manager access. "
                "GuardDuty monitors for unusual secret retrieval patterns, cross-account access, "
                "and credential exfiltration attempts. See: "
                "https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-guardduty.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  GuardDuty Secrets Manager Anomaly Detection
  Detects: CredentialAccess:IAMUser/AnomalousBehavior
  See: https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-guardduty.html

Parameters:
  AlertEmail:
    Type: String
    Description: Email for credential access alerts

Resources:
  # SNS Topic for credential access findings
  CredentialAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: guardduty-credential-access-alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref CredentialAlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # EventBridge rule for CredentialAccess findings
  CredentialAccessRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-credential-access
      Description: Detect credential access anomalies via GuardDuty
      State: ENABLED
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "CredentialAccess:"
            - prefix: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
      Targets:
        - Id: SendToSNS
          Arn: !Ref CredentialAlertTopic
          InputTransformer:
            InputPathsMap:
              findingType: $.detail.type
              severity: $.detail.severity
              principal: $.detail.resource.accessKeyDetails.userName
              sourceIp: $.detail.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4
              accountId: $.account
            InputTemplate: |
              "CRITICAL: GuardDuty Credential Access Alert"
              "Type: <findingType>"
              "Severity: <severity>"
              "Principal: <principal>"
              "Source IP: <sourceIp>"
              "Account: <accountId>"
              "Action: Immediately investigate and rotate affected secrets"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref CredentialAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref CredentialAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt CredentialAccessRule.Arn

  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

Outputs:
  AlertTopicArn:
    Description: SNS topic for credential access alerts
    Value: !Ref CredentialAlertTopic""",
                terraform_template="""# AWS GuardDuty Secrets Manager Anomaly Detection
# Detects: CredentialAccess:IAMUser/AnomalousBehavior
# See: https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-guardduty.html

variable "alert_email" {
  type        = string
  description = "Email for credential access alerts"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "credential_alerts" {
  name              = "guardduty-credential-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.credential_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Enable GuardDuty detector
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 3: Route CredentialAccess findings to SNS
resource "aws_cloudwatch_event_rule" "credential_access" {
  name        = "guardduty-credential-access"
  description = "Detect credential access anomalies via GuardDuty"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "CredentialAccess:" },
        { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "credential-access-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.credential_access.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.credential_alerts.arn

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
      accountId   = "$.account"
    }
    input_template = <<-EOF
      "CRITICAL: GuardDuty Credential Access Alert"
      "Type: <findingType>"
      "Severity: <severity>"
      "Principal: <principal>"
      "Source IP: <sourceIp>"
      "Account: <accountId>"
      "Action: Immediately investigate and rotate affected secrets"
    EOF
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.credential_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.credential_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.credential_access.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Credential Access Anomaly Detected",
                alert_description_template=(
                    "GuardDuty has detected anomalous credential access: {type}. "
                    "Principal {principal} accessed secrets in an unusual pattern from {sourceIp}."
                ),
                investigation_steps=[
                    "Review the specific GuardDuty finding for anomaly details",
                    "Identify which secrets were accessed by this principal",
                    "Check if the access pattern matches known application behaviour",
                    "Verify the source IP is from an expected location",
                    "Review the user's recent activity for lateral movement",
                ],
                containment_actions=[
                    "Immediately rotate all secrets accessed by this principal",
                    "Revoke the principal's access to Secrets Manager",
                    "Add the source IP to a deny list",
                    "Review and restrict IAM permissions for secrets access",
                    "Check for any use of the compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty's ML learns baseline access patterns over 7-14 days. "
                "New applications accessing secrets may trigger initial findings. "
                "Use trusted IP lists for known automation infrastructure."
            ),
            detection_coverage="85% - ML-based detection of anomalous access patterns",
            evasion_considerations=(
                "Slow, gradual access from expected IPs may evade. "
                "Using legitimate application credentials helps blend in."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "$4-5 per million CloudTrail events. "
                "See: https://aws.amazon.com/guardduty/pricing/"
            ),
            prerequisites=["AWS account with CloudTrail enabled"],
        ),
        # =====================================================================
        # STRATEGY 2: Lambda-Based Bulk Secret Access Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1555006-aws-lambda-bulk",
            name="Lambda-Based Bulk Secret Access Detection",
            description=(
                "Custom Lambda function to detect bulk secret access patterns. "
                "Tracks per-principal secret access counts, unusual secrets accessed, "
                "and cross-account access attempts using DynamoDB for baseline tracking."
            ),
            detection_type=DetectionType.CUSTOM_LAMBDA,
            aws_service="lambda",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# Lambda-Based Bulk Secret Access Detection
# Detects: Bulk access, unusual principals, cross-account access

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
  description = "Email for secret access alerts"
}

variable "bulk_threshold" {
  type        = number
  default     = 5
  description = "Number of secrets in 5 min window to trigger bulk alert"
}

variable "allowed_principals" {
  type        = list(string)
  default     = []
  description = "Principal ARNs allowed to access multiple secrets"
}

# Step 1: DynamoDB table for access tracking
resource "aws_dynamodb_table" "secret_access" {
  name         = "secret-access-tracking"
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
}

# Step 2: Lambda function for bulk detection
resource "aws_lambda_function" "secret_monitor" {
  function_name = "secret-access-monitor"
  runtime       = "python3.11"
  handler       = "index.handler"
  role          = aws_iam_role.lambda_role.arn
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      TRACKING_TABLE     = aws_dynamodb_table.secret_access.name
      ALERT_TOPIC_ARN    = aws_sns_topic.alerts.arn
      BULK_THRESHOLD     = tostring(var.bulk_threshold)
      ALLOWED_PRINCIPALS = jsonencode(var.allowed_principals)
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/secret_monitor.zip"

  source {
    content  = <<-PYTHON
import json
import os
import boto3
from datetime import datetime, timezone

dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')
table = dynamodb.Table(os.environ['TRACKING_TABLE'])
BULK_THRESHOLD = int(os.environ.get('BULK_THRESHOLD', '5'))
ALLOWED = json.loads(os.environ.get('ALLOWED_PRINCIPALS', '[]'))


def handler(event, context):
    for record in event.get('Records', []):
        try:
            detail = json.loads(record['body'])
            process_secret_access(detail)
        except Exception as e:
            print(f"Error: {e}")
            raise


def process_secret_access(detail):
    principal_arn = detail.get('userIdentity', {}).get('arn', 'unknown')
    event_name = detail.get('eventName', '')
    secret_id = detail.get('requestParameters', {}).get('secretId', 'unknown')
    source_ip = detail.get('sourceIPAddress', '')
    event_time = detail.get('eventTime', '')
    source_account = detail.get('userIdentity', {}).get('accountId', '')
    target_account = detail.get('recipientAccountId', '')

    # Skip allowed principals
    if principal_arn in ALLOWED:
        return

    # Cross-account access detection
    if source_account and target_account and source_account != target_account:
        send_alert({
            'alert': 'Cross-Account Secret Access',
            'severity': 'CRITICAL',
            'principal': principal_arn,
            'secret': secret_id,
            'source_account': source_account,
            'target_account': target_account,
            'source_ip': source_ip
        })
        return

    # Get 5-minute window ID
    window_id = event_time[:16] if event_time else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M')

    # Update access tracking
    import time
    expires_at = int(time.time()) + 3600  # 1 hour TTL

    response = table.update_item(
        Key={'principal_arn': principal_arn, 'window_id': window_id},
        UpdateExpression='''
            SET access_count = if_not_exists(access_count, :zero) + :one,
                secrets_accessed = if_not_exists(secrets_accessed, :empty_set),
                expires_at = :expires
            ADD secrets_accessed :secret_set
        ''',
        ExpressionAttributeValues={
            ':zero': 0,
            ':one': 1,
            ':empty_set': set(),
            ':secret_set': {secret_id},
            ':expires': expires_at
        },
        ReturnValues='ALL_NEW'
    )

    item = response.get('Attributes', {})
    secrets_count = len(item.get('secrets_accessed', set()))
    access_count = int(item.get('access_count', 0))

    # Bulk access detection
    if secrets_count >= BULK_THRESHOLD:
        send_alert({
            'alert': 'Bulk Secret Access Detected',
            'severity': 'HIGH',
            'principal': principal_arn,
            'secrets_accessed': secrets_count,
            'total_access_count': access_count,
            'time_window': window_id,
            'source_ip': source_ip,
            'recommendation': 'Review principal activity and rotate accessed secrets'
        })


def send_alert(message):
    sns.publish(
        TopicArn=os.environ['ALERT_TOPIC_ARN'],
        Subject=f"Secret Access Alert: {message.get('alert', 'Unknown')}",
        Message=json.dumps(message, indent=2, default=str)
    )
PYTHON
    filename = "index.py"
  }
}

# Step 3: EventBridge rule to capture secret access
resource "aws_cloudwatch_event_rule" "secret_access" {
  name        = "secrets-manager-access"
  description = "Capture Secrets Manager access events"

  event_pattern = jsonencode({
    source      = ["aws.secretsmanager"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["GetSecretValue", "BatchGetSecretValue"]
    }
  })
}

resource "aws_sqs_queue" "secret_events" {
  name                       = "secret-access-events"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400
}

resource "aws_cloudwatch_event_target" "to_sqs" {
  rule      = aws_cloudwatch_event_rule.secret_access.name
  target_id = "SendToSQS"
  arn       = aws_sqs_queue.secret_events.arn
}

resource "aws_lambda_event_source_mapping" "sqs_trigger" {
  event_source_arn = aws_sqs_queue.secret_events.arn
  function_name    = aws_lambda_function.secret_monitor.arn
  batch_size       = 10
}

# Supporting resources
resource "aws_sns_topic" "alerts" {
  name              = "secret-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sqs_queue" "dlq" {
  name                      = "secret-monitor-dlq"
  message_retention_seconds = 1209600
}

resource "aws_iam_role" "lambda_role" {
  name = "secret-access-monitor-role"

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
  name = "secret-access-monitor-policy"
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
        Resource = aws_dynamodb_table.secret_access.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.secret_events.arn
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
  queue_url = aws_sqs_queue.secret_events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.secret_events.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Bulk Secret Access Detected",
                alert_description_template=(
                    "Principal {principal} accessed {secrets_accessed} secrets in a 5-minute window. "
                    "This exceeds the threshold of {threshold} and may indicate credential harvesting."
                ),
                investigation_steps=[
                    "Identify all secrets accessed by this principal",
                    "Verify if this is expected application behaviour",
                    "Check if any secrets were accessed for the first time",
                    "Review the source IP for anomalies",
                    "Look for subsequent use of retrieved credentials",
                ],
                containment_actions=[
                    "Rotate all secrets accessed by this principal",
                    "Temporarily revoke the principal's Secrets Manager access",
                    "Review and tighten IAM policies for secret access",
                    "Enable secret access logging for audit",
                    "Consider implementing secret access approval workflow",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Add legitimate batch-processing applications to allowed_principals. "
                "Tune bulk_threshold based on your application's normal access patterns. "
                "Consider separate thresholds for different secret types."
            ),
            detection_coverage="80% - catches bulk access and cross-account patterns",
            evasion_considerations="Slow access spread over time may evade bulk detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost=(
                "Lambda: $0.20 per million requests. "
                "DynamoDB: ~$1-5/month. "
                "Total: $5-15/month."
            ),
            prerequisites=[
                "CloudTrail enabled for Secrets Manager data events",
                "IAM permissions for Lambda, DynamoDB, SQS, SNS",
            ],
        ),
        # =====================================================================
        # STRATEGY 3: SSM Parameter Store Sensitive Access Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1555006-aws-ssm",
            name="SSM Parameter Store Sensitive Access Detection",
            description=(
                "Detect access to sensitive parameters in AWS Systems Manager Parameter Store. "
                "SecureString parameters often contain credentials and API keys. "
                "Monitors GetParameter and GetParameters API calls."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="ssm",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "GetParameter",
                            "GetParameters",
                            "GetParametersByPath",
                        ]
                    },
                },
                terraform_template="""# SSM Parameter Store Sensitive Access Detection
# Monitors access to SecureString parameters

variable "alert_email" {
  type        = string
  description = "Email for parameter access alerts"
}

variable "sensitive_prefixes" {
  type        = list(string)
  default     = ["/prod/", "/credentials/", "/secrets/", "/api-keys/"]
  description = "Parameter path prefixes considered sensitive"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "ssm_alerts" {
  name              = "ssm-sensitive-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for parameter access
resource "aws_cloudwatch_event_rule" "ssm_access" {
  name        = "ssm-parameter-access"
  description = "Detect SSM Parameter Store access"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "GetParameter",
        "GetParameters",
        "GetParametersByPath"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "ssm_to_sns" {
  rule      = aws_cloudwatch_event_rule.ssm_access.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.ssm_alerts.arn

  input_transformer {
    input_paths = {
      eventName   = "$.detail.eventName"
      user        = "$.detail.userIdentity.arn"
      sourceIp    = "$.detail.sourceIPAddress"
      parameters  = "$.detail.requestParameters"
    }
    input_template = <<-EOF
      {
        "alert": "SSM Parameter Access",
        "event": "<eventName>",
        "user": "<user>",
        "sourceIp": "<sourceIp>",
        "parameters": "<parameters>",
        "action": "Verify this parameter access was authorised"
      }
    EOF
  }
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.ssm_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssm_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ssm_access.arn
        }
      }
    }]
  })
}

output "alert_topic_arn" {
  value       = aws_sns_topic.ssm_alerts.arn
  description = "SNS topic for SSM alerts"
}""",
                alert_severity="high",
                alert_title="SSM Parameter Store Access Detected",
                alert_description_template=(
                    "SSM Parameter {name} accessed by {userIdentity.arn}. "
                    "Verify this access was authorised."
                ),
                investigation_steps=[
                    "Verify the parameter access was authorised",
                    "Check if the parameter contains sensitive data (SecureString)",
                    "Review the accessing principal's normal access patterns",
                    "Check for bulk parameter retrieval",
                    "Look for subsequent use of retrieved values",
                ],
                containment_actions=[
                    "Rotate the parameter value if it contains credentials",
                    "Review IAM policies granting ssm:GetParameter*",
                    "Enable parameter access logging",
                    "Consider using Secrets Manager for high-value secrets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Filter for specific parameter paths (e.g., /prod/, /credentials/). "
                "Exclude known application service roles. "
                "Use separate alerting for SecureString vs String parameters."
            ),
            detection_coverage="85% - catches all parameter access events",
            evasion_considerations="Attacker may use legitimate application credentials",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10/month (EventBridge + SNS)",
            prerequisites=["CloudTrail enabled for SSM data events"],
        ),
        # =====================================================================
        # STRATEGY 4: GCP Secret Manager Access Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1555006-gcp-secrets",
            name="GCP Secret Manager Access Detection",
            description=(
                "Detect access to secrets in GCP Secret Manager using Cloud Audit Logs. "
                "Monitors AccessSecretVersion and ListSecretVersions API calls. "
                "Alerts on unusual access patterns and bulk retrieval."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""# Secret Manager access detection
protoPayload.serviceName="secretmanager.googleapis.com"
protoPayload.methodName=~"AccessSecretVersion|GetSecretVersion|ListSecrets|ListSecretVersions"
protoPayload.authenticationInfo.principalEmail:*""",
                gcp_terraform_template="""# GCP Secret Manager Access Detection

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
  display_name = "Secret Manager Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for secret access
resource "google_logging_metric" "secret_access" {
  name    = "secret-manager-access"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="secretmanager.googleapis.com"
    protoPayload.methodName=~"AccessSecretVersion|GetSecretVersion|ListSecrets|ListSecretVersions"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal accessing secrets"
    }
    labels {
      key         = "secret"
      value_type  = "STRING"
      description = "Secret name"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "secret"    = "EXTRACT(protoPayload.resourceName)"
  }
}

# Step 3: Alert on secret access
resource "google_monitoring_alert_policy" "secret_access" {
  project      = var.project_id
  display_name = "Secret Manager Access Detected"
  combiner     = "OR"

  conditions {
    display_name = "Secret accessed"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.secret_access.name}\" resource.type=\"global\""
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
    content   = "A secret was accessed in Secret Manager. Verify this access was authorised and review the principal's activity."
    mime_type = "text/markdown"
  }
}

# Step 4: Bulk access detection (5+ secrets in 5 minutes)
resource "google_monitoring_alert_policy" "bulk_secret_access" {
  project      = var.project_id
  display_name = "CRITICAL: Bulk Secret Access Detected"
  combiner     = "OR"

  conditions {
    display_name = "Multiple secrets accessed"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.secret_access.name}\" resource.type=\"global\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5

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
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Bulk secret access detected. A principal accessed more than 5 secrets in 5 minutes. Immediately investigate for credential harvesting."
    mime_type = "text/markdown"
  }
}

# Step 5: Cross-project secret access detection
resource "google_logging_metric" "cross_project_secret" {
  name    = "cross-project-secret-access"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="secretmanager.googleapis.com"
    protoPayload.methodName="AccessSecretVersion"
    protoPayload.authenticationInfo.serviceAccountDelegationInfo:*
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "cross_project_secret" {
  project      = var.project_id
  display_name = "Cross-Project Secret Access"
  combiner     = "OR"

  conditions {
    display_name = "Secret accessed via delegation"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cross_project_secret.name}\" resource.type=\"global\""
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
    content   = "A secret was accessed via service account delegation from another project. Verify this cross-project access is authorised."
    mime_type = "text/markdown"
  }
}

output "notification_channel_id" {
  value       = google_monitoring_notification_channel.email_s1.id
  description = "Notification channel for alerts"
}""",
                alert_severity="high",
                alert_title="GCP: Secret Manager Access Detected",
                alert_description_template=(
                    "Secret {secret} accessed by {principal}. "
                    "Verify this access was authorised."
                ),
                investigation_steps=[
                    "Verify the access was authorised for this principal",
                    "Check which secrets were accessed in this time window",
                    "Review the principal's normal access patterns",
                    "Look for service account impersonation or delegation",
                    "Check for subsequent use of retrieved credentials",
                ],
                containment_actions=[
                    "Rotate the accessed secret immediately",
                    "Review IAM bindings for Secret Manager access",
                    "Enable Secret Manager audit logging",
                    "Consider using VPC Service Controls for secret access",
                    "Implement secret access approval workflows",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Tune thresholds based on your application's normal access patterns. "
                "Exclude known automation service accounts from alerting. "
                "Consider separate policies for different secret types."
            ),
            detection_coverage="90% - catches all secret access via audit logs",
            evasion_considerations="Attacker using legitimate service account credentials may blend in",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost=(
                "Cloud Logging: Free tier covers 50GB/month. "
                "Monitoring: Free for first 100 alert policies. "
                "Typical cost: $10-20/month."
            ),
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Data Access logs enabled for Secret Manager",
            ],
        ),
        # Azure Strategy: Credentials from Password Stores: Cloud Secrets Management Stores
        DetectionStrategy(
            strategy_id="t1555006-azure",
            name="Azure Credentials from Password Stores: Cloud Secrets Management Stores Detection",
            description=(
                "Azure detection for Credentials from Password Stores: Cloud Secrets Management Stores. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Direct KQL Query: Detect Cloud Secrets Store Access
// MITRE ATT&CK: T1555.006 - Credentials from Password Stores: Cloud Secrets
// Data Sources: AzureDiagnostics (Key Vault), AzureActivity

// Part 1: Detect suspicious Key Vault secret operations
let KeyVaultSecretOps = AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet", "SecretList", "SecretBackup", "SecretRestore", "SecretPurge")
| extend
    IsHighRisk = OperationName in ("SecretBackup", "SecretPurge"),
    SecretId = id_s
| summarize
    TotalOperations = count(),
    GetCount = countif(OperationName == "SecretGet"),
    ListCount = countif(OperationName == "SecretList"),
    BackupCount = countif(OperationName == "SecretBackup"),
    PurgeCount = countif(OperationName == "SecretPurge"),
    HighRiskOps = countif(IsHighRisk),
    Secrets = make_set(SecretId, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIPAddress, identity_claim_upn_s, Resource
| where TotalOperations > 5 or HighRiskOps > 0;
// Part 2: Detect Key Vault access from new/unusual IPs
let KeyVaultNewIPs = AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName has "Secret"
| summarize
    FirstAccess = min(TimeGenerated),
    AccessCount = count()
    by CallerIPAddress, identity_claim_upn_s, Resource
| join kind=leftanti (
    AzureDiagnostics
    | where TimeGenerated between (ago(30d) .. ago(24h))
    | where ResourceProvider == "MICROSOFT.KEYVAULT"
    | summarize by CallerIPAddress, identity_claim_upn_s
) on CallerIPAddress, identity_claim_upn_s
| extend IsNewIP = true;
// Part 3: Detect access to multiple Key Vaults
let MultiVaultAccess = AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName has "Secret"
| summarize
    VaultCount = dcount(Resource),
    Vaults = make_set(Resource, 10),
    TotalOps = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIPAddress, identity_claim_upn_s
| where VaultCount > 3;  // Accessing many vaults is suspicious
// Combine results
KeyVaultSecretOps
| project
    TimeGenerated = LastSeen,
    Caller = identity_claim_upn_s,
    CallerIpAddress = CallerIPAddress,
    Resource,
    TotalOperations,
    GetCount,
    ListCount,
    BackupCount,
    PurgeCount,
    Secrets,
    TechniqueId = "T1555.006",
    TechniqueName = "Cloud Secrets Management Stores",
    Severity = case(
        BackupCount > 0 or PurgeCount > 0, "Critical",
        TotalOperations > 20, "High",
        "Medium"
    )""",
                sentinel_rule_query="""// Sentinel Analytics Rule: Cloud Secrets Management Store Access
// MITRE ATT&CK: T1555.006
// Detects suspicious Key Vault secret operations

AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet", "SecretList", "SecretBackup", "SecretRestore", "SecretPurge")
| extend
    IsHighRisk = OperationName in ("SecretBackup", "SecretPurge")
| summarize
    TotalOperations = count(),
    GetCount = countif(OperationName == "SecretGet"),
    ListCount = countif(OperationName == "SecretList"),
    BackupCount = countif(OperationName == "SecretBackup"),
    PurgeCount = countif(OperationName == "SecretPurge"),
    HighRiskOps = countif(IsHighRisk),
    Vaults = make_set(Resource, 10),
    Secrets = make_set(id_s, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CallerIPAddress, identity_claim_upn_s
| where TotalOperations > 10 or HighRiskOps > 0
| extend
    AccountName = tostring(split(identity_claim_upn_s, "@")[0]),
    AccountDomain = tostring(split(identity_claim_upn_s, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller = identity_claim_upn_s,
    CallerIpAddress = CallerIPAddress,
    TotalOperations,
    GetCount,
    ListCount,
    BackupCount,
    PurgeCount,
    Vaults,
    Secrets,
    FirstSeen,
    AlertSeverity = case(
        BackupCount > 0 or PurgeCount > 0, "High",
        TotalOperations > 20, "Medium",
        "Low"
    )""",
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Credentials from Password Stores: Cloud Secrets Management Stores (T1555.006)
# Microsoft Defender detects Credentials from Password Stores: Cloud Secrets Management Stores activity

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
  name                = "defender-t1555-006-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1555-006"
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

  description = "Microsoft Defender detects Credentials from Password Stores: Cloud Secrets Management Stores activity"
  display_name = "Defender: Credentials from Password Stores: Cloud Secrets Management Stores"
  enabled      = true
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Credentials from Password Stores: Cloud Secrets Management Stores Detected",
                alert_description_template=(
                    "Credentials from Password Stores: Cloud Secrets Management Stores activity detected. "
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
        "t1555006-aws-guardduty",
        "t1555006-aws-lambda-bulk",
        "t1555006-aws-ssm",
        "t1555006-gcp-secrets",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+25% improvement for Credential Access tactic with multi-layered detection",
)
