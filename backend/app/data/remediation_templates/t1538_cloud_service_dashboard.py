"""
T1538 - Cloud Service Dashboard

Adversaries use cloud dashboards for reconnaissance without triggering API-based detections.
Used by Scattered Spider, LAPSUS$.

Detection Strategy:
- Console sign-ins cannot be directly instrumented for "page views"
- Pragmatic approach: Detect and triage ConsoleLogin events with anomaly logic
- Leverage GuardDuty's purpose-built console anomaly findings
- Deploy multi-region (ConsoleLogin region varies by user type)
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

# Lambda handler code for anomaly evaluation
LAMBDA_HANDLER_CODE = '''"""
Console Login Anomaly Evaluator

Scores console login events based on:
- Out-of-hours access
- Missing MFA
- New source IP (not in baseline)
- New user agent (not in baseline)
- Failed login attempts
"""

import json
import os
import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import ipaddress
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment configuration
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
BASELINE_TABLE = os.environ["BASELINE_TABLE"]
TZ = ZoneInfo(os.environ.get("TZ", "Europe/London"))
BUSINESS_START = int(os.environ.get("BUSINESS_START_HOUR", "8"))
BUSINESS_END = int(os.environ.get("BUSINESS_END_HOUR", "18"))
BUSINESS_DAYS = [int(d) for d in os.environ.get("BUSINESS_DAYS", "0,1,2,3,4").split(",")]
ALLOWLIST_ARNS = set(filter(None, os.environ.get("ALLOWLIST_ARNS", "").split(",")))
ALLOWLIST_CIDRS = [
    ipaddress.ip_network(c) for c in
    filter(None, os.environ.get("ALLOWLIST_SOURCE_CIDRS", "").split(","))
]
ALERT_ON_FAILURES = os.environ.get("ALERT_ON_FAILURES", "true").lower() == "true"
BASELINE_TTL_DAYS = int(os.environ.get("BASELINE_TTL_DAYS", "90"))
ALERT_THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", "40"))

sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")
baseline_table = dynamodb.Table(BASELINE_TABLE)


def lambda_handler(event, context):
    """Process ConsoleLogin event and evaluate for anomalies."""
    logger.info(f"Received event: {json.dumps(event)}")

    detail = event.get("detail", {})
    event_time = datetime.fromisoformat(
        event.get("time", datetime.utcnow().isoformat()).replace("Z", "+00:00")
    )

    # Extract key fields
    principal_arn = detail.get("userIdentity", {}).get("arn", "unknown")
    source_ip = detail.get("sourceIPAddress", "0.0.0.0")
    user_agent = detail.get("userAgent", "unknown")
    mfa_used = detail.get("additionalEventData", {}).get("MFAUsed", "No") == "Yes"
    login_result = detail.get("responseElements", {}).get("ConsoleLogin", "Success")

    # Skip if allowlisted
    if is_allowlisted(principal_arn, source_ip):
        logger.info(f"Skipping allowlisted principal/IP: {principal_arn}, {source_ip}")
        return {"statusCode": 200, "body": "Allowlisted"}

    # Skip failures if not configured to alert
    if login_result == "Failure" and not ALERT_ON_FAILURES:
        logger.info("Skipping failed login (ALERT_ON_FAILURES=false)")
        return {"statusCode": 200, "body": "Failures ignored"}

    # Get or create baseline
    baseline = get_baseline(principal_arn)

    # Calculate anomaly score
    score, reasons = calculate_score(
        event_time=event_time,
        source_ip=source_ip,
        user_agent=user_agent,
        mfa_used=mfa_used,
        login_result=login_result,
        baseline=baseline,
    )

    # Update baseline with new data
    update_baseline(principal_arn, source_ip, user_agent)

    # Alert if score exceeds threshold
    if score >= ALERT_THRESHOLD:
        send_alert(
            principal_arn=principal_arn,
            source_ip=source_ip,
            user_agent=user_agent,
            mfa_used=mfa_used,
            login_result=login_result,
            score=score,
            reasons=reasons,
            event_time=event_time,
        )
        return {"statusCode": 200, "body": f"Alert sent (score={score})"}

    logger.info(f"Below threshold: score={score}, threshold={ALERT_THRESHOLD}")
    return {"statusCode": 200, "body": f"No alert (score={score})"}


def is_allowlisted(principal_arn: str, source_ip: str) -> bool:
    """Check if principal or IP is in allowlist."""
    if principal_arn in ALLOWLIST_ARNS:
        return True

    try:
        ip = ipaddress.ip_address(source_ip)
        for cidr in ALLOWLIST_CIDRS:
            if ip in cidr:
                return True
    except ValueError:
        pass

    return False


def get_baseline(principal_arn: str) -> dict:
    """Retrieve baseline for principal from DynamoDB."""
    try:
        response = baseline_table.get_item(Key={"principal_arn": principal_arn})
        return response.get("Item", {})
    except Exception as e:
        logger.warning(f"Failed to get baseline: {e}")
        return {}


def update_baseline(principal_arn: str, source_ip: str, user_agent: str) -> None:
    """Update baseline with new observed values."""
    ttl_epoch = int((datetime.utcnow() + timedelta(days=BASELINE_TTL_DAYS)).timestamp())

    try:
        baseline_table.update_item(
            Key={"principal_arn": principal_arn},
            UpdateExpression="""
                SET known_ips = list_append(if_not_exists(known_ips, :empty_list), :new_ip),
                    known_user_agents = list_append(if_not_exists(known_user_agents, :empty_list), :new_ua),
                    last_seen = :now,
                    ttl_epoch = :ttl
                ADD login_count :one
            """,
            ExpressionAttributeValues={
                ":empty_list": [],
                ":new_ip": [source_ip],
                ":new_ua": [user_agent],
                ":now": datetime.utcnow().isoformat(),
                ":ttl": ttl_epoch,
                ":one": 1,
            },
        )
    except Exception as e:
        logger.warning(f"Failed to update baseline: {e}")


def calculate_score(
    event_time: datetime,
    source_ip: str,
    user_agent: str,
    mfa_used: bool,
    login_result: str,
    baseline: dict,
) -> tuple[int, list[str]]:
    """Calculate anomaly score based on multiple risk indicators."""
    score = 0
    reasons = []

    # Out of hours (+20)
    local_time = event_time.astimezone(TZ)
    if local_time.weekday() not in BUSINESS_DAYS:
        score += 20
        reasons.append(f"Weekend access ({local_time.strftime('%A')})")
    elif not (BUSINESS_START <= local_time.hour < BUSINESS_END):
        score += 20
        reasons.append(f"Out-of-hours ({local_time.strftime('%H:%M')} {TZ})")

    # No MFA (+25)
    if not mfa_used:
        score += 25
        reasons.append("MFA not used")

    # New source IP (+30)
    known_ips = set(baseline.get("known_ips", []))
    if source_ip not in known_ips:
        score += 30
        reasons.append(f"New source IP: {source_ip}")

    # New user agent (+15)
    known_uas = set(baseline.get("known_user_agents", []))
    if user_agent not in known_uas:
        score += 15
        reasons.append("New user agent")

    # Failed login (+10)
    if login_result == "Failure":
        score += 10
        reasons.append("Failed login attempt")

    return score, reasons


def send_alert(
    principal_arn: str,
    source_ip: str,
    user_agent: str,
    mfa_used: bool,
    login_result: str,
    score: int,
    reasons: list[str],
    event_time: datetime,
) -> None:
    """Publish alert to SNS topic."""
    message = f"""AWS Console Login Anomaly Detected

Principal: {principal_arn}
Source IP: {source_ip}
Time: {event_time.isoformat()}
Login Result: {login_result}
MFA Used: {mfa_used}

Anomaly Score: {score}/100

Risk Indicators:
{chr(10).join(f"  - {r}" for r in reasons)}

Investigation Steps:
1. Verify this login was authorised by the user
2. Check source IP geolocation and reputation
3. Review subsequent console activity in CloudTrail
4. Check for unusual API calls or resource access

Containment Actions:
1. If unauthorised: Force session logout via IAM
2. Reset user credentials immediately
3. Enable/enforce MFA if not already required
4. Review and restrict IAM permissions
"""

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[{login_result}] Console Anomaly: {principal_arn.split('/')[-1]} (Score: {score})",
            Message=message,
        )
        logger.info(f"Alert sent for {principal_arn}")
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
        raise
'''

TEMPLATE = RemediationTemplate(
    technique_id="T1538",
    technique_name="Cloud Service Dashboard",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1538/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit stolen credentials to access cloud service dashboards "
            "and extract operational intelligence. Since console page views cannot be "
            "directly instrumented, detection relies on monitoring ConsoleLogin events "
            "with anomaly logic and leveraging GuardDuty's purpose-built findings."
        ),
        attacker_goal="Discover cloud resources and configurations via web dashboards",
        why_technique=[
            "Visual overview of resources without API knowledge",
            "May expose information not available via CLI/API",
            "No direct API calls to detect after login",
            "Easy navigation across services",
            "Browser-based access blends with legitimate users",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Discovery technique enabling follow-on attacks. Console access with "
            "stolen credentials often precedes data exfiltration or privilege escalation. "
            "GuardDuty finding 'ConsoleLoginSuccess.B' specifically targets this pattern."
        ),
        business_impact=[
            "Environment reconnaissance enabling targeted attacks",
            "Attack planning with full visibility of resources",
            "Configuration exposure (security groups, IAM policies)",
            "Service discovery for lateral movement",
            "Credential validation before API-based attacks",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1530", "T1021.007", "T1059.009", "T1087.004"],
        often_follows=["T1078.004", "T1110", "T1528"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1538-aws-console-anomaly",
            name="AWS Console Login Anomaly Detection",
            description=(
                "Detect anomalous console access using Lambda-based scoring. "
                "Evaluates out-of-hours access, MFA status, new source IPs, and "
                "user agent changes against a per-principal baseline stored in DynamoDB."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, sourceIPAddress, eventName,
       additionalEventData.MFAUsed, responseElements.ConsoleLogin
| filter eventSource = "signin.amazonaws.com"
| filter eventName = "ConsoleLogin"
| stats count(*) as logins,
       count_distinct(sourceIPAddress) as unique_ips
       by userIdentity.arn, bin(1d)
| filter unique_ips > 3
| sort logins desc""",
                terraform_template="""# T1538 Console Login Anomaly Detection
# Deploys Lambda-based anomaly scoring with DynamoDB baseline storage
#
# File structure for full module:
#   t1538-console-anomaly/
#     versions.tf
#     variables.tf
#     main.tf
#     outputs.tf
#     lambda/handler.py

# --- versions.tf ---
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

# --- variables.tf ---
variable "name_prefix" {
  type        = string
  default     = "t1538-console-anomaly"
  description = "Prefix for resource names"
}

variable "alert_email" {
  type        = string
  description = "Email endpoint for alerts (SNS subscription confirmation required)"
}

variable "timezone" {
  type        = string
  default     = "Europe/London"
  description = "IANA timezone for out-of-hours logic"
}

variable "business_start_hour" {
  type    = number
  default = 8
}

variable "business_end_hour" {
  type    = number
  default = 18
}

variable "business_days" {
  type        = list(number)
  default     = [0, 1, 2, 3, 4]
  description = "Business days (Python weekday: 0=Mon, 4=Fri)"
}

variable "allowlisted_principal_arns" {
  type        = list(string)
  default     = []
  description = "Suppress alerts for these principal ARNs (break-glass, automation)"
}

variable "allowlisted_source_cidrs" {
  type        = list(string)
  default     = []
  description = "Suppress alerts for these CIDR ranges (corporate VPN egress)"
}

variable "alert_threshold" {
  type        = number
  default     = 40
  description = "Anomaly score threshold (0-100). Lower = more alerts."
}

variable "alert_on_failures" {
  type        = bool
  default     = true
  description = "Alert on failed login attempts"
}

variable "guardduty_enable" {
  type        = bool
  default     = true
  description = "Enable GuardDuty console anomaly finding integration"
}

variable "guardduty_min_severity" {
  type        = number
  default     = 4
  description = "Minimum GuardDuty severity to alert (4=Medium)"
}

# --- main.tf ---
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# SNS Topic for alerts
resource "aws_sns_topic" "alerts" {
  name         = "${var.name_prefix}-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Console Access Anomaly Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty[0].arn
        }
      }
    }]
  })
}

# DynamoDB baseline store
resource "aws_dynamodb_table" "baseline" {
  name         = "${var.name_prefix}-baseline"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_arn"

  attribute {
    name = "principal_arn"
    type = "S"
  }

  ttl {
    attribute_name = "ttl_epoch"
    enabled        = true
  }

  point_in_time_recovery { enabled = true }
  server_side_encryption { enabled = true }
}

# Lambda execution role
resource "aws_iam_role" "lambda_exec" {
  name = "${var.name_prefix}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.name_prefix}-lambda-policy"
  role = aws_iam_role.lambda_exec.id
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
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.baseline.arn
      }
    ]
  })
}

# Lambda function (anomaly evaluator)
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/handler.zip"
}

resource "aws_lambda_function" "evaluator" {
  function_name    = "${var.name_prefix}-evaluator"
  role             = aws_iam_role.lambda_exec.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 10
  memory_size      = 256

  environment {
    variables = {
      SNS_TOPIC_ARN          = aws_sns_topic.alerts.arn
      BASELINE_TABLE         = aws_dynamodb_table.baseline.name
      TZ                     = var.timezone
      BUSINESS_START_HOUR    = tostring(var.business_start_hour)
      BUSINESS_END_HOUR      = tostring(var.business_end_hour)
      BUSINESS_DAYS          = join(",", [for d in var.business_days : tostring(d)])
      ALLOWLIST_ARNS         = join(",", var.allowlisted_principal_arns)
      ALLOWLIST_SOURCE_CIDRS = join(",", var.allowlisted_source_cidrs)
      ALERT_ON_FAILURES      = var.alert_on_failures ? "true" : "false"
      ALERT_THRESHOLD        = tostring(var.alert_threshold)
      BASELINE_TTL_DAYS      = "90"
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.evaluator.function_name}"
  retention_in_days = 30
}

# EventBridge rule for ConsoleLogin events
resource "aws_cloudwatch_event_rule" "console_login" {
  name        = "${var.name_prefix}-console-login"
  description = "Capture ConsoleLogin and evaluate in Lambda"

  event_pattern = jsonencode({
    source        = ["aws.signin"]
    "detail-type" = ["AWS Console Sign In via CloudTrail"]
    detail = {
      eventName = ["ConsoleLogin"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.console_login.name
  target_id = "LambdaEvaluator"
  arn       = aws_lambda_function.evaluator.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.evaluator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.console_login.arn
}

# GuardDuty integration (optional but recommended)
resource "aws_guardduty_detector" "main" {
  count  = var.guardduty_enable ? 1 : 0
  enable = true
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  count       = var.guardduty_enable ? 1 : 0
  name        = "${var.name_prefix}-guardduty"
  description = "Route GuardDuty console anomaly findings to SNS"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.guardduty_min_severity] }]
      type = [
        { wildcard = "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess*" },
        { wildcard = "UnauthorizedAccess:IAMUser/TorIPCaller*" },
        { wildcard = "UnauthorizedAccess:IAMUser/MaliciousIPCaller*" },
        { wildcard = "*:IAMUser/AnomalousBehavior" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty[0]-dlq"
  message_retention_seconds = 1209600
}

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
      values   = [aws_cloudwatch_event_rule.guardduty[0].arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  count     = var.guardduty_enable ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty[0].name
  target_id = "SNSTopic"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# --- outputs.tf ---
output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.evaluator.function_name
}

output "baseline_table_name" {
  value = aws_dynamodb_table.baseline.name
}""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: T1538 Console Login Anomaly Detection

Parameters:
  NamePrefix:
    Type: String
    Default: t1538-console-anomaly
  AlertEmail:
    Type: String
    Description: Email for alerts (confirmation required)
  Timezone:
    Type: String
    Default: Europe/London
  BusinessStartHour:
    Type: Number
    Default: 8
  BusinessEndHour:
    Type: Number
    Default: 18
  AlertThreshold:
    Type: Number
    Default: 40
    Description: Anomaly score threshold (0-100)
  EnableGuardDuty:
    Type: String
    Default: 'true'
    AllowedValues: ['true', 'false']

Conditions:
  GuardDutyEnabled: !Equals [!Ref EnableGuardDuty, 'true']

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: !Sub '${NamePrefix}-alerts'
      DisplayName: Console Access Anomaly Alerts

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  AlertTopicPolicy:
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
                aws:SourceArn:
                  - !GetAtt ConsoleLoginRule.Arn
                  - !GetAtt GuardDutyRule.Arn

  BaselineTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub '${NamePrefix}-baseline'
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: principal_arn
          AttributeType: S
      KeySchema:
        - AttributeName: principal_arn
          KeyType: HASH
      TimeToLiveSpecification:
        AttributeName: ttl_epoch
        Enabled: true
      PointInTimeRecoverySpecification:
        PointInTimeRecoveryEnabled: true
      SSESpecification:
        SSEEnabled: true

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub '${NamePrefix}-lambda-role'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: LambdaPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'
              - Effect: Allow
                Action: sns:Publish
                Resource: !Ref AlertTopic
              - Effect: Allow
                Action:
                  - dynamodb:GetItem
                  - dynamodb:PutItem
                  - dynamodb:UpdateItem
                Resource: !GetAtt BaselineTable.Arn

  EvaluatorFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub '${NamePrefix}-evaluator'
      Runtime: python3.12
      Handler: index.lambda_handler
      Role: !GetAtt LambdaRole.Arn
      Timeout: 10
      MemorySize: 256
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref AlertTopic
          BASELINE_TABLE: !Ref BaselineTable
          TZ: !Ref Timezone
          BUSINESS_START_HOUR: !Ref BusinessStartHour
          BUSINESS_END_HOUR: !Ref BusinessEndHour
          BUSINESS_DAYS: '0,1,2,3,4'
          ALERT_THRESHOLD: !Ref AlertThreshold
          ALERT_ON_FAILURES: 'true'
          BASELINE_TTL_DAYS: '90'
      Code:
        ZipFile: |
          # See full handler.py in Terraform template
          # This is a placeholder - deploy full code via S3
          import json
          def lambda_handler(event, context):
              print(json.dumps(event))
              return {'statusCode': 200}

  ConsoleLoginRule:
    Type: AWS::Events::Rule
    Properties:
      Name: !Sub '${NamePrefix}-console-login'
      Description: Capture ConsoleLogin events
      EventPattern:
        source: [aws.signin]
        detail-type: [AWS Console Sign In via CloudTrail]
        detail:
          eventName: [ConsoleLogin]
      Targets:
        - Id: LambdaEvaluator
          Arn: !GetAtt EvaluatorFunction.Arn

  LambdaPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref EvaluatorFunction
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt ConsoleLoginRule.Arn

  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Condition: GuardDutyEnabled
    Properties:
      Enable: true

  GuardDutyRule:
    Type: AWS::Events::Rule
    Condition: GuardDutyEnabled
    Properties:
      Name: !Sub '${NamePrefix}-guardduty'
      Description: Route GuardDuty console findings to SNS
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          severity: [{numeric: ['>=', 4]}]
          type:
            - prefix: 'UnauthorizedAccess:IAMUser/ConsoleLoginSuccess'
            - prefix: 'UnauthorizedAccess:IAMUser/TorIPCaller'
      Targets:
        - Id: SNSTopic
          Arn: !Ref AlertTopic

Outputs:
  SNSTopicArn:
    Value: !Ref AlertTopic
  LambdaFunctionName:
    Value: !Ref EvaluatorFunction
  BaselineTableName:
    Value: !Ref BaselineTable""",
                alert_severity="medium",
                alert_title="AWS Console Login Anomaly Detected",
                alert_description_template=(
                    "Console login anomaly for {userIdentity.arn} from {sourceIPAddress}. "
                    "Score: {score}/100. Indicators: {reasons}"
                ),
                investigation_steps=[
                    "Verify login was authorised by contacting the user",
                    "Check source IP geolocation and threat intelligence",
                    "Review subsequent console activity in CloudTrail",
                    "Check for unusual API calls after login",
                    "Verify MFA status and session duration",
                ],
                containment_actions=[
                    "Force session logout via IAM console or CLI",
                    "Reset user credentials immediately",
                    "Enable/enforce MFA if not already required",
                    "Review and restrict IAM permissions",
                    "Check for persistence mechanisms (new users, roles, keys)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Use allowlisted_principal_arns for break-glass and automation accounts. "
                "Use allowlisted_source_cidrs for corporate VPN egress. "
                "Adjust alert_threshold: 40 for SOC tripwire, 60 for high-confidence only."
            ),
            detection_coverage=(
                "85% - Catches anomalous console logins with scoring. "
                "GuardDuty integration adds ML-based anomaly detection."
            ),
            evasion_considerations=(
                "Attackers using stolen credentials from expected IPs during business hours "
                "may score below threshold. GuardDuty's behavioural analysis helps catch these."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-10 (Lambda + DynamoDB + SNS)",
            prerequisites=[
                "CloudTrail enabled with management events",
                "EventBridge configured to receive CloudTrail events",
                "GuardDuty enabled (recommended)",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1538-aws-guardduty",
            name="GuardDuty Console Anomaly Findings",
            description=(
                "Leverage AWS GuardDuty's purpose-built console anomaly detection. "
                "Finding type 'UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B' specifically "
                "detects multiple worldwide successful console logins indicating credential compromise."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# GuardDuty console anomaly findings -> SNS
# This is included in the main t1538-console-anomaly module
# Deploy separately if you only want GuardDuty integration

variable "alert_email" { type = string }
variable "min_severity" {
  type    = number
  default = 4
  description = "Minimum severity (4=Medium, 7=High)"
}

data "aws_caller_identity" "current" {}

resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-console-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_console.arn
          }
      }
    }]
  })
}

resource "aws_cloudwatch_event_rule" "guardduty_console" {
  name        = "guardduty-console-anomalies"
  description = "Route GuardDuty console-related findings to SNS"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_severity] }]
      type = [
        # Primary console anomaly finding
        { wildcard = "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess*" },

        # Credential compromise indicators
        { wildcard = "UnauthorizedAccess:IAMUser/TorIPCaller*" },
        { wildcard = "UnauthorizedAccess:IAMUser/MaliciousIPCaller*" },
        { wildcard = "Recon:IAMUser/TorIPCaller*" },
        { wildcard = "Recon:IAMUser/MaliciousIPCaller*" },

        # Behavioural anomalies
        { wildcard = "*:IAMUser/AnomalousBehavior" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-console-dlq"
  message_retention_seconds = 1209600
}

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
      values   = [aws_cloudwatch_event_rule.guardduty_console.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_console.name
  target_id = "SNSTopic"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}""",
                alert_severity="high",
                alert_title="GuardDuty: Console Access Anomaly",
                alert_description_template=(
                    "GuardDuty detected: {detail.type}. "
                    "Principal: {detail.resource.accessKeyDetails.principalId}. "
                    "Severity: {detail.severity}"
                ),
                investigation_steps=[
                    "Review full GuardDuty finding in Security Hub or GuardDuty console",
                    "Check the geographic locations of login attempts",
                    "Verify with user if logins were authorised",
                    "Review CloudTrail for actions taken during sessions",
                    "Check for concurrent sessions from different locations",
                ],
                containment_actions=[
                    "Immediately disable the IAM user or revoke role sessions",
                    "Rotate all credentials (password, access keys)",
                    "Force MFA re-enrollment",
                    "Review and remove any persistence mechanisms",
                    "Audit all actions taken during anomalous sessions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty uses ML and threat intelligence, so false positives are rare. "
                "Suppress specific principals via GuardDuty suppression rules if needed."
            ),
            detection_coverage=(
                "90% - GuardDuty's ML detects behavioural anomalies that rule-based "
                "detection would miss."
            ),
            evasion_considerations=(
                "Sophisticated attackers may attempt to mimic normal user behaviour. "
                "GuardDuty continuously improves models based on AWS-wide threat intelligence."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$0.10-0.50 (EventBridge + SNS only; GuardDuty pricing separate)",
            prerequisites=[
                "GuardDuty enabled in all regions",
                "CloudTrail enabled (GuardDuty consumes CloudTrail)",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1538-gcp-console",
            name="GCP Console Access Anomaly Detection",
            description=(
                "Detect unusual GCP console access patterns using Cloud Audit Logs. "
                "Monitor for Admin Activity and Data Access logs indicating console reconnaissance."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""-- Console reconnaissance activity
resource.type="audited_resource"
protoPayload.methodName=~"(GetProject|ListProjects|GetIamPolicy|ListInstances|ListBuckets)"
protoPayload.authenticationInfo.principalEmail:*
severity>=NOTICE""",
                gcp_terraform_template="""# GCP Console Reconnaissance Detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Console Anomaly Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "console_recon" {
  project = var.project_id
  name    = "console-reconnaissance"
  filter  = <<-EOT
    resource.type="audited_resource"
    protoPayload.methodName=~"GetProject|ListProjects|GetIamPolicy|ListInstances|ListBuckets|ListServiceAccounts"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal email"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

resource "google_monitoring_alert_policy" "console_recon" {
  project      = var.project_id
  display_name = "Console Reconnaissance Alert"
  combiner     = "OR"

  conditions {
    display_name = "High console reconnaissance activity"
    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/${google_logging_metric.console_recon.name}\\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Unusual console reconnaissance detected. Review Cloud Audit Logs."
    mime_type = "text/markdown"
  }
}

# Security Command Centre integration (if available)
resource "google_scc_notification_config" "console_anomaly" {
  count        = 0  # Enable if SCC is available
  config_id    = "console-anomaly-notifications"
  organization = "organizations/YOUR_ORG_ID"
  description  = "Notify on IAM-related SCC findings"

  streaming_config {
    filter = "category=\\"ADMIN_SERVICE_ACCOUNT\\" OR category=\\"MFA_NOT_ENFORCED\\""
  }

  pubsub_topic = google_pubsub_topic.scc_notifications.id
}""",
                alert_severity="medium",
                alert_title="GCP: Console Reconnaissance Detected",
                alert_description_template="Unusual console activity by {protoPayload.authenticationInfo.principalEmail}.",
                investigation_steps=[
                    "Review accessed resources in Cloud Audit Logs",
                    "Verify principal identity and access authorisation",
                    "Check for follow-up API calls or resource modifications",
                    "Review IAM permissions for the principal",
                    "Check Security Command Centre for related findings",
                ],
                containment_actions=[
                    "Revoke user session via Admin Console",
                    "Disable service account if applicable",
                    "Review and restrict IAM permissions",
                    "Enable 2FA/2SV if not already enforced",
                    "Audit project access and resource changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Baseline normal console activity per user. "
                "Exclude known admin service accounts from alerting."
            ),
            detection_coverage="70% - Catches reconnaissance API patterns",
            evasion_considerations="Hard to distinguish from legitimate admin browsing",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Audit Logs enabled (Admin Activity + Data Access)",
                "Cloud Monitoring API enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1538-aws-guardduty",  # Quickest win - leverage existing ML
        "t1538-aws-console-anomaly",  # Custom anomaly logic
        "t1538-gcp-console",  # GCP coverage
    ],
    total_effort_hours=4.0,
    coverage_improvement="+15% improvement for Discovery tactic",
)
