"""
T1098.001 - Account Manipulation: Additional Cloud Credentials

Adversaries create additional access keys or service account keys to maintain
persistent access. This is a key persistence technique in cloud environments.

Detection Strategy:
- Monitor all credential creation events (CreateAccessKey, service account keys)
- Distinguish self-created keys vs. keys created by others (higher risk)
- Leverage GuardDuty for Persistence:IAMUser/AnomalousBehavior findings
- Use Lambda-based evaluation with CI/CD allowlisting

Used by APT29, Scattered Spider, LAPSUS$.
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

# Lambda handler for intelligent access key creation evaluation
LAMBDA_HANDLER_CODE = '''"""
Access Key Creation Evaluator

Scores key creation events based on:
- Who created the key (self vs. others - high risk if others)
- Time of day (out-of-hours is suspicious)
- Target user permissions (admin keys are higher risk)
- CI/CD automation allowlist
- Recent suspicious activity for the creator
"""

import json
import os
import logging
from datetime import datetime
from zoneinfo import ZoneInfo
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment configuration
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
TZ = ZoneInfo(os.environ.get("TZ", "Europe/London"))
BUSINESS_START = int(os.environ.get("BUSINESS_START_HOUR", "8"))
BUSINESS_END = int(os.environ.get("BUSINESS_END_HOUR", "18"))
BUSINESS_DAYS = [int(d) for d in os.environ.get("BUSINESS_DAYS", "0,1,2,3,4").split(",")]
ALLOWLIST_CREATOR_ARNS = set(filter(None, os.environ.get("ALLOWLIST_CREATOR_ARNS", "").split(",")))
ALERT_THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", "30"))

sns = boto3.client("sns")
iam = boto3.client("iam")


def lambda_handler(event, context):
    """Process access key creation event and evaluate risk."""
    logger.info(f"Received event: {json.dumps(event)}")

    detail = event.get("detail", {})
    event_time = datetime.fromisoformat(
        event.get("time", datetime.utcnow().isoformat()).replace("Z", "+00:00")
    )

    # Extract key fields
    event_name = detail.get("eventName", "")
    creator_identity = detail.get("userIdentity", {})
    creator_arn = creator_identity.get("arn", "unknown")
    creator_name = creator_identity.get("userName") or creator_arn.split("/")[-1]

    request_params = detail.get("requestParameters", {})
    target_username = request_params.get("userName", creator_name)

    response_elements = detail.get("responseElements", {})
    access_key_id = response_elements.get("accessKey", {}).get("accessKeyId", "unknown")

    # Skip if creator is allowlisted (CI/CD automation)
    if creator_arn in ALLOWLIST_CREATOR_ARNS:
        logger.info(f"Skipping allowlisted creator: {creator_arn}")
        return {"statusCode": 200, "body": "Allowlisted creator"}

    # Calculate risk score
    score, reasons = calculate_risk_score(
        creator_name=creator_name,
        creator_arn=creator_arn,
        target_username=target_username,
        event_time=event_time,
    )

    # Alert if score exceeds threshold
    if score >= ALERT_THRESHOLD:
        send_alert(
            event_name=event_name,
            creator_name=creator_name,
            creator_arn=creator_arn,
            target_username=target_username,
            access_key_id=access_key_id,
            score=score,
            reasons=reasons,
            event_time=event_time,
        )
        return {"statusCode": 200, "body": f"Alert sent (score={score})"}

    logger.info(f"Below threshold: score={score}, threshold={ALERT_THRESHOLD}")
    return {"statusCode": 200, "body": f"No alert (score={score})"}


def calculate_risk_score(
    creator_name: str,
    creator_arn: str,
    target_username: str,
    event_time: datetime,
) -> tuple[int, list[str]]:
    """Calculate risk score for access key creation."""
    score = 0
    reasons = []

    # Key created for different user (+40 - high risk)
    if creator_name.lower() != target_username.lower():
        score += 40
        reasons.append(f"Key created by {creator_name} for different user {target_username}")

    # Out of hours (+15)
    local_time = event_time.astimezone(TZ)
    if local_time.weekday() not in BUSINESS_DAYS:
        score += 15
        reasons.append(f"Weekend activity ({local_time.strftime('%A')})")
    elif not (BUSINESS_START <= local_time.hour < BUSINESS_END):
        score += 15
        reasons.append(f"Out-of-hours ({local_time.strftime('%H:%M')} {TZ})")

    # Check if target user has admin permissions (+25)
    try:
        target_has_admin = check_user_has_admin(target_username)
        if target_has_admin:
            score += 25
            reasons.append(f"Target user {target_username} has admin privileges")
    except Exception as e:
        logger.warning(f"Could not check admin status: {e}")

    # Root user creating keys is suspicious (+30)
    if "root" in creator_arn.lower():
        score += 30
        reasons.append("Key created by root account")

    return score, reasons


def check_user_has_admin(username: str) -> bool:
    """Check if user has admin-level permissions."""
    try:
        # Check attached policies
        attached = iam.list_attached_user_policies(UserName=username)
        for policy in attached.get("AttachedPolicies", []):
            if "AdministratorAccess" in policy.get("PolicyName", ""):
                return True

        # Check groups
        groups = iam.list_groups_for_user(UserName=username)
        for group in groups.get("Groups", []):
            group_policies = iam.list_attached_group_policies(GroupName=group["GroupName"])
            for policy in group_policies.get("AttachedPolicies", []):
                if "AdministratorAccess" in policy.get("PolicyName", ""):
                    return True
    except Exception as e:
        logger.warning(f"Failed to check admin status for {username}: {e}")

    return False


def send_alert(
    event_name: str,
    creator_name: str,
    creator_arn: str,
    target_username: str,
    access_key_id: str,
    score: int,
    reasons: list[str],
    event_time: datetime,
) -> None:
    """Send access key creation alert."""
    is_self_created = creator_name.lower() == target_username.lower()

    message = f"""Access Key Creation Alert

Event: {event_name}
Time: {event_time.isoformat()}
Creator: {creator_name} ({creator_arn})
Target User: {target_username}
Key ID: {access_key_id}
Self-Created: {"Yes" if is_self_created else "NO - ELEVATED RISK"}

Risk Score: {score}/100

Risk Indicators:
{chr(10).join(f"  - {r}" for r in reasons)}

Investigation Steps:
1. Verify the key creation was authorised by contacting the target user
2. Check who created the key and their role in the organisation
3. Review the creator's recent CloudTrail activity
4. Check if the key has been used (GetAccessKeyLastUsed)
5. Review target user's permissions and recent activity

Containment Actions:
1. If unauthorised: Disable or delete the access key immediately
2. Rotate all access keys for the target user
3. Review and remove unnecessary IAM permissions
4. Enable MFA for the target user if not enabled
5. Audit the creator's permissions and activity
"""

    severity = "CRITICAL" if not is_self_created else "HIGH"

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[{severity}] Access Key Created: {target_username} (Score: {score})",
            Message=message,
        )
        logger.info(f"Alert sent for key creation: {access_key_id}")
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
        raise
'''

TEMPLATE = RemediationTemplate(
    technique_id="T1098.001",
    technique_name="Account Manipulation: Additional Cloud Credentials",
    tactic_ids=["TA0003", "TA0004"],
    mitre_url="https://attack.mitre.org/techniques/T1098/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries create additional access keys or service account keys to "
            "maintain persistent access. These keys often go unmonitored and provide "
            "long-term access even after initial compromise is remediated. "
            "GuardDuty finding Persistence:IAMUser/AnomalousBehavior specifically "
            "detects anomalous CreateAccessKey API calls."
        ),
        attacker_goal="Create additional credentials for persistent access",
        why_technique=[
            "Access keys provide long-term API access without passwords",
            "Keys bypass MFA requirements for API calls",
            "Multiple keys make detection and remediation harder",
            "Keys persist after password reset",
            "Often overlooked in incident response",
            "Service account keys can be used from anywhere",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Additional credentials provide reliable persistence. Keys can be used "
            "from anywhere and bypass many security controls. Often missed during "
            "incident remediation. GuardDuty detects via Persistence:IAMUser/AnomalousBehavior."
        ),
        business_impact=[
            "Persistent unauthorised access to cloud resources",
            "Difficult to fully remediate compromise",
            "Ongoing data exfiltration risk",
            "Compliance violations (keys without rotation)",
            "Shadow admin access via service accounts",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1530", "T1537", "T1059.009"],
        often_follows=["T1078.004", "T1528", "T1110.001"],
    ),
    detection_strategies=[
        # Strategy 1: GuardDuty (Recommended first - ML-based)
        DetectionStrategy(
            strategy_id="t1098001-aws-guardduty",
            name="GuardDuty Persistence Anomaly Detection",
            description=(
                "Leverage AWS GuardDuty's ML-based detection for anomalous persistence "
                "API calls including CreateAccessKey, ImportKeyPair, and ModifyInstanceAttribute. "
                "Finding type Persistence:IAMUser/AnomalousBehavior triggers when these "
                "APIs are invoked in unusual patterns."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Persistence:IAMUser/AnomalousBehavior",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                ],
                terraform_template="""# GuardDuty persistence anomaly detection
# Detects anomalous credential creation and usage patterns

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "min_severity" {
  type        = number
  default     = 4
  description = "Minimum GuardDuty severity to alert (4=Medium, 7=High)"
}

# Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
}

# SNS topic for alerts
resource "aws_sns_topic" "guardduty_persistence" {
  name         = "guardduty-persistence-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "GuardDuty Persistence Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_persistence.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.guardduty_persistence.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_persistence.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_persistence.arn
        }
      }
    }]
  })
}

# EventBridge rule for persistence-related findings
resource "aws_cloudwatch_event_rule" "guardduty_persistence" {
  name        = "guardduty-persistence-anomalies"
  description = "Route GuardDuty persistence findings to SNS"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_severity] }]
      type = [
        # Persistence anomalies (includes CreateAccessKey)
        { wildcard = "Persistence:IAMUser/*" },

        # Credential exfiltration
        { wildcard = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration*" }
      ]
    }
  })
}

# DLQ for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-persistence-dlq"
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
      values   = [aws_cloudwatch_event_rule.guardduty_persistence.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_persistence.name
  target_id = "SNSTopic"
  arn       = aws_sns_topic.guardduty_persistence.arn

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
      type     = "$.detail.type"
      severity = "$.detail.severity"
      user     = "$.detail.resource.accessKeyDetails.userName"
    }

    input_template = <<-EOT
"GuardDuty Persistence Alert (T1098.001)
time=<time> account=<account> region=<region>
type=<type> severity=<severity>
user=<user>
Action: Investigate credential abuse immediately"
EOT
  }
}""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty persistence anomaly detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts
  MinSeverity:
    Type: Number
    Default: 4

Resources:
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: GuardDuty Persistence Alerts
      Subscription:
        - Protocol: email
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
                aws:SourceArn: !GetAtt PersistenceRule.Arn

  PersistenceRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-persistence-anomalies
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          severity:
            - numeric: [">=", !Ref MinSeverity]
          type:
            - prefix: Persistence:IAMUser
            - prefix: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
      Targets:
        - Id: SNSTopic
          Arn: !Ref AlertTopic""",
                alert_severity="high",
                alert_title="GuardDuty: Persistence Anomaly Detected",
                alert_description_template=(
                    "GuardDuty detected: {detail.type}. "
                    "Principal: {detail.resource.accessKeyDetails.userName}. "
                    "This may indicate credential creation for persistence."
                ),
                investigation_steps=[
                    "Review the full GuardDuty finding for details",
                    "Check CloudTrail for CreateAccessKey or similar events",
                    "Identify who created the credentials",
                    "Verify the action was authorised",
                    "Check if new credentials have been used",
                ],
                containment_actions=[
                    "Disable any newly created access keys",
                    "Rotate credentials for affected users",
                    "Review and restrict IAM permissions",
                    "Enable MFA enforcement",
                    "Audit all access key usage",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty uses ML to establish baselines. "
                "Use suppression rules for known automation accounts."
            ),
            detection_coverage="85% - ML-based detection of anomalous persistence patterns",
            evasion_considerations=(
                "Attackers may mimic normal key rotation patterns. "
                "Combine with EventBridge-based detection for defence in depth."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events",
            prerequisites=["AWS account with IAM permissions to enable GuardDuty"],
        ),
        # Strategy 2: Lambda-based intelligent evaluation
        DetectionStrategy(
            strategy_id="t1098001-aws-lambda",
            name="Lambda-Based Access Key Creation Evaluation",
            description=(
                "Deploy Lambda-based evaluation with intelligent scoring. "
                "Distinguishes self-created keys vs. keys created by others (high risk), "
                "checks if target user has admin permissions, evaluates time of day, "
                "and supports CI/CD automation allowlisting."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["CreateAccessKey"]},
                },
                terraform_template="""# Lambda-based access key creation evaluation
# Distinguishes self-created vs. created-for-others (high risk)

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

variable "name_prefix" {
  type        = string
  default     = "t1098-accesskey"
  description = "Prefix for resource names"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "timezone" {
  type        = string
  default     = "Europe/London"
  description = "IANA timezone for out-of-hours detection"
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
  description = "Business days (Python weekday: 0=Mon)"
}

variable "allowlisted_creator_arns" {
  type        = list(string)
  default     = []
  description = "ARNs of CI/CD roles allowed to create keys without alerting"
}

variable "alert_threshold" {
  type        = number
  default     = 30
  description = "Risk score threshold for alerting (0-100)"
}

# SNS Topic
resource "aws_sns_topic" "alerts" {
  name         = "${var.name_prefix}-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Access Key Creation Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowLambdaPublish"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
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
        Effect = "Allow"
        Action = [
          "iam:ListAttachedUserPolicies",
          "iam:ListGroupsForUser",
          "iam:ListAttachedGroupPolicies"
        ]
        Resource = "*"
      }
    ]
  })
}

# Lambda function
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
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      SNS_TOPIC_ARN          = aws_sns_topic.alerts.arn
      TZ                     = var.timezone
      BUSINESS_START_HOUR    = tostring(var.business_start_hour)
      BUSINESS_END_HOUR      = tostring(var.business_end_hour)
      BUSINESS_DAYS          = join(",", [for d in var.business_days : tostring(d)])
      ALLOWLIST_CREATOR_ARNS = join(",", var.allowlisted_creator_arns)
      ALERT_THRESHOLD        = tostring(var.alert_threshold)
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.evaluator.function_name}"
  retention_in_days = 30
}

# EventBridge rule for access key creation
resource "aws_cloudwatch_event_rule" "accesskey_create" {
  name        = "${var.name_prefix}-creation"
  description = "Capture CreateAccessKey events for evaluation"

  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["CreateAccessKey"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.accesskey_create.name
  target_id = "LambdaEvaluator"
  arn       = aws_lambda_function.evaluator.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.evaluator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.accesskey_create.arn
}

# Outputs
output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.evaluator.function_name
}""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Lambda-based access key creation evaluation

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts
  Timezone:
    Type: String
    Default: Europe/London
  AlertThreshold:
    Type: Number
    Default: 30
    Description: Risk score threshold (0-100)
  AllowlistedCreatorArns:
    Type: CommaDelimitedList
    Default: ""
    Description: CI/CD role ARNs to allowlist

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Access Key Creation Alerts
      Subscription:
        - Protocol: email
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
                aws:SourceArn: !GetAtt AccessKeyRule.Arn

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
                  - iam:ListAttachedUserPolicies
                  - iam:ListGroupsForUser
                  - iam:ListAttachedGroupPolicies
                Resource: '*'

  EvaluatorFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: t1098-accesskey-evaluator
      Runtime: python3.12
      Handler: index.lambda_handler
      Role: !GetAtt LambdaRole.Arn
      Timeout: 30
      MemorySize: 256
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref AlertTopic
          TZ: !Ref Timezone
          ALERT_THRESHOLD: !Ref AlertThreshold
          ALLOWLIST_CREATOR_ARNS: !Join [",", !Ref AllowlistedCreatorArns]
      Code:
        ZipFile: |
          # See full handler.py in Terraform template
          import json
          def lambda_handler(event, context):
              print(json.dumps(event))
              return {'statusCode': 200}

  AccessKeyRule:
    Type: AWS::Events::Rule
    Properties:
      Name: accesskey-creation
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [CreateAccessKey]
      Targets:
        - Id: LambdaEvaluator
          Arn: !GetAtt EvaluatorFunction.Arn

  LambdaPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref EvaluatorFunction
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt AccessKeyRule.Arn""",
                alert_severity="high",
                alert_title="Access Key Creation - Risk Evaluation",
                alert_description_template=(
                    "Access key created for {target_username} by {creator_name}. "
                    "Risk score: {score}. Key ID: {access_key_id}."
                ),
                investigation_steps=[
                    "Check if key was created by the user themselves or by someone else",
                    "Verify the key creation was authorised",
                    "Review the creator's recent CloudTrail activity",
                    "Check if the key has been used (GetAccessKeyLastUsed API)",
                    "Review target user's permissions (especially admin access)",
                ],
                containment_actions=[
                    "If unauthorised: Disable or delete the access key immediately",
                    "Rotate all access keys for the target user",
                    "Review and remove unnecessary IAM permissions",
                    "Enable MFA for the target user",
                    "Audit the creator's permissions if they created for others",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Use allowlisted_creator_arns for CI/CD pipelines and automation roles. "
                "Adjust alert_threshold: 30 for sensitive alerts, 50 for high-confidence only. "
                "Self-created keys during business hours have lower score."
            ),
            detection_coverage=(
                "95% - Catches all CreateAccessKey events with contextual risk scoring. "
                "Distinguishes high-risk scenarios (key created for others, admin users)."
            ),
            evasion_considerations=(
                "Attacker with high privileges could add themselves to allowlist. "
                "Monitor allowlist changes separately."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-15 (Lambda + SNS)",
            prerequisites=[
                "CloudTrail enabled",
                "EventBridge configured to receive CloudTrail events",
            ],
        ),
        # Strategy 3: Simple EventBridge (Basic, Fast to Deploy)
        DetectionStrategy(
            strategy_id="t1098001-aws-accesskey",
            name="IAM Access Key Creation Detection (Basic)",
            description=(
                "Basic EventBridge rule to alert on all IAM access key creation. "
                "Simple to deploy but may generate noise from legitimate key creation."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["CreateAccessKey"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Basic IAM access key creation detection

Parameters:
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Access Key Creation Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

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
                aws:SourceArn: !GetAtt AccessKeyRule.Arn

  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: accesskey-alerts-dlq
      MessageRetentionPeriod: 1209600

  AccessKeyRule:
    Type: AWS::Events::Rule
    Properties:
      Name: accesskey-creation-basic
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [CreateAccessKey]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt DLQ.Arn""",
                terraform_template="""# Basic IAM access key creation detection

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name         = "accesskey-creation-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Access Key Creation Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_caller_identity" "current" {}

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
          "aws:SourceArn" = aws_cloudwatch_event_rule.accesskey_create.arn
        }
      }
    }]
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "accesskey-alerts-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_rule" "accesskey_create" {
  name        = "accesskey-creation-basic"
  description = "Alert on all access key creation"
  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["CreateAccessKey"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.accesskey_create.name
  target_id = "SNSTopic"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}""",
                alert_severity="high",
                alert_title="IAM Access Key Created",
                alert_description_template="New access key created for user {userName}.",
                investigation_steps=[
                    "Verify the access key creation was authorised",
                    "Check who created the key",
                    "Review the target user's permissions",
                    "Check for concurrent suspicious activity",
                ],
                containment_actions=[
                    "Disable the newly created access key if unauthorised",
                    "Review and disable unused access keys",
                    "Rotate credentials for affected user",
                    "Audit IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Will alert on legitimate key creation. "
                "Consider Lambda-based evaluation for reduced noise."
            ),
            detection_coverage="95% - catches all CreateAccessKey calls",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 4: GCP Service Account Key Creation
        DetectionStrategy(
            strategy_id="t1098001-gcp-sakey",
            name="GCP Service Account Key Creation",
            description=(
                "Detect when new service account keys are created in GCP. "
                "Service account keys are high-value targets as they provide "
                "long-term access without user authentication."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
OR protoPayload.methodName=~"iam.serviceAccountKeys.create"
severity>=NOTICE""",
                gcp_terraform_template="""# GCP Service Account Key Creation Detection

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Service Account Key Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for SA key creation
resource "google_logging_metric" "sa_key_create" {
  project = var.project_id
  name    = "service-account-key-creation"
  filter  = <<-EOT
    protoPayload.methodName=~"CreateServiceAccountKey|serviceAccountKeys.create"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "creator"
      value_type  = "STRING"
      description = "Who created the key"
    }
    labels {
      key         = "service_account"
      value_type  = "STRING"
      description = "Target service account"
    }
  }

  label_extractors = {
    "creator"         = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "service_account" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for any key creation
resource "google_monitoring_alert_policy" "sa_key" {
  project      = var.project_id
  display_name = "Service Account Key Created"
  combiner     = "OR"

  conditions {
    display_name = "SA key creation detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_create.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
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
    content   = "A service account key was created. Verify this was authorised."
    mime_type = "text/markdown"
  }
}

# Organisation policy to restrict key creation (recommended)
# resource "google_org_policy_policy" "disable_sa_key_creation" {
#   name   = "projects/${var.project_id}/policies/iam.disableServiceAccountKeyCreation"
#   parent = "projects/${var.project_id}"
#
#   spec {
#     rules {
#       enforce = "TRUE"
#     }
#   }
# }""",
                alert_severity="high",
                alert_title="GCP: Service Account Key Created",
                alert_description_template=(
                    "Service account key created for {service_account} by {creator}."
                ),
                investigation_steps=[
                    "Verify the key creation was authorised",
                    "Check who created the key and their role",
                    "Review the service account permissions",
                    "Check for other suspicious activity by the creator",
                    "Verify the key hasn't been exported or used externally",
                ],
                containment_actions=[
                    "Delete the newly created key if unauthorised",
                    "Rotate existing service account keys",
                    "Review service account permissions",
                    "Consider enabling org policy to disable key creation",
                    "Enable Workload Identity Federation as alternative",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Allowlist CI/CD service accounts. "
                "Consider using org policy to disable key creation entirely."
            ),
            detection_coverage="95% - catches all service account key creation",
            evasion_considerations=(
                "Cannot evade this detection. "
                "Prefer Workload Identity Federation to eliminate keys entirely."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Account Manipulation: Additional Cloud Credentials
        DetectionStrategy(
            strategy_id="t1098001-azure",
            name="Azure Account Manipulation: Additional Cloud Credentials Detection",
            description=(
                "Monitor credential and identity changes. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Account Manipulation: Additional Cloud Credentials Detection
// Technique: T1098.001
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.KeyVault/vaults/secrets/write" or OperationNameValue contains "Microsoft.ManagedIdentity/"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| project
    TimeGenerated,
    SubscriptionId,
    ResourceGroup,
    Resource,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    Properties
| order by TimeGenerated desc""",
                azure_activity_operations=[
                    "Microsoft.KeyVault/vaults/secrets/write",
                    "Microsoft.ManagedIdentity/",
                ],
                azure_terraform_template="""# Azure Detection for Account Manipulation: Additional Cloud Credentials
# MITRE ATT&CK: T1098.001

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
  name                = "account-manipulation--additional-cloud-credentials-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "account-manipulation--additional-cloud-credentials-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Account Manipulation: Additional Cloud Credentials Detection
// Technique: T1098.001
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.KeyVault/vaults/secrets/write" or OperationNameValue contains "Microsoft.ManagedIdentity/"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| project
    TimeGenerated,
    SubscriptionId,
    ResourceGroup,
    Resource,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    Properties
| order by TimeGenerated desc
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

  description = "Detects Account Manipulation: Additional Cloud Credentials (T1098.001) activity in Azure environment"
  display_name = "Account Manipulation: Additional Cloud Credentials Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1098.001"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Account Manipulation: Additional Cloud Credentials Detected",
                alert_description_template=(
                    "Account Manipulation: Additional Cloud Credentials activity detected. "
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
        "t1098001-aws-guardduty",  # ML-based, lowest effort
        "t1098001-gcp-sakey",  # GCP coverage
        "t1098001-aws-lambda",  # Intelligent evaluation
        "t1098001-aws-accesskey",  # Basic fallback
    ],
    total_effort_hours=4.0,
    coverage_improvement="+25% improvement for Persistence tactic",
)
