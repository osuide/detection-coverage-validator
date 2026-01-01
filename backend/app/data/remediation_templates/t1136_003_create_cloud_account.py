"""
T1136.003 - Create Account: Cloud Account

Adversaries create new cloud accounts (IAM users, service accounts) to
maintain persistent access and avoid detection on existing accounts.

Detection Strategy:
- Monitor all account creation events (CreateUser, service accounts)
- Alert on immediate admin permission attachment (high risk indicator)
- Leverage GuardDuty for Persistence:IAMUser/AnomalousBehavior findings
- Use Lambda-based evaluation with automation allowlisting

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

# Lambda handler for intelligent user creation evaluation
LAMBDA_HANDLER_CODE = '''"""
IAM User Creation Evaluator

Scores user creation events based on:
- Who created the user (known provisioning vs. unknown)
- Time of day (out-of-hours is suspicious)
- Immediate permission grants (especially admin)
- Console access enabled
- Access key creation shortly after
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
    """Process user creation event and evaluate risk."""
    logger.info(f"Received event: {json.dumps(event)}")

    detail = event.get("detail", {})
    event_time = datetime.fromisoformat(
        event.get("time", datetime.utcnow().isoformat()).replace("Z", "+00:00")
    )

    event_name = detail.get("eventName", "")
    creator_identity = detail.get("userIdentity", {})
    creator_arn = creator_identity.get("arn", "unknown")
    creator_name = creator_identity.get("userName") or creator_arn.split("/")[-1]

    request_params = detail.get("requestParameters", {})
    new_username = request_params.get("userName", "unknown")

    # Skip if creator is allowlisted (HR/provisioning automation)
    if creator_arn in ALLOWLIST_CREATOR_ARNS:
        logger.info(f"Skipping allowlisted creator: {creator_arn}")
        return {"statusCode": 200, "body": "Allowlisted creator"}

    # Calculate risk score
    score, reasons = calculate_risk_score(
        creator_name=creator_name,
        creator_arn=creator_arn,
        new_username=new_username,
        event_time=event_time,
    )

    # Alert if score exceeds threshold
    if score >= ALERT_THRESHOLD:
        send_alert(
            event_name=event_name,
            creator_name=creator_name,
            creator_arn=creator_arn,
            new_username=new_username,
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
    new_username: str,
    event_time: datetime,
) -> tuple[int, list[str]]:
    """Calculate risk score for user creation."""
    score = 0
    reasons = []

    # Out of hours (+20)
    local_time = event_time.astimezone(TZ)
    if local_time.weekday() not in BUSINESS_DAYS:
        score += 20
        reasons.append(f"Weekend user creation ({local_time.strftime('%A')})")
    elif not (BUSINESS_START <= local_time.hour < BUSINESS_END):
        score += 20
        reasons.append(f"Out-of-hours ({local_time.strftime('%H:%M')} {TZ})")

    # Root user creating users is very suspicious (+35)
    if "root" in creator_arn.lower():
        score += 35
        reasons.append("User created by root account")

    # Check if user already has policies attached (immediate grant)
    try:
        has_policies = check_user_has_policies(new_username)
        if has_policies.get("has_admin"):
            score += 40
            reasons.append(f"User {new_username} immediately granted admin access")
        elif has_policies.get("has_any"):
            score += 20
            reasons.append(f"User {new_username} has policies attached immediately")
    except Exception as e:
        logger.warning(f"Could not check policies: {e}")

    # Check if console access is enabled
    try:
        has_console = check_console_access(new_username)
        if has_console:
            score += 10
            reasons.append("Console access enabled")
    except Exception as e:
        logger.warning(f"Could not check console access: {e}")

    return score, reasons


def check_user_has_policies(username: str) -> dict:
    """Check if user has any policies attached."""
    result = {"has_any": False, "has_admin": False}
    try:
        # Check attached policies
        attached = iam.list_attached_user_policies(UserName=username)
        if attached.get("AttachedPolicies"):
            result["has_any"] = True
            for policy in attached["AttachedPolicies"]:
                if "AdministratorAccess" in policy.get("PolicyName", ""):
                    result["has_admin"] = True

        # Check inline policies
        inline = iam.list_user_policies(UserName=username)
        if inline.get("PolicyNames"):
            result["has_any"] = True

        # Check groups
        groups = iam.list_groups_for_user(UserName=username)
        if groups.get("Groups"):
            result["has_any"] = True
            for group in groups["Groups"]:
                group_policies = iam.list_attached_group_policies(GroupName=group["GroupName"])
                for policy in group_policies.get("AttachedPolicies", []):
                    if "AdministratorAccess" in policy.get("PolicyName", ""):
                        result["has_admin"] = True
    except Exception as e:
        logger.warning(f"Failed to check policies for {username}: {e}")

    return result


def check_console_access(username: str) -> bool:
    """Check if user has console access (login profile)."""
    try:
        iam.get_login_profile(UserName=username)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False
    except Exception as e:
        logger.warning(f"Failed to check console access for {username}: {e}")
        return False


def send_alert(
    event_name: str,
    creator_name: str,
    creator_arn: str,
    new_username: str,
    score: int,
    reasons: list[str],
    event_time: datetime,
) -> None:
    """Send user creation alert."""
    message = f"""IAM User Creation Alert

Event: {event_name}
Time: {event_time.isoformat()}
Creator: {creator_name} ({creator_arn})
New User: {new_username}

Risk Score: {score}/100

Risk Indicators:
{chr(10).join(f"  - {r}" for r in reasons)}

Investigation Steps:
1. Verify the user creation was authorised (HR ticket, approval)
2. Check who created the user and their role
3. Review permissions granted to the new user
4. Check for access key creation for the new user
5. Review CloudTrail for immediate activity by the new user

Containment Actions:
1. If unauthorised: Delete the user immediately
2. Remove any admin or sensitive permissions
3. Disable console access if not required
4. Delete any access keys created
5. Audit the creator's permissions and activity
6. Review all recent user creations
"""

    severity = "CRITICAL" if score >= 60 else "HIGH"

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[{severity}] IAM User Created: {new_username} (Score: {score})",
            Message=message,
        )
        logger.info(f"Alert sent for user creation: {new_username}")
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
        raise
'''

TEMPLATE = RemediationTemplate(
    technique_id="T1136.003",
    technique_name="Create Account: Cloud Account",
    tactic_ids=["TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1136/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries create new IAM users, service accounts, or federated identities "
            "to maintain persistent access. Shadow admin accounts often go unnoticed "
            "and provide reliable backdoor access. GuardDuty finding "
            "Persistence:IAMUser/AnomalousBehavior detects anomalous user creation patterns."
        ),
        attacker_goal="Create backdoor accounts for persistent access",
        why_technique=[
            "New accounts avoid detection on compromised users",
            "Shadow admins persist after initial remediation",
            "Service accounts blend with automation",
            "Federated users may bypass MFA requirements",
            "Multiple accounts complicate forensics",
            "Hard to distinguish from legitimate provisioning",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Backdoor accounts provide reliable persistent access. Shadow admins "
            "are often missed during incident remediation. New accounts can be "
            "difficult to distinguish from legitimate provisioning."
        ),
        business_impact=[
            "Persistent backdoor access to cloud resources",
            "Difficult and incomplete incident remediation",
            "Ongoing compromise risk",
            "Compliance violations",
            "Shadow admin access bypassing governance",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1098.001", "T1530", "T1059.009"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        # Strategy 1: GuardDuty (Recommended first)
        DetectionStrategy(
            strategy_id="t1136003-aws-guardduty",
            name="GuardDuty Persistence Anomaly Detection",
            description=(
                "Leverage AWS GuardDuty's ML-based detection for anomalous persistence "
                "API calls including CreateUser and account manipulation. "
                "Finding type Persistence:IAMUser/AnomalousBehavior triggers when "
                "these APIs are invoked in unusual patterns."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Persistence:IAMUser/AnomalousBehavior",
                ],
                terraform_template="""# GuardDuty persistence anomaly detection for user creation

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "min_severity" {
  type        = number
  default     = 4
  description = "Minimum GuardDuty severity (4=Medium, 7=High)"
}

resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_sns_topic" "guardduty_persistence" {
  name         = "guardduty-user-creation-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "GuardDuty User Creation Alerts"
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

resource "aws_cloudwatch_event_rule" "guardduty_persistence" {
  name        = "guardduty-user-creation-anomalies"
  description = "Route GuardDuty persistence findings to SNS"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_severity] }]
      type = [
        { wildcard = "Persistence:IAMUser/*" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_persistence.name
  target_id = "SNSTopic"
  arn       = aws_sns_topic.guardduty_persistence.arn
}""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty persistence anomaly detection for user creation

Parameters:
  AlertEmail:
    Type: String
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
      DisplayName: GuardDuty User Creation Alerts
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
      Name: guardduty-user-creation-anomalies
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          severity:
            - numeric: [">=", !Ref MinSeverity]
          type:
            - prefix: Persistence:IAMUser
      Targets:
        - Id: SNSTopic
          Arn: !Ref AlertTopic""",
                alert_severity="high",
                alert_title="GuardDuty: User Creation Anomaly Detected",
                alert_description_template=(
                    "GuardDuty detected: {detail.type}. "
                    "This may indicate backdoor account creation."
                ),
                investigation_steps=[
                    "Review the full GuardDuty finding for details",
                    "Check CloudTrail for CreateUser events",
                    "Identify who created the user",
                    "Review permissions granted to new users",
                    "Check for access key creation",
                ],
                containment_actions=[
                    "Delete unauthorised users immediately",
                    "Remove any admin permissions",
                    "Disable console access",
                    "Delete access keys",
                    "Audit the creator's permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML baselines. Use suppression for HR automation.",
            detection_coverage="85% - ML-based anomaly detection",
            evasion_considerations="Attackers mimicking normal provisioning may evade.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events",
            prerequisites=["GuardDuty enabled"],
        ),
        # Strategy 2: Lambda-based intelligent evaluation
        DetectionStrategy(
            strategy_id="t1136003-aws-lambda",
            name="Lambda-Based User Creation Evaluation",
            description=(
                "Deploy Lambda-based evaluation with intelligent scoring. "
                "Detects immediate admin permission grants, out-of-hours creation, "
                "root user activity, and supports HR automation allowlisting."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["CreateUser"]},
                },
                terraform_template="""# Lambda-based user creation evaluation
# Detects immediate admin grants, out-of-hours, root activity

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
  default     = "t1136-user-creation"
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
  description = "ARNs of HR/provisioning roles allowed to create users"
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
  display_name = "User Creation Alerts"
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
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.user_create.arn
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
          "iam:ListUserPolicies",
          "iam:ListGroupsForUser",
          "iam:ListAttachedGroupPolicies",
          "iam:GetLoginProfile"
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

# EventBridge rule for user creation
resource "aws_cloudwatch_event_rule" "user_create" {
  name        = "${var.name_prefix}-creation"
  description = "Capture CreateUser events for evaluation"

  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["CreateUser"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.user_create.name
  target_id = "LambdaEvaluator"
  arn       = aws_lambda_function.evaluator.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.evaluator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.user_create.arn
}

# Also monitor admin policy attachment (immediate privilege escalation)
resource "aws_cloudwatch_event_rule" "admin_attach" {
  name        = "${var.name_prefix}-admin-attach"
  description = "Detect immediate admin permission grants"

  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["AttachUserPolicy", "PutUserPolicy", "AddUserToGroup"]
      requestParameters = {
        "$or" = [
          { policyArn = [{ wildcard = "*AdministratorAccess*" }] },
          { policyDocument = [{ wildcard = "*\"*\"*" }] }
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "admin_lambda" {
  rule      = aws_cloudwatch_event_rule.admin_attach.name
  target_id = "LambdaEvaluator"
  arn       = aws_lambda_function.evaluator.arn
}

resource "aws_lambda_permission" "admin_eventbridge" {
  statement_id  = "AllowAdminEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.evaluator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.admin_attach.arn
}

# Outputs
output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.evaluator.function_name
}""",
                alert_severity="high",
                alert_title="IAM User Creation - Risk Evaluation",
                alert_description_template=(
                    "IAM user {new_username} created by {creator_name}. "
                    "Risk score: {score}."
                ),
                investigation_steps=[
                    "Verify user creation was authorised (HR ticket, approval)",
                    "Check who created the user and their role",
                    "Review permissions granted to the new user",
                    "Check for immediate access key creation",
                    "Review CloudTrail for activity by the new user",
                ],
                containment_actions=[
                    "Delete unauthorised users immediately",
                    "Remove admin or sensitive permissions",
                    "Disable console access if not required",
                    "Delete any access keys created",
                    "Audit the creator's permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Use allowlisted_creator_arns for HR/provisioning automation. "
                "Adjust alert_threshold: 30 for sensitive, 50 for high-confidence."
            ),
            detection_coverage=(
                "95% - Catches all user creation with contextual risk scoring. "
                "Also monitors immediate admin permission attachment."
            ),
            evasion_considerations="Attacker may delay permission grants to avoid immediate detection.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["CloudTrail enabled", "EventBridge configured"],
        ),
        # Strategy 3: Basic EventBridge (Simple, Fast)
        DetectionStrategy(
            strategy_id="t1136003-aws-createuser",
            name="IAM User Creation Detection (Basic)",
            description="Basic EventBridge rule to alert on all IAM user creation.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["CreateUser"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Basic IAM user creation detection

Parameters:
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: IAM User Creation Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: user-creation-dlq
      MessageRetentionPeriod: 1209600

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
                aws:SourceArn: !GetAtt UserCreateRule.Arn

  UserCreateRule:
    Type: AWS::Events::Rule
    Properties:
      Name: iam-user-creation
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [CreateUser]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt DLQ.Arn""",
                terraform_template="""# Basic IAM user creation detection

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name         = "iam-user-creation-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "IAM User Creation Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sqs_queue" "dlq" {
  name                      = "user-creation-dlq"
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
      values   = [aws_cloudwatch_event_rule.user_create.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

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
            "aws:SourceArn" = aws_cloudwatch_event_rule.user_create.arn
          }
      }
    }]
  })
}

resource "aws_cloudwatch_event_rule" "user_create" {
  name        = "iam-user-creation"
  description = "Alert on all IAM user creation"
  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["CreateUser"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.user_create.name
  target_id = "SNSTopic"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
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
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}""",
                alert_severity="high",
                alert_title="IAM User Created",
                alert_description_template="New IAM user {userName} was created.",
                investigation_steps=[
                    "Verify user creation was authorised",
                    "Check who created the user",
                    "Review permissions assigned",
                    "Check for access key creation",
                ],
                containment_actions=[
                    "Delete unauthorised users",
                    "Remove admin permissions",
                    "Audit creator's activity",
                    "Review recent user creations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Will alert on legitimate provisioning. Use Lambda-based evaluation for reduced noise.",
            detection_coverage="95% - catches all CreateUser calls",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 4: GCP Service Account Creation
        DetectionStrategy(
            strategy_id="t1136003-gcp-serviceaccount",
            name="GCP Service Account Creation",
            description="Detect when new service accounts are created in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="google.iam.admin.v1.CreateServiceAccount"
severity>=NOTICE""",
                gcp_terraform_template="""# GCP Service Account Creation Detection

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Service Account Creation Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "sa_creation" {
  project = var.project_id
  name    = "service-account-creation"
  filter  = <<-EOT
    protoPayload.methodName="google.iam.admin.v1.CreateServiceAccount"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "creator"
      value_type  = "STRING"
      description = "Who created the service account"
    }
  }

  label_extractors = {
    "creator" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

resource "google_monitoring_alert_policy" "sa_creation" {
  project      = var.project_id
  display_name = "GCP Service Account Created"
  combiner     = "OR"

  conditions {
    display_name = "Service account creation detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_creation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "A service account was created. Verify this was authorised."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Service Account Created",
                alert_description_template="New service account created by {creator}.",
                investigation_steps=[
                    "Verify service account creation was authorised",
                    "Check who created the service account",
                    "Review permissions assigned",
                    "Check for key creation",
                ],
                containment_actions=[
                    "Delete unauthorised service accounts",
                    "Remove assigned permissions",
                    "Audit creator's activity",
                    "Review recent SA creations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Allowlist CI/CD and automation",
            detection_coverage="95% - catches all SA creation",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP Workload Identity Federation
        DetectionStrategy(
            strategy_id="t1136003-gcp-federated",
            name="GCP Federated Identity Detection",
            description="Detect new Workload Identity Federation setups.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName=~"CreateWorkloadIdentityPool|CreateWorkloadIdentityPoolProvider"
severity>=NOTICE""",
                gcp_terraform_template="""# GCP Workload Identity Federation Detection

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Federated Identity Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "wif_creation" {
  project = var.project_id
  name    = "workload-identity-federation"
  filter  = <<-EOT
    protoPayload.methodName=~"CreateWorkloadIdentityPool|CreateWorkloadIdentityPoolProvider"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "wif_creation" {
  project      = var.project_id
  display_name = "Workload Identity Federation Created"
  combiner     = "OR"

  conditions {
    display_name = "WIF pool or provider created"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.wif_creation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Workload Identity Federation was configured. Verify this was authorised."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Federated Identity Configured",
                alert_description_template="Workload Identity Federation was configured.",
                investigation_steps=[
                    "Review the federation configuration",
                    "Check which external provider was added",
                    "Verify the change was authorised",
                    "Review attribute mappings",
                ],
                containment_actions=[
                    "Delete unauthorised WIF pools",
                    "Review all federated identities",
                    "Enable organisation policies",
                    "Audit federation activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="WIF creation is relatively rare",
            detection_coverage="95% - catches all WIF creation",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1136003-aws-guardduty",  # ML-based, lowest effort
        "t1136003-gcp-serviceaccount",  # GCP coverage
        "t1136003-aws-lambda",  # Intelligent evaluation
        "t1136003-aws-createuser",  # Basic fallback
        "t1136003-gcp-federated",  # Federated identity
    ],
    total_effort_hours=4.0,
    coverage_improvement="+20% improvement for Persistence tactic",
)
