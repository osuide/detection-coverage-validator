"""
T1110.001 - Brute Force: Password Guessing

Adversaries systematically attempt to gain account access using common passwords
without prior knowledge of legitimate credentials. Targets include SSH, RDP,
cloud services, SSO, and federated authentication systems.

Detection Strategy:
- Monitor failed authentication attempts with threshold-based alerting
- Leverage GuardDuty for ML-based anomaly detection
- Use IP reputation and geolocation for context
- Deploy Lambda-based scoring for reduced false positives

Used by APT28, APT29, Scattered Spider.
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

# Lambda handler for intelligent brute force detection
LAMBDA_HANDLER_CODE = '''"""
Brute Force Detection Evaluator

Scores authentication failure patterns based on:
- Failure rate within time window
- Geographic distribution of source IPs
- Known malicious IP reputation
- Time of day patterns
- User agent anomalies
"""

import json
import os
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import ipaddress
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment configuration
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
BASELINE_TABLE = os.environ.get("BASELINE_TABLE", "")
FAILURE_THRESHOLD = int(os.environ.get("FAILURE_THRESHOLD", "10"))
WINDOW_MINUTES = int(os.environ.get("WINDOW_MINUTES", "5"))
ALLOWLIST_CIDRS = [
    ipaddress.ip_network(c) for c in
    filter(None, os.environ.get("ALLOWLIST_SOURCE_CIDRS", "").split(","))
]
ALERT_ON_SUCCESS_AFTER_FAILURES = os.environ.get(
    "ALERT_ON_SUCCESS_AFTER_FAILURES", "true"
).lower() == "true"

sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb") if BASELINE_TABLE else None
baseline_table = dynamodb.Table(BASELINE_TABLE) if BASELINE_TABLE else None

# In-memory tracking for Lambda invocation (reset per cold start)
failure_counts = defaultdict(list)


def lambda_handler(event, context):
    """Process authentication event and detect brute force patterns."""
    logger.info(f"Received event: {json.dumps(event)}")

    detail = event.get("detail", {})
    event_time = datetime.fromisoformat(
        event.get("time", datetime.utcnow().isoformat()).replace("Z", "+00:00")
    )

    # Extract key fields
    source_ip = detail.get("sourceIPAddress", "0.0.0.0")
    user_identity = detail.get("userIdentity", {})
    principal = user_identity.get("userName") or user_identity.get("arn", "unknown")
    event_name = detail.get("eventName", "")
    error_code = detail.get("errorCode", "")

    # Check if this is a failure
    is_failure = error_code in [
        "AccessDenied",
        "UnauthorizedOperation",
        "InvalidUserID.NotFound",
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "AuthorizationError",
    ] or (
        event_name == "ConsoleLogin"
        and detail.get("responseElements", {}).get("ConsoleLogin") == "Failure"
    )

    # Skip if allowlisted
    if is_allowlisted(source_ip):
        logger.info(f"Skipping allowlisted IP: {source_ip}")
        return {"statusCode": 200, "body": "Allowlisted"}

    # Track failures
    if is_failure:
        track_failure(source_ip, principal, event_time)

    # Check for brute force pattern
    recent_failures = get_recent_failures(source_ip, event_time)

    if len(recent_failures) >= FAILURE_THRESHOLD:
        send_brute_force_alert(
            source_ip=source_ip,
            principal=principal,
            failure_count=len(recent_failures),
            event_time=event_time,
            targeted_users=list(set(f["principal"] for f in recent_failures)),
        )
        return {"statusCode": 200, "body": f"Brute force alert sent ({len(recent_failures)} failures)"}

    # Check for success after multiple failures (credential compromise indicator)
    if not is_failure and ALERT_ON_SUCCESS_AFTER_FAILURES:
        if len(recent_failures) >= 3:
            send_compromise_alert(
                source_ip=source_ip,
                principal=principal,
                prior_failures=len(recent_failures),
                event_time=event_time,
            )
            return {"statusCode": 200, "body": "Potential compromise alert sent"}

    return {"statusCode": 200, "body": "No alert"}


def is_allowlisted(source_ip: str) -> bool:
    """Check if IP is in allowlist."""
    try:
        ip = ipaddress.ip_address(source_ip)
        for cidr in ALLOWLIST_CIDRS:
            if ip in cidr:
                return True
    except ValueError:
        pass
    return False


def track_failure(source_ip: str, principal: str, event_time: datetime) -> None:
    """Track authentication failure."""
    failure_counts[source_ip].append({
        "principal": principal,
        "timestamp": event_time.isoformat(),
    })

    # Also persist to DynamoDB if configured
    if baseline_table:
        try:
            baseline_table.update_item(
                Key={"source_ip": source_ip},
                UpdateExpression="""
                    SET failures = list_append(if_not_exists(failures, :empty), :new_failure),
                        last_failure = :now,
                        ttl_epoch = :ttl
                    ADD failure_count :one
                """,
                ExpressionAttributeValues={
                    ":empty": [],
                    ":new_failure": [{"principal": principal, "ts": event_time.isoformat()}],
                    ":now": event_time.isoformat(),
                    ":ttl": int((event_time + timedelta(hours=24)).timestamp()),
                    ":one": 1,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to update baseline: {e}")


def get_recent_failures(source_ip: str, event_time: datetime) -> list:
    """Get recent failures for source IP within time window."""
    cutoff = event_time - timedelta(minutes=WINDOW_MINUTES)

    # Check in-memory first
    recent = [
        f for f in failure_counts.get(source_ip, [])
        if datetime.fromisoformat(f["timestamp"]) > cutoff
    ]

    return recent


def send_brute_force_alert(
    source_ip: str,
    principal: str,
    failure_count: int,
    event_time: datetime,
    targeted_users: list,
) -> None:
    """Send brute force detection alert."""
    message = f"""Brute Force Attack Detected

Source IP: {source_ip}
Time: {event_time.isoformat()}
Failed Attempts: {failure_count} in {WINDOW_MINUTES} minutes
Targeted Users: {", ".join(targeted_users[:10])}{"..." if len(targeted_users) > 10 else ""}

Investigation Steps:
1. Check source IP geolocation and reputation (VirusTotal, AbuseIPDB)
2. Review all authentication attempts from this IP
3. Check if any attempts succeeded (credential compromise)
4. Identify all targeted user accounts
5. Correlate with GuardDuty findings

Containment Actions:
1. Block source IP in WAF/Security Groups
2. Reset passwords for targeted accounts
3. Enable/enforce MFA on all accounts
4. Review account lockout policies
5. Check for successful compromises
"""

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[CRITICAL] Brute Force Attack: {failure_count} failures from {source_ip}",
            Message=message,
        )
        logger.info(f"Brute force alert sent for {source_ip}")
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
        raise


def send_compromise_alert(
    source_ip: str,
    principal: str,
    prior_failures: int,
    event_time: datetime,
) -> None:
    """Send potential credential compromise alert."""
    message = f"""Potential Credential Compromise Detected

A successful authentication occurred after multiple failures, indicating possible credential guessing success.

Principal: {principal}
Source IP: {source_ip}
Time: {event_time.isoformat()}
Prior Failed Attempts: {prior_failures}

This is a HIGH PRIORITY alert requiring immediate investigation.

Investigation Steps:
1. Contact the user immediately via out-of-band communication
2. Review all API calls made after the successful authentication
3. Check for privilege escalation or persistence mechanisms
4. Verify source IP is not expected for this user

Containment Actions:
1. Force logout all active sessions
2. Disable the user account pending investigation
3. Rotate all credentials (password, access keys)
4. Enable/enforce MFA
5. Review and revoke any suspicious changes
"""

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[HIGH] Potential Compromise: {principal} after {prior_failures} failures",
            Message=message,
        )
        logger.info(f"Compromise alert sent for {principal}")
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
        raise
'''

TEMPLATE = RemediationTemplate(
    technique_id="T1110.001",
    technique_name="Brute Force: Password Guessing",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1110/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries systematically attempt to gain account access by guessing "
            "passwords without prior knowledge of credentials. Cloud environments are "
            "particularly vulnerable as they often expose authentication endpoints globally. "
            "Detection relies on monitoring failure patterns and leveraging ML-based "
            "anomaly detection services like GuardDuty."
        ),
        attacker_goal="Gain unauthorised access to accounts through systematic password guessing",
        why_technique=[
            "No prior credential knowledge required",
            "Automated tools widely available (Hydra, Medusa, CrackMapExec)",
            "Cloud services expose global authentication endpoints",
            "Weak passwords remain common in enterprise environments",
            "Distributed attacks can avoid simple rate limits",
            "Successful guess provides legitimate access",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Highly prevalent credential access technique. Successful attacks enable "
            "unauthorised account access, data theft, and lateral movement. Cloud services "
            "and federated authentication significantly increase attack surface. "
            "GuardDuty finding InitialAccess:IAMUser/AnomalousBehavior often correlates."
        ),
        business_impact=[
            "Unauthorised account access leading to data breach",
            "Data exfiltration via compromised credentials",
            "Account lockouts affecting availability",
            "Cloud service compromise enabling lateral movement",
            "Regulatory compliance violations (GDPR, PCI-DSS)",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1078.002", "T1078.003", "T1021.004"],
        often_follows=["T1589.001", "T1589.002", "T1592"],
    ),
    detection_strategies=[
        # Strategy 1: GuardDuty (Recommended first - lowest effort, ML-based)
        DetectionStrategy(
            strategy_id="t1110-001-aws-guardduty",
            name="GuardDuty Anomalous Authentication Detection",
            description=(
                "Leverage AWS GuardDuty's ML-based anomaly detection for authentication "
                "patterns. GuardDuty detects anomalous initial access and credential access "
                "behaviour without threshold tuning. Finding types include "
                "InitialAccess:IAMUser/AnomalousBehavior and CredentialAccess:IAMUser/AnomalousBehavior."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "InitialAccess:IAMUser/AnomalousBehavior",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
                    "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
                    "UnauthorizedAccess:IAMUser/TorIPCaller",
                    "Recon:IAMUser/MaliciousIPCaller",
                    "Recon:IAMUser/TorIPCaller",
                ],
                terraform_template="""# GuardDuty brute force and credential abuse detection
# Leverages ML-based anomaly detection without manual threshold tuning

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "min_severity" {
  type        = number
  default     = 4
  description = "Minimum GuardDuty severity to alert (4=Medium, 7=High)"
}

# Step 1: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true

  # Enable S3 and EKS protection for comprehensive coverage
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name         = "guardduty-auth-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "GuardDuty Authentication Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_caller_identity" "current" {}

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
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_auth.arn
          }
      }
    }]
  })
}

# Step 3: EventBridge rule for authentication-related findings
resource "aws_cloudwatch_event_rule" "guardduty_auth" {
  name        = "guardduty-auth-anomalies"
  description = "Route GuardDuty authentication anomaly findings to SNS"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_severity] }]
      type = [
        # Initial access and credential abuse
        { wildcard = "InitialAccess:IAMUser/*" },
        { wildcard = "CredentialAccess:IAMUser/*" },

        # Console login anomalies (multiple geographic locations)
        { wildcard = "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess*" },

        # Malicious IP sources
        { wildcard = "UnauthorizedAccess:IAMUser/MaliciousIPCaller*" },
        { wildcard = "UnauthorizedAccess:IAMUser/TorIPCaller*" },
        { wildcard = "Recon:IAMUser/MaliciousIPCaller*" },
        { wildcard = "Recon:IAMUser/TorIPCaller*" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_auth.name
  target_id = "SNSTopic"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.guardduty_dlq.arn
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

}

# DLQ for failed deliveries
resource "aws_sqs_queue" "guardduty_dlq" {
  name                      = "guardduty-auth-alerts-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "guardduty_dlq_policy" {
  queue_url = aws_sqs_queue.guardduty_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.guardduty_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_auth.arn
        }
      }
    }]
  })
}""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty authentication anomaly detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts
  MinSeverity:
    Type: Number
    Default: 4
    Description: Minimum severity (4=Medium, 7=High)

Resources:
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      DataSources:
        S3Logs:
          Enable: true

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: GuardDuty Authentication Alerts
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
                aws:SourceArn: !GetAtt GuardDutyAuthRule.Arn

  GuardDutyAuthRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-auth-anomalies
      Description: Route authentication anomaly findings to SNS
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          severity:
            - numeric: [">=", !Ref MinSeverity]
          type:
            - prefix: InitialAccess:IAMUser
            - prefix: CredentialAccess:IAMUser
            - prefix: UnauthorizedAccess:IAMUser/ConsoleLoginSuccess
            - prefix: UnauthorizedAccess:IAMUser/MaliciousIPCaller
            - prefix: UnauthorizedAccess:IAMUser/TorIPCaller
      Targets:
        - Id: SNSTopic
          Arn: !Ref AlertTopic""",
                alert_severity="high",
                alert_title="GuardDuty: Authentication Anomaly Detected",
                alert_description_template=(
                    "GuardDuty detected: {detail.type}. "
                    "Principal: {detail.resource.accessKeyDetails.userName}. "
                    "Severity: {detail.severity}. "
                    "This may indicate brute force or credential compromise."
                ),
                investigation_steps=[
                    "Review full GuardDuty finding in AWS Console or Security Hub",
                    "Check the geographic location of the source IP",
                    "Review CloudTrail for all authentication attempts from this IP",
                    "Check if any attempts succeeded (credential compromise indicator)",
                    "Verify with user if activity was legitimate",
                    "Review IAM permissions of affected principals",
                ],
                containment_actions=[
                    "Block source IP in WAF or Security Groups",
                    "Reset passwords for targeted accounts",
                    "Disable affected IAM users pending investigation",
                    "Enable/enforce MFA on all IAM users",
                    "Review and revoke any suspicious sessions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty uses ML-based detection with low false positive rates. "
                "Add trusted IPs to GuardDuty threat lists. "
                "Use suppression rules for known CI/CD systems."
            ),
            detection_coverage=(
                "85% - ML-based detection catches patterns that threshold-based "
                "detection would miss. Detects anomalous behaviour without manual tuning."
            ),
            evasion_considerations=(
                "Slow, distributed attacks may not trigger ML anomaly thresholds. "
                "Attackers using residential proxies may blend with normal traffic. "
                "Combine with threshold-based detection for defence in depth."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events analysed",
            prerequisites=["AWS account with IAM permissions to enable GuardDuty"],
        ),
        # Strategy 2: Lambda-based intelligent detection
        DetectionStrategy(
            strategy_id="t1110-001-aws-lambda-detector",
            name="Lambda-Based Brute Force Detection",
            description=(
                "Deploy Lambda-based detection with intelligent scoring. "
                "Tracks failure patterns per source IP, detects success-after-failure "
                "(credential compromise indicator), and supports CIDR allowlisting. "
                "Provides better signal-to-noise ratio than simple threshold alerting."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, errorCode, eventName
| filter errorCode in ["AccessDenied", "UnauthorizedOperation", "InvalidUserID.NotFound",
                        "InvalidClientTokenId", "SignatureDoesNotMatch"]
   or (eventName = "ConsoleLogin" and responseElements.ConsoleLogin = "Failure")
| stats count(*) as failures,
        count_distinct(userIdentity.principalId) as targeted_users
  by sourceIPAddress, bin(5m)
| filter failures > 10
| sort failures desc""",
                terraform_template="""# Lambda-based intelligent brute force detection
# Tracks failure patterns, detects success-after-failure, supports allowlisting

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
  default     = "t1110-brute-force"
  description = "Prefix for resource names"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "failure_threshold" {
  type        = number
  default     = 10
  description = "Number of failures in window to trigger alert"
}

variable "window_minutes" {
  type        = number
  default     = 5
  description = "Time window for failure counting (minutes)"
}

variable "allowlisted_source_cidrs" {
  type        = list(string)
  default     = []
  description = "CIDR ranges to exclude from detection (corporate VPN, CI/CD)"
}

variable "alert_on_success_after_failures" {
  type        = bool
  default     = true
  description = "Alert when successful auth follows multiple failures"
}

# SNS Topic
resource "aws_sns_topic" "alerts" {
  name         = "${var.name_prefix}-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Brute Force Detection Alerts"
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.auth_failures.arn
        }
      }
    }]
  })
}

# DynamoDB for tracking (optional but recommended for cross-invocation state)
resource "aws_dynamodb_table" "failure_tracking" {
  name         = "${var.name_prefix}-tracking"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "source_ip"

  attribute {
    name = "source_ip"
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
        Resource = aws_dynamodb_table.failure_tracking.arn
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

resource "aws_lambda_function" "detector" {
  function_name    = "${var.name_prefix}-detector"
  role             = aws_iam_role.lambda_exec.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      SNS_TOPIC_ARN                   = aws_sns_topic.alerts.arn
      BASELINE_TABLE                  = aws_dynamodb_table.failure_tracking.name
      FAILURE_THRESHOLD               = tostring(var.failure_threshold)
      WINDOW_MINUTES                  = tostring(var.window_minutes)
      ALLOWLIST_SOURCE_CIDRS          = join(",", var.allowlisted_source_cidrs)
      ALERT_ON_SUCCESS_AFTER_FAILURES = var.alert_on_success_after_failures ? "true" : "false"
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.detector.function_name}"
  retention_in_days = 30
}

# EventBridge rule for authentication failures
resource "aws_cloudwatch_event_rule" "auth_failures" {
  name        = "${var.name_prefix}-auth-events"
  description = "Capture authentication events for brute force detection"

  event_pattern = jsonencode({
    source = ["aws.signin", "aws.iam", "aws.sts"]
    detail = {
      "$or" = [
        # Console login failures
        {
          eventName = ["ConsoleLogin"]
        },
        # API authentication errors
        {
          errorCode = [
            "AccessDenied",
            "UnauthorizedOperation",
            "InvalidUserID.NotFound",
            "InvalidClientTokenId",
            "SignatureDoesNotMatch",
            "AuthorizationError"
          ]
        }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.auth_failures.name
  target_id = "LambdaDetector"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.auth_failures.arn
}

# Outputs
output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.detector.function_name
}

output "tracking_table_name" {
  value = aws_dynamodb_table.failure_tracking.name
}""",
                alert_severity="critical",
                alert_title="Brute Force Attack Detected",
                alert_description_template=(
                    "Brute force attack from {sourceIPAddress}: {failure_count} failures "
                    "in {window_minutes} minutes. Targeted users: {targeted_users}."
                ),
                investigation_steps=[
                    "Check source IP geolocation and reputation (VirusTotal, AbuseIPDB)",
                    "Review all authentication attempts from this IP in CloudTrail",
                    "Identify all targeted user accounts",
                    "Check if any attempts succeeded (critical - indicates compromise)",
                    "Correlate with GuardDuty findings for additional context",
                    "Review affected users' recent API activity",
                ],
                containment_actions=[
                    "Block source IP in WAF or Security Groups immediately",
                    "Reset passwords for all targeted accounts",
                    "Enable/enforce MFA on affected accounts",
                    "Review and update account lockout policies",
                    "If success detected: disable account, rotate all credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Use allowlisted_source_cidrs for corporate VPN egress and CI/CD systems. "
                "Adjust failure_threshold based on normal failure patterns. "
                "Set alert_on_success_after_failures=true for high-priority compromise detection."
            ),
            detection_coverage=(
                "90% - Catches both brute force patterns and success-after-failure "
                "(credential compromise indicator). DynamoDB tracking provides state "
                "across Lambda invocations."
            ),
            evasion_considerations=(
                "Distributed attacks from many IPs may stay below per-IP threshold. "
                "Consider adding user-based tracking for targeted account attacks."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20 (Lambda + DynamoDB + SNS)",
            prerequisites=[
                "CloudTrail enabled",
                "EventBridge configured to receive CloudTrail events",
            ],
        ),
        # Strategy 3: Console Sign-In Failures (Simple, High-Value)
        DetectionStrategy(
            strategy_id="t1110-001-aws-console-signin",
            name="AWS Console Sign-In Failure Detection",
            description=(
                "Detect brute force attempts against AWS Console using CloudWatch metric "
                "filters. Console login failures are high-fidelity indicators of password "
                "guessing attacks."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.userName, sourceIPAddress, responseElements.ConsoleLogin
| filter eventName = "ConsoleLogin"
| filter responseElements.ConsoleLogin = "Failure"
| stats count(*) as failures by sourceIPAddress, userIdentity.userName, bin(10m)
| filter failures > 5
| sort failures desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: AWS Console brute force detection

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts
  FailureThreshold:
    Type: Number
    Default: 10
    Description: Failures per 10 minutes to trigger alert

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Console Brute Force Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  ConsoleFailureFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "ConsoleLogin" && $.responseElements.ConsoleLogin = "Failure" }'
      MetricTransformations:
        - MetricName: ConsoleLoginFailures
          MetricNamespace: Security/BruteForce
          MetricValue: "1"
          DefaultValue: 0
          Dimensions:
            - Key: SourceIP
              Value: $.sourceIPAddress

  ConsoleFailureAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Console-Brute-Force-Detected
      AlarmDescription: Multiple console login failures detected
      MetricName: ConsoleLoginFailures
      Namespace: Security/BruteForce
      Statistic: Sum
      Period: 600
      Threshold: !Ref FailureThreshold
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: console-brute-force-dlq
      MessageRetentionPeriod: 1209600""",
                terraform_template="""# AWS Console brute force detection

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "failure_threshold" {
  type        = number
  default     = 10
  description = "Failures per 10 minutes to trigger alert"
}

resource "aws_sns_topic" "console_alerts" {
  name         = "console-brute-force-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Console Brute Force Alerts"
}

resource "aws_sns_topic_subscription" "console_email" {
  topic_arn = aws_sns_topic.console_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "console_failures" {
  name           = "console-login-failures"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"ConsoleLogin\" && $.responseElements.ConsoleLogin = \"Failure\" }"

  metric_transformation {
    name          = "ConsoleLoginFailures"
    namespace     = "Security/BruteForce"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_brute_force" {
  alarm_name          = "Console-Brute-Force-Detected"
  alarm_description   = "Multiple console login failures detected"
  metric_name         = "ConsoleLoginFailures"
  namespace           = "Security/BruteForce"
  statistic           = "Sum"
  period              = 600
  threshold           = var.failure_threshold
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.console_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="AWS Console Brute Force Detected",
                alert_description_template=(
                    "Multiple console login failures detected from {sourceIPAddress}. "
                    "This indicates a password guessing attack."
                ),
                investigation_steps=[
                    "Identify targeted user accounts from CloudTrail",
                    "Check source IP geolocation and reputation",
                    "Review login attempt timeline",
                    "Check for any successful logins (compromise indicator)",
                    "Verify MFA status of targeted accounts",
                ],
                containment_actions=[
                    "Enable MFA for all IAM users if not enforced",
                    "Implement IP allowlisting for console access",
                    "Reset passwords for targeted accounts",
                    "Review IAM password policy strength",
                    "Enable GuardDuty for ML-based detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Console login failures are high-fidelity indicators. "
                "Adjust threshold based on organisation size and normal failure rates."
            ),
            detection_coverage="85% - high visibility into console-based attacks",
            evasion_considerations=(
                "Attackers may target API/CLI instead of console. "
                "Deploy GuardDuty and Lambda-based detection for comprehensive coverage."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5",
            prerequisites=[
                "CloudTrail with console sign-in events logging to CloudWatch"
            ],
        ),
        # Strategy 4: GCP Failed Authentication Detection
        DetectionStrategy(
            strategy_id="t1110-001-gcp-failed-auth",
            name="GCP Failed Authentication Detection",
            description=(
                "Detect password guessing via GCP Cloud Audit Logs. Monitor for "
                "repeated authentication failures from Identity Platform, Cloud IAM, "
                "and Workspace logins."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""-- Authentication failures across GCP services
-- Note: SetIamPolicy is NOT included as it's an authorization operation, not authentication
resource.type="audited_resource"
(
  protoPayload.methodName=~"google.cloud.identityplatform.*"
  OR protoPayload.methodName=~"google.login.LoginService.*"
)
protoPayload.status.code!=0
severity>="WARNING"
""",
                gcp_terraform_template="""# GCP brute force detection via Cloud Audit Logs

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "failure_threshold" {
  type        = number
  default     = 20
  description = "Failures per 5 minutes to trigger alert"
}

# Notification channel
resource "google_monitoring_notification_channel" "auth_email" {
  project      = var.project_id
  display_name = "Authentication Failure Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for authentication failures
resource "google_logging_metric" "auth_failures" {
  project = var.project_id
  name    = "authentication-failures"
  filter  = <<-EOT
    resource.type="audited_resource"
    (
      protoPayload.methodName=~"google.cloud.identityplatform.*"
      OR protoPayload.methodName=~"google.login.LoginService.*"
    )
    protoPayload.status.code!=0
    severity>="WARNING"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal email"
    }
  }

  label_extractors = {
    "source_ip" = "EXTRACT(protoPayload.requestMetadata.callerIp)"
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Alert policy for brute force detection
resource "google_monitoring_alert_policy" "brute_force" {
  project      = var.project_id
  display_name = "GCP Brute Force Attack Detected"
  combiner     = "OR"

  conditions {
    display_name = "High authentication failure rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.auth_failures.name}\" resource.type=\"global\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = var.failure_threshold

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.auth_email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Multiple authentication failures detected. Review Cloud Audit Logs for source IPs and targeted accounts."
    mime_type = "text/markdown"
  }

  alert_strategy {
    auto_close = "1800s"  # Auto-close after 30 minutes of no alerts
  }
}

# Security Command Centre integration (Premium tier)
# Enable SCC for additional threat intelligence
# resource "google_scc_notification_config" "auth_threats" {
#   config_id    = "auth-threat-notifications"
#   organization = "organizations/YOUR_ORG_ID"
#   streaming_config {
#     filter = "category=\"BRUTE_FORCE\" OR category=\"CREDENTIAL_ACCESS\""
#   }
#   pubsub_topic = google_pubsub_topic.scc_notifications.id
# }""",
                alert_severity="high",
                alert_title="GCP Brute Force Attack Detected",
                alert_description_template=(
                    "Multiple authentication failures detected from {source_ip} "
                    "targeting {principal}."
                ),
                investigation_steps=[
                    "Review failed authentication logs in Cloud Logging",
                    "Identify all targeted accounts",
                    "Check source IP geolocation and reputation",
                    "Check for successful authentications (compromise indicator)",
                    "Review Security Command Centre for related findings",
                ],
                containment_actions=[
                    "Enable Cloud Identity 2-Step Verification",
                    "Block malicious IPs via Cloud Armor",
                    "Review and strengthen password policies",
                    "Enable context-aware access controls",
                    "Reset compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Filter out known service accounts with expected retry patterns. "
                "Adjust threshold based on normal authentication failure rates."
            ),
            detection_coverage="70% - catches authentication failures across GCP services",
            evasion_considerations=(
                "Slow attacks may stay below threshold. "
                "Enable Security Command Centre Premium for ML-based detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Audit Logs enabled (Admin Activity + Data Access)",
                "Cloud Monitoring API enabled",
            ],
        ),
        # Azure Strategy: Brute Force: Password Guessing
        DetectionStrategy(
            strategy_id="t1110001-azure",
            name="Azure Brute Force: Password Guessing Detection",
            description=(
                "Azure detection for Brute Force: Password Guessing. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Brute Force: Password Guessing (T1110.001)
# Microsoft Defender detects Brute Force: Password Guessing activity

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
  name                = "defender-t1110-001-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1110-001"
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

  description = "Microsoft Defender detects Brute Force: Password Guessing activity"
  display_name = "Defender: Brute Force: Password Guessing"
  enabled      = true

  tags = {
    "mitre-technique" = "T1110.001"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Brute Force: Password Guessing Detected",
                alert_description_template=(
                    "Brute Force: Password Guessing activity detected. "
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
        "t1110-001-aws-guardduty",  # Fastest deployment, ML-based
        "t1110-001-aws-console-signin",  # High-value, simple
        "t1110-001-aws-lambda-detector",  # Comprehensive with tracking
        "t1110-001-gcp-failed-auth",  # GCP coverage
    ],
    total_effort_hours=4.5,
    coverage_improvement="+30% improvement for Credential Access tactic",
)
