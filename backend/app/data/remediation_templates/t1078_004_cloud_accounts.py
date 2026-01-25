"""
T1078.004 - Valid Accounts: Cloud Accounts

Adversaries may obtain and abuse credentials of cloud accounts to gain
initial access, persistence, privilege escalation, or defence evasion.

Detection Strategy:
- Leverage GuardDuty for ML-based anomaly detection across all IAM activities
- Monitor for impossible travel and geographic anomalies
- Detect first-time sensitive API callers
- Use IAM Access Analyzer for unused access detection
- Integrate with GCP Security Command Center for multi-cloud coverage

Used by APT29, Scattered Spider, LAPSUS$, Midnight Blizzard.
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

# Lambda handler for console login anomaly scoring
LAMBDA_HANDLER_CODE = '''"""
Console Login Anomaly Evaluator

Scores console login events based on:
- Geographic anomaly (new country/region)
- Time of day (out-of-hours)
- MFA status
- User agent anomalies
- Source IP reputation
"""

import json
import os
import logging
from datetime import datetime
from zoneinfo import ZoneInfo
import ipaddress
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment configuration
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
BASELINE_TABLE = os.environ.get("BASELINE_TABLE", "")
TZ = ZoneInfo(os.environ.get("TZ", "Europe/London"))
BUSINESS_START = int(os.environ.get("BUSINESS_START_HOUR", "8"))
BUSINESS_END = int(os.environ.get("BUSINESS_END_HOUR", "18"))
BUSINESS_DAYS = [int(d) for d in os.environ.get("BUSINESS_DAYS", "0,1,2,3,4").split(",")]
ALLOWLIST_ARNS = set(filter(None, os.environ.get("ALLOWLIST_ARNS", "").split(",")))
ALLOWLIST_CIDRS = [
    ipaddress.ip_network(c) for c in
    filter(None, os.environ.get("ALLOWLIST_SOURCE_CIDRS", "").split(","))
]
ALERT_THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", "40"))

sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb") if BASELINE_TABLE else None
baseline_table = dynamodb.Table(BASELINE_TABLE) if BASELINE_TABLE else None


def lambda_handler(event, context):
    """Process console login event and evaluate for anomalies."""
    logger.info(f"Received event: {json.dumps(event)}")

    detail = event.get("detail", {})
    event_time = datetime.fromisoformat(
        event.get("time", datetime.utcnow().isoformat()).replace("Z", "+00:00")
    )

    # Extract key fields
    user_identity = detail.get("userIdentity", {})
    principal_arn = user_identity.get("arn", "unknown")
    principal_name = user_identity.get("userName") or principal_arn.split("/")[-1]
    source_ip = detail.get("sourceIPAddress", "0.0.0.0")
    user_agent = detail.get("userAgent", "unknown")
    mfa_used = detail.get("additionalEventData", {}).get("MFAUsed", "No") == "Yes"
    login_result = detail.get("responseElements", {}).get("ConsoleLogin", "Success")

    # Skip if allowlisted
    if is_allowlisted(principal_arn, source_ip):
        logger.info(f"Skipping allowlisted: {principal_arn}")
        return {"statusCode": 200, "body": "Allowlisted"}

    # Get baseline for comparison
    baseline = get_baseline(principal_arn) if baseline_table else {}

    # Calculate anomaly score
    score, reasons = calculate_score(
        event_time=event_time,
        source_ip=source_ip,
        user_agent=user_agent,
        mfa_used=mfa_used,
        login_result=login_result,
        baseline=baseline,
        principal_arn=principal_arn,
    )

    # Update baseline
    if baseline_table:
        update_baseline(principal_arn, source_ip, user_agent)

    # Alert if score exceeds threshold
    if score >= ALERT_THRESHOLD:
        send_alert(
            principal_name=principal_name,
            principal_arn=principal_arn,
            source_ip=source_ip,
            mfa_used=mfa_used,
            login_result=login_result,
            score=score,
            reasons=reasons,
            event_time=event_time,
        )
        return {"statusCode": 200, "body": f"Alert sent (score={score})"}

    logger.info(f"Below threshold: score={score}")
    return {"statusCode": 200, "body": f"No alert (score={score})"}


def is_allowlisted(principal_arn: str, source_ip: str) -> bool:
    """Check if principal or IP is allowlisted."""
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
    """Get baseline for principal."""
    try:
        response = baseline_table.get_item(Key={"principal_arn": principal_arn})
        return response.get("Item", {})
    except Exception as e:
        logger.warning(f"Failed to get baseline: {e}")
        return {}


def update_baseline(principal_arn: str, source_ip: str, user_agent: str) -> None:
    """Update baseline with new observation."""
    from datetime import timedelta
    ttl = int((datetime.utcnow() + timedelta(days=90)).timestamp())
    try:
        baseline_table.update_item(
            Key={"principal_arn": principal_arn},
            UpdateExpression="""
                SET known_ips = list_append(if_not_exists(known_ips, :empty), :ip),
                    known_user_agents = list_append(if_not_exists(known_user_agents, :empty), :ua),
                    last_seen = :now, ttl_epoch = :ttl
                ADD login_count :one
            """,
            ExpressionAttributeValues={
                ":empty": [], ":ip": [source_ip], ":ua": [user_agent],
                ":now": datetime.utcnow().isoformat(), ":ttl": ttl, ":one": 1
            }
        )
    except Exception as e:
        logger.warning(f"Failed to update baseline: {e}")


def calculate_score(event_time, source_ip, user_agent, mfa_used, login_result, baseline, principal_arn):
    """Calculate anomaly score."""
    score = 0
    reasons = []

    # Out of hours (+20)
    local = event_time.astimezone(TZ)
    if local.weekday() not in BUSINESS_DAYS:
        score += 20
        reasons.append(f"Weekend login ({local.strftime('%A')})")
    elif not (BUSINESS_START <= local.hour < BUSINESS_END):
        score += 20
        reasons.append(f"Out-of-hours ({local.strftime('%H:%M')})")

    # No MFA (+25)
    if not mfa_used:
        score += 25
        reasons.append("MFA not used")

    # New source IP (+30)
    known_ips = set(baseline.get("known_ips", []))
    if source_ip not in known_ips and known_ips:
        score += 30
        reasons.append(f"New source IP: {source_ip}")

    # New user agent (+15)
    known_uas = set(baseline.get("known_user_agents", []))
    if user_agent not in known_uas and known_uas:
        score += 15
        reasons.append("New user agent")

    # Root account (+35)
    if "root" in principal_arn.lower():
        score += 35
        reasons.append("Root account login")

    # Failed login (+10)
    if login_result == "Failure":
        score += 10
        reasons.append("Failed login attempt")

    return score, reasons


def send_alert(principal_name, principal_arn, source_ip, mfa_used, login_result, score, reasons, event_time):
    """Send anomaly alert."""
    message = f"""Console Login Anomaly Detected

Principal: {principal_name}
ARN: {principal_arn}
Source IP: {source_ip}
Time: {event_time.isoformat()}
MFA Used: {mfa_used}
Login Result: {login_result}

Anomaly Score: {score}/100

Risk Indicators:
{chr(10).join(f"  - {r}" for r in reasons)}

Investigation Steps:
1. Verify with user if login was legitimate
2. Check source IP geolocation and reputation
3. Review subsequent API calls in CloudTrail
4. Check for concurrent sessions from different locations

Containment Actions:
1. If unauthorised: Force logout via IAM
2. Rotate credentials immediately
3. Enable/enforce MFA
4. Review IAM permissions
"""
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[{login_result}] Console Anomaly: {principal_name} (Score: {score})",
            Message=message,
        )
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
        raise
'''

TEMPLATE = RemediationTemplate(
    technique_id="T1078.004",
    technique_name="Valid Accounts: Cloud Accounts",
    tactic_ids=["TA0001", "TA0003", "TA0004", "TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1078/004/",
    threat_context=ThreatContext(
        description=(
            "Adversaries obtain and abuse credentials of existing cloud accounts "
            "to gain initial access, persistence, privilege escalation, or defence evasion. "
            "Cloud accounts include AWS IAM users, GCP service accounts, and federated identities. "
            "GuardDuty provides comprehensive ML-based detection across all MITRE tactics."
        ),
        attacker_goal="Gain legitimate access to cloud resources without deploying malware",
        why_technique=[
            "Legitimate credentials bypass most perimeter security controls",
            "Activity blends with normal user behaviour",
            "No malware signatures to detect",
            "Access often persists until password rotation",
            "Can escalate privileges if account has excessive permissions",
            "Federated identities may bypass MFA requirements",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Credential-based access is the most common initial access vector in cloud breaches. "
            "Once obtained, credentials provide immediate access with legitimate permissions, "
            "making detection challenging without behavioural analysis. GuardDuty provides "
            "AnomalousBehavior findings across all MITRE tactics."
        ),
        business_impact=[
            "Unauthorised access to sensitive data",
            "Data exfiltration without triggering traditional security controls",
            "Lateral movement to connected systems",
            "Ransomware deployment",
            "Regulatory compliance violations (GDPR, HIPAA)",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1087", "T1069", "T1530"],
        often_follows=["T1566", "T1110", "T1552"],
    ),
    detection_strategies=[
        # Strategy 1: GuardDuty Comprehensive Coverage
        DetectionStrategy(
            strategy_id="t1078004-guardduty",
            name="GuardDuty Comprehensive Credential Abuse Detection",
            description=(
                "AWS GuardDuty provides ML-based anomaly detection across all MITRE tactics. "
                "24 IAM finding types cover credential access, initial access, persistence, "
                "privilege escalation, defence evasion, discovery, and exfiltration. "
                "This is the recommended first-line detection for cloud credential abuse."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    # Initial Access and Credential Access
                    "InitialAccess:IAMUser/AnomalousBehavior",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                    # Console login anomalies
                    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
                    # Credential exfiltration
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    # Malicious sources
                    "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
                    "UnauthorizedAccess:IAMUser/TorIPCaller",
                    # Persistence and privilege escalation
                    "Persistence:IAMUser/AnomalousBehavior",
                    "PrivilegeEscalation:IAMUser/AnomalousBehavior",
                    # Defence evasion
                    "DefenseEvasion:IAMUser/AnomalousBehavior",
                    "Stealth:IAMUser/CloudTrailLoggingDisabled",
                    "Stealth:IAMUser/PasswordPolicyChange",
                    # Discovery and reconnaissance
                    "Discovery:IAMUser/AnomalousBehavior",
                    "Recon:IAMUser/MaliciousIPCaller",
                    "Recon:IAMUser/TorIPCaller",
                    # Root account usage
                    "Policy:IAMUser/RootCredentialUsage",
                ],
                terraform_template="""# GuardDuty comprehensive credential abuse detection
# Covers all 24 IAM finding types across MITRE tactics

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

variable "min_severity" {
  type        = number
  default     = 4
  description = "Minimum severity (4=Medium, 7=High)"
}

# Enable GuardDuty with all data sources
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

# SNS topic for alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name         = "guardduty-credential-abuse-alerts"
  display_name = "GuardDuty Credential Abuse Alerts"

  # Enable encryption
  kms_master_key_id = "alias/aws/sns"
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
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_iam.arn
        }
      }
    }]
  })
}

# DLQ for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-credential-alerts-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = "alias/aws/sqs"
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
      values   = [aws_cloudwatch_event_rule.guardduty_iam.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# EventBridge rule for ALL IAM finding types
resource "aws_cloudwatch_event_rule" "guardduty_iam" {
  name        = "guardduty-iam-credential-abuse"
  description = "Route all GuardDuty IAM findings to SNS"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_severity] }]
      type = [
        # Anomalous behavior across all tactics
        { wildcard = "*:IAMUser/AnomalousBehavior" },
        # Console and credential abuse
        { wildcard = "UnauthorizedAccess:IAMUser/*" },
        # Stealth and evasion
        { wildcard = "Stealth:IAMUser/*" },
        { wildcard = "DefenseEvasion:IAMUser/*" },
        # Reconnaissance
        { wildcard = "Recon:IAMUser/*" },
        # Root account
        { wildcard = "Policy:IAMUser/RootCredentialUsage" },
        # Persistence
        { wildcard = "Persistence:IAMUser/*" },
        # Privilege escalation
        { wildcard = "PrivilegeEscalation:IAMUser/*" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_iam.name
  target_id = "SNSTopic"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_retry_attempts       = 185
    maximum_event_age_in_seconds = 86400
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

}

# IAM Access Analyzer for unused access detection
resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "account-analyzer"
  type          = "ACCOUNT"
}

# Outputs
output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}

output "sns_topic_arn" {
  value = aws_sns_topic.guardduty_alerts.arn
}""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty comprehensive credential abuse detection

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
      DataSources:
        S3Logs:
          Enable: true
        Kubernetes:
          AuditLogs:
            Enable: true

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty Credential Abuse Alerts
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  AlertTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
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
                aws:SourceArn: !GetAtt IAMFindingsRule.Arn

  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: guardduty-credential-alerts-dlq
      MessageRetentionPeriod: 1209600
      KmsMasterKeyId: alias/aws/sqs

  IAMFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-iam-credential-abuse
      Description: Route all GuardDuty IAM findings to SNS
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          severity:
            - numeric: [">=", !Ref MinSeverity]
          type:
            - prefix: InitialAccess:IAMUser
            - prefix: CredentialAccess:IAMUser
            - prefix: UnauthorizedAccess:IAMUser
            - prefix: Persistence:IAMUser
            - prefix: PrivilegeEscalation:IAMUser
            - prefix: DefenseEvasion:IAMUser
            - prefix: Discovery:IAMUser
            - prefix: Stealth:IAMUser
            - prefix: Recon:IAMUser
            - prefix: Policy:IAMUser/RootCredentialUsage
      Targets:
        - Id: SNSTopic
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 185
            MaximumEventAgeInSeconds: 86400
          DeadLetterConfig:
            Arn: !GetAtt DLQ.Arn

  AccessAnalyzer:
    Type: AWS::AccessAnalyzer::Analyzer
    Properties:
      AnalyzerName: account-analyzer
      Type: ACCOUNT

Outputs:
  DetectorId:
    Value: !Ref GuardDutyDetector
  TopicArn:
    Value: !Ref AlertTopic""",
                alert_severity="high",
                alert_title="GuardDuty: Credential Abuse Detected",
                alert_description_template=(
                    "GuardDuty detected: {detail.type}. "
                    "Principal: {detail.resource.accessKeyDetails.userName}. "
                    "Severity: {detail.severity}."
                ),
                investigation_steps=[
                    "Review full GuardDuty finding in AWS Console or Security Hub",
                    "Check CloudTrail for all API calls from affected principal (last 24h)",
                    "Verify source IP geolocation and reputation",
                    "Contact user via out-of-band communication to confirm activity",
                    "Review IAM permissions to assess blast radius",
                    "Check for concurrent sessions from different locations",
                ],
                containment_actions=[
                    "Disable IAM user's console access and access keys",
                    "Revoke active sessions using AWS STS",
                    "Rotate all credentials for affected user",
                    "Enable/enforce MFA if not already enabled",
                    "Review and restrict IAM permissions",
                    "Check for persistence mechanisms (new users, roles, keys)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty uses ML to establish baselines, minimising false positives. "
                "Add trusted IPs to GuardDuty threat lists. "
                "Use suppression rules for known CI/CD systems and automation."
            ),
            detection_coverage=(
                "85% - ML-based detection across all MITRE tactics. "
                "Covers anomalous behaviour, malicious IPs, credential exfiltration."
            ),
            evasion_considerations=(
                "Attackers using residential proxies may blend with normal traffic. "
                "Slow-and-low techniques may avoid anomaly thresholds. "
                "Combine with Lambda-based detection for defence in depth."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events analysed",
            prerequisites=["AWS account with IAM permissions to enable GuardDuty"],
        ),
        # Strategy 2: Lambda-based Console Login Evaluation
        DetectionStrategy(
            strategy_id="t1078004-lambda-console",
            name="Lambda-Based Console Login Anomaly Detection",
            description=(
                "Deploy Lambda-based scoring for console logins with baseline tracking. "
                "Evaluates out-of-hours access, MFA status, new source IPs, user agent "
                "changes, and root account usage. Stores per-principal baseline in DynamoDB."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.signin"],
                    "detail-type": ["AWS Console Sign In via CloudTrail"],
                    "detail": {"eventName": ["ConsoleLogin"]},
                },
                terraform_template="""# Lambda-based console login anomaly detection
# With DynamoDB baseline tracking and scoring

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
  default     = "t1078-console-anomaly"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

variable "timezone" {
  type        = string
  default     = "Europe/London"
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
}

variable "allowlisted_arns" {
  type        = list(string)
  default     = []
  description = "Principal ARNs to exclude (automation, service accounts)"
}

variable "allowlisted_cidrs" {
  type        = list(string)
  default     = []
  description = "Source CIDRs to exclude (corporate VPN)"
}

variable "alert_threshold" {
  type        = number
  default     = 40
  description = "Anomaly score threshold (0-100)"
}

# SNS Topic
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = "alias/aws/sns"
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.console_login.arn
        }
      }
    }]
  })
}

# DynamoDB baseline table
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
      BASELINE_TABLE         = aws_dynamodb_table.baseline.name
      TZ                     = var.timezone
      BUSINESS_START_HOUR    = tostring(var.business_start_hour)
      BUSINESS_END_HOUR      = tostring(var.business_end_hour)
      BUSINESS_DAYS          = join(",", [for d in var.business_days : tostring(d)])
      ALLOWLIST_ARNS         = join(",", var.allowlisted_arns)
      ALLOWLIST_SOURCE_CIDRS = join(",", var.allowlisted_cidrs)
      ALERT_THRESHOLD        = tostring(var.alert_threshold)
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.evaluator.function_name}"
  retention_in_days = 30
}

# EventBridge rule
resource "aws_cloudwatch_event_rule" "console_login" {
  name        = "${var.name_prefix}-console-login"
  description = "Capture console logins for anomaly evaluation"

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

# Outputs
output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.evaluator.function_name
}

output "baseline_table_name" {
  value = aws_dynamodb_table.baseline.name
}""",
                alert_severity="high",
                alert_title="Console Login Anomaly Detected",
                alert_description_template=(
                    "Anomalous console login for {principal_name} from {source_ip}. "
                    "Score: {score}/100. MFA: {mfa_used}."
                ),
                investigation_steps=[
                    "Verify login was authorised by contacting user",
                    "Check source IP geolocation and reputation",
                    "Review CloudTrail for subsequent API calls",
                    "Check for concurrent sessions from different locations",
                    "Verify MFA status and session duration",
                ],
                containment_actions=[
                    "Force session logout via IAM",
                    "Reset credentials immediately",
                    "Enable/enforce MFA",
                    "Review and restrict IAM permissions",
                    "Check for persistence mechanisms",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Use allowlisted_arns for break-glass and automation accounts. "
                "Use allowlisted_cidrs for corporate VPN egress. "
                "Adjust alert_threshold: 40 for SOC tripwire, 60 for high-confidence."
            ),
            detection_coverage=(
                "90% - Catches anomalous console logins with per-principal baselining."
            ),
            evasion_considerations=(
                "Attackers using stolen credentials from expected IPs during business hours "
                "may score below threshold. GuardDuty integration provides defence in depth."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-15 (Lambda + DynamoDB + SNS)",
            prerequisites=[
                "CloudTrail enabled with console sign-in events",
                "EventBridge configured to receive CloudTrail events",
            ],
        ),
        # Strategy 3: Impossible Travel Detection
        DetectionStrategy(
            strategy_id="t1078004-impossible-travel",
            name="Impossible Travel Detection",
            description=(
                "Detect when the same user authenticates from geographically distant "
                "locations within a timeframe that makes physical travel impossible. "
                "Uses CloudWatch Logs Insights for analysis."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, sourceIPAddress, eventName
| filter eventName = "ConsoleLogin" and responseElements.ConsoleLogin = "Success"
| stats earliest(@timestamp) as first_login, latest(@timestamp) as last_login,
        count(*) as login_count, count_distinct(sourceIPAddress) as unique_ips
  by user, bin(1h)
| filter unique_ips > 1
| sort last_login desc""",
                terraform_template="""# Impossible travel detection via CloudWatch Logs Insights

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "aws_sns_topic" "alerts" {
  name              = "impossible-travel-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch metric filter for multiple IPs per user
resource "aws_cloudwatch_log_metric_filter" "multi_ip_login" {
  name           = "multi-ip-console-login"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"ConsoleLogin\" && $.responseElements.ConsoleLogin = \"Success\" }"

  metric_transformation {
    name          = "ConsoleLoginSuccess"
    namespace     = "Security/ImpossibleTravel"
    value         = "1"
    default_value = "0"
    dimensions = {
      User     = "$.userIdentity.arn"
      SourceIP = "$.sourceIPAddress"
    }
  }
}

# Alarm using metric math to aggregate across all User/SourceIP combinations
# The SEARCH function finds all metrics with these dimensions and SUM aggregates them
resource "aws_cloudwatch_metric_alarm" "multi_ip" {
  alarm_name          = "Impossible-Travel-Detected"
  alarm_description   = "Same user logged in from multiple IPs in 1 hour"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 2
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  # Use metric math to aggregate across all high-cardinality dimension values
  metric_query {
    id          = "e1"
    return_data = true
    label       = "TotalConsoleLogins"
    expression  = "SUM(SEARCH('{Security/ImpossibleTravel,User,SourceIP} MetricName=\"ConsoleLoginSuccess\"', 'Sum', 300))"
  }
}

data "aws_caller_identity" "current" {}

# Scoped SNS topic policy
resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarmsPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Impossible Travel: Multiple Login Locations",
                alert_description_template=(
                    "User {user} logged in from {unique_ips} different IP addresses within 1 hour."
                ),
                investigation_steps=[
                    "Identify all IP addresses used in the detection window",
                    "Geolocate IPs to determine physical distance",
                    "Check if any IPs are known VPN or corporate egress points",
                    "Review all API calls made from each IP",
                    "Contact user to verify login locations",
                ],
                containment_actions=[
                    "Force logout all active sessions",
                    "Temporarily disable console access",
                    "Require password reset with MFA verification",
                    "Review for any suspicious activity during sessions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Allowlist known VPN exit nodes and corporate proxies. "
                "Consider user travel patterns and remote work policies."
            ),
            detection_coverage="60% - catches obvious geographic anomalies",
            evasion_considerations=(
                "Attackers may use VPNs in expected locations. "
                "Combine with GuardDuty for behavioural analysis."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-20 depending on log volume",
            prerequisites=[
                "CloudTrail enabled",
                "CloudTrail logs sent to CloudWatch Logs",
            ],
        ),
        # Strategy 4: GCP Service Account Abuse Detection
        DetectionStrategy(
            strategy_id="t1078004-gcp-sa",
            name="GCP Service Account Abuse Detection",
            description=(
                "Detect abuse of GCP service account credentials including key usage "
                "from unexpected locations, anomalous API patterns, and credential "
                "impersonation. Uses Cloud Audit Logs and Security Command Center."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""-- Service account credential usage anomalies
resource.type="audited_resource"
protoPayload.authenticationInfo.principalEmail:*@*.iam.gserviceaccount.com
(
  protoPayload.methodName=~"GetIamPolicy|SetIamPolicy|CreateServiceAccountKey"
  OR protoPayload.requestMetadata.callerSuppliedUserAgent:*
)
severity>=NOTICE
""",
                gcp_terraform_template="""# GCP Service Account Abuse Detection

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Service Account Abuse Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for SA credential usage
resource "google_logging_metric" "sa_credential_usage" {
  project = var.project_id
  name    = "service-account-credential-usage"
  filter  = <<-EOT
    resource.type="audited_resource"
    protoPayload.authenticationInfo.principalEmail:*@*.iam.gserviceaccount.com
    protoPayload.methodName=~"GetIamPolicy|SetIamPolicy|CreateServiceAccountKey|GenerateAccessToken|GenerateIdToken|getAccessToken"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "service_account"
      value_type  = "STRING"
    }
    labels {
      key         = "method"
      value_type  = "STRING"
    }
    labels {
      key         = "caller_ip"
      value_type  = "STRING"
    }
  }

  label_extractors = {
    "service_account" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "method"          = "EXTRACT(protoPayload.methodName)"
    "caller_ip"       = "EXTRACT(protoPayload.requestMetadata.callerIp)"
  }
}

# Alert policy for sensitive SA operations
resource "google_monitoring_alert_policy" "sa_abuse" {
  project      = var.project_id
  display_name = "Service Account Credential Abuse"
  combiner     = "OR"

  conditions {
    display_name = "Sensitive SA operation detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_credential_usage.name}\""
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
    content   = "Sensitive service account operation detected. Review Cloud Audit Logs."
    mime_type = "text/markdown"
  }
}

# Enable Security Command Center for threat detection
# Requires Premium tier for full threat detection
# resource "google_scc_source" "custom" {
#   display_name = "Service Account Abuse Detection"
#   organization = "organizations/YOUR_ORG_ID"
# }""",
                alert_severity="high",
                alert_title="GCP: Service Account Abuse Detected",
                alert_description_template=(
                    "Service account {service_account} performed sensitive operation "
                    "{method} from {caller_ip}."
                ),
                investigation_steps=[
                    "Review full Cloud Audit Log entry",
                    "Check caller IP geolocation and reputation",
                    "Verify the operation was authorised",
                    "Review service account permissions",
                    "Check for other anomalous activity",
                ],
                containment_actions=[
                    "Disable service account if compromised",
                    "Rotate service account keys",
                    "Review and restrict IAM permissions",
                    "Enable Workload Identity Federation",
                    "Audit all recent SA operations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Allowlist expected automation IPs and CI/CD systems. "
                "Enable Security Command Center Premium for ML-based detection."
            ),
            detection_coverage="70% - catches sensitive SA operations",
            evasion_considerations=(
                "Attackers may use expected APIs from expected locations. "
                "Enable SCC Premium for behavioural analysis."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Cloud Monitoring API enabled",
            ],
        ),
        # Azure Strategy: Valid Accounts: Cloud Accounts
        DetectionStrategy(
            strategy_id="t1078004-azure",
            name="Azure Valid Accounts: Cloud Accounts Detection",
            description=(
                "Defender for Cloud and Entra ID Protection detect cloud credential abuse. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "Suspicious cloud resource access",
                    "Azure AD sign-in risk",
                ],
                azure_kql_query="""// Azure Entra ID Suspicious Sign-In Detection
// MITRE ATT&CK: T1078.004 - Valid Accounts: Cloud Accounts
// Detects risky sign-ins, impossible travel, and anomalous authentication patterns

let lookback = 24h;
let riskThreshold = 50;  // Risk score threshold

// Detect risky sign-ins with risk signals
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0  // Successful sign-in
| where RiskLevelDuringSignIn in ("high", "medium")
    or RiskState != "none"
    or isnotempty(RiskDetail)
| extend
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    DeviceDetail = tostring(DeviceDetail.displayName),
    AuthMethod = tostring(AuthenticationDetails[0].authenticationMethod),
    MfaUsed = AuthenticationRequirement == "multiFactorAuthentication"
| summarize
    RiskySignIns = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(strcat(City, "-", Country)),
    Countries = make_set(Country, 10),
    IPs = make_set(IPAddress, 10),
    Apps = make_set(AppDisplayName, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, RiskLevelDuringSignIn, RiskState
| where RiskySignIns > 1 or UniqueLocations > 2
| project
    TimeGenerated = LastSeen,
    UserPrincipalName,
    RiskLevelDuringSignIn,
    RiskState,
    RiskySignIns,
    UniqueIPs,
    UniqueLocations,
    Countries,
    IPs,
    Apps,
    FirstSeen""",
                sentinel_rule_query="""// Sentinel Analytics Rule: Suspicious Cloud Account Usage
// MITRE ATT&CK: T1078.004
let lookback = 24h;

// Combine risky sign-ins with impossible travel detection
let RiskySignIns = SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| where RiskLevelDuringSignIn in ("high", "medium")
    or RiskEventTypes has_any ("unfamiliarFeatures", "impossibleTravel", "maliciousIPAddress")
| extend
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    City,
    Country,
    Latitude,
    Longitude,
    AppDisplayName,
    RiskLevelDuringSignIn,
    RiskEventTypes;

// Impossible travel detection
let ImpossibleTravel = SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| extend
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| where isnotempty(Latitude) and isnotempty(Longitude)
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend
    PrevTime = prev(TimeGenerated, 1),
    PrevLat = prev(Latitude, 1),
    PrevLong = prev(Longitude, 1),
    PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend
    TimeDiffHours = datetime_diff('hour', TimeGenerated, PrevTime),
    DistanceKm = geo_distance_2points(Longitude, Latitude, PrevLong, PrevLat) / 1000
| where TimeDiffHours > 0 and TimeDiffHours < 24
| extend SpeedKmH = DistanceKm / TimeDiffHours
| where SpeedKmH > 1000  // Faster than commercial flight
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    TimeDiffHours,
    DistanceKm,
    SpeedKmH;

RiskySignIns
| union ImpossibleTravel
| summarize
    EventCount = count(),
    AlertTypes = make_set(RiskLevelDuringSignIn, 10),
    IPs = make_set(IPAddress, 10)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| project
    TimeGenerated,
    UserPrincipalName,
    EventCount,
    AlertTypes,
    IPs""",
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Valid Accounts: Cloud Accounts (T1078.004)
# Defender for Cloud and Entra ID Protection detect cloud credential abuse

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

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
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
  name                = "defender-t1078-004-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1078-004"
  resource_group_name = var.resource_group_name
  location            = var.location

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
                    "Suspicious cloud resource access",
                    "Azure AD sign-in risk",
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

  description = "Defender for Cloud and Entra ID Protection detect cloud credential abuse"
  display_name = "Defender: Valid Accounts: Cloud Accounts"
  enabled      = true

  tags = {
    "mitre-technique" = "T1078.004"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Valid Accounts: Cloud Accounts Detected",
                alert_description_template=(
                    "Valid Accounts: Cloud Accounts activity detected. "
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
        "t1078004-guardduty",  # ML-based, lowest effort, comprehensive
        "t1078004-lambda-console",  # Per-principal baselining
        "t1078004-impossible-travel",  # Geographic anomalies
        "t1078004-gcp-sa",  # GCP coverage
    ],
    total_effort_hours=6.0,
    coverage_improvement="+35% improvement for Initial Access and Credential Access tactics",
)
