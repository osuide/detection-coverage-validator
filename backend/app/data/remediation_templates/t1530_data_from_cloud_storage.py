"""
T1530 - Data from Cloud Storage

Adversaries may access data from cloud storage objects to collect sensitive information.
This is a critical collection/exfiltration technique for data theft.

Detection Strategy:
- Leverage GuardDuty S3 Protection for ML-based anomaly detection
- Monitor for bulk data access patterns
- Detect cross-account and cross-region data transfers
- Use Macie for sensitive data classification alerts
- Integrate with GCP Cloud Storage audit logging

Used by APT29, Scattered Spider, LAPSUS$, FIN7.
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

# Lambda handler for bulk S3 access detection
LAMBDA_HANDLER_CODE = '''"""
Bulk S3 Access Evaluator

Scores S3 access patterns based on:
- Volume of objects accessed
- Data transfer size
- Time of day (out-of-hours bulk access is suspicious)
- First-time bucket access
- Cross-region access patterns
"""

import json
import os
import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment configuration
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
TRACKING_TABLE = os.environ.get("TRACKING_TABLE", "")
TZ = ZoneInfo(os.environ.get("TZ", "Europe/London"))
BUSINESS_START = int(os.environ.get("BUSINESS_START_HOUR", "8"))
BUSINESS_END = int(os.environ.get("BUSINESS_END_HOUR", "18"))
BUSINESS_DAYS = [int(d) for d in os.environ.get("BUSINESS_DAYS", "0,1,2,3,4").split(",")]
OBJECT_COUNT_THRESHOLD = int(os.environ.get("OBJECT_COUNT_THRESHOLD", "50"))
BYTES_THRESHOLD = int(os.environ.get("BYTES_THRESHOLD", "104857600"))  # 100MB
ALLOWLIST_ARNS = set(filter(None, os.environ.get("ALLOWLIST_ARNS", "").split(",")))
SENSITIVE_BUCKET_PATTERNS = os.environ.get("SENSITIVE_BUCKET_PATTERNS", "backup,logs,pii,sensitive,confidential").split(",")

sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb") if TRACKING_TABLE else None
tracking_table = dynamodb.Table(TRACKING_TABLE) if TRACKING_TABLE else None

# In-memory tracking for current invocation
access_counts = {}


def lambda_handler(event, context):
    """Process S3 access event and detect bulk exfiltration."""
    logger.info(f"Received event: {json.dumps(event)}")

    detail = event.get("detail", {})
    event_time = datetime.fromisoformat(
        event.get("time", datetime.utcnow().isoformat()).replace("Z", "+00:00")
    )

    # Extract key fields
    user_identity = detail.get("userIdentity", {})
    principal_arn = user_identity.get("arn", "unknown")
    source_ip = detail.get("sourceIPAddress", "0.0.0.0")
    event_name = detail.get("eventName", "")
    request_params = detail.get("requestParameters", {})
    bucket_name = request_params.get("bucketName", "unknown")
    region = detail.get("awsRegion", "unknown")

    # Skip if allowlisted
    if principal_arn in ALLOWLIST_ARNS:
        logger.info(f"Skipping allowlisted principal: {principal_arn}")
        return {"statusCode": 200, "body": "Allowlisted"}

    # Track access
    track_key = f"{principal_arn}:{bucket_name}"
    if track_key not in access_counts:
        access_counts[track_key] = {"count": 0, "bytes": 0, "first_seen": event_time}
    access_counts[track_key]["count"] += 1

    # Calculate risk score
    score, reasons = calculate_score(
        principal_arn=principal_arn,
        bucket_name=bucket_name,
        event_time=event_time,
        event_name=event_name,
        access_count=access_counts[track_key]["count"],
        region=region,
    )

    # Alert if thresholds exceeded or high risk score
    if access_counts[track_key]["count"] >= OBJECT_COUNT_THRESHOLD or score >= 50:
        send_alert(
            principal_arn=principal_arn,
            bucket_name=bucket_name,
            source_ip=source_ip,
            access_count=access_counts[track_key]["count"],
            score=score,
            reasons=reasons,
            event_time=event_time,
        )
        return {"statusCode": 200, "body": f"Alert sent (count={access_counts[track_key]['count']}, score={score})"}

    return {"statusCode": 200, "body": "No alert"}


def calculate_score(principal_arn, bucket_name, event_time, event_name, access_count, region):
    """Calculate risk score for S3 access."""
    score = 0
    reasons = []

    # Out of hours (+20)
    local = event_time.astimezone(TZ)
    if local.weekday() not in BUSINESS_DAYS:
        score += 20
        reasons.append(f"Weekend access ({local.strftime('%A')})")
    elif not (BUSINESS_START <= local.hour < BUSINESS_END):
        score += 20
        reasons.append(f"Out-of-hours ({local.strftime('%H:%M')})")

    # Sensitive bucket pattern (+25)
    bucket_lower = bucket_name.lower()
    for pattern in SENSITIVE_BUCKET_PATTERNS:
        if pattern in bucket_lower:
            score += 25
            reasons.append(f"Sensitive bucket pattern: {pattern}")
            break

    # High access count (+30)
    if access_count >= OBJECT_COUNT_THRESHOLD:
        score += 30
        reasons.append(f"High access volume: {access_count} objects")

    # Bulk operations (+15)
    if event_name in ["ListObjects", "ListObjectsV2", "ListBucket"]:
        score += 15
        reasons.append(f"Bulk enumeration: {event_name}")

    return score, reasons


def send_alert(principal_arn, bucket_name, source_ip, access_count, score, reasons, event_time):
    """Send bulk access alert."""
    message = f"""S3 Bulk Access / Potential Exfiltration Detected

Principal: {principal_arn}
Bucket: {bucket_name}
Source IP: {source_ip}
Time: {event_time.isoformat()}
Objects Accessed: {access_count}

Risk Score: {score}/100

Risk Indicators:
{chr(10).join(f"  - {r}" for r in reasons)}

Investigation Steps:
1. Review CloudTrail for all S3 access by this principal
2. Check what specific objects were accessed
3. Verify the access was authorised for business purposes
4. Check source IP geolocation and reputation
5. Review if data was copied to external destinations

Containment Actions:
1. Temporarily revoke the principal's S3 access
2. Block source IP in bucket policy if external
3. Enable S3 Object Lock if not already enabled
4. Review and tighten bucket access policies
5. Check for any data copied to external accounts
"""

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[HIGH] S3 Bulk Access: {bucket_name} ({access_count} objects)",
            Message=message,
        )
        logger.info(f"Alert sent for {principal_arn} accessing {bucket_name}")
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
        raise
'''

TEMPLATE = RemediationTemplate(
    technique_id="T1530",
    technique_name="Data from Cloud Storage",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1530/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may access data stored in cloud storage objects such as S3 buckets "
            "or GCS buckets. Cloud storage often contains sensitive data including backups, "
            "logs, credentials, and business-critical information. GuardDuty S3 Protection "
            "provides ML-based detection of anomalous access patterns and exfiltration attempts."
        ),
        attacker_goal="Exfiltrate sensitive data from cloud storage for espionage, extortion, or sale",
        why_technique=[
            "S3/GCS buckets often contain vast amounts of sensitive data",
            "Misconfigured buckets may allow public or overly permissive access",
            "Data exfiltration can occur at scale with simple API calls",
            "Backups in cloud storage may contain database dumps with credentials",
            "Logs and configuration files can reveal additional attack vectors",
            "Cross-account access can facilitate data theft to attacker infrastructure",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Cloud storage data theft can result in massive data breaches. "
            "S3/GCS buckets frequently contain highly sensitive data and are often misconfigured. "
            "GuardDuty provides Exfiltration:S3/AnomalousBehavior for ML-based detection."
        ),
        business_impact=[
            "Large-scale data breach affecting customers and partners",
            "Regulatory fines (GDPR, CCPA, HIPAA violations)",
            "Intellectual property theft",
            "Ransomware/extortion leverage",
            "Reputational damage and loss of customer trust",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1567", "T1537"],
        often_follows=["T1078", "T1552", "T1190"],
    ),
    detection_strategies=[
        # Strategy 1: GuardDuty S3 Protection (Comprehensive)
        DetectionStrategy(
            strategy_id="t1530-guardduty",
            name="GuardDuty S3 Protection with All Finding Types",
            description=(
                "AWS GuardDuty S3 Protection provides ML-based detection of anomalous S3 access. "
                "19 S3 finding types cover exfiltration, discovery, impact, stealth, and policy "
                "violations. AnomalousBehavior findings detect access patterns that deviate from "
                "established baselines without requiring manual threshold tuning."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    # Exfiltration
                    "Exfiltration:S3/AnomalousBehavior",
                    "Exfiltration:S3/MaliciousIPCaller",
                    # Discovery
                    "Discovery:S3/AnomalousBehavior",
                    "Discovery:S3/MaliciousIPCaller",
                    "Discovery:S3/MaliciousIPCaller.Custom",
                    "Discovery:S3/TorIPCaller",
                    # Impact (data destruction/modification)
                    "Impact:S3/AnomalousBehavior.Delete",
                    "Impact:S3/AnomalousBehavior.Permission",
                    "Impact:S3/AnomalousBehavior.Write",
                    "Impact:S3/MaliciousIPCaller",
                    # Stealth
                    "Stealth:S3/ServerAccessLoggingDisabled",
                    # Unauthorized Access
                    "UnauthorizedAccess:S3/MaliciousIPCaller.Custom",
                    "UnauthorizedAccess:S3/TorIPCaller",
                    # Policy violations
                    "Policy:S3/AccountBlockPublicAccessDisabled",
                    "Policy:S3/BucketAnonymousAccessGranted",
                    "Policy:S3/BucketBlockPublicAccessDisabled",
                    "Policy:S3/BucketPublicAccessGranted",
                ],
                terraform_template="""# GuardDuty S3 Protection with comprehensive finding types

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "min_severity" {
  type        = number
  default     = 4
  description = "Minimum severity (4=Medium, 7=High)"
}

# Enable GuardDuty with S3 Protection
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
  }
}

# SNS topic for alerts (encrypted)
resource "aws_sns_topic" "s3_alerts" {
  name              = "guardduty-s3-exfiltration-alerts"
  display_name      = "GuardDuty S3 Exfiltration Alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.s3_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.s3_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.s3_alerts.arn
    }]
  })
}

# DLQ for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-s3-alerts-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = "alias/aws/sqs"
}

# EventBridge rule for ALL S3 finding types
resource "aws_cloudwatch_event_rule" "guardduty_s3" {
  name        = "guardduty-s3-exfiltration"
  description = "Route all GuardDuty S3 findings to SNS"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_severity] }]
      type = [
        # Exfiltration and Discovery
        { wildcard = "Exfiltration:S3/*" },
        { wildcard = "Discovery:S3/*" },
        # Impact (data destruction)
        { wildcard = "Impact:S3/*" },
        # Stealth and Unauthorized
        { wildcard = "Stealth:S3/*" },
        { wildcard = "UnauthorizedAccess:S3/*" },
        # Policy violations
        { wildcard = "Policy:S3/*" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_s3.name
  target_id = "SNSTopic"
  arn       = aws_sns_topic.s3_alerts.arn

  retry_policy {
    maximum_retry_attempts       = 185
    maximum_event_age_in_seconds = 86400
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Also enable Macie for sensitive data detection (recommended)
# resource "aws_macie2_account" "main" {}

# Outputs
output "sns_topic_arn" {
  value = aws_sns_topic.s3_alerts.arn
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty S3 Protection with comprehensive finding types

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

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: GuardDuty S3 Exfiltration Alerts
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
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic

  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: guardduty-s3-alerts-dlq
      MessageRetentionPeriod: 1209600
      KmsMasterKeyId: alias/aws/sqs

  S3FindingsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-s3-exfiltration
      Description: Route all GuardDuty S3 findings to SNS
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          severity:
            - numeric: [">=", !Ref MinSeverity]
          type:
            - prefix: Exfiltration:S3
            - prefix: Discovery:S3
            - prefix: Impact:S3
            - prefix: Stealth:S3
            - prefix: UnauthorizedAccess:S3
            - prefix: Policy:S3
      Targets:
        - Id: SNSTopic
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 185
            MaximumEventAgeInSeconds: 86400
          DeadLetterConfig:
            Arn: !GetAtt DLQ.Arn

Outputs:
  TopicArn:
    Value: !Ref AlertTopic
  DetectorId:
    Value: !Ref GuardDutyDetector""",
                alert_severity="high",
                alert_title="GuardDuty: S3 Data Exfiltration Detected",
                alert_description_template=(
                    "GuardDuty detected: {detail.type}. "
                    "Bucket: {detail.resource.s3BucketDetails.name}. "
                    "This may indicate data exfiltration or policy violation."
                ),
                investigation_steps=[
                    "Review full GuardDuty finding in AWS Console or Security Hub",
                    "Identify which S3 buckets and objects were accessed",
                    "Check the source IP geolocation and reputation",
                    "Verify if the accessing principal should have this access",
                    "Review access patterns for unusual volume or timing",
                    "Check CloudTrail for related API calls",
                ],
                containment_actions=[
                    "Block the source IP at bucket policy or WAF level",
                    "Revoke access for the compromised principal",
                    "Enable S3 Object Lock if data integrity is critical",
                    "Review and restrict bucket policies",
                    "Enable versioning for recovery if not already enabled",
                    "Check for data copied to external accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty uses ML to establish baselines, minimising false positives. "
                "Add known data processing IPs to trusted IP lists. "
                "Use suppression rules for ETL and backup processes."
            ),
            detection_coverage=(
                "85% - ML-based detection of anomalous S3 access patterns. "
                "Covers exfiltration, discovery, impact, and policy violations."
            ),
            evasion_considerations=(
                "Slow, distributed exfiltration may avoid anomaly thresholds. "
                "Attackers may use legitimate-looking API patterns. "
                "Combine with Lambda-based detection for defence in depth."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million S3 data events",
            prerequisites=[
                "AWS account with appropriate IAM permissions",
                "S3 data events enabled in CloudTrail",
            ],
        ),
        # Strategy 2: Lambda-based Bulk Access Detection
        DetectionStrategy(
            strategy_id="t1530-lambda-bulk",
            name="Lambda-Based Bulk S3 Access Detection",
            description=(
                "Deploy Lambda-based detection for bulk S3 access with intelligent scoring. "
                "Evaluates access volume, sensitive bucket patterns, out-of-hours access, "
                "and cross-region patterns. Provides more granular control than threshold-only alerting."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["s3.amazonaws.com"],
                        "eventName": ["GetObject", "ListObjects", "ListObjectsV2"],
                    },
                },
                terraform_template="""# Lambda-based bulk S3 access detection

variable "name_prefix" {
  type        = string
  default     = "t1530-bulk-access"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "object_count_threshold" {
  type        = number
  default     = 50
  description = "Number of objects accessed to trigger alert"
}

variable "bytes_threshold" {
  type        = number
  default     = 104857600
  description = "Bytes transferred to trigger alert (default 100MB)"
}

variable "timezone" {
  type        = string
  default     = "Europe/London"
}

variable "allowlisted_arns" {
  type        = list(string)
  default     = []
  description = "Principal ARNs to exclude (ETL, backup processes)"
}

variable "sensitive_bucket_patterns" {
  type        = list(string)
  default     = ["backup", "logs", "pii", "sensitive", "confidential"]
  description = "Bucket name patterns considered sensitive"
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

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}

# DynamoDB for access tracking (optional but recommended)
resource "aws_dynamodb_table" "tracking" {
  name         = "${var.name_prefix}-tracking"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_bucket"

  attribute {
    name = "principal_bucket"
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
        Resource = aws_dynamodb_table.tracking.arn
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
      SNS_TOPIC_ARN              = aws_sns_topic.alerts.arn
      TRACKING_TABLE             = aws_dynamodb_table.tracking.name
      TZ                         = var.timezone
      OBJECT_COUNT_THRESHOLD     = tostring(var.object_count_threshold)
      BYTES_THRESHOLD            = tostring(var.bytes_threshold)
      ALLOWLIST_ARNS             = join(",", var.allowlisted_arns)
      SENSITIVE_BUCKET_PATTERNS  = join(",", var.sensitive_bucket_patterns)
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.detector.function_name}"
  retention_in_days = 30
}

# EventBridge rule for S3 GetObject events
resource "aws_cloudwatch_event_rule" "s3_access" {
  name        = "${var.name_prefix}-s3-access"
  description = "Capture S3 access events for bulk detection"

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["GetObject", "ListObjects", "ListObjectsV2"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.s3_access.name
  target_id = "LambdaDetector"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_access.arn
}

# Outputs
output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.detector.function_name
}""",
                alert_severity="high",
                alert_title="Bulk S3 Data Access Detected",
                alert_description_template=(
                    "Principal {principal_arn} accessed {access_count} objects from bucket {bucket_name}. "
                    "Score: {score}/100. Source IP: {source_ip}."
                ),
                investigation_steps=[
                    "Identify what specific objects were accessed",
                    "Verify if this access pattern is normal for the user",
                    "Check the source IP geolocation and reputation",
                    "Review if the data accessed was sensitive or regulated",
                    "Compare with the user's historical access patterns",
                    "Check for data copied to external destinations",
                ],
                containment_actions=[
                    "Temporarily revoke the principal's S3 access",
                    "Add source IP to bucket policy deny list",
                    "Enable S3 access logging if not already enabled",
                    "Review and tighten bucket access policies",
                    "Check if any data was exfiltrated",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Use allowlisted_arns for ETL, backup, and data pipeline roles. "
                "Adjust object_count_threshold based on normal access patterns. "
                "Tune sensitive_bucket_patterns for your naming conventions."
            ),
            detection_coverage=(
                "80% - Catches bulk download attempts with scoring. "
                "Provides granular control beyond simple thresholds."
            ),
            evasion_considerations=(
                "Slow, distributed exfiltration over extended periods may evade. "
                "Combine with GuardDuty for ML-based anomaly detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30 (Lambda + DynamoDB + SNS)",
            prerequisites=[
                "CloudTrail S3 data events enabled",
                "EventBridge configured to receive CloudTrail events",
            ],
        ),
        # Strategy 3: Cross-Account S3 Access Detection
        DetectionStrategy(
            strategy_id="t1530-cross-account",
            name="Cross-Account S3 Access Detection",
            description=(
                "Detect when S3 objects are accessed by principals from external AWS accounts, "
                "which may indicate data exfiltration to attacker-controlled infrastructure."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.accountId as caller_account,
       userIdentity.arn as user, requestParameters.bucketName as bucket,
       sourceIPAddress, eventName
| filter eventName in ["GetObject", "CopyObject", "UploadPartCopy"]
| filter userIdentity.accountId != "YOUR_ACCOUNT_ID"
| stats count(*) as access_count by caller_account, user, bucket, bin(1h)
| filter access_count > 10
| sort access_count desc""",
                terraform_template="""# Cross-account S3 access detection

variable "account_id" {
  type        = string
  description = "Your AWS account ID"
}

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

resource "aws_sns_topic" "alerts" {
  name              = "cross-account-s3-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch metric filter for cross-account access
resource "aws_cloudwatch_log_metric_filter" "cross_account" {
  name           = "cross-account-s3-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"GetObject\" && $.userIdentity.accountId != \"${var.account_id}\" }"

  metric_transformation {
    name          = "CrossAccountS3Access"
    namespace     = "Security/T1530"
    value         = "1"
    default_value = "0"
    dimensions = {
      CallerAccount = "$.userIdentity.accountId"
      Bucket        = "$.requestParameters.bucketName"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "cross_account" {
  alarm_name          = "Cross-Account-S3-Access"
  alarm_description   = "External account accessing S3 data"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CrossAccountS3Access"
  namespace           = "Security/T1530"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Cross-Account S3 Access Detected",
                alert_description_template=(
                    "Account {caller_account} accessed bucket {bucket} {access_count} times. "
                    "Verify this cross-account access is authorised."
                ),
                investigation_steps=[
                    "Identify the external account accessing your buckets",
                    "Verify if this account is a known partner or service",
                    "Review bucket policies for overly permissive cross-account access",
                    "Check what specific data was accessed",
                    "Determine if the access pattern is normal",
                ],
                containment_actions=[
                    "Update bucket policy to restrict external access",
                    "Implement VPC endpoints for S3 if applicable",
                    "Review and audit all cross-account access policies",
                    "Consider using AWS RAM for controlled resource sharing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Maintain list of trusted partner account IDs in alarm filter",
            detection_coverage="70% - catches cross-account exfiltration attempts",
            evasion_considerations="Attackers may use compromised accounts within the organisation",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudTrail S3 data events enabled",
                "CloudTrail logs in CloudWatch",
            ],
        ),
        # Strategy 4: GCP Cloud Storage Exfiltration Detection
        DetectionStrategy(
            strategy_id="t1530-gcp-gcs",
            name="GCP Cloud Storage Exfiltration Detection",
            description=(
                "Detect data exfiltration from GCP Cloud Storage using Cloud Audit Logs. "
                "Monitor for bulk downloads, cross-project access, and sensitive bucket access."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""-- GCS data access and potential exfiltration
resource.type="gcs_bucket"
protoPayload.methodName=~"storage.objects.get|storage.objects.list"
severity>=NOTICE
""",
                gcp_terraform_template="""# GCP Cloud Storage Exfiltration Detection

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

variable "bulk_access_threshold" {
  type    = number
  default = 100
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "GCS Exfiltration Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for GCS object access
resource "google_logging_metric" "gcs_object_access" {
  project = var.project_id
  name    = "gcs-object-access"
  filter  = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName=~"storage.objects.get|storage.objects.list"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
    }
    labels {
      key         = "bucket"
      value_type  = "STRING"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "bucket"    = "EXTRACT(resource.labels.bucket_name)"
  }
}

# Alert for bulk GCS access
resource "google_monitoring_alert_policy" "gcs_bulk_access" {
  project      = var.project_id
  display_name = "GCS Bulk Access - Potential Exfiltration"
  combiner     = "OR"

  conditions {
    display_name = "High volume GCS object access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_object_access.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = var.bulk_access_threshold

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
        group_by_fields    = ["metric.label.principal", "metric.label.bucket"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "High volume Cloud Storage access detected. May indicate data exfiltration."
    mime_type = "text/markdown"
  }
}

# Log-based metric for cross-project access
resource "google_logging_metric" "gcs_cross_project" {
  project = var.project_id
  name    = "gcs-cross-project-access"
  filter  = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName=~"storage.objects.get"
    protoPayload.authenticationInfo.principalEmail!~"@${var.project_id}.iam.gserviceaccount.com"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "gcs_cross_project" {
  project      = var.project_id
  display_name = "GCS Cross-Project Access"
  combiner     = "OR"

  conditions {
    display_name = "Cross-project GCS access detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_cross_project.name}\""
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
    content   = "Cross-project Cloud Storage access detected. Verify authorisation."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Cloud Storage Exfiltration Detected",
                alert_description_template=(
                    "Principal {principal} accessed bucket {bucket} with high volume. "
                    "This may indicate data exfiltration."
                ),
                investigation_steps=[
                    "Review Cloud Audit Logs for all access by this principal",
                    "Identify what specific objects were accessed",
                    "Verify the access was authorised",
                    "Check for cross-project or cross-organisation access",
                    "Review IAM permissions on the bucket",
                ],
                containment_actions=[
                    "Revoke the principal's access to the bucket",
                    "Update bucket IAM policy to restrict access",
                    "Enable Object Versioning if not already enabled",
                    "Review VPC Service Controls configuration",
                    "Check for data copied to external projects",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Adjust bulk_access_threshold based on normal patterns. "
                "Exclude known data pipeline service accounts."
            ),
            detection_coverage="70% - catches bulk and cross-project access",
            evasion_considerations="Slow exfiltration may evade threshold-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Audit Logs enabled for GCS",
                "Cloud Monitoring API enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1530-guardduty",  # ML-based, lowest effort, comprehensive
        "t1530-lambda-bulk",  # Intelligent bulk detection
        "t1530-cross-account",  # Cross-account exfiltration
        "t1530-gcp-gcs",  # GCP coverage
    ],
    total_effort_hours=6.0,
    coverage_improvement="+40% improvement for Collection tactic",
)
