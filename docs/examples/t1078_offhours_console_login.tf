# T1078 Off-Hours Console Access Detection (Production-Grade)
# Features: timezone-aware filtering, allowlisting, dynamic severity, DLQ, SNS encryption
# IMPORTANT: Deploy in us-east-1 plus regional sign-in endpoints for full coverage
#
# Fixes applied based on ReAct validation:
# 1. Explicit archive provider declaration (Pattern 8)
# 2. Quoted "detail-type" key in jsonencode (Pattern 9)
# 3. SQS queue policy for EventBridge DLQ (Pattern 6 - CRITICAL)
# 4. Defence-in-depth SNS topic policy conditions

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
  default     = "t1078-offhours"
  description = "Prefix for resource names"
}

variable "alert_email" {
  type        = string
  description = "Email for SNS alerts (requires subscription confirmation)"
}

variable "timezone" {
  type        = string
  default     = "Europe/London"
  description = "IANA timezone for business-hours evaluation"
}

variable "business_start_hour" {
  type        = number
  default     = 8
  description = "Business start hour (0-23) in configured timezone"
}

variable "business_end_hour" {
  type        = number
  default     = 18
  description = "Business end hour (0-23) in configured timezone"
}

variable "business_days" {
  type        = list(number)
  default     = [0, 1, 2, 3, 4]
  description = "Business days as Python weekday numbers (Mon=0...Sun=6)"
}

variable "allowlisted_principal_arns" {
  type        = list(string)
  default     = []
  description = "Principal ARNs to suppress (e.g., break-glass admin role)"
}

variable "allowlisted_source_cidrs" {
  type        = list(string)
  default     = []
  description = "Source IP CIDRs to suppress (e.g., corporate VPN egress)"
}

variable "sns_kms_key_id" {
  type        = string
  default     = "alias/aws/sns"
  description = "KMS key for SNS topic encryption"
}

variable "lambda_log_retention_days" {
  type    = number
  default = 30
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Step 1: Encrypted SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = var.sns_kms_key_id
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Lambda execution role with least privilege
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

resource "aws_iam_policy" "lambda_policy" {
  name = "${var.name_prefix}-lambda-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# Step 3: Lambda function for timezone-aware filtering
resource "aws_lambda_function" "offhours_filter" {
  function_name = "${var.name_prefix}-filter"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.12"
  handler       = "index.lambda_handler"
  timeout       = 10
  memory_size   = 256

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN          = aws_sns_topic.alerts.arn
      TZ                     = var.timezone
      BUSINESS_START_HOUR    = tostring(var.business_start_hour)
      BUSINESS_END_HOUR      = tostring(var.business_end_hour)
      BUSINESS_DAYS          = join(",", [for d in var.business_days : tostring(d)])
      ALLOWLIST_ARNS         = join(",", var.allowlisted_principal_arns)
      ALLOWLIST_SOURCE_CIDRS = join(",", var.allowlisted_source_cidrs)
      ACCOUNT_ID             = data.aws_caller_identity.current.account_id
      DEPLOY_REGION          = data.aws_region.current.name
    }
  }
}

# Lambda code
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"

  source {
    content  = <<-PYTHON
import json, os, ipaddress, boto3
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

sns = boto3.client("sns")

def _env_list(name):
    raw = os.getenv(name, "").strip()
    return [x.strip() for x in raw.split(",") if x.strip()] if raw else []

def _parse_int(name, default):
    try: return int(os.getenv(name, str(default)))
    except: return default

def _parse_dt(s):
    if not s: return datetime.now(timezone.utc)
    if s.endswith("Z"): s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)

def _ip_in_allowlist(ip_str, cidrs):
    if not ip_str or not cidrs: return False
    try: ip = ipaddress.ip_address(ip_str)
    except: return False
    for cidr in cidrs:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False): return True
        except: continue
    return False

def lambda_handler(event, context):
    tz = ZoneInfo(os.getenv("TZ", "Europe/London"))
    start_hour = _parse_int("BUSINESS_START_HOUR", 8)
    end_hour = _parse_int("BUSINESS_END_HOUR", 18)
    business_days = set(int(x) for x in _env_list("BUSINESS_DAYS") or ["0","1","2","3","4"])
    allow_arns = set(_env_list("ALLOWLIST_ARNS"))
    allow_cidrs = _env_list("ALLOWLIST_SOURCE_CIDRS")

    detail = event.get("detail", {}) or {}
    principal_arn = (detail.get("userIdentity") or {}).get("arn", "")
    principal_type = (detail.get("userIdentity") or {}).get("type", "")
    username = (detail.get("userIdentity") or {}).get("userName", "") or principal_arn or "unknown"
    source_ip = detail.get("sourceIPAddress", "")
    user_agent = detail.get("userAgent", "")
    mfa_used = (detail.get("additionalEventData") or {}).get("MFAUsed", "Unknown")

    event_time_utc = _parse_dt(detail.get("eventTime") or event.get("time") or "")
    event_time_local = event_time_utc.astimezone(tz)
    weekday = event_time_local.weekday()
    in_business_day = weekday in business_days
    in_business_hours = (start_hour <= event_time_local.hour < end_hour)

    if principal_arn and principal_arn in allow_arns:
        return {"decision": "suppressed_allowlist_principal"}
    if _ip_in_allowlist(source_ip, allow_cidrs):
        return {"decision": "suppressed_allowlist_ip"}
    if in_business_day and in_business_hours:
        return {"decision": "suppressed_in_hours"}

    reason = "weekend" if not in_business_day else "outside_business_hours"
    severity = "HIGH" if (principal_type == "Root" or str(mfa_used).lower() == "no") else "MEDIUM"

    payload = {
        "control": "T1078-OffHoursConsoleAccess", "decision": "alert", "severity": severity,
        "reason": reason, "timezone": str(tz),
        "event_time_utc": event_time_utc.isoformat(), "event_time_local": event_time_local.isoformat(),
        "principal": {"arn": principal_arn, "type": principal_type, "username": username, "mfa_used": mfa_used},
        "network": {"source_ip": source_ip, "user_agent": user_agent},
        "cloudtrail": {"eventName": detail.get("eventName",""), "eventID": detail.get("eventID","")},
        "account": os.getenv("ACCOUNT_ID",""), "deploy_region": os.getenv("DEPLOY_REGION","")
    }
    subject = f"Off-hours AWS Console login [{severity}] - {username[:40]}"[:100]
    sns.publish(TopicArn=os.environ["SNS_TOPIC_ARN"], Subject=subject, Message=json.dumps(payload, indent=2))
    return {"decision": "alerted", "severity": severity}
PYTHON
    filename = "index.py"
  }
}

# Step 4: Log retention
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.offhours_filter.function_name}"
  retention_in_days = var.lambda_log_retention_days
}

# Step 5: DLQ for failed events
resource "aws_sqs_queue" "event_dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600 # 14 days
}

# Step 5a: SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this policy, EventBridge cannot send failed events to the DLQ
# Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html
data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.event_dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.console_login_success.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.event_dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 6: EventBridge rule
# Note: "detail-type" is quoted for clarity and JSON semantics consistency
resource "aws_cloudwatch_event_rule" "console_login_success" {
  name        = "${var.name_prefix}-console-login-success"
  description = "Route ConsoleLogin success to Lambda for off-hours filtering"

  event_pattern = jsonencode({
    "source"      = ["aws.signin"]
    "detail-type" = [{ "wildcard" = "AWS Console Sign* via CloudTrail" }]
    "detail" = {
      "eventName" = ["ConsoleLogin"]
      "responseElements" = {
        "ConsoleLogin" = ["Success"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.console_login_success.name
  target_id = "OffHoursFilterLambda"
  arn       = aws_lambda_function.offhours_filter.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
  }
}

resource "aws_lambda_permission" "allow_eventbridge_invoke" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.offhours_filter.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.console_login_success.arn
}

# Step 7: SNS topic policy (least privilege with defence-in-depth conditions)
resource "aws_sns_topic_policy" "restrict_publish" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowLambdaPublishOnly"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.lambda_exec.arn }
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

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "event_rule_name" {
  value = aws_cloudwatch_event_rule.console_login_success.name
}

output "lambda_function_name" {
  value = aws_lambda_function.offhours_filter.function_name
}

output "dlq_url" {
  value = aws_sqs_queue.event_dlq.url
}

# OPERATIONAL NOTES:
# 1. Deploy in us-east-1 plus regional sign-in endpoints for full coverage
# 2. CloudTrail must log management events for EventBridge to receive sign-in events
# 3. This covers console sign-ins; add separate controls for programmatic access
#    (AssumeRole, GetFederationToken, access key usage anomalies)
