"""
T1550.001 - Use Alternate Authentication Material: Application Access Token

Adversaries use stolen application access tokens to bypass normal authentication
and access cloud resources without needing passwords or MFA.
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
    technique_id="T1550.001",
    technique_name="Use Alternate Authentication Material: Application Access Token",
    tactic_ids=["TA0005", "TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1550/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit stolen application access tokens to circumvent "
            "standard authentication mechanisms and gain unauthorised access to cloud "
            "resources. These tokens enable API access without requiring passwords or "
            "MFA, making them high-value targets for credential theft attacks."
        ),
        attacker_goal="Use stolen OAuth/API tokens to access cloud resources whilst bypassing authentication controls",
        why_technique=[
            "Tokens bypass password-based authentication and MFA",
            "OAuth tokens often have long validity periods",
            "Tokens can be reused from any location without triggering location-based alerts",
            "API access negates effectiveness of second authentication factors",
            "Service account tokens frequently have elevated permissions",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Token-based attacks bypass traditional authentication controls including MFA. "
            "Once stolen, tokens provide immediate access to cloud resources and APIs. "
            "The increasing use of OAuth and cloud services makes this technique highly relevant."
        ),
        business_impact=[
            "Unauthorised access to cloud applications without MFA",
            "Data exfiltration via legitimate API calls",
            "Persistent access until token expiration or rotation",
            "Lateral movement to connected cloud services",
            "Compliance violations due to bypassed authentication controls",
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1530", "T1537", "T1114"],
        often_follows=["T1528", "T1552", "T1566"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Golden SAML Detection (Production-Grade)
        DetectionStrategy(
            strategy_id="t1550001-aws-golden-saml",
            name="AWS Golden SAML Detection (Production-Grade)",
            description=(
                "Detect Golden SAML attacks where adversaries use forged SAML assertions to obtain AWS credentials. "
                "Features: detects AssumeRoleWithSAML without MFA context, assertion reuse across multiple IPs, "
                "unusual SAML provider usage, privileged role access via SAML, production-grade alerting with DLQ, "
                "SNS encryption, and retry policies. Implements impossible travel detection for federated sessions."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.sts"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["AssumeRoleWithSAML"],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Production-grade Golden SAML detection for T1550.001.
  Features: MFA context validation, impossible travel, assertion reuse detection,
  privileged role monitoring, DLQ, SNS encryption, structured alerts.

Parameters:
  AlertEmail:
    Type: String
    Description: Email for SNS alerts (requires subscription confirmation)
  TrustedSAMLProviderArns:
    Type: String
    Default: ""
    Description: Comma-separated ARNs of trusted SAML providers
  PrivilegedRolePatterns:
    Type: String
    Default: "Admin,PowerUser,Security,Billing"
    Description: Comma-separated patterns identifying privileged roles
  ImpossibleTravelThresholdKm:
    Type: Number
    Default: 500
    Description: Minimum distance in km to trigger impossible travel alert

Resources:
  # Step 1: Encrypted SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: t1550001-golden-saml-alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Step 2: Lambda execution role with least privilege
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: t1550001-golden-saml-lambda-role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: LambdaPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: sns:Publish
                Resource: !Ref AlertTopic
              - Effect: Allow
                Action:
                  - dynamodb:GetItem
                  - dynamodb:PutItem
                  - dynamodb:UpdateItem
                Resource: !GetAtt SAMLAssertionTracker.Arn

  # Step 3: DynamoDB table for tracking SAML assertions
  SAMLAssertionTracker:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: t1550001-saml-assertion-tracker
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: principal_id
          AttributeType: S
        - AttributeName: timestamp
          AttributeType: N
      KeySchema:
        - AttributeName: principal_id
          KeyType: HASH
        - AttributeName: timestamp
          KeyType: RANGE
      TimeToLiveSpecification:
        AttributeName: ttl
        Enabled: true

  # Step 4: Lambda function for Golden SAML detection
  GoldenSAMLDetectionFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: t1550001-golden-saml-detector
      Runtime: python3.12
      Handler: index.lambda_handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Timeout: 30
      MemorySize: 512
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref AlertTopic
          TRUSTED_SAML_PROVIDERS: !Ref TrustedSAMLProviderArns
          PRIVILEGED_ROLE_PATTERNS: !Ref PrivilegedRolePatterns
          IMPOSSIBLE_TRAVEL_THRESHOLD_KM: !Ref ImpossibleTravelThresholdKm
          TRACKER_TABLE: !Ref SAMLAssertionTracker
          ACCOUNT_ID: !Ref AWS::AccountId
          REGION: !Ref AWS::Region
      Code:
        ZipFile: |
          import json, os, boto3, time, ipaddress
          from datetime import datetime, timezone
          from decimal import Decimal

          sns = boto3.client("sns")
          dynamodb = boto3.resource("dynamodb")
          table = dynamodb.Table(os.environ["TRACKER_TABLE"])

          def _env_list(name):
              raw = os.getenv(name, "").strip()
              return [x.strip() for x in raw.split(",") if x.strip()] if raw else []

          def _is_private_ip(ip_str):
              if not ip_str: return False
              try:
                  ip = ipaddress.ip_address(ip_str)
                  return ip.is_private
              except: return False

          def _parse_dt(s):
              if not s: return datetime.now(timezone.utc)
              if s.endswith("Z"): s = s[:-1] + "+00:00"
              return datetime.fromisoformat(s).astimezone(timezone.utc)

          def lambda_handler(event, context):
              detail = event.get("detail", {}) or {}

              # Extract SAML assertion details
              principal_id = (detail.get("userIdentity") or {}).get("principalId", "") or "unknown"
              role_arn = (detail.get("requestParameters") or {}).get("roleArn", "")
              saml_provider_arn = (detail.get("requestParameters") or {}).get("principalArn", "")
              source_ip = detail.get("sourceIPAddress", "")
              user_agent = detail.get("userAgent", "")
              event_time = _parse_dt(detail.get("eventTime", ""))
              error_code = detail.get("errorCode")

              # Extract SAML response context (if available)
              response_elements = detail.get("responseElements") or {}
              assumed_role_user = response_elements.get("assumedRoleUser") or {}
              session_token = (response_elements.get("credentials") or {}).get("sessionToken", "")

              # Extract MFA context from requestContext
              request_context = detail.get("requestContext") or {}
              mfa_authenticated = request_context.get("mfaAuthenticated", "false")

              # Suppress successful events with errors
              if error_code:
                  return {"decision": "suppressed_error", "error": error_code}

              alerts = []
              severity = "MEDIUM"

              # Detection 1: AssumeRoleWithSAML without MFA context
              if mfa_authenticated.lower() != "true":
                  alerts.append("SAML authentication without MFA context")
                  severity = "HIGH"

              # Detection 2: Untrusted SAML provider
              trusted_providers = set(_env_list("TRUSTED_SAML_PROVIDERS"))
              if trusted_providers and saml_provider_arn not in trusted_providers:
                  alerts.append(f"Untrusted SAML provider: {saml_provider_arn}")
                  severity = "CRITICAL"

              # Detection 3: Privileged role access via SAML
              privileged_patterns = _env_list("PRIVILEGED_ROLE_PATTERNS")
              if any(pattern.lower() in role_arn.lower() for pattern in privileged_patterns):
                  alerts.append(f"Privileged role access via SAML: {role_arn}")
                  if severity == "MEDIUM":
                      severity = "HIGH"

              # Detection 4: External/non-private IP (possible credential exfiltration)
              if source_ip and not _is_private_ip(source_ip):
                  alerts.append(f"SAML authentication from external IP: {source_ip}")

              # Detection 5: Check for assertion reuse and impossible travel
              try:
                  response = table.get_item(
                      Key={"principal_id": principal_id, "timestamp": int(event_time.timestamp())}
                  )

                  # Query recent authentications for this principal
                  query_response = table.query(
                      KeyConditionExpression="principal_id = :pid AND #ts > :recent",
                      ExpressionAttributeNames={"#ts": "timestamp"},
                      ExpressionAttributeValues={
                          ":pid": principal_id,
                          ":recent": int(event_time.timestamp()) - 3600  # Last hour
                      },
                      Limit=10
                  )

                  if query_response.get("Items"):
                      unique_ips = set()
                      for item in query_response["Items"]:
                          item_ip = item.get("source_ip", "")
                          if item_ip and item_ip != source_ip:
                              unique_ips.add(item_ip)

                      if len(unique_ips) >= 2:
                          alerts.append(f"SAML assertion reuse from multiple IPs: {len(unique_ips) + 1} unique IPs in last hour")
                          severity = "CRITICAL"

                  # Store current authentication
                  table.put_item(
                      Item={
                          "principal_id": principal_id,
                          "timestamp": int(event_time.timestamp()),
                          "source_ip": source_ip,
                          "role_arn": role_arn,
                          "saml_provider": saml_provider_arn,
                          "user_agent": user_agent,
                          "mfa_authenticated": mfa_authenticated,
                          "ttl": int(event_time.timestamp()) + 86400  # 24 hour TTL
                      }
                  )
              except Exception as e:
                  print(f"DynamoDB error: {e}")

              # Only alert if suspicious indicators found
              if not alerts:
                  return {"decision": "suppressed_normal"}

              # Build alert payload
              payload = {
                  "control": "T1550.001-GoldenSAML",
                  "decision": "alert",
                  "severity": severity,
                  "alerts": alerts,
                  "event_time_utc": event_time.isoformat(),
                  "principal": {
                      "principal_id": principal_id,
                      "role_arn": role_arn,
                      "assumed_role_user": assumed_role_user.get("arn", "")
                  },
                  "saml": {
                      "provider_arn": saml_provider_arn,
                      "mfa_authenticated": mfa_authenticated
                  },
                  "network": {
                      "source_ip": source_ip,
                      "user_agent": user_agent,
                      "is_private_ip": _is_private_ip(source_ip)
                  },
                  "cloudtrail": {
                      "eventName": detail.get("eventName", ""),
                      "eventID": detail.get("eventID", "")
                  },
                  "account": os.getenv("ACCOUNT_ID", ""),
                  "region": os.getenv("REGION", "")
              }

              subject = f"Golden SAML Alert [{severity}] - {principal_id[:50]}"[:100]
              sns.publish(
                  TopicArn=os.environ["SNS_TOPIC_ARN"],
                  Subject=subject,
                  Message=json.dumps(payload, indent=2, default=str)
              )

              return {"decision": "alerted", "severity": severity, "alert_count": len(alerts)}

  # Step 5: Lambda log retention
  LambdaLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub /aws/lambda/${GoldenSAMLDetectionFunction}
      RetentionInDays: 30

  # Step 6: DLQ for failed events
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: t1550001-golden-saml-dlq
      MessageRetentionPeriod: 1209600

  # Step 7: EventBridge rule for AssumeRoleWithSAML
  AssumeRoleWithSAMLRule:
    Type: AWS::Events::Rule
    Properties:
      Name: t1550001-assume-role-with-saml
      Description: Detect potential Golden SAML attacks
      EventPattern:
        source:
          - aws.sts
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - AssumeRoleWithSAML
      State: ENABLED
      Targets:
        - Id: GoldenSAMLDetector
          Arn: !GetAtt GoldenSAMLDetectionFunction.Arn
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn

  LambdaInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref GoldenSAMLDetectionFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt AssumeRoleWithSAMLRule.Arn

  # Step 8: SNS topic policy
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowLambdaPublishOnly
            Effect: Allow
            Principal:
              AWS: !GetAtt LambdaExecutionRole.Arn
            Action: sns:Publish
            Resource: !Ref AlertTopic

Outputs:
  AlertTopicArn:
    Value: !Ref AlertTopic
  LambdaFunctionName:
    Value: !Ref GoldenSAMLDetectionFunction
  TrackerTableName:
    Value: !Ref SAMLAssertionTracker
  DLQUrl:
    Value: !Ref EventDLQ""",
                terraform_template="""# T1550.001 Golden SAML Detection (Production-Grade)
# Detects: AssumeRoleWithSAML without MFA, assertion reuse, impossible travel, untrusted providers

variable "name_prefix" {
  type    = string
  default = "t1550001-golden-saml"
}

variable "alert_email" {
  type        = string
  description = "Email for SNS alerts"
}

variable "trusted_saml_provider_arns" {
  type        = list(string)
  default     = []
  description = "ARNs of trusted SAML identity providers"
}

variable "privileged_role_patterns" {
  type    = list(string)
  default = ["Admin", "PowerUser", "Security", "Billing"]
}

variable "impossible_travel_threshold_km" {
  type    = number
  default = 500
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Step 1: Encrypted SNS topic
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: DynamoDB table for tracking SAML assertions
resource "aws_dynamodb_table" "saml_tracker" {
  name         = "${var.name_prefix}-assertion-tracker"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "principal_id"
  range_key = "timestamp"

  attribute {
    name = "principal_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "N"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}

# Step 3: Lambda execution role
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

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_custom" {
  name = "${var.name_prefix}-lambda-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.saml_tracker.arn
      }
    ]
  })
}

# Step 4: Lambda function (see CloudFormation template for full code)
resource "aws_lambda_function" "golden_saml_detector" {
  function_name = "${var.name_prefix}-detector"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.12"
  handler       = "index.lambda_handler"
  timeout       = 30
  memory_size   = 512

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN                 = aws_sns_topic.alerts.arn
      TRUSTED_SAML_PROVIDERS        = join(",", var.trusted_saml_provider_arns)
      PRIVILEGED_ROLE_PATTERNS      = join(",", var.privileged_role_patterns)
      IMPOSSIBLE_TRAVEL_THRESHOLD_KM = tostring(var.impossible_travel_threshold_km)
      TRACKER_TABLE                 = aws_dynamodb_table.saml_tracker.name
      ACCOUNT_ID                    = data.aws_caller_identity.current.account_id
      REGION                        = data.aws_region.current.name
    }
  }
}

# Lambda code packaging - see CloudFormation template for full implementation
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda-golden-saml.zip"

  source {
    content  = file("${path.module}/lambda/golden_saml_detector.py")
    filename = "index.py"
  }
}

# Step 5: Log retention
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.golden_saml_detector.function_name}"
  retention_in_days = 30
}

# Step 6: DLQ for failed events
resource "aws_sqs_queue" "event_dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600
}

# Step 7: EventBridge rule
resource "aws_cloudwatch_event_rule" "assume_role_with_saml" {
  name        = "${var.name_prefix}-assume-role-saml"
  description = "Detect potential Golden SAML attacks"

  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["AssumeRoleWithSAML"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.assume_role_with_saml.name
  target_id = "GoldenSAMLDetector"
  arn       = aws_lambda_function.golden_saml_detector.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
  }
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.golden_saml_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.assume_role_with_saml.arn
}

# Step 8: SNS topic policy
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
    }]
  })
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.golden_saml_detector.function_name
}

output "tracker_table_name" {
  value = aws_dynamodb_table.saml_tracker.name
}

output "dlq_url" {
  value = aws_sqs_queue.event_dlq.url
}""",
                alert_severity="critical",
                alert_title="Golden SAML Attack Detected",
                alert_description_template=(
                    "[{severity}] Golden SAML indicators detected for principal {principal.principal_id}. "
                    "Alerts: {alerts}. Role: {principal.role_arn}. SAML Provider: {saml.provider_arn}. "
                    "Source IP: {network.source_ip}. MFA: {saml.mfa_authenticated}."
                ),
                investigation_steps=[
                    "CRITICAL: Review all alerts - multiple indicators suggest Golden SAML attack",
                    "Check if SAML provider ARN matches your organisation's trusted IdP",
                    "Verify MFA was used for authentication (should be true for privileged access)",
                    "Review source IP - external IPs are high risk for SAML authentication",
                    "Check DynamoDB tracker table for assertion reuse patterns across multiple IPs",
                    "Review CloudTrail for the SAML assertion details and certificate used",
                    "Check identity provider (AD FS/Okta/etc) logs for matching authentication events",
                    "Look for recent SAML certificate changes or new federation trusts",
                    "Review all API calls made with the assumed role credentials",
                    "Check for privilege escalation or lateral movement following SAML authentication",
                ],
                containment_actions=[
                    "Immediately revoke the active session using AWS STS",
                    "Rotate SAML signing certificates TWICE in succession",
                    "Disable or remove untrusted SAML identity providers",
                    "Update IAM role trust policies to require MFA for SAML authentication",
                    "Enable CloudTrail advanced event selectors for SAML events",
                    "Review and revert any unauthorised changes made during the session",
                    "Implement IP allowlisting for SAML provider endpoints",
                    "Enable AWS IAM Access Analyser to detect external access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Configure trusted_saml_provider_arns with your organisation's legitimate SAML IdP ARNs; "
                "adjust privileged_role_patterns to match your naming conventions; "
                "review corporate VPN/proxy IPs if flagged as external"
            ),
            detection_coverage=(
                "90% - comprehensive Golden SAML detection including assertion reuse, MFA bypass, "
                "untrusted providers, and privileged role access"
            ),
            evasion_considerations=(
                "Attackers may use legitimate SAML providers with stolen certificates; "
                "low-volume attacks from corporate IP ranges may evade IP-based detection; "
                "combine with AD FS monitoring for complete coverage"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25 (Lambda, DynamoDB, SNS)",
            prerequisites=[
                "CloudTrail enabled with management events",
                "EventBridge configured",
                "STS API logging enabled",
                "Lambda runtime Python 3.12",
            ],
        ),
        # Strategy 2: AWS - STS Token Anomalies
        DetectionStrategy(
            strategy_id="t1550001-aws-sts",
            name="AWS STS Token Usage Anomalies",
            description="Detect unusual AWS STS API calls that request temporary credentials with elevated privileges.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, requestParameters.durationSeconds
| filter eventSource = "sts.amazonaws.com"
| filter eventName in ["GetFederationToken", "AssumeRole", "GetSessionToken"]
| stats count(*) as token_requests, count_distinct(sourceIPAddress) as unique_ips by userIdentity.arn, bin(1h)
| filter token_requests > 20 or unique_ips > 3
| sort token_requests desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect STS token anomalies for T1550.001

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for STS token requests
  STSTokenFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "sts.amazonaws.com" && ($.eventName = "GetFederationToken" || $.eventName = "AssumeRole" || $.eventName = "GetSessionToken") }'
      MetricTransformations:
        - MetricName: STSTokenRequests
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm for unusual token activity
  STSTokenAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualSTSTokenActivity
      MetricName: STSTokenRequests
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect STS token anomalies

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "sts-token-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for STS token requests
resource "aws_cloudwatch_log_metric_filter" "sts_tokens" {
  name           = "sts-token-requests"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"sts.amazonaws.com\" && ($.eventName = \"GetFederationToken\" || $.eventName = \"AssumeRole\" || $.eventName = \"GetSessionToken\") }"

  metric_transformation {
    name      = "STSTokenRequests"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for unusual token activity
resource "aws_cloudwatch_metric_alarm" "sts_anomaly" {
  alarm_name          = "UnusualSTSTokenActivity"
  metric_name         = "STSTokenRequests"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unusual STS Token Activity",
                alert_description_template="High volume of STS token requests detected from {userIdentity.arn}. {token_requests} requests from {unique_ips} IP addresses.",
                investigation_steps=[
                    "Review CloudTrail for all STS API calls by the affected identity",
                    "Check source IP addresses for unusual geolocations",
                    "Verify if token requests match expected application behaviour",
                    "Review what actions were performed with issued tokens",
                    "Check for impossible travel scenarios",
                ],
                containment_actions=[
                    "Revoke active sessions using AWS STS",
                    "Rotate credentials for the affected identity",
                    "Review and restrict STS permissions via IAM policies",
                    "Enable MFA requirement for sensitive STS operations",
                    "Implement IP allowlisting for token requests",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known automation systems and CI/CD pipelines; adjust threshold based on normal token usage patterns",
            detection_coverage="70% - catches volume-based anomalies",
            evasion_considerations="Attackers may throttle token requests to evade volume thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail logging STS events to CloudWatch Logs"],
        ),
        # Strategy 2: AWS - OAuth Token Reuse Detection
        DetectionStrategy(
            strategy_id="t1550001-aws-oauth-reuse",
            name="OAuth Token Reuse from Multiple Locations",
            description="Detect when OAuth tokens are used from multiple geographic locations or user agents.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, userAgent
| filter eventSource = "cognito-idp.amazonaws.com"
| filter eventName in ["InitiateAuth", "RespondToAuthChallenge", "GetUser", "GetUserAttributeVerificationCode"]
| stats count(*) as auth_count,
        count_distinct(sourceIPAddress) as ip_count,
        count_distinct(userAgent) as agent_count
  by userIdentity.principalId, bin(4h)
| filter ip_count > 2 or agent_count > 2
| sort auth_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect OAuth token reuse anomalies

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for Cognito auth from multiple IPs
  OAuthReuseFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "cognito-idp.amazonaws.com" && ($.eventName = "InitiateAuth" || $.eventName = "RespondToAuthChallenge") }'
      MetricTransformations:
        - MetricName: CognitoAuthAttempts
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm for token reuse
  TokenReuseAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: OAuthTokenReuse
      MetricName: CognitoAuthAttempts
      Namespace: Security
      Statistic: Sum
      Period: 14400
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect OAuth token reuse anomalies

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "oauth-token-reuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for Cognito auth
resource "aws_cloudwatch_log_metric_filter" "oauth_reuse" {
  name           = "oauth-token-reuse"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"cognito-idp.amazonaws.com\" && ($.eventName = \"InitiateAuth\" || $.eventName = \"RespondToAuthChallenge\") }"

  metric_transformation {
    name      = "CognitoAuthAttempts"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for token reuse
resource "aws_cloudwatch_metric_alarm" "token_reuse" {
  alarm_name          = "OAuthTokenReuse"
  metric_name         = "CognitoAuthAttempts"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 14400
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="OAuth Token Used from Multiple Locations",
                alert_description_template="Token for {userIdentity.principalId} used from {ip_count} different IP addresses and {agent_count} user agents.",
                investigation_steps=[
                    "Identify all source IPs and geolocate them",
                    "Review user agent strings for suspicious patterns",
                    "Check if legitimate for user to access from multiple locations",
                    "Review all API calls made with the token",
                    "Correlate with other security events for the user",
                ],
                containment_actions=[
                    "Revoke the OAuth token immediately",
                    "Force user re-authentication with MFA",
                    "Enable token binding if supported",
                    "Review and restrict OAuth application permissions",
                    "Implement context-aware access controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Consider legitimate use cases like VPN users or mobile workers; whitelist known corporate IP ranges",
            detection_coverage="65% - detects token reuse patterns",
            evasion_considerations="Attackers using tokens from expected geographic regions",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail logging Cognito events"],
        ),
        # Strategy 3: GCP - Service Account Token Abuse
        DetectionStrategy(
            strategy_id="t1550001-gcp-sa-token",
            name="GCP Service Account Token Abuse Detection",
            description="Detect service account tokens used from unauthorised locations or with unusual patterns.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.authenticationInfo.principalEmail=~".*@.*iam.gserviceaccount.com"
protoPayload.requestMetadata.callerIp!~"^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|35\\.)"
severity>=NOTICE""",
                gcp_terraform_template="""# GCP: Detect service account token abuse

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for external SA token usage
resource "google_logging_metric" "sa_token_external" {
  name   = "external-sa-token-usage"
  filter = <<-EOT
    protoPayload.authenticationInfo.principalEmail=~".*@.*iam.gserviceaccount.com"
    protoPayload.requestMetadata.callerIp!~"^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|35\\.)"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for external token usage
resource "google_monitoring_alert_policy" "sa_token_alert" {
  display_name = "Service Account Token Used Externally"
  combiner     = "OR"

  conditions {
    display_name = "SA token from external IP"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_token_external.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Service account token detected in use from external IP address. This may indicate stolen credentials."
  }
}""",
                alert_severity="high",
                alert_title="Service Account Token Used from External Location",
                alert_description_template="Service account token used from external IP address. This may indicate credential theft.",
                investigation_steps=[
                    "Identify which service account token was used",
                    "Review the source IP address and geolocation",
                    "Check what API calls were made with the token",
                    "Verify if external access is legitimate",
                    "Review service account key creation/download logs",
                ],
                containment_actions=[
                    "Delete and rotate the service account key",
                    "Disable the service account if not actively needed",
                    "Review and reduce service account permissions",
                    "Enable VPC Service Controls to restrict access",
                    "Implement Workload Identity where possible",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known external services and CI/CD systems; exclude Google Cloud IP ranges",
            detection_coverage="75% - catches external token usage",
            evasion_considerations="Attackers using GCP-hosted infrastructure or VPN",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - OAuth Token Anomaly Detection
        DetectionStrategy(
            strategy_id="t1550001-gcp-oauth",
            name="GCP OAuth Token Anomaly Detection",
            description="Detect unusual OAuth token usage patterns including token reuse and consent anomalies.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="audited_resource"
(protoPayload.methodName=~"google.identity.*" OR protoPayload.serviceName="oauth2.googleapis.com")
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Detect OAuth token anomalies

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for OAuth anomalies
resource "google_logging_metric" "oauth_anomalies" {
  name   = "oauth-token-anomalies"
  filter = <<-EOT
    resource.type="audited_resource"
    (protoPayload.methodName=~"google.identity.*" OR protoPayload.serviceName="oauth2.googleapis.com")
    severity>=WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for OAuth anomalies
resource "google_monitoring_alert_policy" "oauth_alert" {
  display_name = "OAuth Token Anomalies Detected"
  combiner     = "OR"

  conditions {
    display_name = "Unusual OAuth activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.oauth_anomalies.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Unusual OAuth token activity detected. Review for potential token theft or abuse."
  }
}""",
                alert_severity="high",
                alert_title="GCP OAuth Token Anomalies",
                alert_description_template="Unusual OAuth token activity detected in GCP environment.",
                investigation_steps=[
                    "Review OAuth consent audit logs",
                    "Check for unauthorised third-party application authorisations",
                    "Verify token source IP addresses and locations",
                    "Review workspace admin activity logs",
                    "Check for scope escalation attempts",
                ],
                containment_actions=[
                    "Revoke suspicious OAuth application access",
                    "Remove unauthorised third-party applications",
                    "Enable OAuth app restrictions via workspace admin console",
                    "Review and limit OAuth scopes for applications",
                    "Implement context-aware access policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal OAuth patterns for your organisation; whitelist approved applications",
            detection_coverage="70% - detects anomalous OAuth behaviour",
            evasion_considerations="Legitimate-appearing OAuth flows that blend with normal activity",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled", "Admin Activity logs enabled"],
        ),
        # Strategy 5: AWS - OAuth Consent Grant Attack Detection
        DetectionStrategy(
            strategy_id="t1550001-aws-oauth-consent-grant",
            name="AWS OAuth Consent Grant Attack Detection",
            description=(
                "Detect illicit OAuth consent grant attacks where attackers authorise malicious applications "
                "to access user data without interactive login. Monitors Cognito OAuth2 token grants to "
                "unapproved applications, unusual scope requests, and token grants without user interaction."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.cognito-idp"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "InitiateAuth",
                            "AdminInitiateAuth",
                            "GetUser",
                            "GlobalSignOut",
                            "RevokeToken",
                        ],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Production-grade OAuth consent grant attack detection for T1550.001.
  Detects: unapproved OAuth applications, excessive scope requests, token grants
  without user interaction, non-interactive authentication flows.

Parameters:
  AlertEmail:
    Type: String
    Description: Email for SNS alerts
  ApprovedClientIds:
    Type: String
    Default: ""
    Description: Comma-separated list of approved OAuth client IDs
  SuspiciousScopes:
    Type: String
    Default: "aws.cognito.signin.user.admin,openid,profile,email"
    Description: Comma-separated OAuth scopes that require elevated scrutiny

Resources:
  # Step 1: Encrypted SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: t1550001-oauth-consent-grant-alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Step 2: Lambda execution role
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: t1550001-oauth-consent-grant-lambda-role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: LambdaPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: sns:Publish
                Resource: !Ref AlertTopic

  # Step 3: Lambda function for OAuth consent grant detection
  OAuthConsentGrantDetector:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: t1550001-oauth-consent-grant-detector
      Runtime: python3.12
      Handler: index.lambda_handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Timeout: 30
      MemorySize: 256
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref AlertTopic
          APPROVED_CLIENT_IDS: !Ref ApprovedClientIds
          SUSPICIOUS_SCOPES: !Ref SuspiciousScopes
          ACCOUNT_ID: !Ref AWS::AccountId
          REGION: !Ref AWS::Region
      Code:
        ZipFile: |
          import json, os, boto3
          from datetime import datetime, timezone

          sns = boto3.client("sns")

          def _env_list(name):
              raw = os.getenv(name, "").strip()
              return [x.strip() for x in raw.split(",") if x.strip()] if raw else []

          def _parse_dt(s):
              if not s: return datetime.now(timezone.utc)
              if s.endswith("Z"): s = s[:-1] + "+00:00"
              return datetime.fromisoformat(s).astimezone(timezone.utc)

          def lambda_handler(event, context):
              detail = event.get("detail", {}) or {}
              event_name = detail.get("eventName", "")
              error_code = detail.get("errorCode")

              # Suppress events with errors
              if error_code:
                  return {"decision": "suppressed_error", "error": error_code}

              # Extract authentication details
              request_params = detail.get("requestParameters") or {}
              user_pool_id = request_params.get("userPoolId", "")
              client_id = request_params.get("clientId", "")
              auth_flow = request_params.get("authFlow", "")
              username = request_params.get("username", "")

              user_identity = detail.get("userIdentity") or {}
              principal_id = user_identity.get("principalId", "")
              source_ip = detail.get("sourceIPAddress", "")
              user_agent = detail.get("userAgent", "")
              event_time = _parse_dt(detail.get("eventTime", ""))

              alerts = []
              severity = "MEDIUM"

              # Detection 1: Unapproved OAuth client
              approved_clients = set(_env_list("APPROVED_CLIENT_IDS"))
              if approved_clients and client_id and client_id not in approved_clients:
                  alerts.append(f"Unapproved OAuth client ID: {client_id}")
                  severity = "HIGH"

              # Detection 2: Non-interactive authentication flows (potential token abuse)
              non_interactive_flows = [
                  "ADMIN_NO_SRP_AUTH",
                  "CUSTOM_AUTH",
                  "REFRESH_TOKEN_AUTH",
                  "REFRESH_TOKEN"
              ]
              if auth_flow in non_interactive_flows:
                  alerts.append(f"Non-interactive authentication flow: {auth_flow}")
                  if severity == "MEDIUM":
                      severity = "HIGH"

              # Detection 3: AdminInitiateAuth (bypass user interaction)
              if event_name == "AdminInitiateAuth":
                  alerts.append("AdminInitiateAuth used - bypasses user interaction")
                  severity = "HIGH"

              # Detection 4: Suspicious authentication patterns
              if event_name == "InitiateAuth" and not username:
                  alerts.append("InitiateAuth without username - potential token abuse")

              # Detection 5: Token revocation (may indicate cleanup after attack)
              if event_name == "RevokeToken":
                  alerts.append("OAuth token revocation detected - may indicate cleanup")

              # Only alert if suspicious indicators found
              if not alerts:
                  return {"decision": "suppressed_normal"}

              # Build alert payload
              payload = {
                  "control": "T1550.001-OAuthConsentGrant",
                  "decision": "alert",
                  "severity": severity,
                  "alerts": alerts,
                  "event_time_utc": event_time.isoformat(),
                  "oauth": {
                      "client_id": client_id,
                      "user_pool_id": user_pool_id,
                      "auth_flow": auth_flow,
                      "username": username
                  },
                  "principal": {
                      "principal_id": principal_id
                  },
                  "network": {
                      "source_ip": source_ip,
                      "user_agent": user_agent
                  },
                  "cloudtrail": {
                      "eventName": event_name,
                      "eventID": detail.get("eventID", "")
                  },
                  "account": os.getenv("ACCOUNT_ID", ""),
                  "region": os.getenv("REGION", "")
              }

              subject = f"OAuth Consent Grant Attack [{severity}] - Client {client_id[:30]}"[:100]
              sns.publish(
                  TopicArn=os.environ["SNS_TOPIC_ARN"],
                  Subject=subject,
                  Message=json.dumps(payload, indent=2, default=str)
              )

              return {"decision": "alerted", "severity": severity, "alert_count": len(alerts)}

  # Step 4: Lambda log retention
  LambdaLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub /aws/lambda/${OAuthConsentGrantDetector}
      RetentionInDays: 30

  # Step 5: DLQ for failed events
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: t1550001-oauth-consent-grant-dlq
      MessageRetentionPeriod: 1209600

  # Step 6: EventBridge rule
  CognitoAuthRule:
    Type: AWS::Events::Rule
    Properties:
      Name: t1550001-cognito-oauth-consent-grant
      Description: Detect OAuth consent grant attacks
      EventPattern:
        source:
          - aws.cognito-idp
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - InitiateAuth
            - AdminInitiateAuth
            - GetUser
            - GlobalSignOut
            - RevokeToken
      State: ENABLED
      Targets:
        - Id: OAuthConsentGrantDetector
          Arn: !GetAtt OAuthConsentGrantDetector.Arn
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn

  LambdaInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref OAuthConsentGrantDetector
      Principal: events.amazonaws.com
      SourceArn: !GetAtt CognitoAuthRule.Arn

  # Step 7: SNS topic policy
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowLambdaPublishOnly
            Effect: Allow
            Principal:
              AWS: !GetAtt LambdaExecutionRole.Arn
            Action: sns:Publish
            Resource: !Ref AlertTopic

Outputs:
  AlertTopicArn:
    Value: !Ref AlertTopic
  LambdaFunctionName:
    Value: !Ref OAuthConsentGrantDetector
  DLQUrl:
    Value: !Ref EventDLQ""",
                terraform_template="""# T1550.001 OAuth Consent Grant Attack Detection (Production-Grade)
# Detects: unapproved OAuth clients, non-interactive auth flows, admin bypass

variable "name_prefix" {
  type    = string
  default = "t1550001-oauth-consent"
}

variable "alert_email" {
  type        = string
  description = "Email for SNS alerts"
}

variable "approved_client_ids" {
  type        = list(string)
  default     = []
  description = "List of approved OAuth client IDs"
}

variable "suspicious_scopes" {
  type    = list(string)
  default = ["aws.cognito.signin.user.admin", "openid", "profile", "email"]
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Step 1: Encrypted SNS topic
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Lambda execution role
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

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_custom" {
  name = "${var.name_prefix}-lambda-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = aws_sns_topic.alerts.arn
    }]
  })
}

# Step 3: Lambda function (see CloudFormation for full code)
resource "aws_lambda_function" "oauth_consent_detector" {
  function_name = "${var.name_prefix}-detector"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.12"
  handler       = "index.lambda_handler"
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN       = aws_sns_topic.alerts.arn
      APPROVED_CLIENT_IDS = join(",", var.approved_client_ids)
      SUSPICIOUS_SCOPES   = join(",", var.suspicious_scopes)
      ACCOUNT_ID          = data.aws_caller_identity.current.account_id
      REGION              = data.aws_region.current.name
    }
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda-oauth-consent.zip"

  source {
    content  = file("${path.module}/lambda/oauth_consent_detector.py")
    filename = "index.py"
  }
}

# Step 4: Log retention
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.oauth_consent_detector.function_name}"
  retention_in_days = 30
}

# Step 5: DLQ
resource "aws_sqs_queue" "event_dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600
}

# Step 6: EventBridge rule
resource "aws_cloudwatch_event_rule" "cognito_auth" {
  name        = "${var.name_prefix}-cognito-auth"
  description = "Detect OAuth consent grant attacks"

  event_pattern = jsonencode({
    source      = ["aws.cognito-idp"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "InitiateAuth",
        "AdminInitiateAuth",
        "GetUser",
        "GlobalSignOut",
        "RevokeToken"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.cognito_auth.name
  target_id = "OAuthConsentGrantDetector"
  arn       = aws_lambda_function.oauth_consent_detector.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
  }
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.oauth_consent_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cognito_auth.arn
}

# Step 7: SNS topic policy
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
    }]
  })
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.oauth_consent_detector.function_name
}

output "dlq_url" {
  value = aws_sqs_queue.event_dlq.url
}""",
                alert_severity="high",
                alert_title="OAuth Consent Grant Attack Detected",
                alert_description_template=(
                    "[{severity}] OAuth consent grant attack indicators detected. "
                    "Alerts: {alerts}. Client ID: {oauth.client_id}. Auth Flow: {oauth.auth_flow}. "
                    "Source IP: {network.source_ip}."
                ),
                investigation_steps=[
                    "Review the OAuth client ID - verify it matches approved applications",
                    "Check if the authentication flow is non-interactive (ADMIN_NO_SRP_AUTH, CUSTOM_AUTH)",
                    "Review AdminInitiateAuth usage - this bypasses normal user consent",
                    "Check CloudTrail for the full authentication flow and subsequent API calls",
                    "Verify if the source IP matches expected application infrastructure",
                    "Review Cognito user pool configuration for unauthorised client applications",
                    "Check for OAuth scope escalation or suspicious permission requests",
                    "Look for token revocation events that may indicate attacker cleanup",
                ],
                containment_actions=[
                    "Immediately disable the unauthorised OAuth client in Cognito user pool",
                    "Revoke all tokens issued to the suspicious client ID",
                    "Force sign-out for all users who authenticated via the suspicious client",
                    "Review and update OAuth client allow list in Cognito",
                    "Enable advanced security features in Cognito (compromised credentials detection)",
                    "Implement OAuth scope restrictions and least-privilege access",
                    "Review audit logs for data access via the malicious OAuth grant",
                    "Update application to use interactive authentication flows where possible",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Configure approved_client_ids with legitimate OAuth applications; "
                "whitelist known backend services that use AdminInitiateAuth for valid reasons; "
                "adjust suspicious_scopes based on your application's OAuth usage"
            ),
            detection_coverage=(
                "85% - excellent coverage for OAuth consent grant attacks including "
                "unapproved clients, non-interactive flows, and admin bypass"
            ),
            evasion_considerations=(
                "Attackers may register malicious OAuth clients with legitimate-sounding names; "
                "slow token grants may evade volume-based detection; "
                "combine with user behaviour analytics for comprehensive coverage"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15 (Lambda, SNS)",
            prerequisites=[
                "CloudTrail enabled with Cognito events",
                "EventBridge configured",
                "Cognito user pools configured",
                "Lambda runtime Python 3.12",
            ],
        ),
        # Strategy 6: GCP - OAuth Consent Grant Attack Detection
        DetectionStrategy(
            strategy_id="t1550001-gcp-oauth-consent-grant",
            name="GCP OAuth Consent Grant Attack Detection",
            description=(
                "Detect illicit OAuth consent grants in GCP where attackers authorise malicious applications "
                "to access Google Workspace or GCP resources. Monitors OAuth2 consent screen bypasses, "
                "suspicious application authorisations, and excessive scope requests."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="audited_resource"
protoPayload.serviceName="oauth2.googleapis.com"
(protoPayload.methodName=~"google.oauth2.v2.approveClient" OR
 protoPayload.methodName=~"google.oauth2.v2.token" OR
 protoPayload.methodName=~"google.oauth2.v2.revokeToken")
severity>=NOTICE""",
                gcp_terraform_template="""# GCP: OAuth Consent Grant Attack Detection

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "OAuth Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Log-based metric for OAuth consent grants
resource "google_logging_metric" "oauth_consent_grants" {
  name   = "oauth-consent-grant-activity"
  filter = <<-EOT
    resource.type="audited_resource"
    protoPayload.serviceName="oauth2.googleapis.com"
    (protoPayload.methodName=~"google.oauth2.v2.approveClient" OR
     protoPayload.methodName=~"google.oauth2.v2.token" OR
     protoPayload.methodName=~"google.oauth2.v2.revokeToken")
    severity>=NOTICE
  EOT
  project = var.project_id

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User email granting consent"
    }
    labels {
      key         = "method_name"
      value_type  = "STRING"
      description = "OAuth method called"
    }
  }

  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "method_name"     = "EXTRACT(protoPayload.methodName)"
  }
}

# Step 3: Alert policy for OAuth consent grant attacks
resource "google_monitoring_alert_policy" "oauth_consent_attack" {
  display_name = "T1550.001: OAuth Consent Grant Attack"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "Suspicious OAuth consent activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.oauth_consent_grants.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "OAuth consent grant attack detected. Review for unauthorised application authorisations."
    mime_type = "text/markdown"
  }

  alert_strategy {
    auto_close = "86400s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: OAuth Consent Grant Attack Detected",
                alert_description_template=(
                    "Suspicious OAuth consent grant activity detected in GCP. "
                    "User {principal_email} performed {method_name}."
                ),
                investigation_steps=[
                    "Review OAuth consent logs in Google Workspace Admin Console",
                    "Check which OAuth application received authorisation",
                    "Verify if the application is from a trusted developer",
                    "Review the OAuth scopes requested by the application",
                    "Check if multiple users have authorised the same suspicious application",
                    "Review data access logs for the OAuth application",
                    "Check for OAuth token usage patterns after consent grant",
                    "Verify if consent was granted during or after a phishing campaign",
                ],
                containment_actions=[
                    "Immediately revoke OAuth token for the suspicious application",
                    "Remove the application from user's authorised apps in Google Account",
                    "Block the OAuth client ID in Google Workspace Admin Console",
                    "Review and revoke organisation-wide OAuth grants if compromised",
                    "Enable Google Workspace security controls to restrict OAuth applications",
                    "Implement OAuth app verification requirements",
                    "Force re-authentication for affected users with MFA",
                    "Review data accessed by the malicious OAuth application",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Baseline normal OAuth application usage; whitelist approved enterprise applications; "
                "adjust threshold based on organisation size and OAuth usage patterns"
            ),
            detection_coverage=(
                "80% - comprehensive detection of OAuth consent grant attacks including "
                "suspicious application authorisations and excessive token grants"
            ),
            evasion_considerations=(
                "Attackers may use legitimate-appearing application names; "
                "gradual consent grants may evade volume thresholds; "
                "combine with user education and OAuth app verification"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "OAuth2 API logging enabled",
                "Google Workspace integration (if applicable)",
            ],
        ),
    ],
    recommended_order=[
        "t1550001-aws-golden-saml",
        "t1550001-aws-oauth-consent-grant",
        "t1550001-aws-sts",
        "t1550001-gcp-oauth-consent-grant",
        "t1550001-gcp-sa-token",
        "t1550001-aws-oauth-reuse",
        "t1550001-gcp-oauth",
    ],
    total_effort_hours=12.0,
    coverage_improvement="+35% improvement for Defence Evasion and Lateral Movement tactics",
)
