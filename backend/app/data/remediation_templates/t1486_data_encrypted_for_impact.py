"""
T1486 - Data Encrypted for Impact

Adversaries encrypt data to disrupt availability (ransomware).
In cloud, includes encrypting S3 objects with SSE-C, RDS encryption changes.
Used by LockBit, Conti, REvil, Black Basta.
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
    technique_id="T1486",
    technique_name="Data Encrypted for Impact",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1486/",
    threat_context=ThreatContext(
        description=(
            "Adversaries encrypt data to disrupt availability and demand ransom. "
            "In cloud environments, this includes encrypting S3 objects with SSE-C "
            "(server-side encryption with customer-provided keys), RDS encryption, "
            "and EBS volume encryption changes."
        ),
        attacker_goal="Encrypt data to disrupt operations and demand ransom",
        why_technique=[
            "Direct financial motivation",
            "Cloud storage easily re-encrypted",
            "SSE-C keys controlled by attacker",
            "Backups may also be encrypted",
            "High pressure on victims",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=10,
        severity_reasoning=(
            "Critical impact - ransomware causes major business disruption. "
            "Cloud encryption changes can lock out legitimate users permanently."
        ),
        business_impact=[
            "Complete data inaccessibility",
            "Business operations disruption",
            "Ransom payment pressure",
            "Potential permanent data loss",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1530", "T1485"],
    ),
    detection_strategies=[
        # AWS GuardDuty Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1486-aws-guardduty",
            name="AWS GuardDuty Anomaly Detection",
            description=(
                "AWS GuardDuty detects anomalous encryption-related activities that may indicate ransomware or data encryption for impact. The anomaly detection identifies unusual KMS or encryption API patterns."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Impact:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for T1486

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty-T1486-Alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for GuardDuty findings
  GuardDutyRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Capture GuardDuty findings for T1486
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Impact:IAMUser/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
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
                aws:SourceArn: !GetAtt GuardDutyRule.Arn""",
                terraform_template="""# GuardDuty alerts for T1486

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: SNS Topic
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "guardduty-t1486-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for findings
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-t1486"
  description = "Capture GuardDuty findings for T1486"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Impact:IAMUser/" }]
    }
  })
}

# Step 3: Target with DLQ and retry
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-t1486-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
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

# Step 4: SNS topic policy
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
        StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty.arn }
      }
    }]
  })
}""",
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML baselines; tune suppression rules for known benign patterns",
            detection_coverage="70% - detects anomalous behaviour but may miss attacks that blend with normal activity",
            evasion_considerations="Using legitimate encryption tools, encrypting during maintenance windows, mimicking backup operations",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events",
            prerequisites=[
                "AWS GuardDuty enabled",
                "CloudTrail logging active",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1486-aws-s3-mass-putobject",
            name="AWS S3 Mass Object Replacement Detection",
            description="Detect mass PutObject operations indicating ransomware replacing files with encrypted versions.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["s3.amazonaws.com"],
                        "eventName": ["PutObject", "CopyObject"],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 mass object replacement (ransomware pattern)

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create encrypted SNS topic for alerts
  RansomwareAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: s3-mass-putobject-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for S3 PutObject/CopyObject
  S3MassOperationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: s3-mass-putobject-detection
      Description: Detect mass S3 object replacements
      EventPattern:
        source:
          - aws.s3
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventSource:
            - s3.amazonaws.com
          eventName:
            - PutObject
            - CopyObject
      State: ENABLED
      Targets:
        - Arn: !GetAtt AggregationFunction.Arn
          Id: lambda-target
          RetryPolicy:
            MaximumRetryAttempts: 2
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn

  # Step 3: Lambda function to aggregate events and detect mass operations
  AggregationFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: s3-ransomware-aggregator
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Timeout: 60
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref RansomwareAlertTopic
          THRESHOLD: '100'
          TIME_WINDOW_SECONDS: '300'
      Code:
        ZipFile: |
          import json
          import boto3
          import os
          from datetime import datetime, timedelta
          from collections import defaultdict

          sns = boto3.client('sns')
          cloudtrail = boto3.client('cloudtrail')

          THRESHOLD = int(os.environ['THRESHOLD'])
          TIME_WINDOW = int(os.environ['TIME_WINDOW_SECONDS'])
          SNS_TOPIC = os.environ['SNS_TOPIC_ARN']

          def handler(event, context):
              detail = event['detail']
              user_arn = detail['userIdentity'].get('arn', 'unknown')
              bucket = detail['requestParameters'].get('bucketName', 'unknown')

              # Query recent S3 operations by this user
              end_time = datetime.utcnow()
              start_time = end_time - timedelta(seconds=TIME_WINDOW)

              events = cloudtrail.lookup_events(
                  LookupAttributes=[
                      {'AttributeKey': 'EventName', 'AttributeValue': 'PutObject'}
                  ],
                  StartTime=start_time,
                  EndTime=end_time
              )

              # Count operations per user/bucket
              user_operations = defaultdict(int)
              for evt in events.get('Events', []):
                  evt_detail = json.loads(evt['CloudTrailEvent'])
                  evt_user = evt_detail['userIdentity'].get('arn', '')
                  if evt_user == user_arn:
                      user_operations[bucket] += 1

              total_ops = sum(user_operations.values())

              # Alert if threshold exceeded
              if total_ops > THRESHOLD:
                  message = f"RANSOMWARE ALERT: {total_ops} S3 objects modified in {TIME_WINDOW}s\n"
                  message += f"User: {user_arn}\n"
                  message += f"Affected buckets: {dict(user_operations)}\n"
                  message += f"Time: {datetime.utcnow().isoformat()}"

                  sns.publish(
                      TopicArn=SNS_TOPIC,
                      Subject='S3 Mass Operation Detected - Possible Ransomware',
                      Message=message
                  )

              return {'statusCode': 200}

  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: s3-ransomware-detection-dlq
      MessageRetentionPeriod: 1209600  # 14 days
      KmsMasterKeyId: alias/aws/sqs

  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
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
        - PolicyName: CloudTrailReadOnly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - cloudtrail:LookupEvents
                Resource: '*'
        - PolicyName: SNSPublish
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - sns:Publish
                Resource: !Ref RansomwareAlertTopic

  LambdaInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref AggregationFunction
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt S3MassOperationRule.Arn""",
                terraform_template="""# Detect S3 mass object replacement (ransomware pattern)

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
  description = "Email address for security alerts"
}

variable "threshold" {
  type        = number
  default     = 100
  description = "Number of PutObject operations to trigger alert"
}

variable "time_window_seconds" {
  type        = number
  default     = 300
  description = "Time window in seconds for counting operations"
}

# Step 1: Create encrypted SNS topic for alerts
resource "aws_sns_topic" "ransomware_alerts" {
  name              = "s3-mass-putobject-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ransomware_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create DLQ for failed events
resource "aws_sqs_queue" "event_dlq" {
  name                      = "s3-ransomware-detection-dlq"
  message_retention_seconds = 1209600  # 14 days
  kms_master_key_id         = "alias/aws/sqs"
}

# Step 3: Lambda function to aggregate events
data "archive_file" "lambda_code" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"

  source {
    content  = <<-EOF
import json
import boto3
import os
from datetime import datetime, timedelta
from collections import defaultdict

sns = boto3.client('sns')
cloudtrail = boto3.client('cloudtrail')

THRESHOLD = int(os.environ['THRESHOLD'])
TIME_WINDOW = int(os.environ['TIME_WINDOW_SECONDS'])
SNS_TOPIC = os.environ['SNS_TOPIC_ARN']

def handler(event, context):
    detail = event['detail']
    user_arn = detail['userIdentity'].get('arn', 'unknown')
    bucket = detail['requestParameters'].get('bucketName', 'unknown')

    # Query recent S3 operations by this user
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(seconds=TIME_WINDOW)

    events = cloudtrail.lookup_events(
        LookupAttributes=[
            {'AttributeKey': 'EventName', 'AttributeValue': 'PutObject'}
        ],
        StartTime=start_time,
        EndTime=end_time
    )

    # Count operations per user/bucket
    user_operations = defaultdict(int)
    for evt in events.get('Events', []):
        evt_detail = json.loads(evt['CloudTrailEvent'])
        evt_user = evt_detail['userIdentity'].get('arn', '')
        if evt_user == user_arn:
            user_operations[bucket] += 1

    total_ops = sum(user_operations.values())

    # Alert if threshold exceeded
    if total_ops > THRESHOLD:
        message = f"RANSOMWARE ALERT: {total_ops} S3 objects modified in {TIME_WINDOW}s\\n"
        message += f"User: {user_arn}\\n"
        message += f"Affected buckets: {dict(user_operations)}\\n"
        message += f"Time: {datetime.utcnow().isoformat()}"

        sns.publish(
            TopicArn=SNS_TOPIC,
            Subject='S3 Mass Operation Detected - Possible Ransomware',
            Message=message
        )

    return {'statusCode': 200}
EOF
    filename = "index.py"
  }
}

resource "aws_lambda_function" "aggregation" {
  filename         = data.archive_file.lambda_code.output_path
  function_name    = "s3-ransomware-aggregator"
  role            = aws_iam_role.lambda_execution.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.lambda_code.output_base64sha256
  runtime         = "python3.12"
  timeout         = 60

  environment {
    variables = {
      SNS_TOPIC_ARN         = aws_sns_topic.ransomware_alerts.arn
      THRESHOLD             = var.threshold
      TIME_WINDOW_SECONDS   = var.time_window_seconds
    }
  }
}

resource "aws_iam_role" "lambda_execution" {
  name = "s3-ransomware-aggregator-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "cloudtrail_read" {
  name = "cloudtrail-read"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["cloudtrail:LookupEvents"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "sns_publish" {
  name = "sns-publish"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = aws_sns_topic.ransomware_alerts.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "s3_mass_operations" {
  name        = "s3-mass-putobject-detection"
  description = "Detect mass S3 object replacements"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutObject", "CopyObject"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.s3_mass_operations.name
  target_id = "lambda-target"
  arn       = aws_lambda_function.aggregation.arn

  retry_policy {
    maximum_retry_attempts = 2
    maximum_event_age      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
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

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.aggregation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_mass_operations.arn
}""",
                alert_severity="critical",
                alert_title="S3 Mass Object Replacement Detected",
                alert_description_template="User {userIdentity.arn} performed {count} PutObject operations in 5 minutes - possible ransomware.",
                investigation_steps=[
                    "Review CloudTrail for object keys being modified",
                    "Check if encryption algorithm changed (SSE-C indicators)",
                    "Look for ransom note files (.txt, .html, .ransom extensions)",
                    "Verify if user activity is authorised",
                    "Check S3 bucket versioning status",
                ],
                containment_actions=[
                    "Immediately disable user credentials",
                    "Enable MFA Delete on affected buckets",
                    "Restore from S3 versioning if enabled",
                    "Restore from backup in separate account",
                    "Engage incident response team",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="May trigger on legitimate batch uploads - tune threshold based on environment",
            detection_coverage="90% - catches modern ransomware mass-replacement patterns",
            evasion_considerations="Attacker could slow down operations below threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20 (Lambda invocations + CloudTrail lookups)",
            prerequisites=["CloudTrail S3 data events enabled", "EventBridge enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1486-aws-ssec",
            name="AWS S3 SSE-C Encryption Detection",
            description="Detect S3 objects being encrypted with customer-provided keys (SSE-C ransomware technique).",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName, userIdentity.arn
| filter eventSource = "s3.amazonaws.com"
| filter eventName = "PutObject" or eventName = "CopyObject"
| filter requestParameters.SSECustomerAlgorithm != ""
| stats count(*) as ssec_uploads by userIdentity.arn, requestParameters.bucketName, bin(1h)
| filter ssec_uploads > 10
| sort ssec_uploads desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect potential S3 ransomware via SSE-C

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: s3-ssec-ransomware-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  SSECFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "s3.amazonaws.com") && ($.eventName = "PutObject" || $.eventName = "CopyObject") && ($.requestParameters.SSECustomerAlgorithm = "*") }'
      MetricTransformations:
        - MetricName: S3SSECUploads
          MetricNamespace: Security/Ransomware
          MetricValue: "1"

  SSECAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3-SSE-C-Ransomware-Detection
      MetricName: S3SSECUploads
      Namespace: Security/Ransomware
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]
      AlarmDescription: Detects high-volume SSE-C encryption indicating ransomware""",
                terraform_template="""# Detect potential S3 ransomware via SSE-C

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name              = "s3-ssec-ransomware-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "ssec_uploads" {
  name           = "s3-ssec-uploads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.eventName = \"PutObject\" || $.eventName = \"CopyObject\") && ($.requestParameters.SSECustomerAlgorithm = \"*\") }"

  metric_transformation {
    name      = "S3SSECUploads"
    namespace = "Security/Ransomware"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ransomware" {
  alarm_name          = "S3-SSE-C-Ransomware-Detection"
  alarm_description   = "Detects high-volume SSE-C encryption indicating ransomware"
  metric_name         = "S3SSECUploads"
  namespace           = "Security/Ransomware"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Potential S3 Ransomware - SSE-C Encryption",
                alert_description_template="High volume of S3 objects encrypted with customer-provided keys by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify if SSE-C usage was authorised",
                    "Check which buckets affected",
                    "Identify encryption key source (HMAC in CloudTrail)",
                    "Check for ransom notes",
                    "Review user identity and session details",
                ],
                containment_actions=[
                    "Immediately revoke user credentials",
                    "Check for unaffected backups",
                    "Enable versioning recovery",
                    "Do not pay ransom without legal counsel",
                    "Preserve CloudTrail logs for forensics",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="SSE-C is rarely used legitimately in most organisations",
            detection_coverage="85% - catches SSE-C based ransomware (Codefinger campaign)",
            evasion_considerations="May use SSE-KMS with attacker-controlled key instead",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1486-aws-kms",
            name="AWS KMS Key Policy Changes and CreateGrant",
            description="Detect KMS key policy changes and CreateGrant operations that could lock out legitimate users or enable unauthorised encryption.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.kms"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "PutKeyPolicy",
                            "CreateKey",
                            "ScheduleKeyDeletion",
                            "CreateGrant",
                            "ImportKeyMaterial",
                            "DeleteKeyMaterial",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect KMS key manipulation for ransomware

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create encrypted SNS topic
  KMSAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: kms-manipulation-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for KMS operations
  KMSManipulationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: kms-key-manipulation-detection
      Description: Detect KMS operations that could enable ransomware
      EventPattern:
        source:
          - aws.kms
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventSource:
            - kms.amazonaws.com
          eventName:
            - PutKeyPolicy
            - CreateKey
            - ScheduleKeyDeletion
            - CreateGrant
            - ImportKeyMaterial
            - DeleteKeyMaterial
      State: ENABLED
      Targets:
        - Arn: !Ref KMSAlertTopic
          Id: sns-target
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600

  # Step 3: SNS topic policy
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref KMSAlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref KMSAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt KMSManipulationRule.Arn

  # DLQ for failed events
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: kms-manipulation-detection-dlq
      MessageRetentionPeriod: 1209600  # 14 days
      KmsMasterKeyId: alias/aws/sqs""",
                terraform_template="""# Detect KMS key manipulation for ransomware

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "kms_alerts" {
  name              = "kms-manipulation-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.kms_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create DLQ for failed events
resource "aws_sqs_queue" "event_dlq" {
  name                      = "kms-manipulation-detection-dlq"
  message_retention_seconds = 1209600  # 14 days
  kms_master_key_id         = "alias/aws/sqs"
}

# Step 3: EventBridge rule for KMS operations
resource "aws_cloudwatch_event_rule" "kms_manipulation" {
  name        = "kms-key-manipulation-detection"
  description = "Detect KMS operations that could enable ransomware"

  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName = [
        "PutKeyPolicy",
        "CreateKey",
        "ScheduleKeyDeletion",
        "CreateGrant",
        "ImportKeyMaterial",
        "DeleteKeyMaterial"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.kms_manipulation.name
  target_id = "sns-target"
  arn       = aws_sns_topic.kms_alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
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

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.kms_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sns:Publish"
      Resource = aws_sns_topic.kms_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.kms_manipulation.arn
          }
      }
    }]
  })
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.event_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.event_dlq.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="KMS Key Manipulation Detected",
                alert_description_template="KMS operation {eventName} by {userIdentity.arn} - potential ransomware preparation.",
                investigation_steps=[
                    "Review the specific KMS operation performed",
                    "Verify change was authorised by legitimate administrator",
                    "Check what data is encrypted with this key",
                    "Review CreateGrant grantee principal for unusual accounts",
                    "Verify key is still accessible to legitimate services",
                    "Check CloudTrail for mass encryption operations following this event",
                ],
                containment_actions=[
                    "Revoke unauthorised grants immediately",
                    "Revert key policy if unauthorised",
                    "Review KMS permissions for all principals",
                    "Disable compromised credentials",
                    "Check for data lockout across S3, EBS, RDS",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="KMS policy changes are infrequent - whitelist known automation",
            detection_coverage="95% - catches key policy changes and grant creation used in ransomware",
            evasion_considerations="Cannot evade KMS logging when using KMS keys",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "EventBridge enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1486-aws-ebs-encryption",
            name="AWS EBS Volume Encryption Anomalies",
            description="Detect EBS volume and snapshot creation with unusual KMS keys indicating ransomware preparation.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["ec2.amazonaws.com"],
                        "eventName": ["CreateVolume", "ModifyVolume", "CreateSnapshot"],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EBS encryption anomalies indicating ransomware

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create encrypted SNS topic
  EBSAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: ebs-encryption-anomaly-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for EBS operations
  EBSEncryptionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: ebs-encryption-anomaly-detection
      Description: Detect unusual EBS encryption and snapshot activity
      EventPattern:
        source:
          - aws.ec2
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventSource:
            - ec2.amazonaws.com
          eventName:
            - CreateVolume
            - ModifyVolume
            - CreateSnapshot
      State: ENABLED
      Targets:
        - Arn: !Ref EBSAlertTopic
          Id: sns-target
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn

  # Step 3: SNS topic policy
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref EBSAlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref EBSAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt EBSEncryptionRule.Arn

  # DLQ for failed events
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: ebs-encryption-detection-dlq
      MessageRetentionPeriod: 1209600  # 14 days
      KmsMasterKeyId: alias/aws/sqs""",
                terraform_template="""# Detect EBS encryption anomalies

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "ebs_alerts" {
  name              = "ebs-encryption-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ebs_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create DLQ for failed events
resource "aws_sqs_queue" "event_dlq" {
  name                      = "ebs-encryption-detection-dlq"
  message_retention_seconds = 1209600  # 14 days
  kms_master_key_id         = "alias/aws/sqs"
}

# Step 3: EventBridge rule for EBS operations
resource "aws_cloudwatch_event_rule" "ebs_encryption" {
  name        = "ebs-encryption-anomaly-detection"
  description = "Detect unusual EBS encryption and snapshot activity"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["CreateVolume", "ModifyVolume", "CreateSnapshot"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ebs_encryption.name
  target_id = "sns-target"
  arn       = aws_sns_topic.ebs_alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
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

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.ebs_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sns:Publish"
      Resource = aws_sns_topic.ebs_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.ebs_encryption.arn
          }
      }
    }]
  })
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.event_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.event_dlq.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="EBS Volume Encryption Anomaly Detected",
                alert_description_template="EBS volume operation by {userIdentity.arn} with encryption key {responseElements.kmsKeyId}.",
                investigation_steps=[
                    "Review KMS key used for encryption",
                    "Verify if key is authorised for this account",
                    "Check volume attachment history",
                    "Review user identity and session context",
                    "Check for multiple volume operations in short timeframe",
                ],
                containment_actions=[
                    "Disable compromised credentials immediately",
                    "Delete unauthorised volumes",
                    "Review KMS key policies",
                    "Check EC2 instances for suspicious activity",
                    "Restore from EBS snapshots if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune based on expected KMS keys - whitelist known infrastructure automation",
            detection_coverage="75% - catches EBS-based encryption attacks",
            evasion_considerations="Attacker could use default AWS managed keys",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "EventBridge enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1486-aws-rds-encryption",
            name="AWS RDS Encryption Modification Detection",
            description="Detect unauthorised RDS database encryption changes or snapshot operations.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.rds"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["rds.amazonaws.com"],
                        "eventName": [
                            "ModifyDBInstance",
                            "ModifyDBCluster",
                            "CreateDBSnapshot",
                            "CopyDBSnapshot",
                            "RestoreDBInstanceFromDBSnapshot",
                        ],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect RDS encryption modifications

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create encrypted SNS topic
  RDSAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: rds-encryption-modification-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for RDS operations
  RDSEncryptionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: rds-encryption-modification-detection
      Description: Detect RDS encryption and snapshot operations
      EventPattern:
        source:
          - aws.rds
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventSource:
            - rds.amazonaws.com
          eventName:
            - ModifyDBInstance
            - ModifyDBCluster
            - CreateDBSnapshot
            - CopyDBSnapshot
            - RestoreDBInstanceFromDBSnapshot
      State: ENABLED
      Targets:
        - Arn: !Ref RDSAlertTopic
          Id: sns-target
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn

  # Step 3: SNS topic policy
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref RDSAlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref RDSAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt RDSEncryptionRule.Arn

  # DLQ for failed events
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: rds-encryption-detection-dlq
      MessageRetentionPeriod: 1209600  # 14 days
      KmsMasterKeyId: alias/aws/sqs""",
                terraform_template="""# Detect RDS encryption modifications

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "rds_alerts" {
  name              = "rds-encryption-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.rds_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create DLQ for failed events
resource "aws_sqs_queue" "event_dlq" {
  name                      = "rds-encryption-detection-dlq"
  message_retention_seconds = 1209600  # 14 days
  kms_master_key_id         = "alias/aws/sqs"
}

# Step 3: EventBridge rule for RDS operations
resource "aws_cloudwatch_event_rule" "rds_encryption" {
  name        = "rds-encryption-modification-detection"
  description = "Detect RDS encryption and snapshot operations"

  event_pattern = jsonencode({
    source      = ["aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["rds.amazonaws.com"]
      eventName = [
        "ModifyDBInstance",
        "ModifyDBCluster",
        "CreateDBSnapshot",
        "CopyDBSnapshot",
        "RestoreDBInstanceFromDBSnapshot"
      ]
    }
  })
}

# Step 4: Route to SNS with retry and DLQ
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.rds_encryption.name
  target_id = "sns-target"
  arn       = aws_sns_topic.rds_alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
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

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.rds_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sns:Publish"
      Resource = aws_sns_topic.rds_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.rds_encryption.arn
          }
      }
    }]
  })
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.event_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.event_dlq.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="RDS Encryption Modification Detected",
                alert_description_template="RDS operation {eventName} performed by {userIdentity.arn} on {requestParameters.dBInstanceIdentifier}.",
                investigation_steps=[
                    "Review the specific RDS operation performed",
                    "Check if encryption was enabled/disabled",
                    "Verify KMS key used for snapshots",
                    "Review user identity and permissions",
                    "Check for unauthorised snapshot copies to external accounts",
                ],
                containment_actions=[
                    "Revoke compromised credentials immediately",
                    "Delete unauthorised snapshots",
                    "Restore RDS instance from known-good snapshot",
                    "Review RDS backup retention policies",
                    "Enable automated backups if disabled",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter expected automation - may need to whitelist backup jobs",
            detection_coverage="80% - catches RDS encryption manipulation",
            evasion_considerations="Cannot bypass if CloudTrail enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "EventBridge enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1486-gcp-storage-encryption",
            name="GCP Cloud Storage Mass Object Creation with CMEK",
            description="Detect mass Cloud Storage object creation with customer-managed encryption keys indicating ransomware.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="storage.objects.create"
protoPayload.request.metadata.encryption.encryptionAlgorithm!=""''',
                gcp_terraform_template="""# GCP: Detect Cloud Storage ransomware via CMEK

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "threshold" {
  type        = number
  default     = 100
  description = "Number of encrypted object creations to trigger alert"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts - Ransomware"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for encrypted object creation
resource "google_logging_metric" "storage_cmek_uploads" {
  project = var.project_id
  name   = "storage-cmek-mass-uploads"
  filter = <<-EOT
    protoPayload.methodName="storage.objects.create"
    protoPayload.request.metadata.encryption.encryptionAlgorithm!=""
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "bucket_name"
      value_type  = "STRING"
      description = "Cloud Storage bucket name"
    }
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User or service account performing the operation"
    }
  }

  label_extractors = {
    "bucket_name"      = "EXTRACT(protoPayload.resourceName)"
    "principal_email"  = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for mass uploads
resource "google_monitoring_alert_policy" "storage_ransomware" {
  project      = var.project_id
  display_name = "Cloud Storage Mass CMEK Encryption - Ransomware Detection"
  combiner     = "OR"

  conditions {
    display_name = "High volume of encrypted object uploads"
    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/$${google_logging_metric.storage_cmek_uploads.name}\\" resource.type=\\"gcs_bucket\\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = var.threshold

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "CRITICAL: Mass Cloud Storage object encryption detected - possible ransomware attack. Investigate immediately."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="critical",
                alert_title="GCP Cloud Storage Mass Encryption Detected",
                alert_description_template="High volume of encrypted object creation in Cloud Storage - possible ransomware.",
                investigation_steps=[
                    "Review Cloud Audit Logs for object creation patterns",
                    "Check which buckets are affected",
                    "Identify the principal email performing operations",
                    "Verify if CMEK usage was authorised",
                    "Check for ransom note objects (.txt, .html)",
                    "Review bucket versioning and object lifecycle",
                ],
                containment_actions=[
                    "Immediately disable compromised service account or user credentials",
                    "Enable object versioning if not already enabled",
                    "Restore from bucket versioning previous versions",
                    "Review IAM permissions on affected buckets",
                    "Engage incident response team",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on normal upload patterns - whitelist known backup services",
            detection_coverage="85% - catches CMEK-based Cloud Storage ransomware",
            evasion_considerations="Attacker could use default Google-managed encryption or slow down operations",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled for Cloud Storage"],
        ),
        DetectionStrategy(
            strategy_id="t1486-gcp-disk-encryption",
            name="GCP Compute Disk Encryption with CMEK/CSEK",
            description="Detect Compute Engine disk creation with unusual customer-managed or customer-supplied encryption keys.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="v1.compute.disks.insert"
(protoPayload.request.diskEncryptionKey.kmsKeyName!="" OR protoPayload.request.diskEncryptionKey.rawKey!="")""",
                gcp_terraform_template="""# GCP: Detect Compute disk encryption anomalies

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts - Disk Encryption"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for disk encryption
resource "google_logging_metric" "disk_encryption_cmek" {
  project = var.project_id
  name   = "compute-disk-cmek-csek-creation"
  filter = <<-EOT
    protoPayload.methodName="v1.compute.disks.insert"
    (protoPayload.request.diskEncryptionKey.kmsKeyName!="" OR protoPayload.request.diskEncryptionKey.rawKey!="")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "zone"
      value_type  = "STRING"
      description = "Compute zone"
    }
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User or service account"
    }
  }

  label_extractors = {
    "zone"            = "EXTRACT(protoPayload.request.zone)"
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "disk_encryption_anomaly" {
  project      = var.project_id
  display_name = "Compute Disk Encryption Anomaly Detection"
  combiner     = "OR"

  conditions {
    display_name = "Unusual disk encryption detected"
    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/$${google_logging_metric.disk_encryption_cmek.name}\\" resource.type=\\"gce_disk\\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Compute Engine disk created with customer-managed or customer-supplied encryption key. Verify this is authorised activity."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP Compute Disk Encryption Anomaly",
                alert_description_template="Compute disk created with CMEK/CSEK by {protoPayload.authenticationInfo.principalEmail}.",
                investigation_steps=[
                    "Review the KMS key or CSEK used for encryption",
                    "Verify if the encryption key is authorised",
                    "Check which zone and project the disk was created in",
                    "Review the principal performing the operation",
                    "Check for multiple disk creation operations in short timeframe",
                ],
                containment_actions=[
                    "Disable compromised credentials immediately",
                    "Delete unauthorised disks",
                    "Review IAM permissions for Compute Engine",
                    "Check attached VM instances for suspicious activity",
                    "Restore from snapshots if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known infrastructure automation using CMEK",
            detection_coverage="75% - catches disk-based encryption attacks",
            evasion_considerations="Attacker could use Google-managed encryption",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"],
        ),
        DetectionStrategy(
            strategy_id="t1486-gcp-sql-encryption",
            name="GCP Cloud SQL Instance Configuration Changes",
            description="Detect Cloud SQL instance updates that could affect encryption or data availability.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="cloudsql.instances.update"
protoPayload.request.settings.backupConfiguration!=null OR protoPayload.request.diskEncryptionConfiguration!=null""",
                gcp_terraform_template="""# GCP: Detect Cloud SQL configuration changes

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts - Cloud SQL"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric
resource "google_logging_metric" "sql_config_changes" {
  project = var.project_id
  name   = "cloudsql-encryption-backup-changes"
  filter = <<-EOT
    protoPayload.methodName="cloudsql.instances.update"
    (protoPayload.request.settings.backupConfiguration!=null OR protoPayload.request.diskEncryptionConfiguration!=null)
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_name"
      value_type  = "STRING"
      description = "Cloud SQL instance name"
    }
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "User or service account"
    }
  }

  label_extractors = {
    "instance_name"   = "EXTRACT(protoPayload.resourceName)"
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "sql_changes" {
  project      = var.project_id
  display_name = "Cloud SQL Encryption/Backup Configuration Changes"
  combiner     = "OR"

  conditions {
    display_name = "Cloud SQL configuration modified"
    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/$${google_logging_metric.sql_config_changes.name}\\" resource.type=\\"cloudsql_database\\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Cloud SQL instance encryption or backup configuration was modified. Verify this change is authorised."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP Cloud SQL Configuration Changed",
                alert_description_template="Cloud SQL instance configuration modified by {protoPayload.authenticationInfo.principalEmail}.",
                investigation_steps=[
                    "Review the specific configuration changes made",
                    "Verify if backup configuration was disabled",
                    "Check if disk encryption key was changed",
                    "Review the principal performing the operation",
                    "Verify instance is still accessible",
                ],
                containment_actions=[
                    "Revert unauthorised configuration changes",
                    "Revoke compromised credentials",
                    "Enable automated backups if disabled",
                    "Review Cloud SQL IAM permissions",
                    "Restore from backup if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Cloud SQL configuration changes are infrequent - whitelist known DBA automation",
            detection_coverage="80% - catches Cloud SQL encryption manipulation",
            evasion_considerations="Limited evasion options with Cloud Audit Logs enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Cloud SQL"],
        ),
        DetectionStrategy(
            strategy_id="t1486-gcp-cmek",
            name="GCP CMEK Key Changes Detection",
            description="Detect changes to customer-managed encryption keys.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"cloudkms.*.UpdateCryptoKeyPrimaryVersion|cloudkms.*.DestroyCryptoKeyVersion"''',
                gcp_terraform_template="""# GCP: Detect CMEK manipulation

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "cmek_changes" {
  project = var.project_id
  name   = "cmek-key-changes"
  filter = <<-EOT
    protoPayload.methodName=~"cloudkms.*Update|cloudkms.*Destroy"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "cmek_changes" {
  project      = var.project_id
  display_name = "CMEK Key Changes"
  combiner     = "OR"
  conditions {
    display_name = "Key modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cmek_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="critical",
                alert_title="GCP: CMEK Key Changed",
                alert_description_template="Customer-managed encryption key was modified.",
                investigation_steps=[
                    "Review key version changes",
                    "Verify change was authorised",
                    "Check affected resources",
                    "Verify data still accessible",
                ],
                containment_actions=[
                    "Restore previous key version",
                    "Review KMS permissions",
                    "Check for data lockout",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Key changes are infrequent",
            detection_coverage="90% - catches key manipulation",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1486-aws-s3-mass-putobject",
        "t1486-aws-ssec",
        "t1486-aws-kms",
        "t1486-aws-ebs-encryption",
        "t1486-aws-rds-encryption",
        "t1486-gcp-storage-encryption",
        "t1486-gcp-disk-encryption",
        "t1486-gcp-sql-encryption",
        "t1486-gcp-cmek",
    ],
    total_effort_hours=8.5,
    coverage_improvement="+60% improvement for Impact tactic across AWS and GCP",
)
