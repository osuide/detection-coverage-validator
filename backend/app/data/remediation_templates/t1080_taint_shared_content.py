"""
T1080 - Taint Shared Content

Adversaries deliver payloads to remote systems by adding malicious content to shared
storage locations like network drives, cloud storage, or code repositories.
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
    technique_id="T1080",
    technique_name="Taint Shared Content",
    tactic_ids=["TA0008"],  # Lateral Movement
    mitre_url="https://attack.mitre.org/techniques/T1080/",
    threat_context=ThreatContext(
        description=(
            "Adversaries deliver payloads to remote systems by adding malicious content to "
            "shared storage locations such as network drives, cloud storage, or code repositories. "
            "By modifying legitimate files or adding malicious programmes, scripts, or exploit code "
            "to otherwise valid files in shared locations, adversaries can use tainted content to "
            "move laterally through the environment and gain execution on multiple systems."
        ),
        attacker_goal="Establish persistent foothold and move laterally by tainting shared storage",
        why_technique=[
            "Shared storage locations provide access to multiple systems",
            "Users and systems regularly access shared content, enabling lateral movement",
            "Malicious content can remain dormant until accessed",
            "Cloud storage services often have broad access permissions",
            "Modified binaries or documents may be trusted by users and security tools",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Taint Shared Content enables widespread lateral movement with minimal effort. "
            "Compromised shared storage can affect numerous systems simultaneously. "
            "Cloud storage misconfigurations amplify the risk, allowing attackers to reach "
            "multiple users and systems through a single point of compromise."
        ),
        business_impact=[
            "Widespread malware distribution across the organisation",
            "Data corruption or ransomware affecting shared resources",
            "Compromised code repositories leading to supply chain attacks",
            "Loss of trust in shared infrastructure",
            "Significant remediation costs for cleaning infected systems",
        ],
        typical_attack_phase="lateral-movement",
        often_precedes=["T1059", "T1204", "T1566"],
        often_follows=["T1078", "T1110", "T1190"],
    ),
    detection_strategies=[
        # Strategy 1: AWS S3 Object Modification Monitoring
        DetectionStrategy(
            strategy_id="t1080-aws-s3-modification",
            name="AWS S3 Shared Storage Modification Detection",
            description=(
                "Monitor S3 buckets used for shared content for suspicious file modifications, "
                "especially executable files, scripts, or documents with embedded macros."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["PutObject", "CopyObject"],
                        "requestParameters": {
                            "key": [
                                {"suffix": ".exe"},
                                {"suffix": ".dll"},
                                {"suffix": ".scr"},
                                {"suffix": ".bat"},
                                {"suffix": ".ps1"},
                                {"suffix": ".vbs"},
                                {"suffix": ".js"},
                                {"suffix": ".docm"},
                                {"suffix": ".xlsm"},
                                {"suffix": ".pptm"},
                            ]
                        },
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious file uploads to shared S3 storage

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: T1080-SharedStorageAlerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule to detect executable/script uploads
  SuspiciousFileUploadRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1080-SuspiciousFileUpload
      Description: Detect uploads of executables and scripts to shared S3
      EventPattern:
        source:
          - aws.s3
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - PutObject
            - CopyObject
          requestParameters:
            key:
              - suffix: .exe
              - suffix: .dll
              - suffix: .scr
              - suffix: .bat
              - suffix: .ps1
              - suffix: .vbs
              - suffix: .js
              - suffix: .docm
              - suffix: .xlsm
      State: ENABLED
      Targets:
        - Id: EmailAlert
          Arn: !Ref AlertTopic

  # Step 3: Grant EventBridge permission to publish to SNS
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
                aws:SourceArn: !GetAtt SuspiciousFileUploadRule.Arn""",
                terraform_template="""# Detect suspicious file uploads to shared S3 storage

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "t1080-shared-storage-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule to detect executable/script uploads
resource "aws_cloudwatch_event_rule" "suspicious_upload" {
  name        = "t1080-suspicious-file-upload"
  description = "Detect uploads of executables and scripts to shared S3"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutObject", "CopyObject"]
      requestParameters = {
        key = [
          { suffix = ".exe" },
          { suffix = ".dll" },
          { suffix = ".scr" },
          { suffix = ".bat" },
          { suffix = ".ps1" },
          { suffix = ".vbs" },
          { suffix = ".js" },
          { suffix = ".docm" },
          { suffix = ".xlsm" }
        ]
      }
    }
  })
}

# SQS DLQ for failed EventBridge deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "s3-suspicious-upload-eventbridge-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.dlq.arn
    }]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.suspicious_upload.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

# Step 3: Grant EventBridge permission to publish to SNS
data "aws_caller_identity" "current" {}

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
          "aws:SourceArn" = aws_cloudwatch_event_rule.suspicious_upload.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Suspicious File Upload to Shared S3 Storage",
                alert_description_template=(
                    "Executable or script file uploaded to shared S3 bucket {bucket} by {userIdentity.arn}. "
                    "File: {requestParameters.key}. Source IP: {sourceIPAddress}. "
                    "This may indicate an attempt to taint shared content."
                ),
                investigation_steps=[
                    "Identify the S3 bucket and object that was uploaded",
                    "Review the file type and determine if it's expected in this location",
                    "Verify the identity of the user who uploaded the file",
                    "Check the source IP address and verify it's expected",
                    "Scan the file for malicious content using antivirus tools",
                    "Review access patterns to determine if the file has been accessed",
                    "Check for similar uploads across other shared buckets",
                ],
                containment_actions=[
                    "Quarantine or delete the suspicious file from the S3 bucket",
                    "Revoke access for the uploading principal if compromised",
                    "Enable S3 Object Lock to prevent file modifications",
                    "Implement bucket policies to restrict executable uploads",
                    "Enable S3 Versioning to track and revert malicious changes",
                    "Consider enabling Amazon Macie to scan for sensitive data",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised software distribution buckets and deployment pipelines",
            detection_coverage="75% - covers common executable and script file types",
            evasion_considerations="Attackers may use archive formats (.zip, .tar) or rename extensions",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "SNS email subscription confirmation",
            ],
        ),
        # Strategy 2: Unusual S3 Object Overwrite Detection
        DetectionStrategy(
            strategy_id="t1080-aws-s3-overwrite",
            name="S3 Object Overwrite Pattern Detection",
            description=(
                "Detect when existing S3 objects are repeatedly overwritten or modified, "
                "which may indicate binary infection or document macro injection."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, requestParameters.bucketName as bucket,
       requestParameters.key as object_key, sourceIPAddress, userAgent
| filter eventName = "PutObject"
| stats count(*) as modification_count by bucket, object_key, user, bin(1h) as time_window
| filter modification_count >= 3
| sort modification_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect repeated S3 object modifications

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudWatch Log Group containing CloudTrail logs
  AlertEmail:
    Type: String
    Description: Email address for alerts
  ModificationThreshold:
    Type: Number
    Default: 3
    Description: Number of modifications to trigger alert

Resources:
  # Step 1: Create metric filter for S3 overwrites
  S3OverwriteFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "PutObject" && $.requestParameters.key = * }'
      MetricTransformations:
        - MetricName: S3ObjectOverwrites
          MetricNamespace: Security/T1080
          MetricValue: "1"
          DefaultValue: 0

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create alarm for excessive modifications
  OverwriteAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1080-ExcessiveS3Modifications
      AlarmDescription: Multiple modifications to S3 objects detected
      MetricName: S3ObjectOverwrites
      Namespace: Security/T1080
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: !Ref ModificationThreshold
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect repeated S3 object modifications

variable "cloudtrail_log_group" {
  description = "CloudWatch Log Group containing CloudTrail logs"
  type        = string
}

variable "alert_email" {
  description = "Email address for alerts"
  type        = string
}

variable "modification_threshold" {
  description = "Number of modifications to trigger alert"
  type        = number
  default     = 3
}

# Step 1: Create metric filter for S3 overwrites
resource "aws_cloudwatch_log_metric_filter" "s3_overwrites" {
  name           = "t1080-s3-overwrites"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ $.eventName = \"PutObject\" && $.requestParameters.key = * }"

  metric_transformation {
    name      = "S3ObjectOverwrites"
    namespace = "Security/T1080"
    value     = "1"
    default_value = 0
  }
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "t1080-s3-overwrite-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for excessive modifications
resource "aws_cloudwatch_metric_alarm" "overwrite_alarm" {
  alarm_name          = "t1080-excessive-s3-modifications"
  alarm_description   = "Multiple modifications to S3 objects detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "S3ObjectOverwrites"
  namespace           = "Security/T1080"
  period              = 300
  statistic           = "Sum"
  threshold           = var.modification_threshold
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
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
                alert_severity="medium",
                alert_title="Excessive S3 Object Modifications Detected",
                alert_description_template=(
                    "S3 object {object_key} in bucket {bucket} was modified {modification_count} times "
                    "in one hour by {user}. This may indicate binary infection or content tainting."
                ),
                investigation_steps=[
                    "Identify which object was repeatedly modified",
                    "Review the modification history using S3 versioning",
                    "Compare file hashes to detect malicious changes",
                    "Verify if the user normally has write access to this location",
                    "Check if similar patterns exist across other objects",
                    "Review user agent strings for suspicious tools or scripts",
                ],
                containment_actions=[
                    "Enable S3 Versioning to track all changes",
                    "Restore known-good version of the modified object",
                    "Implement MFA Delete to prevent unauthorised deletions",
                    "Review and restrict write permissions to shared buckets",
                    "Consider implementing bucket policies with IP restrictions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baseline for normal modification patterns; exclude CI/CD processes",
            detection_coverage="70% - detects patterns of repeated modifications",
            evasion_considerations="Slow, incremental modifications may avoid threshold triggers",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudTrail S3 data events enabled",
                "CloudTrail logs in CloudWatch Logs",
            ],
        ),
        # Strategy 3: GCP Cloud Storage Modification Detection
        DetectionStrategy(
            strategy_id="t1080-gcp-storage-modification",
            name="GCP Cloud Storage Shared Content Monitoring",
            description=(
                "Monitor Google Cloud Storage buckets for uploads of executable files, "
                "scripts, or documents with embedded macros to shared locations."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="storage.objects.create"
OR protoPayload.methodName="storage.objects.update"
AND (
  protoPayload.resourceName=~".*\\.exe$"
  OR protoPayload.resourceName=~".*\\.dll$"
  OR protoPayload.resourceName=~".*\\.bat$"
  OR protoPayload.resourceName=~".*\\.ps1$"
  OR protoPayload.resourceName=~".*\\.sh$"
  OR protoPayload.resourceName=~".*\\.py$"
  OR protoPayload.resourceName=~".*\\.docm$"
  OR protoPayload.resourceName=~".*\\.xlsm$"
)""",
                gcp_terraform_template="""# GCP: Detect suspicious file uploads to shared Cloud Storage

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "T1080 Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for suspicious uploads
resource "google_logging_metric" "suspicious_uploads" {
  name    = "t1080-suspicious-storage-uploads"
  project = var.project_id

  filter = <<-EOT
    protoPayload.methodName="storage.objects.create"
    OR protoPayload.methodName="storage.objects.update"
    AND (
      protoPayload.resourceName=~".*\\.exe$"
      OR protoPayload.resourceName=~".*\\.dll$"
      OR protoPayload.resourceName=~".*\\.bat$"
      OR protoPayload.resourceName=~".*\\.ps1$"
      OR protoPayload.resourceName=~".*\\.sh$"
      OR protoPayload.resourceName=~".*\\.py$"
      OR protoPayload.resourceName=~".*\\.docm$"
      OR protoPayload.resourceName=~".*\\.xlsm$"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    display_name = "Suspicious Cloud Storage Uploads"
  }
}

# Step 3: Create alert policy to trigger on suspicious uploads
resource "google_monitoring_alert_policy" "suspicious_uploads" {
  project      = var.project_id
  display_name = "T1080: Suspicious Cloud Storage Upload"
  combiner     = "OR"

  conditions {
    display_name = "Executable or script uploaded to shared storage"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_uploads.name}\" AND resource.type=\"gcs_bucket\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "604800s"  # 7 days
  }

  documentation {
    content = "Suspicious file uploaded to Cloud Storage. Investigate for potential taint shared content attack (T1080)."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious File Upload to Cloud Storage",
                alert_description_template=(
                    "Executable or script file uploaded to Cloud Storage bucket. "
                    "File: {protoPayload.resourceName}. User: {protoPayload.authenticationInfo.principalEmail}. "
                    "This may indicate taint shared content attack."
                ),
                investigation_steps=[
                    "Identify the specific bucket and object that was uploaded",
                    "Verify the identity of the principal who uploaded the file",
                    "Check the file type and determine if it's expected",
                    "Review bucket IAM policies and public access settings",
                    "Scan the file for malicious content",
                    "Check if the file has been accessed or downloaded",
                    "Review logs for similar suspicious uploads",
                ],
                containment_actions=[
                    "Remove the suspicious object from the bucket",
                    "Enable Object Versioning to track changes",
                    "Review and restrict bucket IAM permissions",
                    "Implement bucket-level organisation policies",
                    "Enable uniform bucket-level access",
                    "Consider implementing VPC Service Controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised software distribution buckets and deployment accounts",
            detection_coverage="75% - covers common executable and script types",
            evasion_considerations="Attackers may use archive formats or obfuscate file extensions",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="45 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Audit Logs enabled for Cloud Storage",
                "Admin Activity and Data Access logs",
            ],
        ),
        # Strategy 4: File Integrity Monitoring for Shared Storage
        DetectionStrategy(
            strategy_id="t1080-file-integrity",
            name="Shared Storage File Integrity Monitoring",
            description=(
                "Implement file integrity monitoring to detect unauthorised modifications to "
                "critical shared files and detect binary infection attempts."
            ),
            detection_type=DetectionType.CUSTOM_LAMBDA,
            aws_service="lambda",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# File Integrity Monitoring for S3 Shared Storage

variable "monitored_bucket" {
  description = "S3 bucket to monitor for file integrity"
  type        = string
}

variable "alert_email" {
  description = "Email address for alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "t1080-file-integrity-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create DynamoDB table to store file hashes
resource "aws_dynamodb_table" "file_hashes" {
  name           = "t1080-file-integrity-hashes"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "bucket_object_key"

  attribute {
    name = "bucket_object_key"
    type = "S"
  }

  ttl {
    attribute_name = "expiration_time"
    enabled        = true
  }
}

# Step 3: Create Lambda function to check file integrity
resource "aws_lambda_function" "file_integrity_check" {
  filename      = "file_integrity_lambda.zip"  # Package your Lambda code
  function_name = "t1080-file-integrity-monitor"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60

  environment {
    variables = {
      HASH_TABLE_NAME = aws_dynamodb_table.file_hashes.name
      SNS_TOPIC_ARN   = aws_sns_topic.alerts.arn
    }
  }
}

resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.file_integrity_check.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${var.monitored_bucket}"
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = var.monitored_bucket

  lambda_function {
    lambda_function_arn = aws_lambda_function.file_integrity_check.arn
    events              = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "t1080-file-integrity-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "t1080-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "arn:aws:s3:::${var.monitored_bucket}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.file_hashes.arn
      },
      {
        Effect = "Allow"
        Action = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}""",
                alert_severity="high",
                alert_title="File Integrity Violation in Shared Storage",
                alert_description_template=(
                    "File {object_key} in bucket {bucket} was modified. "
                    "Previous hash: {previous_hash}. New hash: {new_hash}. "
                    "Modified by: {user}. Investigate for potential binary infection."
                ),
                investigation_steps=[
                    "Compare file hashes to identify exact changes",
                    "Review S3 versioning to access previous file versions",
                    "Analyse the modified file for malicious content",
                    "Identify who modified the file and verify authorisation",
                    "Check if other files in the same bucket were modified",
                    "Review CloudTrail logs for related suspicious activity",
                ],
                containment_actions=[
                    "Restore the file to its previous known-good version",
                    "Quarantine the modified file for forensic analysis",
                    "Revoke access for the compromised principal",
                    "Enable S3 Object Lock for critical shared files",
                    "Implement stricter bucket policies and access controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude files that are expected to change frequently; baseline normal update patterns",
            detection_coverage="90% - detects any unauthorised file modifications",
            evasion_considerations="Sophisticated attackers may attempt to preserve file hashes",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "S3 versioning enabled",
                "Lambda function code deployment",
                "DynamoDB table creation",
            ],
        ),
        # Azure Strategy: Taint Shared Content
        DetectionStrategy(
            strategy_id="t1080-azure",
            name="Azure Taint Shared Content Detection",
            description=(
                "Azure detection for Taint Shared Content. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Taint Shared Content
// MITRE ATT&CK: T1080
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources""",
                azure_terraform_template="""# Azure Detection for Taint Shared Content
# MITRE ATT&CK: T1080

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
  name                = "taint-shared-content-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "taint-shared-content-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Taint Shared Content
// MITRE ATT&CK: T1080
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources
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

  description = "Detects Taint Shared Content (T1080) activity in Azure environment"
  display_name = "Taint Shared Content Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1080"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Taint Shared Content Detected",
                alert_description_template=(
                    "Taint Shared Content activity detected. "
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
        "t1080-aws-s3-modification",
        "t1080-gcp-storage-modification",
        "t1080-aws-s3-overwrite",
        "t1080-file-integrity",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+30% improvement for Lateral Movement tactic",
)
