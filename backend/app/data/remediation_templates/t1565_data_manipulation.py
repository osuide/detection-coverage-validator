"""
T1565 - Data Manipulation

Adversaries manipulate data to influence outcomes, conceal activity, or compromise integrity.
Includes stored, transmitted, and runtime data manipulation across cloud environments.
Used by FIN13 and other financially motivated threat actors.
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
    technique_id="T1565",
    technique_name="Data Manipulation",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1565/",
    threat_context=ThreatContext(
        description=(
            "Adversaries manipulate data to influence external outcomes, conceal malicious activity, "
            "or compromise data integrity. In cloud environments, this includes modifying database records, "
            "altering stored objects in S3/GCS, tampering with configuration files, and manipulating "
            "log data to hide tracks. This technique has three sub-techniques: stored data manipulation, "
            "transmitted data manipulation, and runtime data manipulation."
        ),
        attacker_goal="Modify, insert, or delete data to influence outcomes or conceal malicious activity",
        why_technique=[
            "Financial fraud through incremental transaction manipulation",
            "Conceal evidence of compromise by altering logs",
            "Influence business decisions through modified reports",
            "Compromise data integrity for competitive advantage",
            "Cloud storage and databases easily modified via API",
            "Difficult to detect without integrity monitoring",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="low_to_moderate",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "High impact on data integrity and business operations. "
            "Can result in financial fraud, corrupted decision-making, and loss of trust in data. "
            "Difficult to detect and may go unnoticed for extended periods."
        ),
        business_impact=[
            "Financial loss through fraudulent data modifications",
            "Compromised data integrity affecting business decisions",
            "Regulatory compliance violations",
            "Loss of customer trust",
            "Forensic challenges due to altered logs",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1098", "T1530"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1565-aws-s3-modification",
            name="AWS S3 Object Modification Detection",
            description="Detect unauthorised modification or deletion of S3 objects that may indicate data manipulation.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "PutObject",
                            "DeleteObject",
                            "DeleteObjects",
                            "CopyObject",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 object manipulation for data integrity monitoring

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule to detect S3 modifications
  S3ModificationRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.s3]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [PutObject, DeleteObject, DeleteObjects, CopyObject]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Grant EventBridge permission to publish to SNS
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
                aws:SourceArn: !GetAtt S3ModificationRule.Arn""",
                terraform_template="""# Detect S3 object manipulation for data integrity monitoring

variable "alert_email" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "s3-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule to detect S3 modifications
resource "aws_cloudwatch_event_rule" "s3_modification" {
  name = "s3-data-manipulation"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["PutObject", "DeleteObject", "DeleteObjects", "CopyObject"] }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "s3-manipulation-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.s3_modification.name
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

resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.s3_modification.arn
        }
      }
    }]
  })
}

# Step 3: Grant EventBridge permission to publish to SNS
data "aws_caller_identity" "current" {}

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
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.s3_modification.arn,
              aws_cloudwatch_event_rule.rds_modification.arn,
              aws_cloudwatch_event_rule.cloudtrail_tampering.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="S3 Object Modified or Deleted",
                alert_description_template="S3 object modified/deleted by {userIdentity.arn} in bucket {requestParameters.bucketName}.",
                investigation_steps=[
                    "Verify the modification was authorised",
                    "Review what data was changed or deleted",
                    "Check S3 versioning history for original content",
                    "Examine user's recent activity for suspicious patterns",
                    "Compare with change management records",
                ],
                containment_actions=[
                    "Enable S3 Object Lock on critical buckets",
                    "Enable S3 versioning for recovery capability",
                    "Implement MFA Delete for critical buckets",
                    "Review and restrict S3 write permissions",
                    "Restore data from versions or backups if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised data pipeline roles and scheduled processes; focus on sensitive buckets",
            detection_coverage="95% - catches all S3 modifications",
            evasion_considerations="Cannot evade CloudTrail logging; attackers may use legitimate credentials",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled with S3 data events"],
        ),
        DetectionStrategy(
            strategy_id="t1565-aws-rds-modification",
            name="AWS RDS Database Modification Detection",
            description="Detect unauthorised changes to RDS database instances and configurations.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.rds"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "ModifyDBInstance",
                            "ModifyDBCluster",
                            "RestoreDBInstanceFromDBSnapshot",
                            "ModifyDBSnapshot",
                            "ModifyDBClusterSnapshot",
                        ]
                    },
                },
                terraform_template="""# Detect RDS database modification

variable "alert_email" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "rds-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for RDS modifications
resource "aws_cloudwatch_event_rule" "rds_modification" {
  name = "rds-data-manipulation"
  event_pattern = jsonencode({
    source      = ["aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "ModifyDBInstance",
        "ModifyDBCluster",
        "RestoreDBInstanceFromDBSnapshot",
        "ModifyDBSnapshot",
        "ModifyDBClusterSnapshot"
      ]
    }
  })
}

resource "aws_sqs_queue" "rds_dlq" {
  name                      = "rds-manipulation-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.rds_modification.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.rds_dlq.arn
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

resource "aws_sqs_queue_policy" "rds_dlq_policy" {
  queue_url = aws_sqs_queue.rds_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.rds_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.rds_modification.arn
        }
      }
    }]
  })
}

# Step 3: Grant EventBridge permission to publish to SNS
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
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.s3_modification.arn,
              aws_cloudwatch_event_rule.rds_modification.arn,
              aws_cloudwatch_event_rule.cloudtrail_tampering.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="RDS Database Modified",
                alert_description_template="RDS database modified by {userIdentity.arn}: {eventName}.",
                investigation_steps=[
                    "Verify the modification was authorised",
                    "Review what changes were made to the database",
                    "Check if this aligns with change management",
                    "Examine audit logs for data-level changes",
                    "Verify database integrity and backups",
                ],
                containment_actions=[
                    "Enable RDS backup and point-in-time recovery",
                    "Implement database activity streams",
                    "Review and restrict RDS IAM permissions",
                    "Enable enhanced monitoring",
                    "Restore from backup if unauthorised changes detected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised database administrators and automation roles",
            detection_coverage="90% - catches infrastructure-level modifications",
            evasion_considerations="Does not detect data-level SQL modifications; use database audit logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1565-aws-cloudtrail-modification",
            name="AWS CloudTrail Log Manipulation Detection",
            description="Detect attempts to disable CloudTrail or modify log files to conceal malicious activity.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.cloudtrail"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "StopLogging",
                            "DeleteTrail",
                            "UpdateTrail",
                            "PutEventSelectors",
                        ]
                    },
                },
                terraform_template="""# Detect CloudTrail tampering to prevent log manipulation

variable "alert_email" { type = string }

# Step 1: Create SNS topic for critical alerts
resource "aws_sns_topic" "alerts" {
  name = "cloudtrail-tampering-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Detect CloudTrail modifications
resource "aws_cloudwatch_event_rule" "cloudtrail_tampering" {
  name = "cloudtrail-tampering-detection"
  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors"
      ]
    }
  })
}

resource "aws_sqs_queue" "cloudtrail_dlq" {
  name                      = "cloudtrail-tampering-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_tampering.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.cloudtrail_dlq.arn
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

resource "aws_sqs_queue_policy" "cloudtrail_dlq_policy" {
  queue_url = aws_sqs_queue.cloudtrail_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.cloudtrail_dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.cloudtrail_tampering.arn
        }
      }
    }]
  })
}

# Step 3: Grant EventBridge permission to publish to SNS
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
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.s3_modification.arn,
              aws_cloudwatch_event_rule.rds_modification.arn,
              aws_cloudwatch_event_rule.cloudtrail_tampering.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="CloudTrail Logging Modified",
                alert_description_template="CloudTrail modified by {userIdentity.arn}: {eventName}. This may indicate log tampering.",
                investigation_steps=[
                    "Immediately verify CloudTrail is still enabled",
                    "Review what changes were made to logging configuration",
                    "Check if any logs were deleted from S3",
                    "Examine user's recent activity for other suspicious actions",
                    "Verify change was authorised through proper channels",
                ],
                containment_actions=[
                    "Re-enable CloudTrail logging immediately",
                    "Implement S3 Object Lock on CloudTrail bucket",
                    "Restrict CloudTrail permissions to minimal users",
                    "Enable MFA Delete on CloudTrail S3 bucket",
                    "Configure organisation-level CloudTrail",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="CloudTrail changes should be rare; validate all alerts",
            detection_coverage="95% - catches all CloudTrail modifications",
            evasion_considerations="Cannot evade; modifications are logged before taking effect",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1565-aws-dynamodb-modification",
            name="AWS DynamoDB Table Modification Detection",
            description="Detect unauthorised modifications to DynamoDB tables and their configurations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.tableName
| filter eventSource = "dynamodb.amazonaws.com"
| filter eventName in ["UpdateTable", "DeleteTable", "UpdateTimeToLive", "UpdateContinuousBackups"]
| stats count(*) as modification_count by userIdentity.arn, requestParameters.tableName, bin(1h)
| sort @timestamp desc""",
                terraform_template="""# Detect DynamoDB table modification

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "dynamodb-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for DynamoDB modifications
resource "aws_cloudwatch_log_metric_filter" "dynamodb_modification" {
  name           = "dynamodb-table-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"dynamodb.amazonaws.com\" && ($.eventName = \"UpdateTable\" || $.eventName = \"DeleteTable\" || $.eventName = \"UpdateTimeToLive\" || $.eventName = \"UpdateContinuousBackups\") }"

  metric_transformation {
    name      = "DynamoDBModifications"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Create alarm for modifications
resource "aws_cloudwatch_metric_alarm" "dynamodb_alert" {
  alarm_name          = "DynamoDB-Table-Modified"
  metric_name         = "DynamoDBModifications"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="DynamoDB Table Modified",
                alert_description_template="DynamoDB table {requestParameters.tableName} modified by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify the modification was authorised",
                    "Review what changes were made to the table",
                    "Check DynamoDB point-in-time recovery status",
                    "Examine if data integrity was affected",
                    "Review user's access patterns",
                ],
                containment_actions=[
                    "Enable point-in-time recovery on critical tables",
                    "Implement DynamoDB Streams for audit trail",
                    "Review and restrict table modification permissions",
                    "Restore from backup if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised DevOps and infrastructure automation",
            detection_coverage="85% - catches table-level modifications",
            evasion_considerations="Does not detect item-level data manipulation; enable DynamoDB Streams",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1565-gcp-storage-modification",
            name="GCP Storage Object Modification Detection",
            description="Detect unauthorised modification or deletion of GCS objects.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"storage.objects.(update|patch|delete|rewrite)"
protoPayload.authenticationInfo.principalEmail!=""''',
                gcp_terraform_template="""# GCP: Detect storage object manipulation

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create log metric for object modifications
resource "google_logging_metric" "storage_modification" {
  project = var.project_id
  name   = "storage-object-modification"
  filter = <<-EOT
    protoPayload.methodName=~"storage.objects.(update|patch|delete|rewrite)"
    protoPayload.authenticationInfo.principalEmail!=""
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "storage_modification" {
  project      = var.project_id
  display_name = "GCS Object Modification"
  combiner     = "OR"
  conditions {
    display_name = "Object modified or deleted"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.storage_modification.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Storage Object Modified",
                alert_description_template="GCS object modified or deleted.",
                investigation_steps=[
                    "Verify the modification was authorised",
                    "Check object versioning for previous content",
                    "Review what data was changed or deleted",
                    "Examine user's recent activity",
                    "Compare with change management records",
                ],
                containment_actions=[
                    "Enable Object Versioning on critical buckets",
                    "Implement retention policies",
                    "Review and restrict IAM permissions",
                    "Restore data from versions if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised service accounts and data pipelines",
            detection_coverage="95% - catches all GCS modifications",
            evasion_considerations="Cannot evade audit logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1565-gcp-cloudsql-modification",
            name="GCP Cloud SQL Database Modification Detection",
            description="Detect unauthorised changes to Cloud SQL instances and configurations.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="sqladmin.googleapis.com"
protoPayload.methodName=~"cloudsql.instances.(update|patch|restore)"''',
                gcp_terraform_template="""# GCP: Detect Cloud SQL modification

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create log metric for Cloud SQL modifications
resource "google_logging_metric" "cloudsql_modification" {
  project = var.project_id
  name   = "cloudsql-instance-modification"
  filter = <<-EOT
    protoPayload.serviceName="sqladmin.googleapis.com"
    protoPayload.methodName=~"cloudsql.instances.(update|patch|restore)"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "cloudsql_modification" {
  project      = var.project_id
  display_name = "Cloud SQL Instance Modified"
  combiner     = "OR"
  conditions {
    display_name = "Instance configuration changed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cloudsql_modification.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Cloud SQL Modified",
                alert_description_template="Cloud SQL instance configuration was modified.",
                investigation_steps=[
                    "Verify the modification was authorised",
                    "Review what changes were made",
                    "Check if this aligns with change management",
                    "Examine database audit logs for data changes",
                    "Verify database integrity and backups",
                ],
                containment_actions=[
                    "Enable automated backups",
                    "Implement database audit logging",
                    "Review and restrict IAM permissions",
                    "Restore from backup if unauthorised changes detected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised database administrators",
            detection_coverage="90% - catches infrastructure-level modifications",
            evasion_considerations="Does not detect data-level SQL modifications; enable database audit logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1565-gcp-logging-modification",
            name="GCP Cloud Logging Tampering Detection",
            description="Detect attempts to disable or modify Cloud Logging to conceal malicious activity.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="logging.googleapis.com"
protoPayload.methodName=~"google.logging.v2.ConfigServiceV2.(DeleteSink|UpdateSink|DeleteLogMetric)"''',
                gcp_terraform_template="""# GCP: Detect Cloud Logging tampering

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s3" {
  project      = var.project_id
  display_name = "Critical Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create log metric for logging tampering
resource "google_logging_metric" "logging_tampering" {
  project = var.project_id
  name   = "cloud-logging-tampering"
  filter = <<-EOT
    protoPayload.serviceName="logging.googleapis.com"
    protoPayload.methodName=~"google.logging.v2.ConfigServiceV2.(DeleteSink|UpdateSink|DeleteLogMetric)"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "logging_tampering" {
  project      = var.project_id
  display_name = "Cloud Logging Tampering Detected"
  combiner     = "OR"
  conditions {
    display_name = "Logging configuration modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.logging_tampering.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s3.id]
  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Cloud Logging Configuration Modified",
                alert_description_template="Cloud Logging configuration was modified. This may indicate log tampering.",
                investigation_steps=[
                    "Immediately verify logging is still active",
                    "Review what changes were made to logging configuration",
                    "Check if any log sinks were deleted",
                    "Examine user's recent activity for other suspicious actions",
                    "Verify change was authorised",
                ],
                containment_actions=[
                    "Restore deleted log sinks immediately",
                    "Implement organisation-level log sinks",
                    "Restrict logging administration permissions",
                    "Enable log bucket locking",
                    "Review IAM policies for logging access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Logging changes should be rare; validate all alerts",
            detection_coverage="95% - catches all logging configuration changes",
            evasion_considerations="Cannot evade; modifications are logged before taking effect",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Data Manipulation
        DetectionStrategy(
            strategy_id="t1565-azure",
            name="Azure Data Manipulation Detection",
            description=(
                "Azure detection for Data Manipulation. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Data Manipulation (T1565)
# Microsoft Defender detects Data Manipulation activity

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
  name                = "defender-t1565-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1565"
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

  description = "Microsoft Defender detects Data Manipulation activity"
  display_name = "Defender: Data Manipulation"
  enabled      = true
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Data Manipulation Detected",
                alert_description_template=(
                    "Data Manipulation activity detected. "
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
        "t1565-aws-cloudtrail-modification",
        "t1565-gcp-logging-modification",
        "t1565-aws-s3-modification",
        "t1565-gcp-storage-modification",
        "t1565-aws-rds-modification",
        "t1565-gcp-cloudsql-modification",
        "t1565-aws-dynamodb-modification",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+28% improvement for Impact tactic",
)
