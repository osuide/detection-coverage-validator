"""
T1565.001 - Data Manipulation: Stored Data Manipulation

Adversaries insert, delete, or manipulate data at rest to influence external outcomes,
hide activity, and compromise data integrity. In cloud environments, this includes
modifying database records, S3 objects, configuration files, and application data.
Used by APT38, SUNSPOT, and sophisticated actors targeting financial systems.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    Campaign,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
    CloudProvider,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1565.001",
    technique_name="Data Manipulation: Stored Data Manipulation",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1565/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries insert, delete, or manipulate data at rest in order to influence "
            "external outcomes or hide activity, thus threatening the integrity of the data. "
            "In cloud environments, this includes unauthorised modifications to databases, "
            "S3 objects, configuration files, and business-critical data stores. Attackers "
            "may manipulate financial records, audit logs, application configurations, or "
            "customer data to achieve their objectives."
        ),
        attacker_goal="Manipulate stored data to influence business processes, hide evidence, or disrupt operations",
        why_technique=[
            "Influence business decisions with false data",
            "Hide evidence of compromise by modifying logs",
            "Disrupt operations through data corruption",
            "Financial fraud via database manipulation",
            "Prevent forensic investigation",
            "Manipulate backups to ensure persistence",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="APT38 DYEPACK SWIFT Manipulation",
                year=2024,
                description="Used DYEPACK malware to create, delete, and alter records in SWIFT transaction databases to facilitate financial theft",
                reference_url="https://attack.mitre.org/software/S0554/",
            ),
            Campaign(
                name="SUNSPOT Supply Chain Attack",
                year=2020,
                description="Manipulated SolarWinds Orion source files during build process by creating backups and replacing original files with malicious code",
                reference_url="https://attack.mitre.org/software/S0562/",
            ),
            Campaign(
                name="MultiLayer Wiper",
                year=2024,
                description="Changed deleted file path information in file system metadata to prevent recovery of deleted files",
                reference_url="https://attack.mitre.org/software/S1129/",
            ),
        ],
        prevalence="moderate",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Critical integrity impact - manipulated data can lead to incorrect business decisions, "
            "financial losses, regulatory violations, and loss of trust. Difficult to detect without "
            "proper integrity monitoring. May go unnoticed for extended periods, amplifying damage."
        ),
        business_impact=[
            "Data integrity compromise",
            "Financial fraud and losses",
            "Incorrect business decisions",
            "Regulatory compliance violations",
            "Loss of customer trust",
            "Evidence destruction preventing forensics",
        ],
        typical_attack_phase="impact",
        often_precedes=["T1485", "T1486"],
        often_follows=["T1078.004", "T1098.001", "T1552.001"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1565-001-aws-s3-integrity",
            name="AWS S3 Object Modification Detection",
            description="Detect unauthorised modifications to critical S3 objects using CloudTrail and Object Lock.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["PutObject", "CopyObject", "DeleteObject"]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 data manipulation

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts
  CriticalBucketPrefix:
    Type: String
    Default: "critical-"
    Description: Prefix for critical buckets to monitor

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: s3-data-manipulation-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # EventBridge rule for S3 modifications
  S3ModificationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: s3-data-manipulation
      Description: Alert on modifications to critical S3 objects
      EventPattern:
        source: [aws.s3]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [PutObject, CopyObject, DeleteObject]
          requestParameters:
            bucketName:
              - prefix: !Ref CriticalBucketPrefix
      State: ENABLED
      Targets:
        - Id: AlertTarget
          Arn: !Ref AlertTopic

  # Allow EventBridge to publish to SNS
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

Outputs:
  TopicArn:
    Value: !Ref AlertTopic
    Description: SNS topic ARN for alerts""",
                terraform_template="""# AWS: Detect S3 data manipulation
# Step 1: SNS topic for alerts
# Step 2: EventBridge rule for S3 modifications
# Step 3: Enable S3 Object Lock on critical buckets

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "critical_bucket_prefix" {
  type        = string
  default     = "critical-"
  description = "Prefix for critical buckets to monitor"
}

resource "aws_sns_topic" "alerts" {
  name = "s3-data-manipulation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "s3_modification" {
  name        = "s3-data-manipulation"
  description = "Alert on modifications to critical S3 objects"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutObject", "CopyObject", "DeleteObject"]
      requestParameters = {
        bucketName = [{
          prefix = var.critical_bucket_prefix
        }]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.s3_modification.name
  target_id = "AlertTarget"
  arn       = aws_sns_topic.alerts.arn
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
    }]
  })
}

# Enable Object Lock for data integrity (apply to critical buckets)
# Note: Object Lock must be enabled at bucket creation
resource "aws_s3_bucket" "critical_data" {
  bucket = "${var.critical_bucket_prefix}data-store"

  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "critical_data" {
  bucket = aws_s3_bucket.critical_data.id

  rule {
    default_retention {
      mode = "GOVERNANCE"  # or "COMPLIANCE" for stricter control
      days = 90
    }
  }
}""",
                alert_severity="high",
                alert_title="S3 Data Manipulation Detected",
                alert_description_template="Critical S3 object modified by {userIdentity.arn} in bucket {requestParameters.bucketName}.",
                investigation_steps=[
                    "Verify modification was authorised and part of normal business operations",
                    "Review CloudTrail logs for the complete sequence of actions by the user",
                    "Compare object versions to identify what data was changed",
                    "Check if the modification aligns with expected application behaviour",
                    "Review IAM permissions for the user/role that made the change",
                    "Investigate other objects modified by the same principal",
                ],
                containment_actions=[
                    "Enable S3 Object Lock on critical buckets to prevent modifications",
                    "Enable S3 Versioning to maintain modification history",
                    "Restore previous object version if manipulation confirmed",
                    "Revoke IAM credentials if compromise suspected",
                    "Enable MFA Delete for critical buckets",
                    "Review and restrict S3 write permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter expected application writes and authorised maintenance windows. Create allowlists for legitimate automation.",
            detection_coverage="90% - detects API-based modifications; does not detect direct instance access",
            evasion_considerations="Attackers with instance/container access could modify files directly; ensure CloudTrail data events are enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15 (CloudTrail data events, EventBridge)",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "S3 bucket identification",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1565-001-aws-rds-modification",
            name="AWS RDS Database Modification Detection",
            description="Detect unauthorised database modifications through API calls and database audit logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch_logs",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters.dBInstanceIdentifier
| filter eventSource = "rds.amazonaws.com"
| filter eventName in ["ModifyDBInstance", "ModifyDBCluster", "RestoreDBInstanceFromDBSnapshot"]
| filter errorCode not exists
| stats count() by userIdentity.arn, eventName
| filter count > 3""",
                terraform_template="""# AWS: Detect RDS database manipulation
# Step 1: Enable RDS Enhanced Monitoring and Audit Logs
# Step 2: Create CloudWatch query and alarm
# Step 3: Alert on suspicious database modifications

variable "alert_email" {
  type = string
}

variable "db_instance_identifier" {
  type        = string
  description = "RDS instance to monitor"
}

# SNS topic for alerts
resource "aws_sns_topic" "rds_alerts" {
  name = "rds-manipulation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.rds_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for RDS modifications
resource "aws_cloudwatch_event_rule" "rds_modification" {
  name        = "rds-data-manipulation"
  description = "Alert on RDS instance modifications"

  event_pattern = jsonencode({
    source      = ["aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "ModifyDBInstance",
        "ModifyDBCluster",
        "RestoreDBInstanceFromDBSnapshot",
        "ModifyDBParameterGroup"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.rds_modification.name
  target_id = "AlertTarget"
  arn       = aws_sns_topic.rds_alerts.arn
}

# Enable RDS audit logging (MySQL/MariaDB example)
resource "aws_db_parameter_group" "audit_enabled" {
  name   = "rds-audit-logging"
  family = "mysql8.0"  # Adjust for your DB engine

  parameter {
    name  = "server_audit_logging"
    value = "1"
  }

  parameter {
    name  = "server_audit_events"
    value = "CONNECT,QUERY,QUERY_DDL,QUERY_DML"
  }
}

# CloudWatch log group for RDS audit logs
resource "aws_cloudwatch_log_group" "rds_audit" {
  name              = "/aws/rds/instance/${var.db_instance_identifier}/audit"
  retention_in_days = 90
}

# Metric filter for suspicious modifications
resource "aws_cloudwatch_log_metric_filter" "suspicious_modifications" {
  name           = "rds-suspicious-modifications"
  log_group_name = aws_cloudwatch_log_group.rds_audit.name

  pattern = "[timestamp, user, host, connection_id, query_id, operation = UPDATE|DELETE|INSERT, database, ...]"

  metric_transformation {
    name      = "RDSSuspiciousModifications"
    namespace = "Security/RDS"
    value     = "1"
  }
}

# Alarm for high modification rate
resource "aws_cloudwatch_metric_alarm" "high_modification_rate" {
  alarm_name          = "rds-high-modification-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RDSSuspiciousModifications"
  namespace           = "Security/RDS"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "High rate of database modifications detected"
  alarm_actions       = [aws_sns_topic.rds_alerts.arn]
}""",
                alert_severity="high",
                alert_title="RDS Database Manipulation Detected",
                alert_description_template="RDS instance {requestParameters.dBInstanceIdentifier} modified by {userIdentity.arn}.",
                investigation_steps=[
                    "Review what database parameters or settings were changed",
                    "Check RDS audit logs for unauthorised data modifications",
                    "Verify modification was part of authorised maintenance",
                    "Review recent database query patterns for anomalies",
                    "Check if backup/restore operations were legitimate",
                    "Investigate the user/role that made the modification",
                ],
                containment_actions=[
                    "Enable RDS deletion protection",
                    "Enable database audit logging",
                    "Review and restore from automated backups if needed",
                    "Restrict IAM permissions for RDS modifications",
                    "Enable Multi-AZ for critical databases",
                    "Implement database change management processes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised maintenance windows, automated backups, and legitimate application operations",
            detection_coverage="85% - detects API modifications; application-level data changes require audit logs",
            evasion_considerations="Application-level modifications may bypass detection without database audit logs enabled",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-30 (CloudWatch Logs, Enhanced Monitoring)",
            prerequisites=[
                "CloudTrail enabled",
                "RDS Enhanced Monitoring",
                "Database audit logs",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1565-001-aws-dynamodb-modification",
            name="AWS DynamoDB Table Modification Detection",
            description="Detect unauthorised modifications to DynamoDB tables and items using DynamoDB Streams and CloudTrail.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.dynamodb"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "UpdateTable",
                            "DeleteTable",
                            "UpdateItem",
                            "DeleteItem",
                        ]
                    },
                },
                terraform_template="""# AWS: Detect DynamoDB data manipulation
# Step 1: Enable DynamoDB Streams for data-level tracking
# Step 2: Create EventBridge rule for table modifications
# Step 3: Process DynamoDB Streams with Lambda for item-level changes

variable "alert_email" {
  type = string
}

variable "critical_table_names" {
  type        = list(string)
  description = "DynamoDB tables to monitor for manipulation"
}

# SNS topic for alerts
resource "aws_sns_topic" "dynamodb_alerts" {
  name = "dynamodb-manipulation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dynamodb_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for table-level operations
resource "aws_cloudwatch_event_rule" "dynamodb_table_modification" {
  name        = "dynamodb-table-manipulation"
  description = "Alert on DynamoDB table modifications"

  event_pattern = jsonencode({
    source      = ["aws.dynamodb"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "UpdateTable",
        "DeleteTable",
        "UpdateTimeToLive",
        "UpdateContinuousBackups"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.dynamodb_table_modification.name
  target_id = "AlertTarget"
  arn       = aws_sns_topic.dynamodb_alerts.arn
}

# Enable Point-in-Time Recovery for data integrity
resource "aws_dynamodb_table" "critical_table" {
  for_each = toset(var.critical_table_names)

  name           = each.value
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # Enable streams for item-level change tracking
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  # Enable point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Environment = "production"
    Monitoring  = "enabled"
  }
}

# Lambda function to process DynamoDB Streams (item-level changes)
resource "aws_lambda_function" "stream_processor" {
  filename      = "dynamodb_stream_processor.zip"
  function_name = "dynamodb-manipulation-detector"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.dynamodb_alerts.arn
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "dynamodb-stream-processor-role"

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

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_dynamodb_sns" {
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeStream",
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:ListStreams"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.dynamodb_alerts.arn]
      }
    ]
  })
}""",
                alert_severity="high",
                alert_title="DynamoDB Data Manipulation Detected",
                alert_description_template="DynamoDB table {requestParameters.tableName} modified by {userIdentity.arn}.",
                investigation_steps=[
                    "Review what table settings or items were modified",
                    "Check DynamoDB Streams for item-level changes",
                    "Verify modification was part of authorised operations",
                    "Review application logs for corresponding requests",
                    "Check if Point-in-Time Recovery is enabled",
                    "Investigate the principal that made the changes",
                ],
                containment_actions=[
                    "Enable Point-in-Time Recovery for restoration",
                    "Enable DynamoDB Streams for change tracking",
                    "Restore table from backup if manipulation confirmed",
                    "Review and restrict IAM permissions",
                    "Enable deletion protection on critical tables",
                    "Implement application-level change auditing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="High false positive rate for item operations; focus on table-level changes or implement application-level filtering",
            detection_coverage="95% for table operations, 70% for item operations with filtering",
            evasion_considerations="Normal application operations generate high volume; requires careful tuning",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-40 (DynamoDB Streams, Lambda)",
            prerequisites=["CloudTrail enabled", "DynamoDB Streams enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1565-001-gcp-storage-integrity",
            name="GCP Cloud Storage Object Modification Detection",
            description="Detect unauthorised modifications to Cloud Storage objects using Audit Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName=~"storage.objects.(create|update|patch|delete)"
protoPayload.resourceName=~"projects/_/buckets/critical-.*"
protoPayload.status.code=0""",
                gcp_terraform_template="""# GCP: Detect Cloud Storage data manipulation
# Step 1: Enable Cloud Audit Logs for Storage
# Step 2: Create log-based metric
# Step 3: Create alert policy

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

variable "critical_bucket_prefix" {
  type    = string
  default = "critical-"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Team"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for storage modifications
resource "google_logging_metric" "storage_modification" {
  name   = "storage-data-manipulation"
  filter = <<-EOT
    protoPayload.methodName=~"storage.objects.(create|update|patch|delete)"
    protoPayload.resourceName=~"projects/_/buckets/${var.critical_bucket_prefix}.*"
    protoPayload.status.code=0
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User who modified the object"
    }
    labels {
      key         = "bucket"
      value_type  = "STRING"
      description = "Bucket containing modified object"
    }
  }

  label_extractors = {
    user   = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    bucket = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for storage modifications
resource "google_monitoring_alert_policy" "storage_modification" {
  display_name = "Cloud Storage Data Manipulation"
  combiner     = "OR"

  conditions {
    display_name = "Storage object modified"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.storage_modification.name}\" AND resource.type=\"gcs_bucket\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content = "Critical Cloud Storage object has been modified. Investigate for unauthorised data manipulation."
  }
}

# Enable Object Versioning on critical buckets
resource "google_storage_bucket" "critical_data" {
  name     = "${var.critical_bucket_prefix}data-store"
  location = "US"

  versioning {
    enabled = true
  }

  # Enable retention policy to prevent premature deletion
  retention_policy {
    retention_period = 7776000  # 90 days in seconds
  }

  # Enable uniform bucket-level access
  uniform_bucket_level_access {
    enabled = true
  }
}""",
                alert_severity="high",
                alert_title="GCP: Cloud Storage Data Manipulation",
                alert_description_template="Critical Cloud Storage object modified by {protoPayload.authenticationInfo.principalEmail}.",
                investigation_steps=[
                    "Verify modification was authorised",
                    "Review object versions to identify changes",
                    "Check Audit Logs for complete action sequence",
                    "Investigate the principal's recent activities",
                    "Review IAM permissions for the user/service account",
                    "Check if modification aligns with application behaviour",
                ],
                containment_actions=[
                    "Enable Object Versioning to maintain history",
                    "Enable Retention Policy to prevent premature deletion",
                    "Restore previous object version if needed",
                    "Review and restrict IAM permissions",
                    "Enable Bucket Lock for critical data",
                    "Implement signed URLs for temporary access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter expected application writes and maintenance operations; adjust threshold based on normal activity",
            detection_coverage="90% - detects API-based modifications",
            evasion_considerations="Direct VM access could bypass detection; ensure all access is through APIs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-20 (Cloud Logging, Monitoring)",
            prerequisites=[
                "Cloud Audit Logs enabled for Storage",
                "Critical buckets identified",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1565-001-gcp-sql-modification",
            name="GCP Cloud SQL Database Modification Detection",
            description="Detect unauthorised Cloud SQL database modifications through Audit Logs and database flags.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName=~"cloudsql.(instances|databases).(update|patch|delete)"
protoPayload.status.code=0""",
                gcp_terraform_template="""# GCP: Detect Cloud SQL data manipulation
# Step 1: Enable Cloud SQL Audit Logging
# Step 2: Create log-based metric
# Step 3: Create alert policy

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Database Security Team"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for Cloud SQL modifications
resource "google_logging_metric" "sql_modification" {
  name   = "cloudsql-data-manipulation"
  filter = <<-EOT
    protoPayload.methodName=~"cloudsql.(instances|databases).(update|patch|delete)"
    protoPayload.status.code=0
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User who modified the database"
    }
    labels {
      key         = "instance"
      value_type  = "STRING"
      description = "Cloud SQL instance"
    }
  }

  label_extractors = {
    user     = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    instance = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for SQL modifications
resource "google_monitoring_alert_policy" "sql_modification" {
  display_name = "Cloud SQL Data Manipulation"
  combiner     = "OR"

  conditions {
    display_name = "Database modified"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sql_modification.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Cloud SQL instance has been modified. Investigate for unauthorised database changes."
  }
}

# Enable database flags for audit logging (PostgreSQL example)
resource "google_sql_database_instance" "primary" {
  name             = "primary-instance"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    # Enable database audit logging
    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }

    database_flags {
      name  = "pgaudit.log"
      value = "all"  # Log all operations
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    # Enable automated backups
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
      transaction_log_retention_days = 7
    }

    # Enable deletion protection
    deletion_protection_enabled = true
  }

  deletion_protection = true
}

# Separate log sink for database audit logs
resource "google_logging_project_sink" "database_audit" {
  name        = "database-audit-logs"
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"

  filter = <<-EOT
    resource.type="cloudsql_database"
    logName=~"projects/${var.project_id}/logs/cloudaudit.googleapis.com"
  EOT

  unique_writer_identity = true
}

resource "google_storage_bucket" "audit_logs" {
  name     = "${var.project_id}-database-audit-logs"
  location = "US"

  uniform_bucket_level_access {
    enabled = true
  }

  retention_policy {
    retention_period = 7776000  # 90 days
  }
}

resource "google_storage_bucket_iam_member" "audit_writer" {
  bucket = google_storage_bucket.audit_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.database_audit.writer_identity
}""",
                alert_severity="high",
                alert_title="GCP: Cloud SQL Database Manipulation",
                alert_description_template="Cloud SQL instance {protoPayload.resourceName} modified by {protoPayload.authenticationInfo.principalEmail}.",
                investigation_steps=[
                    "Review what database settings or data were changed",
                    "Check database audit logs for unauthorised queries",
                    "Verify modification was part of authorised maintenance",
                    "Review recent database activity patterns",
                    "Check Point-in-Time Recovery status",
                    "Investigate the principal's permissions and recent actions",
                ],
                containment_actions=[
                    "Enable deletion protection on instances",
                    "Enable Point-in-Time Recovery",
                    "Restore from backup if manipulation confirmed",
                    "Review and restrict IAM database permissions",
                    "Enable database audit logging",
                    "Implement database change management processes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised maintenance windows and automated operations",
            detection_coverage="85% - detects instance modifications; query-level requires audit logs",
            evasion_considerations="Application-level data changes require database audit logs to detect",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-35 (Cloud Logging, automated backups)",
            prerequisites=["Cloud Audit Logs enabled", "Database audit flags enabled"],
        ),
    ],
    recommended_order=[
        "t1565-001-aws-s3-integrity",
        "t1565-001-gcp-storage-integrity",
        "t1565-001-aws-rds-modification",
        "t1565-001-gcp-sql-modification",
        "t1565-001-aws-dynamodb-modification",
    ],
    total_effort_hours=8.5,
    coverage_improvement="+30% improvement for Impact tactic detection",
)
