"""
T1213.006 - Data from Information Repositories: Databases

Adversaries exploit databases to extract valuable information including usernames,
password hashes, PII, and financial records. Targets include MySQL, PostgreSQL,
MongoDB, Amazon RDS, Azure SQL, Google Firebase, and Snowflake.
Used by APT41, FIN6, Leviathan, Sandworm Team, Sea Turtle, and Turla.
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
    technique_id="T1213.006",
    technique_name="Data from Information Repositories: Databases",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1213/006/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit databases to extract valuable information hosted "
            "on-premises or in cloud environments (PaaS/SaaS). Target databases include "
            "MySQL, PostgreSQL, MongoDB, Amazon RDS, Azure SQL, Google Firebase, and Snowflake. "
            "Data of interest encompasses usernames, password hashes, personally identifiable "
            "information, and financial records to support lateral movement, command & control, "
            "exfiltration, extortion, or resale."
        ),
        attacker_goal="Extract sensitive data from database systems for exfiltration or exploitation",
        why_technique=[
            "Databases contain high-value sensitive data",
            "Cloud databases increasingly targeted",
            "Legitimate admin tools mask malicious activity",
            "Credential reuse enables database access",
            "SaaS platforms offer bulk export features",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Direct access to sensitive organisational data including credentials, PII, "
            "and financial records. Successful extraction enables further attacks, "
            "regulatory violations, and significant business impact."
        ),
        business_impact=[
            "Data breach and exfiltration",
            "Credential theft for lateral movement",
            "Regulatory compliance violations",
            "Intellectual property theft",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1041", "T1567", "T1486"],
        often_follows=["T1078", "T1212", "T1552"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1213-006-aws-rds-export",
            name="AWS RDS Unusual Export Activity",
            description="Detect unusual RDS snapshot exports or data extraction patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.dBSnapshotIdentifier
| filter eventSource = "rds.amazonaws.com"
| filter eventName in ["CreateDBSnapshot", "CopyDBSnapshot", "ModifyDBSnapshotAttribute", "CreateDBClusterSnapshot"]
| stats count(*) as snapshot_ops by userIdentity.principalId, bin(1h)
| filter snapshot_ops > 3
| sort snapshot_ops desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual RDS snapshot and export activity

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: RDS Export Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for RDS snapshot operations
  RDSSnapshotFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: /aws/cloudtrail/events
      FilterPattern: '{ ($.eventSource = "rds.amazonaws.com") && ($.eventName = "CreateDBSnapshot" || $.eventName = "CopyDBSnapshot" || $.eventName = "ModifyDBSnapshotAttribute") }'
      MetricTransformations:
        - MetricName: RDSSnapshotOperations
          MetricNamespace: Security/Database
          MetricValue: "1"
          DefaultValue: 0

  # Alarm for excessive snapshot operations
  RDSSnapshotAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualRDSSnapshotActivity
      AlarmDescription: Detects unusual RDS snapshot export activity
      MetricName: RDSSnapshotOperations
      Namespace: Security/Database
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect unusual RDS snapshot and export activity

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
  default     = "/aws/cloudtrail/events"
}

# SNS Topic for alerts
resource "aws_sns_topic" "rds_alerts" {
  name         = "rds-export-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "RDS Export Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.rds_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for RDS snapshot operations
resource "aws_cloudwatch_log_metric_filter" "rds_snapshots" {
  name           = "rds-snapshot-operations"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"rds.amazonaws.com\") && ($.eventName = \"CreateDBSnapshot\" || $.eventName = \"CopyDBSnapshot\" || $.eventName = \"ModifyDBSnapshotAttribute\") }"

  metric_transformation {
    name      = "RDSSnapshotOperations"
    namespace = "Security/Database"
    value     = "1"
    default_value = 0
  }
}

# Alarm for excessive snapshot operations
resource "aws_cloudwatch_metric_alarm" "rds_snapshot_activity" {
  alarm_name          = "UnusualRDSSnapshotActivity"
  alarm_description   = "Detects unusual RDS snapshot export activity"
  metric_name         = "RDSSnapshotOperations"
  namespace           = "Security/Database"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.rds_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.rds_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.rds_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Unusual RDS Database Export Activity Detected",
                alert_description_template="Unusual RDS snapshot operations detected from {principalId}. {snapshot_ops} operations in 1 hour.",
                investigation_steps=[
                    "Identify the principal creating snapshots",
                    "Review snapshot sharing permissions",
                    "Check for snapshot exports to external accounts",
                    "Verify if activity matches approved backup schedules",
                    "Review S3 buckets for exported data",
                ],
                containment_actions=[
                    "Revoke snapshot sharing permissions",
                    "Delete unauthorised snapshots",
                    "Rotate database credentials",
                    "Review IAM permissions for the principal",
                    "Enable RDS encryption if not enabled",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on backup schedules; exclude automated backup principals",
            detection_coverage="60% - covers snapshot-based extraction",
            evasion_considerations="Direct database queries via legitimate tools won't trigger",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging enabled", "RDS API logging"],
        ),
        DetectionStrategy(
            strategy_id="t1213-006-aws-cli-tools",
            name="AWS Database CLI Tool Execution",
            description="Detect unusual execution of database client tools from EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, processName, userName, instanceId
| filter processName in ["mysql", "psql", "sqlcmd", "mongosh", "mongo", "redis-cli"]
| filter userName not in ["root", "postgres", "mysql", "mongod"]
| stats count(*) as executions by userName, processName, instanceId
| filter executions > 5
| sort executions desc""",
                terraform_template="""# Detect unusual database CLI tool execution

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "ec2_log_group" {
  type        = string
  description = "EC2 process monitoring log group"
}

# SNS Topic for alerts
resource "aws_sns_topic" "db_tool_alerts" {
  name         = "database-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Database Tool Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.db_tool_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for database CLI tool usage
resource "aws_cloudwatch_log_metric_filter" "db_cli_tools" {
  name           = "database-cli-tools"
  log_group_name = var.ec2_log_group
  pattern        = "[mysql, psql, sqlcmd, mongosh, mongo, redis-cli]"

  metric_transformation {
    name      = "DatabaseCLIExecution"
    namespace = "Security/Database"
    value     = "1"
    default_value = 0
  }
}

# Alarm for excessive CLI tool usage
resource "aws_cloudwatch_metric_alarm" "db_cli_activity" {
  alarm_name          = "UnusualDatabaseCLIActivity"
  alarm_description   = "Detects unusual database CLI tool execution"
  metric_name         = "DatabaseCLIExecution"
  namespace           = "Security/Database"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.db_tool_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.db_tool_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.db_tool_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Unusual Database CLI Tool Execution Detected",
                alert_description_template="Database CLI tool {processName} executed {executions} times by non-admin user {userName}.",
                investigation_steps=[
                    "Verify user authorisation for database access",
                    "Review command history for the user",
                    "Check database audit logs for queries executed",
                    "Identify data accessed or exported",
                    "Review network connections from instance",
                ],
                containment_actions=[
                    "Disable compromised user account",
                    "Rotate database credentials",
                    "Review database access logs",
                    "Implement database firewall rules",
                    "Enable query auditing if not enabled",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude developer/admin users; tune based on job roles",
            detection_coverage="50% - requires process monitoring enabled",
            evasion_considerations="Requires process logging on EC2; doesn't cover all database tools",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudWatch agent with process monitoring",
                "EC2 instances with logging",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1213-006-gcp-sql-export",
            name="GCP Cloud SQL Export Detection",
            description="Detect unusual Cloud SQL export operations and data extraction.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloudsql_database"
protoPayload.methodName=~"cloudsql.instances.export"
OR protoPayload.methodName=~"cloudsql.backupRuns.insert"
OR protoPayload.methodName=~"cloudsql.instances.clone"''',
                gcp_terraform_template="""# GCP: Detect Cloud SQL export and data extraction

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Database Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for Cloud SQL exports
resource "google_logging_metric" "sql_exports" {
  project = var.project_id
  name    = "cloud-sql-export-operations"

  filter = <<-EOT
    resource.type="cloudsql_database"
    (protoPayload.methodName=~"cloudsql.instances.export" OR
     protoPayload.methodName=~"cloudsql.backupRuns.insert" OR
     protoPayload.methodName=~"cloudsql.instances.clone")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User performing export"
    }
  }

  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Alert policy for unusual export activity
resource "google_monitoring_alert_policy" "sql_export_alert" {
  project      = var.project_id
  display_name = "Unusual Cloud SQL Export Activity"
  combiner     = "OR"

  conditions {
    display_name = "High SQL export rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sql_exports.name}\" AND resource.type=\"cloudsql_database\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Unusual Cloud SQL Export Activity",
                alert_description_template="Unusual Cloud SQL export operations detected from {user}.",
                investigation_steps=[
                    "Identify the user performing exports",
                    "Review export destinations (GCS buckets)",
                    "Check for bucket permissions changes",
                    "Verify if exports match approved backup schedules",
                    "Review Cloud SQL audit logs for queries",
                ],
                containment_actions=[
                    "Revoke export permissions",
                    "Delete unauthorised exports from GCS",
                    "Rotate database credentials",
                    "Review IAM permissions for the user",
                    "Enable Cloud SQL encryption if not enabled",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude automated backup service accounts; adjust threshold for backup frequency",
            detection_coverage="65% - covers export-based extraction",
            evasion_considerations="Direct SQL queries via client tools won't trigger",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud SQL Admin API logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1213-006-gcp-firestore-export",
            name="GCP Firestore Bulk Export Detection",
            description="Detect unusual Firestore/Firebase bulk export operations.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_firestore_database"
protoPayload.methodName="google.firestore.admin.v1.FirestoreAdmin.ExportDocuments"''',
                gcp_terraform_template="""# GCP: Detect Firestore bulk export operations

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Firestore Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for Firestore exports
resource "google_logging_metric" "firestore_exports" {
  project = var.project_id
  name    = "firestore-export-operations"

  filter = <<-EOT
    resource.type="cloud_firestore_database"
    protoPayload.methodName="google.firestore.admin.v1.FirestoreAdmin.ExportDocuments"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User performing export"
    }
  }

  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Alert policy for Firestore exports
resource "google_monitoring_alert_policy" "firestore_export_alert" {
  project      = var.project_id
  display_name = "Unusual Firestore Export Activity"
  combiner     = "OR"

  conditions {
    display_name = "Firestore export detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.firestore_exports.name}\" AND resource.type=\"cloud_firestore_database\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Firestore Bulk Export Detected",
                alert_description_template="Firestore export operation detected from {user}.",
                investigation_steps=[
                    "Identify the user performing export",
                    "Review export destination bucket",
                    "Check for bucket permission changes",
                    "Verify if export is authorised",
                    "Review Firestore access patterns",
                ],
                containment_actions=[
                    "Revoke export permissions",
                    "Delete unauthorised exports",
                    "Review IAM permissions",
                    "Enable Firestore security rules",
                    "Rotate service account keys if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Firestore exports are relatively rare; verify all exports",
            detection_coverage="70% - covers Firestore export API",
            evasion_considerations="Individual document reads won't trigger; requires bulk export",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Firestore Admin API logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1213-006-aws-dynamodb-export",
            name="AWS DynamoDB Export Detection",
            description="Detect unusual DynamoDB export to S3 or excessive scan operations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.tableName
| filter eventSource = "dynamodb.amazonaws.com"
| filter eventName in ["ExportTableToPointInTime", "Scan", "Query"]
| stats count(*) as operations by userIdentity.principalId, eventName, bin(1h)
| filter operations > 100
| sort operations desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual DynamoDB export and scan activity

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: DynamoDB Export Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for DynamoDB exports
  DynamoDBExportFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: /aws/cloudtrail/events
      FilterPattern: '{ ($.eventSource = "dynamodb.amazonaws.com") && ($.eventName = "ExportTableToPointInTime") }'
      MetricTransformations:
        - MetricName: DynamoDBExports
          MetricNamespace: Security/Database
          MetricValue: "1"
          DefaultValue: 0

  # Alarm for DynamoDB exports
  DynamoDBExportAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualDynamoDBExportActivity
      AlarmDescription: Detects unusual DynamoDB export operations
      MetricName: DynamoDBExports
      Namespace: Security/Database
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect unusual DynamoDB export and scan activity

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
  default     = "/aws/cloudtrail/events"
}

# SNS Topic for alerts
resource "aws_sns_topic" "dynamodb_alerts" {
  name         = "dynamodb-export-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "DynamoDB Export Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dynamodb_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for DynamoDB exports
resource "aws_cloudwatch_log_metric_filter" "dynamodb_exports" {
  name           = "dynamodb-export-operations"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"dynamodb.amazonaws.com\") && ($.eventName = \"ExportTableToPointInTime\") }"

  metric_transformation {
    name      = "DynamoDBExports"
    namespace = "Security/Database"
    value     = "1"
    default_value = 0
  }
}

# Alarm for DynamoDB exports
resource "aws_cloudwatch_metric_alarm" "dynamodb_export_activity" {
  alarm_name          = "UnusualDynamoDBExportActivity"
  alarm_description   = "Detects unusual DynamoDB export operations"
  metric_name         = "DynamoDBExports"
  namespace           = "Security/Database"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.dynamodb_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.dynamodb_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.dynamodb_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Unusual DynamoDB Export Activity Detected",
                alert_description_template="DynamoDB export operation detected from {principalId} on table {tableName}.",
                investigation_steps=[
                    "Identify the principal performing export",
                    "Review export destination S3 bucket",
                    "Check for S3 bucket permission changes",
                    "Verify if export is authorised",
                    "Review DynamoDB access patterns",
                ],
                containment_actions=[
                    "Revoke export permissions",
                    "Delete unauthorised exports from S3",
                    "Rotate credentials for compromised principal",
                    "Review IAM permissions",
                    "Enable DynamoDB encryption if not enabled",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="DynamoDB exports are rare; verify all export operations",
            detection_coverage="65% - covers export API and excessive scans",
            evasion_considerations="Small incremental queries may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging enabled", "DynamoDB API logging"],
        ),
    ],
    recommended_order=[
        "t1213-006-aws-rds-export",
        "t1213-006-gcp-sql-export",
        "t1213-006-aws-dynamodb-export",
        "t1213-006-gcp-firestore-export",
        "t1213-006-aws-cli-tools",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+25% improvement for Collection tactic database monitoring",
)
