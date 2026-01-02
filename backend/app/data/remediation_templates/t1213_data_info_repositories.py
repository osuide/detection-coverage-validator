"""
T1213 - Data from Information Repositories

Adversaries leverage information repositories to extract valuable data that aids
in Credential Access, Lateral Movement, Defense Evasion, or direct target access.
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
    technique_id="T1213",
    technique_name="Data from Information Repositories",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1213/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage information repositories to extract valuable data that aids "
            "in Credential Access, Lateral Movement, Defense Evasion, or direct target access. "
            "These collaboration tools store sensitive materials including network diagrams, credentials, "
            "source code, customer data, and PII that threat actors can exploit. In cloud environments, "
            "this includes SharePoint, Confluence, code repositories, databases, CRM systems, and messaging platforms."
        ),
        attacker_goal="Harvest sensitive information from collaboration platforms and internal repositories",
        why_technique=[
            "Repositories contain high-value targets like credentials and network diagrams",
            "Cloud-based repositories are accessible from anywhere with valid credentials",
            "Information repositories often have weak access controls",
            "Single compromised account can access vast amounts of sensitive data",
            "Automated tools can rapidly scrape repository contents",
            "Data from repositories enables lateral movement and privilege escalation",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Information repositories contain concentrated stores of sensitive data. "
            "A single compromised account can expose credentials, intellectual property, "
            "customer data, and internal documentation. This technique frequently leads to "
            "credential theft, lateral movement, and large-scale data breaches."
        ),
        business_impact=[
            "Intellectual property theft from code repositories and documentation",
            "Credential exposure enabling further compromise",
            "Customer PII breach from CRM systems and databases",
            "Regulatory violations (GDPR, CCPA, HIPAA, PCI-DSS)",
            "Reputational damage from sensitive data leaks",
            "Competitive intelligence loss",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1567", "T1041", "T1048"],
        often_follows=["T1078", "T1110", "T1528"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Unusual Database Access Patterns
        DetectionStrategy(
            strategy_id="t1213-aws-dbaccess",
            name="Unusual Database Repository Access Detection",
            description=(
                "Detect anomalous access patterns to RDS databases that may serve as "
                "information repositories containing customer data, logs, or business intelligence."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventName,
       sourceIPAddress, requestParameters.dBInstanceIdentifier as database
| filter eventSource = "rds.amazonaws.com"
| filter eventName in ["DescribeDBInstances", "DescribeDBSnapshots", "CreateDBSnapshot", "DownloadDBLogFilePortion"]
| stats count(*) as access_count, count_distinct(database) as unique_databases
  by user, sourceIPAddress, bin(1h) as time_window
| filter access_count >= 20 or unique_databases >= 5
| sort access_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual database access for T1213

Parameters:
  CloudTrailLogGroup:
    Type: String
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

  # Step 2: Metric filter for database access
  DatabaseAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "rds.amazonaws.com") && ($.eventName = "DescribeDBInstances" || $.eventName = "DescribeDBSnapshots" || $.eventName = "CreateDBSnapshot") }'
      MetricTransformations:
        - MetricName: DatabaseRepositoryAccess
          MetricNamespace: Security/T1213
          MetricValue: "1"

  # Step 3: Alarm on excessive access
  DatabaseAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1213-UnusualDatabaseAccess
      MetricName: DatabaseRepositoryAccess
      Namespace: Security/T1213
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

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
                terraform_template="""# Detect unusual database access for T1213

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "database-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for database access
resource "aws_cloudwatch_log_metric_filter" "db_access" {
  name           = "database-repository-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"rds.amazonaws.com\") && ($.eventName = \"DescribeDBInstances\" || $.eventName = \"DescribeDBSnapshots\" || $.eventName = \"CreateDBSnapshot\") }"

  metric_transformation {
    name      = "DatabaseRepositoryAccess"
    namespace = "Security/T1213"
    value     = "1"
  }
}

# Step 3: Alarm on excessive access
resource "aws_cloudwatch_metric_alarm" "db_access" {
  alarm_name          = "T1213-UnusualDatabaseAccess"
  metric_name         = "DatabaseRepositoryAccess"
  namespace           = "Security/T1213"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
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
                alert_title="Unusual Database Repository Access Detected",
                alert_description_template=(
                    "User {user} performed {access_count} database operations across {unique_databases} "
                    "databases in 1 hour from {sourceIPAddress}. This may indicate repository data collection."
                ),
                investigation_steps=[
                    "Identify which databases were accessed",
                    "Verify if user typically accesses these databases",
                    "Check for snapshot creation or log downloads",
                    "Review source IP location and reputation",
                    "Examine database logs for actual data queries",
                    "Determine if sensitive customer or business data was accessed",
                ],
                containment_actions=[
                    "Revoke database credentials for compromised principal",
                    "Block source IP at security group level",
                    "Review database access permissions",
                    "Enable database activity monitoring (DAM)",
                    "Consider implementing VPC endpoints for database access",
                    "Rotate database passwords if compromise suspected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist DBAs, monitoring tools, and backup solutions",
            detection_coverage="65% - covers enumeration of database repositories",
            evasion_considerations="Direct database connections bypass CloudTrail; slow access patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Strategy 2: AWS - Code Repository Access Monitoring
        DetectionStrategy(
            strategy_id="t1213-aws-coderepo",
            name="Code Repository Bulk Access Detection",
            description=(
                "Detect unusual access to CodeCommit repositories that may indicate "
                "source code or secrets collection from version control systems."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventName,
       sourceIPAddress, requestParameters.repositoryName as repo
| filter eventSource = "codecommit.amazonaws.com"
| filter eventName in ["GitPull", "GetFile", "GetFolder", "ListRepositories", "BatchGetRepositories"]
| stats count(*) as git_operations, count_distinct(repo) as unique_repos
  by user, sourceIPAddress, bin(30m) as time_window
| filter git_operations >= 30 or unique_repos >= 3
| sort git_operations desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect bulk code repository access for T1213

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

  # Step 2: Metric filter for repository access
  CodeRepoFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "codecommit.amazonaws.com") && ($.eventName = "GitPull" || $.eventName = "GetFile" || $.eventName = "GetFolder") }'
      MetricTransformations:
        - MetricName: CodeRepositoryAccess
          MetricNamespace: Security/T1213
          MetricValue: "1"

  # Step 3: Alarm for bulk access
  CodeRepoAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1213-BulkCodeRepoAccess
      MetricName: CodeRepositoryAccess
      Namespace: Security/T1213
      Statistic: Sum
      Period: 1800
      Threshold: 30
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

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
                terraform_template="""# Detect bulk code repository access for T1213

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "code-repo-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for repository access
resource "aws_cloudwatch_log_metric_filter" "code_repo" {
  name           = "code-repository-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"codecommit.amazonaws.com\") && ($.eventName = \"GitPull\" || $.eventName = \"GetFile\" || $.eventName = \"GetFolder\") }"

  metric_transformation {
    name      = "CodeRepositoryAccess"
    namespace = "Security/T1213"
    value     = "1"
  }
}

# Step 3: Alarm for bulk access
resource "aws_cloudwatch_metric_alarm" "code_repo" {
  alarm_name          = "T1213-BulkCodeRepoAccess"
  metric_name         = "CodeRepositoryAccess"
  namespace           = "Security/T1213"
  statistic           = "Sum"
  period              = 1800
  threshold           = 30
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
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
                alert_title="Bulk Code Repository Access Detected",
                alert_description_template=(
                    "User {user} performed {git_operations} repository operations across {unique_repos} "
                    "repositories in 30 minutes from {sourceIPAddress}. This may indicate source code collection."
                ),
                investigation_steps=[
                    "Identify which repositories were accessed",
                    "Check if user normally works with these repositories",
                    "Review what files or branches were accessed",
                    "Verify source IP is from expected location",
                    "Check for cloning of entire repositories",
                    "Look for access to repositories containing secrets or credentials",
                ],
                containment_actions=[
                    "Revoke repository access for compromised account",
                    "Rotate any credentials stored in accessed repositories",
                    "Review repository permissions and access policies",
                    "Enable branch protection on sensitive repositories",
                    "Implement IP allowlists for repository access",
                    "Scan repositories for exposed secrets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline developer activity; whitelist CI/CD service accounts",
            detection_coverage="70% - catches bulk repository access patterns",
            evasion_considerations="Slow cloning over time; using git over SSH instead of HTTPS",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CodeCommit in use"],
        ),
        # Strategy 3: AWS - SharePoint/WorkDocs Access
        DetectionStrategy(
            strategy_id="t1213-aws-workdocs",
            name="Document Repository Bulk Download Detection",
            description=(
                "Detect bulk downloads from WorkDocs or similar document repositories "
                "that may indicate collection of business documentation and files."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventName,
       sourceIPAddress, requestParameters.documentId
| filter eventSource = "workdocs.amazonaws.com"
| filter eventName in ["GetDocument", "GetDocumentVersion", "DescribeDocumentVersions", "DescribeFolderContents"]
| stats count(*) as doc_accesses, count_distinct(requestParameters.documentId) as unique_docs
  by user, sourceIPAddress, bin(1h) as time_window
| filter doc_accesses >= 50 or unique_docs >= 20
| sort doc_accesses desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect bulk document repository access for T1213

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

  # Step 2: Metric filter for document access
  WorkDocsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "workdocs.amazonaws.com") && ($.eventName = "GetDocument" || $.eventName = "GetDocumentVersion") }'
      MetricTransformations:
        - MetricName: DocumentRepositoryAccess
          MetricNamespace: Security/T1213
          MetricValue: "1"

  # Step 3: Alarm for bulk downloads
  WorkDocsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1213-BulkDocumentAccess
      MetricName: DocumentRepositoryAccess
      Namespace: Security/T1213
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

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
                terraform_template="""# Detect bulk document repository access for T1213

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "workdocs-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for document access
resource "aws_cloudwatch_log_metric_filter" "workdocs" {
  name           = "document-repository-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"workdocs.amazonaws.com\") && ($.eventName = \"GetDocument\" || $.eventName = \"GetDocumentVersion\") }"

  metric_transformation {
    name      = "DocumentRepositoryAccess"
    namespace = "Security/T1213"
    value     = "1"
  }
}

# Step 3: Alarm for bulk downloads
resource "aws_cloudwatch_metric_alarm" "workdocs" {
  alarm_name          = "T1213-BulkDocumentAccess"
  metric_name         = "DocumentRepositoryAccess"
  namespace           = "Security/T1213"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
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
                alert_title="Bulk Document Repository Access Detected",
                alert_description_template=(
                    "User {user} accessed {doc_accesses} documents ({unique_docs} unique) "
                    "in 1 hour from {sourceIPAddress}. This may indicate bulk document collection."
                ),
                investigation_steps=[
                    "Identify which documents were accessed",
                    "Verify if user normally accesses this volume of documents",
                    "Check document sensitivity and classification",
                    "Review source IP and user agent",
                    "Determine if documents contain PII or confidential data",
                    "Check for any document sharing or export activities",
                ],
                containment_actions=[
                    "Revoke user's document repository access",
                    "Review and restrict folder permissions",
                    "Enable document download restrictions",
                    "Implement data loss prevention (DLP) policies",
                    "Consider enabling watermarking for sensitive documents",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal user behaviour; whitelist search indexers and backup tools",
            detection_coverage="65% - depends on repository usage patterns",
            evasion_considerations="Slow downloads over extended periods; accessing via mobile apps",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "WorkDocs or similar service in use"],
        ),
        # Strategy 4: GCP - Cloud Storage Repository Access
        DetectionStrategy(
            strategy_id="t1213-gcp-gcs",
            name="GCP Storage Repository Bulk Access Detection",
            description=(
                "Detect bulk access to Cloud Storage buckets used as document or "
                "file repositories that may indicate systematic data collection."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="storage.objects.get"
protoPayload.serviceName="storage.googleapis.com"
protoPayload.authenticationInfo.principalEmail!=""''',
                gcp_terraform_template="""# GCP: Detect bulk storage repository access

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for storage access
resource "google_logging_metric" "storage_access" {
  project = var.project_id
  name   = "storage-repository-access"
  filter = <<-EOT
    protoPayload.methodName="storage.objects.get"
    protoPayload.serviceName="storage.googleapis.com"
    protoPayload.authenticationInfo.principalEmail!=""
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for bulk access
resource "google_monitoring_alert_policy" "storage_access" {
  project      = var.project_id
  display_name = "Bulk Storage Repository Access"
  combiner     = "OR"

  conditions {
    display_name = "High volume document downloads"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.storage_access.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
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
    content = "Bulk access to storage repositories detected (T1213)"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Bulk Storage Repository Access Detected",
                alert_description_template=(
                    "High volume of Cloud Storage object downloads detected. "
                    "This may indicate systematic collection from document repositories."
                ),
                investigation_steps=[
                    "Identify which buckets and objects were accessed",
                    "Verify the principal's authorisation for this access",
                    "Check if buckets contain sensitive business documents",
                    "Review download volume and patterns",
                    "Determine if access is from expected location",
                    "Look for follow-on exfiltration activities",
                ],
                containment_actions=[
                    "Revoke compromised service account keys",
                    "Review and restrict IAM permissions on buckets",
                    "Enable uniform bucket-level access",
                    "Implement VPC Service Controls",
                    "Consider enabling Object Lifecycle policies",
                    "Enable audit logging if not already active",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate data processing jobs and backup solutions",
            detection_coverage="70% - catches bulk download patterns",
            evasion_considerations="Slow downloads; using multiple service accounts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled for Cloud Storage"],
        ),
        # Strategy 5: GCP - BigQuery Data Repository Access
        DetectionStrategy(
            strategy_id="t1213-gcp-bigquery",
            name="GCP BigQuery Repository Enumeration Detection",
            description=(
                "Detect unusual BigQuery access patterns that may indicate collection "
                "of data from analytics repositories, data warehouses, or business intelligence systems."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName=~"google.cloud.bigquery.v2.JobService.*"
protoPayload.serviceName="bigquery.googleapis.com"
(protoPayload.methodName="google.cloud.bigquery.v2.JobService.Query" OR
 protoPayload.methodName="google.cloud.bigquery.v2.JobService.GetQueryResults")""",
                gcp_terraform_template="""# GCP: Detect unusual BigQuery repository access

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for BigQuery access
resource "google_logging_metric" "bigquery_access" {
  project = var.project_id
  name   = "bigquery-repository-access"
  filter = <<-EOT
    protoPayload.methodName=~"google.cloud.bigquery.v2.JobService.*"
    protoPayload.serviceName="bigquery.googleapis.com"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for excessive queries
resource "google_monitoring_alert_policy" "bigquery_access" {
  project      = var.project_id
  display_name = "Unusual BigQuery Repository Access"
  combiner     = "OR"

  conditions {
    display_name = "High volume BigQuery operations"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.bigquery_access.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "Unusual BigQuery data repository access detected (T1213)"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Unusual BigQuery Repository Access",
                alert_description_template=(
                    "High volume of BigQuery operations detected. "
                    "This may indicate collection of data from analytics repositories."
                ),
                investigation_steps=[
                    "Review which datasets and tables were queried",
                    "Check query patterns for SELECT * or EXPORT operations",
                    "Verify if user typically runs this volume of queries",
                    "Examine query results for sensitive data extraction",
                    "Check for data export to external destinations",
                    "Review principal's authorisation for data access",
                ],
                containment_actions=[
                    "Revoke BigQuery access for compromised principal",
                    "Review and restrict dataset permissions",
                    "Enable column-level security for sensitive data",
                    "Implement VPC Service Controls for BigQuery",
                    "Review and update IAM bindings on datasets",
                    "Consider implementing query cost controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline analytics workloads; whitelist BI tools and data pipelines",
            detection_coverage="70% - catches bulk query patterns",
            evasion_considerations="Targeted queries on specific high-value data; slow querying over time",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled for BigQuery"],
        ),
    ],
    recommended_order=[
        "t1213-aws-coderepo",
        "t1213-gcp-bigquery",
        "t1213-aws-dbaccess",
        "t1213-gcp-gcs",
        "t1213-aws-workdocs",
    ],
    total_effort_hours=7.5,
    coverage_improvement="+20% improvement for Collection tactic",
)
