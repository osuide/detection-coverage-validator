"""
T1119 - Automated Collection

Adversaries may use automated techniques to collect internal data once established
in a system or network, using scripts or command-line tools to search for and copy
information at specific intervals.
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
    technique_id="T1119",
    technique_name="Automated Collection",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1119/",
    threat_context=ThreatContext(
        description=(
            "Adversaries employ automated techniques to collect internal data once established "
            "in a system or network. This includes using scripts and command-line tools to search "
            "for and copy information fitting set criteria such as file type, location, or name at "
            "specific intervals. In cloud environments, attackers leverage APIs, data pipelines, "
            "CLIs, and ETL services for automated data gathering."
        ),
        attacker_goal="Systematically collect sensitive data at scale using automated tools and scripts",
        why_technique=[
            "Allows collection at scale without manual interaction",
            "Cloud APIs enable rapid enumeration and data extraction",
            "Scheduled scripts can continuously harvest new data",
            "Automated collection is harder to detect than manual browsing",
            "Compressing and staging data enables efficient exfiltration",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Automated collection indicates advanced attacker presence and intent to exfiltrate data. "
            "Cloud APIs make bulk data access trivial. This technique typically precedes exfiltration "
            "and indicates the attacker has sufficient access to deploy collection tools."
        ),
        business_impact=[
            "Large-scale data theft affecting intellectual property",
            "Regulatory violations (GDPR, CCPA, HIPAA)",
            "Loss of competitive advantage",
            "Precursor to ransomware or extortion",
            "Reputation damage from data breach disclosure",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1567", "T1537", "T1048"],
        often_follows=["T1078", "T1059", "T1105"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Bulk S3 Enumeration
        DetectionStrategy(
            strategy_id="t1119-aws-s3enum",
            name="Automated S3 Bucket Enumeration Detection",
            description=(
                "Detect automated collection via rapid S3 ListBucket operations that "
                "enumerate bucket contents prior to bulk data download."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, requestParameters.bucketName as bucket,
       sourceIPAddress, eventName
| filter eventName in ["ListObjects", "ListObjectsV2", "ListBuckets"]
| stats count(*) as list_count, count_distinct(bucket) as unique_buckets
  by user, sourceIPAddress, bin(15m) as time_window
| filter list_count >= 50 or unique_buckets >= 5
| sort list_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect automated S3 enumeration for T1119

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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for S3 list operations
  S3EnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "ListObjects" || $.eventName = "ListObjectsV2" || $.eventName = "ListBuckets") }'
      MetricTransformations:
        - MetricName: S3Enumeration
          MetricNamespace: Security/T1119
          MetricValue: "1"

  # Step 3: Alarm on excessive enumeration
  S3EnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1119-S3Enumeration
      MetricName: S3Enumeration
      Namespace: Security/T1119
      Statistic: Sum
      Period: 900
      Threshold: 50
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect automated S3 enumeration for T1119

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "s3-enumeration-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for S3 list operations
resource "aws_cloudwatch_log_metric_filter" "s3_enum" {
  name           = "s3-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"ListObjects\" || $.eventName = \"ListObjectsV2\" || $.eventName = \"ListBuckets\") }"

  metric_transformation {
    name      = "S3Enumeration"
    namespace = "Security/T1119"
    value     = "1"
  }
}

# Step 3: Alarm on excessive enumeration
resource "aws_cloudwatch_metric_alarm" "s3_enum" {
  alarm_name          = "T1119-S3Enumeration"
  metric_name         = "S3Enumeration"
  namespace           = "Security/T1119"
  statistic           = "Sum"
  period              = 900
  threshold           = 50
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Automated S3 Enumeration Detected",
                alert_description_template=(
                    "User {user} performed {list_count} S3 list operations across {unique_buckets} "
                    "buckets in 15 minutes from {sourceIPAddress}. This may indicate automated collection."
                ),
                investigation_steps=[
                    "Identify what buckets were enumerated",
                    "Check if user/role typically accesses these buckets",
                    "Review follow-on GetObject requests for bulk downloads",
                    "Verify source IP location and reputation",
                    "Check for any data exfiltration indicators",
                ],
                containment_actions=[
                    "Revoke credentials for compromised principal",
                    "Block source IP at security group/WAF level",
                    "Enable S3 Object Lock on sensitive buckets",
                    "Review and restrict S3 bucket policies",
                    "Enable MFA Delete for critical buckets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate backup tools, data pipelines, and CSPM solutions",
            detection_coverage="75% - catches rapid enumeration patterns",
            evasion_considerations="Slow enumeration over extended time periods, using multiple principals",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudTrail with S3 data events enabled",
                "CloudTrail logs in CloudWatch",
            ],
        ),
        # Strategy 2: AWS - Scripted API Usage
        DetectionStrategy(
            strategy_id="t1119-aws-scriptedapi",
            name="Scripted AWS API Usage Detection",
            description=(
                "Detect non-browser User-Agent strings making API calls, indicating "
                "automated scripts or tools collecting data."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, userAgent, eventName,
       sourceIPAddress, requestParameters
| filter userAgent like /(?i)(python|powershell|curl|wget|boto3|aws-cli|aws-sdk)/
| filter eventName in ["GetObject", "DescribeInstances", "GetParameter", "GetSecretValue"]
| stats count(*) as api_calls, count_distinct(eventName) as unique_apis,
        count_distinct(sourceIPAddress) as unique_ips
  by user, userAgent, bin(1h) as time_window
| filter api_calls >= 100
| sort api_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect scripted API usage for automated collection

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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for scripted API calls
  ScriptedAPIFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.userAgent = "*python*" || $.userAgent = "*boto3*" || $.userAgent = "*powershell*" || $.userAgent = "*aws-cli*" }'
      MetricTransformations:
        - MetricName: ScriptedAPICalls
          MetricNamespace: Security/T1119
          MetricValue: "1"

  # Step 3: Alarm for high-volume scripted activity
  ScriptedAPIAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1119-ScriptedAPIUsage
      MetricName: ScriptedAPICalls
      Namespace: Security/T1119
      Statistic: Sum
      Period: 3600
      Threshold: 100
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect scripted API usage for automated collection

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "scripted-api-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for scripted API calls
resource "aws_cloudwatch_log_metric_filter" "scripted_api" {
  name           = "scripted-api-calls"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.userAgent = \"*python*\" || $.userAgent = \"*boto3*\" || $.userAgent = \"*powershell*\" || $.userAgent = \"*aws-cli*\" }"

  metric_transformation {
    name      = "ScriptedAPICalls"
    namespace = "Security/T1119"
    value     = "1"
  }
}

# Step 3: Alarm for high-volume scripted activity
resource "aws_cloudwatch_metric_alarm" "scripted_api" {
  alarm_name          = "T1119-ScriptedAPIUsage"
  metric_name         = "ScriptedAPICalls"
  namespace           = "Security/T1119"
  statistic           = "Sum"
  period              = 3600
  threshold           = 100
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="High-Volume Scripted API Usage Detected",
                alert_description_template=(
                    "User {user} made {api_calls} API calls in 1 hour using {userAgent}. "
                    "This may indicate automated collection scripts."
                ),
                investigation_steps=[
                    "Identify the user/role making scripted calls",
                    "Review what APIs and resources were accessed",
                    "Check if this is authorised automation or DevOps activity",
                    "Verify source IP geolocation",
                    "Look for any sensitive data access patterns",
                ],
                containment_actions=[
                    "Verify legitimacy with the account owner",
                    "Rotate credentials if compromise is suspected",
                    "Review and restrict IAM permissions",
                    "Monitor for data exfiltration attempts",
                    "Consider implementing SCPs to restrict scripted access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Baseline normal automation; whitelist known CI/CD, backup, and monitoring tools",
            detection_coverage="60% - catches scripted collection but has high false positives",
            evasion_considerations="Custom User-Agent strings, browser-based collection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Strategy 3: AWS - Secrets Manager Bulk Access
        DetectionStrategy(
            strategy_id="t1119-aws-secretsenum",
            name="Bulk Secrets Enumeration Detection",
            description=(
                "Detect automated collection of secrets via rapid Secrets Manager "
                "or SSM Parameter Store enumeration and retrieval."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventName,
       sourceIPAddress, requestParameters.secretId
| filter eventName in ["GetSecretValue", "GetParameter", "GetParameters", "DescribeSecret", "ListSecrets"]
| stats count(*) as secret_accesses, count_distinct(requestParameters.secretId) as unique_secrets
  by user, sourceIPAddress, bin(1h) as time_window
| filter secret_accesses >= 20 or unique_secrets >= 10
| sort secret_accesses desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect bulk secrets access for T1119

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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for secrets access
  SecretsAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "GetSecretValue" || $.eventName = "GetParameter" || $.eventName = "GetParameters") }'
      MetricTransformations:
        - MetricName: SecretsAccess
          MetricNamespace: Security/T1119
          MetricValue: "1"

  # Step 3: Alarm on bulk access
  SecretsAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1119-BulkSecretsAccess
      MetricName: SecretsAccess
      Namespace: Security/T1119
      Statistic: Sum
      Period: 3600
      Threshold: 20
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect bulk secrets access for T1119

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "secrets-access-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for secrets access
resource "aws_cloudwatch_log_metric_filter" "secrets_access" {
  name           = "bulk-secrets-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"GetSecretValue\" || $.eventName = \"GetParameter\" || $.eventName = \"GetParameters\") }"

  metric_transformation {
    name      = "SecretsAccess"
    namespace = "Security/T1119"
    value     = "1"
  }
}

# Step 3: Alarm on bulk access
resource "aws_cloudwatch_metric_alarm" "secrets_access" {
  alarm_name          = "T1119-BulkSecretsAccess"
  metric_name         = "SecretsAccess"
  namespace           = "Security/T1119"
  statistic           = "Sum"
  period              = 3600
  threshold           = 20
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Bulk Secrets Access Detected",
                alert_description_template=(
                    "User {user} accessed {secret_accesses} secrets ({unique_secrets} unique) "
                    "in 1 hour from {sourceIPAddress}. This indicates automated credential collection."
                ),
                investigation_steps=[
                    "Identify which secrets were accessed",
                    "Verify if the user/role should have this access",
                    "Check for credential usage after collection",
                    "Review source IP location and reputation",
                    "Determine if secrets were exfiltrated",
                ],
                containment_actions=[
                    "Immediately rotate all accessed secrets",
                    "Revoke credentials for compromised principal",
                    "Review and restrict IAM policies for secrets access",
                    "Enable resource-based policies on critical secrets",
                    "Monitor for unauthorised use of stolen credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist deployment pipelines and application startup patterns",
            detection_coverage="85% - highly effective for bulk secrets collection",
            evasion_considerations="Slow collection over extended periods, targeting specific secrets",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Strategy 4: GCP - Cloud Storage Enumeration
        DetectionStrategy(
            strategy_id="t1119-gcp-gcsenum",
            name="GCP Storage Bucket Enumeration Detection",
            description=(
                "Detect automated enumeration of Cloud Storage buckets and objects "
                "that may indicate collection operations."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"storage\\..*\\.(list|get)"
protoPayload.serviceName="storage.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect automated Cloud Storage enumeration

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

# Step 2: Log-based metric for storage enumeration
resource "google_logging_metric" "gcs_enum" {
  name   = "gcs-enumeration"
  filter = <<-EOT
    protoPayload.methodName=~"storage\\..*\\.(list|get)"
    protoPayload.serviceName="storage.googleapis.com"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for bulk enumeration
resource "google_monitoring_alert_policy" "gcs_enum" {
  display_name = "Automated Storage Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "High volume storage access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_enum.name}\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "900s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Automated collection of Cloud Storage data detected (T1119)"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Automated Storage Enumeration Detected",
                alert_description_template=(
                    "High volume of Cloud Storage list/get operations detected. "
                    "This may indicate automated data collection."
                ),
                investigation_steps=[
                    "Identify the principal performing enumeration",
                    "Review which buckets and objects were accessed",
                    "Check if this is authorised backup or data pipeline activity",
                    "Verify source IP geolocation",
                    "Look for subsequent data download patterns",
                ],
                containment_actions=[
                    "Revoke compromised service account keys",
                    "Review and restrict IAM permissions on buckets",
                    "Enable VPC Service Controls to limit data access",
                    "Implement Object Lifecycle policies to protect data",
                    "Monitor for data exfiltration to external destinations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate data processing jobs and backup tools",
            detection_coverage="70% - catches bulk enumeration patterns",
            evasion_considerations="Slow enumeration, using multiple service accounts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled for Cloud Storage"],
        ),
        # Strategy 5: GCP - Secret Manager Bulk Access
        DetectionStrategy(
            strategy_id="t1119-gcp-secretsenum",
            name="GCP Secret Manager Enumeration Detection",
            description=(
                "Detect bulk access to Secret Manager which may indicate "
                "automated credential collection."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"AccessSecretVersion|ListSecrets"
protoPayload.serviceName="secretmanager.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect bulk Secret Manager access

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

# Step 2: Log-based metric for secret access
resource "google_logging_metric" "secret_access" {
  name   = "secret-manager-bulk-access"
  filter = <<-EOT
    protoPayload.methodName=~"AccessSecretVersion|ListSecrets"
    protoPayload.serviceName="secretmanager.googleapis.com"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for bulk access
resource "google_monitoring_alert_policy" "secret_access" {
  display_name = "Bulk Secret Access Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume secret access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.secret_access.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Automated credential collection detected via Secret Manager (T1119)"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Bulk Secret Access Detected",
                alert_description_template=(
                    "High volume of Secret Manager access operations detected. "
                    "This indicates automated credential collection."
                ),
                investigation_steps=[
                    "Identify which secrets were accessed",
                    "Verify the principal's authorisation for secret access",
                    "Check for credential usage after collection",
                    "Review audit logs for exfiltration indicators",
                    "Determine scope of compromise",
                ],
                containment_actions=[
                    "Rotate all accessed secrets immediately",
                    "Disable compromised service account",
                    "Review and restrict IAM bindings on secrets",
                    "Enable VPC Service Controls for Secret Manager",
                    "Monitor for unauthorised use of stolen credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist application deployments and automated workflows",
            detection_coverage="90% - highly effective for bulk secret access",
            evasion_considerations="Slow collection, targeting specific high-value secrets",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Secret Manager"],
        ),
    ],
    recommended_order=[
        "t1119-aws-secretsenum",
        "t1119-gcp-secretsenum",
        "t1119-aws-s3enum",
        "t1119-gcp-gcsenum",
        "t1119-aws-scriptedapi",
    ],
    total_effort_hours=7.5,
    coverage_improvement="+25% improvement for Collection tactic",
)
