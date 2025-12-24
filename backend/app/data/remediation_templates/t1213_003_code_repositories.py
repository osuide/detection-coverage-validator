"""
T1213.003 - Data from Information Repositories: Code Repositories

Adversaries leverage code repositories to extract sensitive information including
proprietary source code and embedded credentials from private repositories.
Used by APT41, APT29, LAPSUS$, Scattered Spider.
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
    technique_id="T1213.003",
    technique_name="Data from Information Repositories: Code Repositories",
    tactic_ids=["TA0009"],  # Collection
    mitre_url="https://attack.mitre.org/techniques/T1213/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage code repositories (GitHub, GitLab, SourceForge, BitBucket) "
            "to extract sensitive information. Attackers with network or repository access can "
            "collect proprietary source code and embedded credentials from private repositories. "
            "This enables development of exploits and unauthorised account access through stolen credentials."
        ),
        attacker_goal="Extract proprietary source code and embedded credentials from private code repositories",
        why_technique=[
            "Access to proprietary intellectual property",
            "Discovery of hardcoded credentials and secrets",
            "Understanding of security controls and weaknesses",
            "Enables development of targeted exploits",
            "Facilitates lateral movement via stolen credentials",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "High-value target for intellectual property theft. Credentials in code repositories "
            "enable further compromise. Increases with cloud adoption and DevOps practices."
        ),
        business_impact=[
            "Intellectual property theft",
            "Exposure of embedded credentials and secrets",
            "Competitive disadvantage",
            "Regulatory compliance violations",
            "Enables further attacks via stolen credentials",
        ],
        typical_attack_phase="collection",
        often_precedes=[
            "T1078.004",
            "T1552.001",
            "T1567.001",
        ],  # Cloud Accounts, Credentials in Files, Exfil to Code Repo
        often_follows=[
            "T1087.004",
            "T1526",
            "T1538",
        ],  # Cloud Account Discovery, Cloud Service Discovery, Dashboard
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1213-003-aws-codecommit",
            name="AWS CodeCommit Anomalous Access",
            description="Detect unusual repository cloning and bulk downloads from CodeCommit.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, requestParameters.repositoryName
| filter eventSource = "codecommit.amazonaws.com"
| filter eventName in ["GitPull", "GetRepository", "BatchGetRepositories"]
| stats count(*) as operations by userIdentity.principalId, bin(1h)
| filter operations > 20
| sort operations desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect anomalous CodeCommit repository access

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Detect bulk repository downloads
  BulkRepoAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "codecommit.amazonaws.com") && ($.eventName = "GitPull" || $.eventName = "GetRepository") }'
      MetricTransformations:
        - MetricName: CodeCommitBulkAccess
          MetricNamespace: Security/CodeRepositories
          MetricValue: "1"
          DefaultValue: 0

  BulkRepoAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CodeCommit-BulkRepositoryAccess
      AlarmDescription: Detects anomalous bulk repository access
      MetricName: CodeCommitBulkAccess
      Namespace: Security/CodeRepositories
      Statistic: Sum
      Period: 3600
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]

  # Detect repository access from unusual locations
  UnusualLocationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "codecommit.amazonaws.com") && ($.eventName = "GitPull") && ($.sourceIPAddress != "AWS Internal") }'
      MetricTransformations:
        - MetricName: CodeCommitExternalAccess
          MetricNamespace: Security/CodeRepositories
          MetricValue: "1"
          DefaultValue: 0

  UnusualLocationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CodeCommit-UnusualLocationAccess
      AlarmDescription: Repository access from external IPs
      MetricName: CodeCommitExternalAccess
      Namespace: Security/CodeRepositories
      Statistic: Sum
      Period: 3600
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect anomalous CodeCommit repository access

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "aws_sns_topic" "code_repo_alerts" {
  name = "codecommit-security-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.code_repo_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Detect bulk repository downloads
resource "aws_cloudwatch_log_metric_filter" "bulk_repo_access" {
  name           = "codecommit-bulk-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"codecommit.amazonaws.com\") && ($.eventName = \"GitPull\" || $.eventName = \"GetRepository\") }"

  metric_transformation {
    name      = "CodeCommitBulkAccess"
    namespace = "Security/CodeRepositories"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "bulk_repo_access" {
  alarm_name          = "CodeCommit-BulkRepositoryAccess"
  alarm_description   = "Detects anomalous bulk repository access"
  metric_name         = "CodeCommitBulkAccess"
  namespace           = "Security/CodeRepositories"
  statistic           = "Sum"
  period              = 3600
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.code_repo_alerts.arn]
}

# Detect repository access from unusual locations
resource "aws_cloudwatch_log_metric_filter" "unusual_location" {
  name           = "codecommit-external-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"codecommit.amazonaws.com\") && ($.eventName = \"GitPull\") && ($.sourceIPAddress != \"AWS Internal\") }"

  metric_transformation {
    name      = "CodeCommitExternalAccess"
    namespace = "Security/CodeRepositories"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unusual_location" {
  alarm_name          = "CodeCommit-UnusualLocationAccess"
  alarm_description   = "Repository access from external IPs"
  metric_name         = "CodeCommitExternalAccess"
  namespace           = "Security/CodeRepositories"
  statistic           = "Sum"
  period              = 3600
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.code_repo_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Anomalous Code Repository Access Detected",
                alert_description_template="Bulk repository access detected from {principalId}.",
                investigation_steps=[
                    "Review repository access patterns for the user",
                    "Check if user account credentials were compromised",
                    "Identify which repositories were accessed",
                    "Review user's typical access patterns and geographic locations",
                    "Check for OAuth token usage or API key access",
                    "Verify if user is a legitimate developer with repository access",
                ],
                containment_actions=[
                    "Suspend suspicious user accounts immediately",
                    "Rotate exposed credentials and secrets",
                    "Review repository access logs for data exfiltration",
                    "Enable MFA for all repository access",
                    "Implement IP allowlisting for repository access",
                    "Scan repositories for exposed secrets using tools like git-secrets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on developer activity. Exclude CI/CD service accounts.",
            detection_coverage="65% - catches bulk access patterns",
            evasion_considerations="Slow, incremental access may evade detection. Legitimate developer accounts can be used.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail logging enabled",
                "CloudTrail logs sent to CloudWatch",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1213-003-aws-secrets-scan",
            name="AWS Secrets Manager Access Correlation",
            description="Detect correlation between repository access and Secrets Manager queries.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, eventSource
| filter eventSource in ["codecommit.amazonaws.com", "secretsmanager.amazonaws.com"]
| filter eventName in ["GitPull", "GetSecretValue", "DescribeSecret"]
| stats count(*) as events by userIdentity.principalId, eventSource, bin(1h)
| filter events > 5""",
                terraform_template="""# Correlate repository access with secrets access

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "aws_sns_topic" "secrets_correlation_alerts" {
  name = "repo-secrets-correlation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.secrets_correlation_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Detect Secrets Manager access patterns
resource "aws_cloudwatch_log_metric_filter" "secrets_access" {
  name           = "secrets-manager-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"secretsmanager.amazonaws.com\") && ($.eventName = \"GetSecretValue\" || $.eventName = \"DescribeSecret\") }"

  metric_transformation {
    name      = "SecretsManagerAccess"
    namespace = "Security/CodeRepositories"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "secrets_enumeration" {
  alarm_name          = "Secrets-Enumeration-Detected"
  alarm_description   = "High volume of Secrets Manager queries"
  metric_name         = "SecretsManagerAccess"
  namespace           = "Security/CodeRepositories"
  statistic           = "Sum"
  period              = 1800
  threshold           = 15
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.secrets_correlation_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Code Repository and Secrets Access Correlation",
                alert_description_template="User {principalId} accessed repositories and queried secrets.",
                investigation_steps=[
                    "Review correlation timeline between repository and secrets access",
                    "Check if accessed secrets are referenced in repositories",
                    "Verify user's authorisation for both repository and secrets access",
                    "Review CloudTrail for other suspicious activities",
                    "Check for credential harvesting attempts",
                ],
                containment_actions=[
                    "Suspend suspicious user account",
                    "Rotate all accessed secrets immediately",
                    "Review and remove hardcoded secrets from repositories",
                    "Implement secrets scanning in CI/CD pipeline",
                    "Enable MFA and IP restrictions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate CI/CD pipelines and deployment automation",
            detection_coverage="60% - detects correlated access patterns",
            evasion_considerations="Time-delayed access may avoid correlation",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging", "Secrets Manager in use"],
        ),
        DetectionStrategy(
            strategy_id="t1213-003-gcp-source-repos",
            name="GCP Cloud Source Repositories Access Monitoring",
            description="Detect anomalous access to Cloud Source Repositories.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="source.googleapis.com/Repository"
protoPayload.methodName=~"google.devtools.source.*"
protoPayload.methodName=~"(Clone|Download|Get)"''',
                gcp_terraform_template="""# GCP: Detect anomalous Cloud Source Repositories access

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "Code Repository Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Detect bulk repository access
resource "google_logging_metric" "bulk_repo_access" {
  name   = "cloud-source-repos-bulk-access"
  filter = <<-EOT
    resource.type="source.googleapis.com/Repository"
    protoPayload.methodName=~"google.devtools.source.*"
    protoPayload.methodName=~"(Clone|Download|Get)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User accessing repository"
    }
  }

  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

resource "google_monitoring_alert_policy" "bulk_repo_access" {
  display_name = "Cloud Source Repositories - Bulk Access"
  combiner     = "OR"

  conditions {
    display_name = "High repository access rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.bulk_repo_access.name}\""
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

  alert_strategy {
    auto_close = "604800s"  # 7 days
  }
}

# Detect repository access from unusual locations
resource "google_logging_metric" "unusual_location_access" {
  name   = "cloud-source-repos-unusual-location"
  filter = <<-EOT
    resource.type="source.googleapis.com/Repository"
    protoPayload.methodName=~"google.devtools.source.*Clone"
    NOT protoPayload.requestMetadata.callerSuppliedUserAgent=~"git|gcloud"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }

  label_extractors = {
    "source_ip" = "EXTRACT(protoPayload.requestMetadata.callerIp)"
  }
}

resource "google_monitoring_alert_policy" "unusual_location_access" {
  display_name = "Cloud Source Repositories - Unusual Location"
  combiner     = "OR"

  conditions {
    display_name = "Repository access from unusual location"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.unusual_location_access.name}\""
      duration        = "1800s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "1800s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Anomalous Code Repository Access",
                alert_description_template="Unusual repository access pattern detected in Cloud Source Repositories.",
                investigation_steps=[
                    "Review repository access logs for suspicious patterns",
                    "Check user authentication method (OAuth, service account)",
                    "Verify geographic location of access",
                    "Review which repositories were accessed",
                    "Check for concurrent Secrets Manager or IAM activity",
                    "Verify user's typical development patterns",
                ],
                containment_actions=[
                    "Suspend suspicious user or service account",
                    "Review and rotate exposed secrets",
                    "Enable VPC Service Controls for repository access",
                    "Implement IP allowlisting",
                    "Enable Binary Authorisation for container images",
                    "Scan repositories for secrets using Secret Manager",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude CI/CD service accounts and known developer IPs",
            detection_coverage="65% - detects anomalous access patterns",
            evasion_considerations="Gradual access and use of legitimate accounts may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled", "Cloud Source Repositories in use"],
        ),
        DetectionStrategy(
            strategy_id="t1213-003-gcp-secret-correlation",
            name="GCP Secret Manager and Repository Access Correlation",
            description="Detect correlation between repository cloning and secret access.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""(resource.type="source.googleapis.com/Repository" OR resource.type="secretmanager.googleapis.com/Secret")
(protoPayload.methodName=~"google.devtools.source.*Clone" OR protoPayload.methodName=~"google.cloud.secretmanager.*AccessSecretVersion")""",
                gcp_terraform_template="""# GCP: Correlate repository and secret access

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "Repository-Secrets Correlation Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Detect Secret Manager access patterns
resource "google_logging_metric" "secret_access" {
  name   = "secret-manager-access-pattern"
  filter = <<-EOT
    resource.type="secretmanager.googleapis.com/Secret"
    protoPayload.methodName=~"google.cloud.secretmanager.*AccessSecretVersion"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal accessing secrets"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

resource "google_monitoring_alert_policy" "secret_enumeration" {
  display_name = "Secret Manager - Enumeration Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume of secret access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.secret_access.name}\""
      duration        = "1800s"
      comparison      = "COMPARISON_GT"
      threshold_value = 15
      aggregations {
        alignment_period   = "1800s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "High volume of Secret Manager access detected. Investigate for potential credential harvesting."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Repository and Secrets Access Correlation",
                alert_description_template="Correlated access to repositories and secrets detected.",
                investigation_steps=[
                    "Review timeline of repository and secret access",
                    "Identify which secrets were accessed",
                    "Check if secrets are referenced in accessed repositories",
                    "Verify principal's authorisation for both services",
                    "Review for other suspicious IAM or service activities",
                ],
                containment_actions=[
                    "Disable suspicious service account or user",
                    "Rotate all accessed secrets immediately",
                    "Scan repositories for hardcoded credentials",
                    "Enable VPC Service Controls",
                    "Implement least-privilege IAM policies",
                    "Enable Secret Manager audit logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal CI/CD patterns and exclude automation accounts",
            detection_coverage="60% - catches correlated suspicious activity",
            evasion_considerations="Delayed access patterns and legitimate accounts may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Logging enabled", "Secret Manager in use"],
        ),
    ],
    recommended_order=[
        "t1213-003-aws-codecommit",
        "t1213-003-gcp-source-repos",
        "t1213-003-aws-secrets-scan",
        "t1213-003-gcp-secret-correlation",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+25% improvement for Collection tactic detection",
)
