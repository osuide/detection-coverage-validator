"""
T1593 - Search Open Websites/Domains

Adversaries search publicly available websites and domains to gather intelligence
on targets. Includes social media, search engines, and code repositories.
Used by Kimsuky, Mustang Panda, Sandworm Team, Star Blizzard, Volt Typhoon.
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
    technique_id="T1593",
    technique_name="Search Open Websites/Domains",
    tactic_ids=["TA0043"],
    mitre_url="https://attack.mitre.org/techniques/T1593/",
    threat_context=ThreatContext(
        description=(
            "Adversaries search publicly available websites and domains to gather "
            "intelligence on targets for use in subsequent attack phases. This includes "
            "searching social media platforms, news sites, business-related platforms, "
            "search engines, and code repositories to identify victim information, "
            "credentials, and organisational details."
        ),
        attacker_goal="Gather intelligence on targets through publicly available online resources",
        why_technique=[
            "Completely passive reconnaissance",
            "No technical infrastructure required",
            "Difficult to detect or prevent",
            "Publicly accessible information",
            "Enables targeted phishing campaigns",
            "May reveal credentials in repositories",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=4,
        severity_reasoning=(
            "Pre-compromise reconnaissance technique. While not directly harmful, it "
            "enables targeted attacks and can reveal sensitive organisational information "
            "or credentials that facilitate subsequent attack stages."
        ),
        business_impact=[
            "Enables targeted phishing campaigns",
            "Credential exposure in repositories",
            "Organisational intelligence gathering",
            "Attack surface enumeration",
            "Social engineering preparation",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1566", "T1078", "T1589", "T1598"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1593-aws-repo-monitor",
            name="AWS: Code Repository Credential Monitoring",
            description="Monitor and scan code repositories for exposed credentials and sensitive data.",
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="codeartifact",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""# This is a preventive control - use git-secrets or similar tools
# Example git-secrets patterns to detect AWS credentials:
# Pattern: AWS API Key
# Pattern: AWS Secret Key
# Pattern: AWS Account ID
# Scan commits for exposed credentials before they are pushed""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: EventBridge rule to monitor repository events

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Repository Security Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # EventBridge Rule for CodeCommit events
  CodeCommitEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: codecommit-push-monitor
      Description: Monitor CodeCommit repository push events
      EventPattern:
        source:
          - aws.codecommit
        detail-type:
          - CodeCommit Repository State Change
        detail:
          event:
            - referenceCreated
            - referenceUpdated
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: NotifyOnPush

  # EventBridge Rule for CodeArtifact package events
  CodeArtifactEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: codeartifact-package-monitor
      Description: Monitor CodeArtifact package events
      EventPattern:
        source:
          - aws.codeartifact
        detail-type:
          - CodeArtifact Package Version State Change
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: NotifyOnPackage

Outputs:
  AlertTopicArn:
    Value: !Ref AlertTopic
    Description: SNS Topic ARN for security alerts""",
                terraform_template="""# Monitor AWS code repositories for security events

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS Topic for alerts
resource "aws_sns_topic" "repo_alerts" {
  name         = "repository-security-alerts"
  display_name = "Repository Security Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.repo_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge Rule for CodeCommit events
resource "aws_cloudwatch_event_rule" "codecommit_push" {
  name        = "codecommit-push-monitor"
  description = "Monitor CodeCommit repository push events"

  event_pattern = jsonencode({
    source      = ["aws.codecommit"]
    detail-type = ["CodeCommit Repository State Change"]
    detail = {
      event = ["referenceCreated", "referenceUpdated"]
    }
  })
}

resource "aws_cloudwatch_event_target" "codecommit_sns" {
  rule      = aws_cloudwatch_event_rule.codecommit_push.name
  target_id = "NotifyOnPush"
  arn       = aws_sns_topic.repo_alerts.arn
}

# EventBridge Rule for CodeArtifact package events
resource "aws_cloudwatch_event_rule" "codeartifact_package" {
  name        = "codeartifact-package-monitor"
  description = "Monitor CodeArtifact package events"

  event_pattern = jsonencode({
    source      = ["aws.codeartifact"]
    detail-type = ["CodeArtifact Package Version State Change"]
  })
}

resource "aws_cloudwatch_event_target" "codeartifact_sns" {
  rule      = aws_cloudwatch_event_rule.codeartifact_package.name
  target_id = "NotifyOnPackage"
  arn       = aws_sns_topic.repo_alerts.arn
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "repo_alerts_policy" {
  arn = aws_sns_topic.repo_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.repo_alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Repository Activity Detected",
                alert_description_template="Code repository activity detected: {repositoryName}.",
                investigation_steps=[
                    "Review commit history for sensitive data",
                    "Scan for exposed credentials using git-secrets or truffleHog",
                    "Check repository permissions and access logs",
                    "Verify commit author identity",
                    "Review for unusual push patterns",
                ],
                containment_actions=[
                    "Rotate any exposed credentials immediately",
                    "Remove sensitive data from git history",
                    "Implement pre-commit hooks (git-secrets)",
                    "Review and restrict repository access",
                    "Enable branch protection rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="This monitors legitimate repository activity. Focus on credential scanning tools for actionable alerts.",
            detection_coverage="30% - only detects repository activity, not external searches",
            evasion_considerations="Cannot detect adversaries searching public repositories externally",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["AWS CodeCommit or CodeArtifact in use"],
        ),
        DetectionStrategy(
            strategy_id="t1593-gcp-repo-monitor",
            name="GCP: Source Repository Monitoring",
            description="Monitor GCP source repositories for suspicious activity and exposed secrets.",
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="n/a",
            gcp_service="cloud_source_repositories",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="sourcerepo.googleapis.com/Repo"
protoPayload.methodName=~"google.devtools.source.*"
protoPayload.methodName!="google.devtools.source.v1.RepoApi.GetRepo"''',
                gcp_terraform_template="""# GCP: Monitor source repositories for security events

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Repository Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Log metric for repository push events
resource "google_logging_metric" "repo_push_events" {
  name    = "repository-push-events"
  project = var.project_id

  filter = <<-EOT
    resource.type="sourcerepo.googleapis.com/Repo"
    protoPayload.methodName=~"google.devtools.source.*Push"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Alert policy for unusual repository activity
resource "google_monitoring_alert_policy" "repo_activity" {
  display_name = "Unusual Repository Activity"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "High push rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.repo_push_events.name}\" resource.type=\"sourcerepo.googleapis.com/Repo\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Repository push activity exceeds normal threshold. Review commits for exposed credentials."
    mime_type = "text/markdown"
  }
}

# Log sink for repository audit logs
resource "google_logging_project_sink" "repo_audit_sink" {
  name    = "repository-audit-sink"
  project = var.project_id

  destination = "logging.googleapis.com/projects/${var.project_id}/locations/global/buckets/repository-audit-logs"

  filter = <<-EOT
    resource.type="sourcerepo.googleapis.com/Repo"
    protoPayload.methodName=~"google.devtools.source.*"
  EOT

  unique_writer_identity = true
}""",
                alert_severity="medium",
                alert_title="GCP: Repository Activity Detected",
                alert_description_template="Unusual activity in GCP source repository.",
                investigation_steps=[
                    "Review commit logs and authors",
                    "Scan for secrets using gitleaks or truffleHog",
                    "Check IAM permissions on repository",
                    "Review access logs for unusual patterns",
                    "Verify no credentials were exposed",
                ],
                containment_actions=[
                    "Rotate exposed credentials",
                    "Remove secrets from repository history",
                    "Implement Secret Manager integration",
                    "Review and restrict repository IAM",
                    "Enable pre-commit secret scanning",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Focus on credential scanning tools rather than activity monitoring",
            detection_coverage="30% - only detects internal repository activity",
            evasion_considerations="Cannot detect external reconnaissance of public repositories",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Source Repositories in use"],
        ),
        DetectionStrategy(
            strategy_id="t1593-preventive-audit",
            name="Multi-Cloud: Preventive Security Audit",
            description="Regular audits to prevent information leakage that adversaries could exploit.",
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="n/a",
            gcp_service="n/a",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""# Preventive measures - no real-time query
# Regular audits should include:
# 1. Public repository scans for credentials
# 2. Social media monitoring for company mentions
# 3. Search engine queries for exposed information
# 4. Review of public-facing websites for sensitive data
# 5. Third-party breach monitoring services""",
                terraform_template="""# Multi-cloud preventive controls for information leakage

# AWS: Enable AWS Secrets Manager for credential storage
resource "aws_secretsmanager_secret" "example" {
  name        = "app-credentials"
  description = "Application credentials - never commit to code"

  tags = {
    Purpose = "Prevent credential exposure"
  }
}

# AWS: IAM policy to enforce MFA and least privilege
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# AWS: S3 bucket policy to prevent public access
resource "aws_s3_bucket_public_access_block" "prevent_public" {
  bucket = "your-bucket-name"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}""",
                gcp_terraform_template="""# GCP: Preventive controls for information leakage

variable "project_id" {
  type = string
}

# GCP: Secret Manager for credential storage
resource "google_secret_manager_secret" "app_credentials" {
  secret_id = "app-credentials"
  project   = var.project_id

  replication {
    auto {}
  }

  labels = {
    purpose = "prevent-credential-exposure"
  }
}

# GCP: Organisation policy to prevent public bucket access
resource "google_storage_bucket_iam_binding" "prevent_public" {
  bucket = "your-bucket-name"
  role   = "roles/storage.objectViewer"

  members = [
    "serviceAccount:your-service-account@project.iam.gserviceaccount.com"
  ]

  # Explicitly no allUsers or allAuthenticatedUsers
}

# GCP: Enable VPC Service Controls to prevent data exfiltration
resource "google_access_context_manager_service_perimeter" "perimeter" {
  parent = "accessPolicies/${var.access_policy_id}"
  name   = "accessPolicies/${var.access_policy_id}/servicePerimeters/restrict_public_access"
  title  = "Restrict Public Access"

  status {
    restricted_services = [
      "storage.googleapis.com",
      "secretmanager.googleapis.com"
    ]
  }
}""",
                alert_severity="informational",
                alert_title="Security Audit Required",
                alert_description_template="Scheduled security audit for information leakage prevention.",
                investigation_steps=[
                    "Scan all repositories for exposed credentials",
                    "Review public-facing websites for sensitive information",
                    "Monitor social media for organisational mentions",
                    "Check search engines for exposed documents",
                    "Review third-party breach databases",
                    "Audit cloud storage for public access",
                ],
                containment_actions=[
                    "Remove exposed credentials and rotate",
                    "Remove sensitive information from public sites",
                    "Implement pre-commit hooks organisation-wide",
                    "Enable Secret Manager/Vault for all credentials",
                    "Train developers on security best practices",
                    "Implement data loss prevention (DLP) controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Regular audits with manual review",
            detection_coverage="50% - preventive controls reduce attack surface",
            evasion_considerations="This is preventive, not detective - reduces information available to adversaries",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4-8 hours initial setup, ongoing maintenance",
            estimated_monthly_cost="$0-50 depending on tools used",
            prerequisites=[
                "Organisational security programme",
                "Code repository access",
                "Secret scanning tools",
            ],
        ),
    ],
    recommended_order=[
        "t1593-preventive-audit",
        "t1593-aws-repo-monitor",
        "t1593-gcp-repo-monitor",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+15% improvement for Reconnaissance tactic (primarily preventive)",
)
