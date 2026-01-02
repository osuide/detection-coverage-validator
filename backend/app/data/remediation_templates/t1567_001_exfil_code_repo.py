"""
T1567.001 - Exfiltration Over Web Service: Exfiltration to Code Repository

Adversaries exfiltrate data to code repositories (GitHub, GitLab, Bitbucket) to blend
with legitimate development activity and leverage encrypted HTTPS channels.
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
    technique_id="T1567.001",
    technique_name="Exfiltration Over Web Service: Exfiltration to Code Repository",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1567/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exfiltrate data to code repositories such as GitHub, GitLab, "
            "and Bitbucket instead of their primary command and control channels. This "
            "technique leverages API access and HTTPS encryption to blend exfiltration "
            "with legitimate development activity, making detection challenging."
        ),
        attacker_goal="Exfiltrate stolen data through code repository services to evade detection",
        why_technique=[
            "Blends with legitimate developer activity",
            "HTTPS encryption protects data in transit",
            "Repository services rarely blocked in development environments",
            "Large file support via Git LFS",
            "API access simplifies automated exfiltration",
            "Public repositories provide easy adversary access",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Code repository exfiltration is difficult to detect as it closely mimics "
            "legitimate developer workflows. The widespread use of these services in "
            "development environments and HTTPS encryption make this an attractive "
            "technique for adversaries. Data loss can result in significant IP theft "
            "and regulatory violations."
        ),
        business_impact=[
            "Intellectual property and source code theft",
            "Sensitive data exfiltration (credentials, PII, financial data)",
            "Regulatory compliance violations (GDPR, HIPAA)",
            "Reputational damage from data breaches",
            "Potential supply chain compromise",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1552.001", "T1530", "T1005", "T1074"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Git Push Detection
        DetectionStrategy(
            strategy_id="t1567-001-aws-git",
            name="AWS Git Push to External Repositories",
            description="Detect git push operations or repository API calls following sensitive file access.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters, sourceIPAddress
| filter eventName in ["RunCommand", "StartSession"]
| filter requestParameters.commands[0] =~ /git\\s+push|curl.*github|curl.*gitlab|curl.*bitbucket/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect git operations and repository API calls

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

  # Step 2: Metric filter for git/repository operations
  GitPushFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "RunCommand" || $.eventName = "StartSession") && ($.requestParameters.commands[0] = "*git push*" || $.requestParameters.commands[0] = "*github.com*" || $.requestParameters.commands[0] = "*gitlab.com*" || $.requestParameters.commands[0] = "*bitbucket.org*") }'
      MetricTransformations:
        - MetricName: GitRepositoryActivity
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: CloudWatch alarm
  GitPushAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Git-Repository-Exfiltration
      MetricName: GitRepositoryActivity
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect git operations and repository API calls

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "git-repository-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for git/repository operations
resource "aws_cloudwatch_log_metric_filter" "git_push" {
  name           = "git-repository-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"RunCommand\" || $.eventName = \"StartSession\") && ($.requestParameters.commands[0] = \"*git push*\" || $.requestParameters.commands[0] = \"*github.com*\" || $.requestParameters.commands[0] = \"*gitlab.com*\" || $.requestParameters.commands[0] = \"*bitbucket.org*\") }"

  metric_transformation {
    name      = "GitRepositoryActivity"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "git_push" {
  alarm_name          = "Git-Repository-Exfiltration"
  metric_name         = "GitRepositoryActivity"
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
                alert_title="Git Repository Exfiltration Detected",
                alert_description_template="Git push or repository API activity detected from {principalId} at {sourceIPAddress}.",
                investigation_steps=[
                    "Identify the instance and user performing git operations",
                    "Review CloudTrail logs for preceding file access events",
                    "Check repository URL and verify if it's an authorised corporate repository",
                    "Examine the size and nature of data being pushed",
                    "Review user's recent activities and access patterns",
                ],
                containment_actions=[
                    "Revoke the user's credentials immediately",
                    "Block network access to external repository services",
                    "Isolate the affected instance",
                    "Contact repository service to remove potentially exfiltrated data",
                    "Review and restrict SSM/Session Manager permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known developer instances and CI/CD pipelines; exclude corporate repository domains",
            detection_coverage="70% - catches command-based git operations",
            evasion_considerations="Using GUI tools, pre-installed git clients, or direct API calls via Python/curl",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging", "SSM Session Manager logging enabled"],
        ),
        # Strategy 2: AWS - HTTPS POST to Repository APIs
        DetectionStrategy(
            strategy_id="t1567-001-aws-https",
            name="AWS HTTPS POST to Code Repository APIs",
            description="Detect HTTPS POST requests to GitHub/GitLab/Bitbucket APIs following sensitive file reads.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, bytes
| filter dstAddr =~ /api\\.github\\.com|gitlab\\.com|bitbucket\\.org/
| filter action = "ACCEPT"
| stats sum(bytes) as total_bytes, count(*) as requests by srcAddr, bin(5m)
| filter total_bytes > 1048576 or requests > 10
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor HTTPS traffic to code repository APIs

Parameters:
  VPCFlowLogGroup:
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

  # Step 2: Create log metric filter
  RepositoryAPIFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination="*api.github.com*" || destination="*gitlab.com*" || destination="*bitbucket.org*", ...]'
      MetricTransformations:
        - MetricName: RepositoryAPIConnections
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on unusual volume
  RepositoryAPIAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Repository-API-Exfiltration
      MetricName: RepositoryAPIConnections
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Monitor HTTPS traffic to code repository APIs

variable "vpc_flow_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "repository-api-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create log metric filter
resource "aws_cloudwatch_log_metric_filter" "repository_api" {
  name           = "repository-api-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination=\"*api.github.com*\" || destination=\"*gitlab.com*\" || destination=\"*bitbucket.org*\", ...]"

  metric_transformation {
    name      = "RepositoryAPIConnections"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on unusual volume
resource "aws_cloudwatch_metric_alarm" "repository_api" {
  alarm_name          = "Repository-API-Exfiltration"
  metric_name         = "RepositoryAPIConnections"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Code Repository API Activity Detected",
                alert_description_template="High volume HTTPS traffic to repository APIs from {srcAddr}: {requests} requests, {total_bytes} bytes.",
                investigation_steps=[
                    "Identify the source instance generating repository API traffic",
                    "Review VPC Flow Logs for data volume and timing patterns",
                    "Check for correlation with sensitive file access",
                    "Examine instance processes and running applications",
                    "Verify if instance should have legitimate repository access",
                ],
                containment_actions=[
                    "Isolate the source instance",
                    "Block repository API domains at security group/NACL level",
                    "Terminate suspicious processes",
                    "Review and rotate any exposed credentials",
                    "Implement web proxy for repository access control",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD servers and developer workstations; adjust byte threshold for environment",
            detection_coverage="75% - catches HTTPS-based repository uploads",
            evasion_considerations="Low and slow exfiltration, using corporate proxies",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "DNS resolution logging"],
        ),
        # Strategy 3: AWS - File Archive Before Repository Upload
        DetectionStrategy(
            strategy_id="t1567-001-aws-archive",
            name="AWS File Packaging Before Repository Upload",
            description="Detect file archiving (tar, gzip, zip) followed by repository API uploads.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.commands
| filter eventName = "SendCommand"
| filter requestParameters.commands[0] =~ /tar|gzip|zip|7z/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect file archiving before repository uploads

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

  # Step 2: EventBridge rule for archiving commands
  ArchiveCommandRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ssm]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [SendCommand]
          requestParameters:
            commands:
              - prefix: tar
              - prefix: gzip
              - prefix: zip
              - prefix: 7z
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

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
                aws:SourceArn: !GetAtt ArchiveCommandRule.Arn""",
                terraform_template="""# Detect file archiving before repository uploads

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "file-archive-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for archiving commands
resource "aws_cloudwatch_event_rule" "archive_command" {
  name = "file-archiving-detected"
  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand"]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "file-archive-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.archive_command.name
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.archive_command.arn
        }
      }
    }]
  })
}

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
            "aws:SourceArn" = aws_cloudwatch_event_rule.archive_command.arn
          }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="File Archiving Activity Detected",
                alert_description_template="File archiving command executed by {principalId}: {commands}",
                investigation_steps=[
                    "Review the archiving command and target files",
                    "Check for subsequent repository API calls",
                    "Identify files being archived (sensitive data?)",
                    "Verify if this is part of legitimate backup operations",
                    "Check timing (outside business hours is suspicious)",
                ],
                containment_actions=[
                    "Monitor for follow-up exfiltration attempts",
                    "Review and delete any created archives",
                    "Restrict SSM command execution permissions",
                    "Enable file integrity monitoring on sensitive directories",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist scheduled backup jobs; correlate with repository uploads to reduce noise",
            detection_coverage="60% - catches archive-based staging",
            evasion_considerations="Direct file uploads without archiving",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging", "SSM enabled"],
        ),
        # Strategy 4: GCP - Repository API Detection
        DetectionStrategy(
            strategy_id="t1567-001-gcp-api",
            name="GCP Repository API Upload Detection",
            description="Detect HTTPS POST requests to GitHub/GitLab/Bitbucket APIs from GCP instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
jsonPayload.connection.dest_ip=~"api\\.github\\.com|gitlab\\.com|bitbucket\\.org"
jsonPayload.bytes_sent > 1048576""",
                gcp_terraform_template="""# GCP: Detect repository API uploads

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

# Step 2: Log-based metric for repository API traffic
resource "google_logging_metric" "repo_api" {
  project = var.project_id
  name   = "repository-api-uploads"
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.connection.dest_ip=~"api\\.github\\.com|gitlab\\.com|bitbucket\\.org"
    jsonPayload.bytes_sent > 1048576
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "repo_upload" {
  project      = var.project_id
  display_name = "Code Repository Upload Detected"
  combiner     = "OR"

  conditions {
    display_name = "Repository API upload activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.repo_api.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
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
                alert_title="GCP: Code Repository Upload Detected",
                alert_description_template="Large data upload to repository API detected from GCP instance.",
                investigation_steps=[
                    "Identify the source GCE instance",
                    "Review VPC Flow Logs for connection details",
                    "Check for sensitive file access preceding the upload",
                    "Verify if instance should have repository access",
                    "Examine instance metadata and service accounts",
                ],
                containment_actions=[
                    "Isolate the instance via VPC firewall rules",
                    "Stop the instance if necessary",
                    "Revoke service account credentials",
                    "Block repository API domains in Cloud Armor/firewall",
                    "Review and rotate any exposed secrets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist Cloud Build workers and development instances; adjust byte threshold",
            detection_coverage="75% - catches repository API uploads",
            evasion_considerations="Using Cloud NAT to obscure source, slow uploads over time",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging enabled"],
        ),
        # Strategy 5: GCP - Git Command Detection
        DetectionStrategy(
            strategy_id="t1567-001-gcp-git",
            name="GCP Git Command Execution Detection",
            description="Detect git push commands executed on GCP instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="RunCommand"
protoPayload.request.command=~"git\\s+push|curl.*github|curl.*gitlab|curl.*bitbucket"''',
                gcp_terraform_template="""# GCP: Detect git command execution

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

# Step 2: Log-based metric for git commands
resource "google_logging_metric" "git_commands" {
  project = var.project_id
  name   = "git-command-execution"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="RunCommand"
    protoPayload.request.command=~"git\\s+push|curl.*github|curl.*gitlab|curl.*bitbucket"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "git_push" {
  project      = var.project_id
  display_name = "Git Repository Exfiltration"
  combiner     = "OR"

  conditions {
    display_name = "Git push or repository API command"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.git_commands.name}\""
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
                alert_title="GCP: Git Repository Command Detected",
                alert_description_template="Git push or repository API command executed on GCP instance.",
                investigation_steps=[
                    "Identify the instance and user executing git commands",
                    "Review command details and target repository",
                    "Check for sensitive file access before git push",
                    "Verify if repository is corporate-owned",
                    "Examine user's role and authorised activities",
                ],
                containment_actions=[
                    "Disable the service account or user credentials",
                    "Isolate the instance",
                    "Review and remove any pushed sensitive data",
                    "Restrict OS Login and SSH access",
                    "Implement application-level controls for git operations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist Cloud Build and CI/CD instances; exclude corporate repository domains",
            detection_coverage="70% - catches command-based git operations",
            evasion_considerations="Using GUI tools, pre-configured git clients",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Logging enabled", "OS Login or SSH logging enabled"],
        ),
    ],
    recommended_order=[
        "t1567-001-aws-git",
        "t1567-001-aws-https",
        "t1567-001-gcp-api",
        "t1567-001-gcp-git",
        "t1567-001-aws-archive",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+18% improvement for Exfiltration tactic",
)
