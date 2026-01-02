"""
T1491.001 - Defacement: Internal Defacement

Adversaries modify systems within an organisation to intimidate or mislead users.
Includes altering internal websites, changing server login messages, or replacing desktop wallpapers.
Used by Black Basta, BlackCat, Lazarus Group, Gamaredon Group.
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
    technique_id="T1491.001",
    technique_name="Defacement: Internal Defacement",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1491/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify systems within an organisation to intimidate or mislead users "
            "and undermine system integrity. Methods include altering internal websites, changing "
            "server login messages, replacing desktop wallpapers, or modifying cloud-hosted web "
            "applications. The technique may involve disturbing or offensive images to cause "
            "discomfort or pressure compliance. Internal defacement typically occurs after primary "
            "intrusion objectives are achieved, as it exposes attacker presence."
        ),
        attacker_goal="Intimidate users, demonstrate control, or pressure ransom payment",
        why_technique=[
            "Psychological pressure on victims",
            "Demonstrates attacker control",
            "Often used in ransomware campaigns",
            "Forces acknowledgement of breach",
            "Can disrupt business operations",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "High psychological impact and business disruption. While not directly destructive, "
            "internal defacement signals full system compromise and often accompanies ransomware. "
            "Can severely damage organisational morale and customer confidence."
        ),
        business_impact=[
            "Employee intimidation and fear",
            "Loss of system confidence",
            "Business operations disruption",
            "Reputational damage if publicised",
            "Often precedes or accompanies ransomware",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1486", "T1485", "T1078.001"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1491-001-aws-s3-web",
            name="AWS S3 Static Website Modification Detection",
            description="Detect unauthorised modifications to S3-hosted static websites.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName, requestParameters.key, userIdentity.arn
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutObject", "DeleteObject", "PutBucketWebsite"]
| filter requestParameters.bucketName like /website|www|static/
| filter requestParameters.key like /index.html|login|home|banner/
| stats count(*) as modifications by userIdentity.arn, requestParameters.bucketName, bin(5m)
| filter modifications > 5
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 website defacement attempts

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
      KmsMasterKeyId: alias/aws/sns
      DisplayName: S3 Website Defacement Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  WebsiteModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "s3.amazonaws.com") && ($.eventName = "PutObject" || $.eventName = "DeleteObject" || $.eventName = "PutBucketWebsite") && ($.requestParameters.key = "*index.html*" || $.requestParameters.key = "*login*" || $.requestParameters.key = "*home*") }'
      MetricTransformations:
        - MetricName: S3WebsiteModifications
          MetricNamespace: Security/Defacement
          MetricValue: "1"

  WebsiteModificationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3-Website-Defacement-Alert
      AlarmDescription: Detects potential S3 website defacement
      MetricName: S3WebsiteModifications
      Namespace: Security/Defacement
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
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
                terraform_template="""# AWS: Detect S3 website defacement

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "aws_sns_topic" "defacement_alerts" {
  name         = "s3-website-defacement-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "S3 Website Defacement Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.defacement_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "website_modifications" {
  name           = "s3-website-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.eventName = \"PutObject\" || $.eventName = \"DeleteObject\" || $.eventName = \"PutBucketWebsite\") && ($.requestParameters.key = \"*index.html*\" || $.requestParameters.key = \"*login*\" || $.requestParameters.key = \"*home*\") }"

  metric_transformation {
    name      = "S3WebsiteModifications"
    namespace = "Security/Defacement"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "website_defacement" {
  alarm_name          = "S3-Website-Defacement-Alert"
  alarm_description   = "Detects potential S3 website defacement"
  metric_name         = "S3WebsiteModifications"
  namespace           = "Security/Defacement"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.defacement_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.defacement_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.defacement_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Potential S3 Website Defacement",
                alert_description_template="Multiple modifications to S3-hosted website files by {userIdentity.arn} in bucket {requestParameters.bucketName}.",
                investigation_steps=[
                    "Review the modified files in S3",
                    "Check if changes were authorised through change management",
                    "Compare current content with previous versions",
                    "Identify the user/role that made changes",
                    "Review CloudTrail for associated suspicious activity",
                    "Check for ransom notes or offensive content",
                ],
                containment_actions=[
                    "Immediately revoke the compromised credentials",
                    "Restore website files from backups or S3 versioning",
                    "Enable MFA delete on the bucket",
                    "Review and restrict bucket policies",
                    "Enable S3 Object Lock if not already enabled",
                    "Document defacement for incident response",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known CI/CD roles and deployment windows. Adjust threshold based on normal deployment frequency.",
            detection_coverage="75% - catches S3 website modifications, misses EC2-hosted sites",
            evasion_considerations="Attacker may use legitimate deployment pipelines or modify non-critical pages first",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=[
                "CloudTrail S3 data events enabled",
                "S3 versioning enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1491-001-aws-ec2-web",
            name="AWS EC2 Web Server File Modification Detection",
            description="Detect unauthorised file modifications on EC2 instances hosting web applications.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @message like /WRITE|CLOSE_WRITE|MODIFY/
| filter @message like /index.html|login.html|index.php|default.aspx|banner/
| stats count(*) as file_changes by bin(5m)
| filter file_changes > 10
| sort @timestamp desc""",
                terraform_template="""# AWS: Detect EC2 web file modifications
# Requires installation of file integrity monitoring agent

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "web_server_log_group" {
  type        = string
  description = "CloudWatch log group for web server file monitoring"
  default     = "/aws/ec2/file-integrity"
}

resource "aws_sns_topic" "file_modification_alerts" {
  name         = "ec2-web-defacement-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "EC2 Web Server Defacement Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.file_modification_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "web_file_changes" {
  name           = "ec2-web-file-modifications"
  log_group_name = var.web_server_log_group
  pattern        = "[time, event=WRITE||CLOSE_WRITE||MODIFY, file=*index.html*||*login.html*||*index.php*||*default.aspx*]"

  metric_transformation {
    name      = "WebFileModifications"
    namespace = "Security/Defacement"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "web_defacement" {
  alarm_name          = "EC2-Web-Defacement-Alert"
  alarm_description   = "Detects potential web server defacement"
  metric_name         = "WebFileModifications"
  namespace           = "Security/Defacement"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.file_modification_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.file_modification_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.file_modification_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

# Note: Requires file integrity monitoring agent on EC2 instances
# Example: auditd, OSSEC, or CloudWatch agent with file monitoring""",
                alert_severity="high",
                alert_title="Potential EC2 Web Server Defacement",
                alert_description_template="High volume of web file modifications detected on EC2 instances.",
                investigation_steps=[
                    "Identify affected EC2 instance(s)",
                    "Review modified files for defacement",
                    "Check SSH/RDP access logs",
                    "Review running processes on the instance",
                    "Check for unauthorised user accounts",
                    "Examine web server access logs",
                ],
                containment_actions=[
                    "Isolate affected instances from network",
                    "Restore files from known good backups",
                    "Terminate compromised instances if necessary",
                    "Deploy fresh instances from golden AMI",
                    "Review security group rules",
                    "Rotate all credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude deployment times and automated update processes. Whitelist known administrative activities.",
            detection_coverage="70% - requires file integrity monitoring deployment",
            evasion_considerations="Attacker may disable monitoring agents or modify files during legitimate maintenance windows",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$10-20 (includes agent costs)",
            prerequisites=[
                "File integrity monitoring agent installed",
                "CloudWatch agent configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1491-001-gcp-storage-web",
            name="GCP Cloud Storage Website Modification Detection",
            description="Detect unauthorised modifications to GCP Storage-hosted websites.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gcs_bucket"
protoPayload.methodName=~"storage.objects.(create|update|delete|patch)"
(protoPayload.resourceName=~"index.html" OR protoPayload.resourceName=~"login" OR protoPayload.resourceName=~"home" OR protoPayload.resourceName=~"banner")""",
                gcp_terraform_template="""# GCP: Detect Cloud Storage website defacement

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "website_modifications" {
  name   = "storage-website-modifications"
  project = var.project_id
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName=~"storage.objects.(create|update|delete|patch)"
    (protoPayload.resourceName=~"index.html" OR
     protoPayload.resourceName=~"login" OR
     protoPayload.resourceName=~"home" OR
     protoPayload.resourceName=~"banner")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "bucket_name"
      value_type  = "STRING"
      description = "Affected bucket"
    }
  }

  label_extractors = {
    bucket_name = "EXTRACT(resource.labels.bucket_name)"
  }
}

resource "google_monitoring_alert_policy" "website_defacement" {
  project      = var.project_id
  display_name = "GCP Storage Website Defacement Alert"
  combiner     = "OR"

  conditions {
    display_name = "High volume of website file modifications"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.website_modifications.name}\" resource.type=\"gcs_bucket\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
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
}""",
                alert_severity="high",
                alert_title="GCP: Potential Cloud Storage Website Defacement",
                alert_description_template="Multiple modifications to website files in Cloud Storage bucket.",
                investigation_steps=[
                    "Review modified objects in Cloud Storage",
                    "Check object versions for unauthorised changes",
                    "Identify the principal that made changes",
                    "Review Cloud Audit Logs for related activity",
                    "Compare current content with previous versions",
                    "Check for ransom notes or malicious content",
                ],
                containment_actions=[
                    "Revoke compromised service account credentials",
                    "Restore objects from versioning or backups",
                    "Review and restrict bucket IAM policies",
                    "Enable retention policies on critical buckets",
                    "Review organisation-wide IAM bindings",
                    "Document incident for security review",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known deployment service accounts. Adjust threshold based on deployment patterns.",
            detection_coverage="75% - catches Cloud Storage modifications, misses GCE-hosted sites",
            evasion_considerations="Attacker may use legitimate CI/CD pipelines or modify less-monitored files",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled", "Object versioning enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1491-001-gcp-gce-web",
            name="GCP Compute Engine Web Application Modification",
            description="Detect unauthorised changes to web applications on GCE instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(protoPayload.methodName="v1.compute.instances.setMetadata" OR
 protoPayload.methodName="beta.compute.instances.updateAccessConfig")
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Detect GCE instance configuration changes
# For file-level monitoring, deploy agents to instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "instance_modifications" {
  name    = "gce-instance-modifications"
  project = var.project_id
  filter  = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName="v1.compute.instances.setMetadata" OR
     protoPayload.methodName="beta.compute.instances.updateAccessConfig")
    severity>=WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "instance_changes" {
  project      = var.project_id
  display_name = "GCE Instance Suspicious Modifications"
  combiner     = "OR"

  conditions {
    display_name = "Instance configuration changed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.instance_modifications.name}\" resource.type=\"gce_instance\""
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
}

# Note: For file-level monitoring, deploy Cloud Monitoring agent
# with file integrity monitoring configuration""",
                alert_severity="medium",
                alert_title="GCP: GCE Instance Configuration Changed",
                alert_description_template="Compute Engine instance configuration was modified.",
                investigation_steps=[
                    "Identify the modified instance",
                    "Review metadata and configuration changes",
                    "Check who made the modifications",
                    "Review SSH access logs",
                    "Inspect running web applications",
                    "Check for unauthorised network exposure",
                ],
                containment_actions=[
                    "Snapshot the instance for forensics",
                    "Isolate instance from network if compromised",
                    "Restore from known good snapshot",
                    "Review firewall rules and IAM permissions",
                    "Rotate service account keys",
                    "Deploy fresh instances from trusted images",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude infrastructure-as-code deployments and automated scaling events.",
            detection_coverage="60% - catches instance-level changes, requires agent for file monitoring",
            evasion_considerations="File-level changes require additional monitoring agents",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$8-15",
            prerequisites=["Cloud Audit Logs enabled", "Instance snapshots configured"],
        ),
    ],
    recommended_order=[
        "t1491-001-aws-s3-web",
        "t1491-001-gcp-storage-web",
        "t1491-001-aws-ec2-web",
        "t1491-001-gcp-gce-web",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+18% improvement for Impact tactic",
)
