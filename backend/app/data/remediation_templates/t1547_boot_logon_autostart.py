"""
T1547 - Boot or Logon Autostart Execution

Adversaries configure system settings to automatically execute programs during system
boot or logon to maintain persistence. In cloud environments, this includes modifying
startup scripts, user data, launch configurations, and container initialisation processes.
Used by APT42, BoxCaon, Dtrack, Mis-Type, Misdat, and xCaon.
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
    technique_id="T1547",
    technique_name="Boot or Logon Autostart Execution",
    tactic_ids=["TA0003", "TA0004"],  # Persistence, Privilege Escalation
    mitre_url="https://attack.mitre.org/techniques/T1547/",
    threat_context=ThreatContext(
        description=(
            "Adversaries configure system settings to automatically execute programs during "
            "system boot or logon to maintain persistence or gain higher-level privileges. "
            "In cloud environments, this includes modifying EC2 user data, launch templates, "
            "container startup configurations, VM startup scripts, and service account "
            "configurations to ensure malicious code executes automatically."
        ),
        attacker_goal="Maintain persistent execution by configuring automatic program execution at boot or logon",
        why_technique=[
            "Survives instance reboots and auto-scaling events",
            "Executes with system-level or elevated privileges",
            "Difficult to detect without baseline monitoring",
            "Blends with legitimate startup configurations",
            "Persists across container restarts and deployments",
            "Enables long-term access to cloud resources",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "High risk due to ability to maintain persistent access with automatic re-execution "
            "across reboots and scaling events. Commonly used for cryptomining, backdoor "
            "persistence, and establishing long-term footholds. Particularly dangerous in "
            "cloud environments with auto-scaling where persistence mechanisms propagate."
        ),
        business_impact=[
            "Persistent unauthorised access across reboots",
            "Privilege escalation opportunities",
            "Cryptomining resource abuse",
            "Backdoor re-establishment after remediation",
            "Data exfiltration infrastructure",
            "Auto-scaling propagation of compromise",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1496.001", "T1053", "T1059.009"],
        often_follows=["T1078.004", "T1190", "T1068", "T1611"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1547-aws-ec2-userdata",
            name="AWS EC2 User Data Modification Detection",
            description="Detect modifications to EC2 instance user data that could establish persistence via boot execution.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.instanceId, requestParameters.userData
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "ModifyInstanceAttribute" or eventName = "RunInstances"
| filter requestParameters.userData like /curl|wget|bash|python|sh|cron|systemd/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 user data modifications for persistence

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

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
                AWS:SourceAccount: !Ref AWS::AccountId

  # Detect user data modifications
  UserDataModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "ModifyInstanceAttribute") || ($.eventName = "RunInstances") }'
      MetricTransformations:
        - MetricName: EC2UserDataModifications
          MetricNamespace: Security
          MetricValue: "1"

  UserDataModificationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousEC2UserDataModification
      MetricName: EC2UserDataModifications
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 2
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]
      AlarmDescription: Detects modifications to EC2 user data""",
                terraform_template="""# Detect EC2 user data modifications for persistence

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "ec2-userdata-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for user data changes
resource "aws_cloudwatch_log_metric_filter" "userdata_mod" {
  name           = "ec2-userdata-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = ModifyInstanceAttribute) || ($.eventName = RunInstances) }"

  metric_transformation {
    name      = "EC2UserDataModifications"
    namespace = "Security"
    value     = "1"
  }
}

# Alert on suspicious modifications
resource "aws_cloudwatch_metric_alarm" "userdata_mod" {
  alarm_name          = "SuspiciousEC2UserDataModification"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EC2UserDataModifications"
  namespace           = "Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 2
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects modifications to EC2 user data for persistence"
}""",
                alert_severity="high",
                alert_title="Suspicious EC2 User Data Modification",
                alert_description_template="EC2 user data modified for instance {instanceId} by {principalId}.",
                investigation_steps=[
                    "Review user data content for suspicious commands",
                    "Check for download commands (curl, wget)",
                    "Verify modification was authorised",
                    "Review principal's recent activity",
                    "Check for malicious scripts or backdoors",
                    "Inspect startup scripts for persistence mechanisms",
                ],
                containment_actions=[
                    "Remove malicious user data scripts",
                    "Terminate compromised instances",
                    "Revoke unauthorised EC2 permissions",
                    "Implement launch template approval workflow",
                    "Enable IMDSv2 to prevent metadata abuse",
                    "Review and restrict IAM roles",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised CI/CD pipelines and deployment automation tools",
            detection_coverage="75% - catches user data modifications",
            evasion_considerations="Attackers may use base64 encoding or obfuscation in user data",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs Insights"],
        ),
        DetectionStrategy(
            strategy_id="t1547-aws-launch-template",
            name="AWS Launch Template Modification Detection",
            description="Detect modifications to EC2 launch templates that could establish persistence.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.launchTemplateName, responseElements.launchTemplateVersion
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "CreateLaunchTemplateVersion" or eventName = "ModifyLaunchTemplate"
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 launch template modifications

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

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
                AWS:SourceAccount: !Ref AWS::AccountId

  # Detect launch template changes
  LaunchTemplateFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "CreateLaunchTemplateVersion") || ($.eventName = "ModifyLaunchTemplate") }'
      MetricTransformations:
        - MetricName: LaunchTemplateModifications
          MetricNamespace: Security
          MetricValue: "1"

  LaunchTemplateAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousLaunchTemplateModification
      MetricName: LaunchTemplateModifications
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 2
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect EC2 launch template modifications

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "launch-template-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for launch template changes
resource "aws_cloudwatch_log_metric_filter" "launch_template" {
  name           = "launch-template-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = CreateLaunchTemplateVersion) || ($.eventName = ModifyLaunchTemplate) }"

  metric_transformation {
    name      = "LaunchTemplateModifications"
    namespace = "Security"
    value     = "1"
  }
}

# Alert on modifications
resource "aws_cloudwatch_metric_alarm" "launch_template" {
  alarm_name          = "SuspiciousLaunchTemplateModification"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "LaunchTemplateModifications"
  namespace           = "Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 2
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects launch template modifications"
}""",
                alert_severity="high",
                alert_title="Suspicious Launch Template Modification",
                alert_description_template="Launch template {launchTemplateName} modified by {principalId}.",
                investigation_steps=[
                    "Compare new version with previous versions",
                    "Check user data in launch template",
                    "Verify modification was authorised",
                    "Review auto-scaling groups using this template",
                    "Check for malicious startup scripts",
                    "Inspect IAM roles and security groups",
                ],
                containment_actions=[
                    "Revert to previous launch template version",
                    "Update auto-scaling groups to use clean template",
                    "Revoke unauthorised EC2 permissions",
                    "Implement change approval workflow",
                    "Review all instances launched from template",
                    "Terminate compromised instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised infrastructure teams and CI/CD systems",
            detection_coverage="80% - catches launch template modifications",
            evasion_considerations="Attackers may modify incrementally to avoid detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs"],
        ),
        DetectionStrategy(
            strategy_id="t1547-aws-asg-config",
            name="AWS Auto Scaling Group Configuration Changes",
            description="Detect modifications to Auto Scaling Group configurations that could propagate persistence.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.autoScalingGroupName, requestParameters.launchTemplate
| filter eventSource = "autoscaling.amazonaws.com"
| filter eventName = "UpdateAutoScalingGroup" or eventName = "CreateAutoScalingGroup"
| sort @timestamp desc""",
                terraform_template="""# Detect Auto Scaling Group configuration changes

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "asg-config-change-alerts"
  kms_master_key_id = "alias/aws/sns"
}

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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for ASG changes
resource "aws_cloudwatch_log_metric_filter" "asg_config" {
  name           = "asg-configuration-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = UpdateAutoScalingGroup) || ($.eventName = CreateAutoScalingGroup) }"

  metric_transformation {
    name      = "ASGConfigurationChanges"
    namespace = "Security"
    value     = "1"
  }
}

# Alert on ASG changes
resource "aws_cloudwatch_metric_alarm" "asg_config" {
  alarm_name          = "SuspiciousASGConfigChange"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ASGConfigurationChanges"
  namespace           = "Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects Auto Scaling Group configuration changes"
}""",
                alert_severity="high",
                alert_title="Auto Scaling Group Configuration Changed",
                alert_description_template="ASG {autoScalingGroupName} configuration modified by {principalId}.",
                investigation_steps=[
                    "Review launch template or configuration changes",
                    "Check for new instances launched with modified config",
                    "Verify modification was authorised",
                    "Review user data in associated templates",
                    "Check scaling policies and triggers",
                    "Inspect recently launched instances",
                ],
                containment_actions=[
                    "Revert ASG to previous configuration",
                    "Terminate instances launched with modified config",
                    "Suspend auto-scaling activities temporarily",
                    "Revoke unauthorised ASG permissions",
                    "Implement configuration change approval",
                    "Review all ASG-launched instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist scheduled scaling operations and authorised DevOps tools",
            detection_coverage="75% - catches ASG configuration changes",
            evasion_considerations="Changes may appear as legitimate scaling operations",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1547-aws-ssm-run-command",
            name="AWS Systems Manager Run Command Persistence Detection",
            description="Detect use of SSM Run Command to configure startup persistence on instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.documentName, requestParameters.instanceIds.0
| filter eventSource = "ssm.amazonaws.com"
| filter eventName = "SendCommand"
| filter requestParameters.documentName like /cron|systemd|rc.local|init.d|startup/
| sort @timestamp desc""",
                terraform_template="""# Detect SSM Run Command for persistence

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "ssm-persistence-alerts"
  kms_master_key_id = "alias/aws/sns"
}

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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for SSM commands
resource "aws_cloudwatch_log_metric_filter" "ssm_persistence" {
  name           = "ssm-persistence-commands"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = SendCommand) }"

  metric_transformation {
    name      = "SSMPersistenceCommands"
    namespace = "Security"
    value     = "1"
  }
}

# Alert on suspicious SSM commands
resource "aws_cloudwatch_metric_alarm" "ssm_persistence" {
  alarm_name          = "SuspiciousSSMPersistenceCommand"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SSMPersistenceCommands"
  namespace           = "Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects SSM Run Command for persistence"
}""",
                alert_severity="high",
                alert_title="SSM Run Command Persistence Detected",
                alert_description_template="SSM command {documentName} executed on instances by {principalId}.",
                investigation_steps=[
                    "Review SSM command document content",
                    "Check command parameters and targets",
                    "Verify command execution was authorised",
                    "Review command output and results",
                    "Check affected instances for persistence",
                    "Inspect cron jobs and systemd services",
                ],
                containment_actions=[
                    "Terminate unauthorised SSM commands",
                    "Remove persistence mechanisms from instances",
                    "Revoke excessive SSM permissions",
                    "Review and clean affected instances",
                    "Implement command approval workflow",
                    "Enable SSM Session Manager logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised configuration management and patching operations",
            detection_coverage="70% - catches SSM-based persistence",
            evasion_considerations="Legitimate-looking commands may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "SSM logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1547-gcp-startup-script",
            name="GCP Compute Engine Startup Script Modification",
            description="Detect modifications to VM instance startup scripts that could establish persistence.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="compute.googleapis.com"
(protoPayload.methodName="v1.compute.instances.insert" OR
 protoPayload.methodName="v1.compute.instances.setMetadata")
protoPayload.request.metadata.items.key="startup-script"''',
                gcp_terraform_template="""# GCP: Detect startup script modifications

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for startup script changes
resource "google_logging_metric" "startup_script" {
  project = var.project_id
  name   = "startup-script-modifications"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName="v1.compute.instances.insert" OR
     protoPayload.methodName="v1.compute.instances.setMetadata")
    protoPayload.request.metadata.items.key="startup-script"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_name"
      value_type  = "STRING"
      description = "Instance name"
    }
  }
  label_extractors = {
    "instance_name" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for startup script changes
resource "google_monitoring_alert_policy" "startup_script" {
  project      = var.project_id
  display_name = "Suspicious Startup Script Modification"
  combiner     = "OR"
  conditions {
    display_name = "Startup script modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.startup_script.name}\""
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
  documentation {
    content   = "VM startup script modification detected. Review script content for persistence mechanisms."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Startup Script Modified",
                alert_description_template="VM startup script modification detected.",
                investigation_steps=[
                    "Review startup script content",
                    "Check for download commands (curl, wget)",
                    "Verify modification was authorised",
                    "Review instance metadata",
                    "Check for malicious commands or backdoors",
                    "Inspect shutdown scripts as well",
                ],
                containment_actions=[
                    "Remove malicious startup scripts",
                    "Stop and delete compromised instances",
                    "Update instance templates with clean scripts",
                    "Revoke unauthorised Compute permissions",
                    "Implement metadata change approval",
                    "Review all instances from same template",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised deployment pipelines and infrastructure automation",
            detection_coverage="80% - catches startup script modifications",
            evasion_considerations="Scripts may be obfuscated or base64 encoded",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1547-gcp-instance-template",
            name="GCP Instance Template Modification Detection",
            description="Detect modifications to instance templates that could propagate persistence across deployments.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName="v1.compute.instanceTemplates.insert"''',
                gcp_terraform_template="""# GCP: Detect instance template modifications

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for instance template changes
resource "google_logging_metric" "instance_template" {
  project = var.project_id
  name   = "instance-template-modifications"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    protoPayload.methodName="v1.compute.instanceTemplates.insert"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "template_name"
      value_type  = "STRING"
      description = "Template name"
    }
  }
  label_extractors = {
    "template_name" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for template changes
resource "google_monitoring_alert_policy" "instance_template" {
  project      = var.project_id
  display_name = "Instance Template Created or Modified"
  combiner     = "OR"
  conditions {
    display_name = "New instance template detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.instance_template.name}\""
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
  documentation {
    content   = "Instance template modification detected. Review template configuration for persistence mechanisms."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Instance Template Modified",
                alert_description_template="Instance template modification detected.",
                investigation_steps=[
                    "Review template metadata and startup scripts",
                    "Check instance groups using this template",
                    "Verify template creation was authorised",
                    "Review service accounts and scopes",
                    "Check for malicious configurations",
                    "Inspect recently created instances",
                ],
                containment_actions=[
                    "Delete unauthorised instance templates",
                    "Update instance groups to use clean templates",
                    "Terminate instances from compromised templates",
                    "Revoke unauthorised template permissions",
                    "Implement template approval workflow",
                    "Review all deployments using template",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised infrastructure teams and deployment systems",
            detection_coverage="75% - catches template modifications",
            evasion_considerations="Templates may look legitimate until deployed",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1547-gcp-managed-instance-group",
            name="GCP Managed Instance Group Configuration Changes",
            description="Detect modifications to Managed Instance Groups that could propagate persistence.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="compute.googleapis.com"
(protoPayload.methodName=~"instanceGroupManagers.insert" OR
 protoPayload.methodName=~"instanceGroupManagers.patch" OR
 protoPayload.methodName=~"instanceGroupManagers.setInstanceTemplate")""",
                gcp_terraform_template="""# GCP: Detect Managed Instance Group changes

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s3" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for MIG changes
resource "google_logging_metric" "mig_changes" {
  project = var.project_id
  name   = "managed-instance-group-changes"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName=~"instanceGroupManagers.insert" OR
     protoPayload.methodName=~"instanceGroupManagers.patch" OR
     protoPayload.methodName=~"instanceGroupManagers.setInstanceTemplate")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "group_name"
      value_type  = "STRING"
      description = "Instance group name"
    }
  }
  label_extractors = {
    "group_name" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for MIG changes
resource "google_monitoring_alert_policy" "mig_changes" {
  project      = var.project_id
  display_name = "Managed Instance Group Configuration Changed"
  combiner     = "OR"
  conditions {
    display_name = "MIG configuration modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.mig_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s3.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
  documentation {
    content   = "Managed Instance Group configuration changed. Review template and instances for persistence."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Managed Instance Group Modified",
                alert_description_template="Managed Instance Group configuration changed.",
                investigation_steps=[
                    "Review instance template changes",
                    "Check instances launched after modification",
                    "Verify modification was authorised",
                    "Review auto-scaling policies",
                    "Check startup scripts in template",
                    "Inspect recently created instances",
                ],
                containment_actions=[
                    "Revert to previous instance template",
                    "Delete instances from compromised template",
                    "Suspend auto-scaling temporarily",
                    "Revoke unauthorised MIG permissions",
                    "Implement configuration change approval",
                    "Review all MIG instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist scheduled operations and authorised deployment tools",
            detection_coverage="75% - catches MIG configuration changes",
            evasion_considerations="Changes may appear as legitimate scaling operations",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1547-gcp-os-login",
            name="GCP OS Login SSH Key Addition Detection",
            description="Detect SSH public key additions via OS Login that could establish persistent access.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="oslogin.googleapis.com"
protoPayload.methodName="google.cloud.oslogin.v1.OsLoginService.ImportSshPublicKey"''',
                gcp_terraform_template="""# GCP: Detect OS Login SSH key additions

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s4" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for SSH key additions
resource "google_logging_metric" "ssh_key_add" {
  project = var.project_id
  name   = "os-login-ssh-key-additions"
  filter = <<-EOT
    protoPayload.serviceName="oslogin.googleapis.com"
    protoPayload.methodName="google.cloud.oslogin.v1.OsLoginService.ImportSshPublicKey"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user_email"
      value_type  = "STRING"
      description = "User adding SSH key"
    }
  }
  label_extractors = {
    "user_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Alert policy for SSH key additions
resource "google_monitoring_alert_policy" "ssh_key_add" {
  project      = var.project_id
  display_name = "SSH Key Added via OS Login"
  combiner     = "OR"
  conditions {
    display_name = "New SSH key imported"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ssh_key_add.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 1
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s4.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
  documentation {
    content   = "SSH public key imported via OS Login. Verify authorisation and review for persistence."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: SSH Key Added via OS Login",
                alert_description_template="SSH public key imported via OS Login.",
                investigation_steps=[
                    "Review SSH key fingerprint and metadata",
                    "Verify user authorisation for key addition",
                    "Check for subsequent SSH connections",
                    "Review user's recent activity",
                    "Check if key is used across multiple projects",
                    "Inspect for unauthorised access patterns",
                ],
                containment_actions=[
                    "Remove unauthorised SSH keys",
                    "Revoke compromised user access",
                    "Enable 2FA for OS Login",
                    "Review all SSH keys for user",
                    "Implement key approval process",
                    "Monitor SSH access patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Normal for developers adding their SSH keys, baseline per user",
            detection_coverage="85% - catches SSH key additions",
            evasion_considerations="Legitimate operation, hard to distinguish malicious intent",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled", "OS Login enabled"],
        ),
        # Azure Strategy: Boot or Logon Autostart Execution
        DetectionStrategy(
            strategy_id="t1547-azure",
            name="Azure Boot or Logon Autostart Execution Detection",
            description=(
                "Azure detection for Boot or Logon Autostart Execution. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Boot or Logon Autostart Execution (T1547)
# Microsoft Defender detects Boot or Logon Autostart Execution activity

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

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
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
  name                = "defender-t1547-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1547"
  resource_group_name = var.resource_group_name
  location            = var.location

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

  description = "Microsoft Defender detects Boot or Logon Autostart Execution activity"
  display_name = "Defender: Boot or Logon Autostart Execution"
  enabled      = true

  tags = {
    "mitre-technique" = "T1547"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Boot or Logon Autostart Execution Detected",
                alert_description_template=(
                    "Boot or Logon Autostart Execution activity detected. "
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
        "t1547-aws-ec2-userdata",  # Most common AWS persistence
        "t1547-aws-launch-template",  # Template-based propagation
        "t1547-gcp-startup-script",  # Most common GCP persistence
        "t1547-aws-asg-config",  # Auto-scaling persistence
        "t1547-gcp-instance-template",  # GCP template propagation
        "t1547-gcp-managed-instance-group",  # GCP auto-scaling
        "t1547-aws-ssm-run-command",  # SSM-based persistence
        "t1547-gcp-os-login",  # SSH key persistence
    ],
    total_effort_hours=9.0,
    coverage_improvement="+12% improvement for Persistence and Privilege Escalation tactics",
)
