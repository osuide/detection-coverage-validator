"""
T1072 - Software Deployment Tools

Adversaries exploit centralised software deployment suites to execute commands and move
across enterprise networks. Includes SCCM, AWS Systems Manager, GCP Deployment Manager,
Intune, PDQ Deploy, and similar tools.
Used by APT32, Sandworm Team, Mustang Panda, Threat Group-1314.
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
    technique_id="T1072",
    technique_name="Software Deployment Tools",
    tactic_ids=["TA0002", "TA0008"],  # Execution, Lateral Movement
    mitre_url="https://attack.mitre.org/techniques/T1072/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit centralised software deployment suites to achieve "
            "network-wide code execution and lateral movement. These legitimate administrative "
            "tools—including SCCM, AWS Systems Manager, Microsoft Intune, Azure Arc, GCP Deployment "
            "Manager, PDQ Deploy, and BigFix—become attack vectors when compromised. Access to "
            "enterprise-wide endpoint management software enables remote code execution on all "
            "connected systems, often with SYSTEM-level privileges."
        ),
        attacker_goal="Achieve network-wide code execution and lateral movement via compromised deployment tools",
        why_technique=[
            "Network-wide or enterprise-wide code execution capability",
            "Legitimate administrative tool abuse evades detection",
            "Often executes with SYSTEM or elevated privileges",
            "Can target cloud, on-premises, and hybrid environments",
            "Enables rapid malware distribution across infrastructure",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Enables network-wide compromise with elevated privileges. Successful exploitation "
            "allows rapid malware distribution, ransomware deployment, and complete enterprise "
            "takeover. Particularly dangerous in cloud and hybrid environments where deployment "
            "tools manage thousands of systems."
        ),
        business_impact=[
            "Enterprise-wide malware distribution",
            "Ransomware deployment across infrastructure",
            "Complete environment compromise",
            "Privileged code execution on all managed systems",
            "Rapid lateral movement capability",
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1486", "T1485", "T1490", "T1489"],
        often_follows=["T1078.004", "T1098.003", "T1098.001", "T1110"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1072-aws-ssm-session",
            name="AWS Systems Manager Suspicious Sessions",
            description="Detect suspicious or unauthorised AWS Systems Manager Run Command executions.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.instanceIds, requestParameters.documentName
| filter eventName = "SendCommand"
| filter eventSource = "ssm.amazonaws.com"
| stats count(*) as commands by userIdentity.principalId, requestParameters.documentName, bin(1h)
| filter commands > 20 or requestParameters.documentName like /AWS-RunPowerShellScript|AWS-RunShellScript/
| sort commands desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious AWS Systems Manager Run Command activity

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: SSM Suspicious Activity Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for high-volume Run Command usage
  SSMCommandFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "SendCommand" && $.eventSource = "ssm.amazonaws.com" }'
      MetricTransformations:
        - MetricName: SSMRunCommandExecutions
          MetricNamespace: Security/SSM
          MetricValue: "1"
          DefaultValue: 0

  # Alarm for suspicious command volume
  SSMCommandAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighVolumeSSMCommands
      AlarmDescription: Detects high volume of SSM Run Command executions
      MetricName: SSMRunCommandExecutions
      Namespace: Security/SSM
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]
      TreatMissingData: notBreaching""",
                terraform_template="""# Detect suspicious AWS Systems Manager activity

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "ssm_alerts" {
  name         = "ssm-suspicious-activity-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "SSM Suspicious Activity Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for SSM Run Command executions
resource "aws_cloudwatch_log_metric_filter" "ssm_commands" {
  name           = "ssm-run-command-executions"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"SendCommand\" && $.eventSource = \"ssm.amazonaws.com\" }"

  metric_transformation {
    name      = "SSMRunCommandExecutions"
    namespace = "Security/SSM"
    value     = "1"
  }
}

# Alarm for high-volume command execution
resource "aws_cloudwatch_metric_alarm" "ssm_command_volume" {
  alarm_name          = "HighVolumeSSMCommands"
  alarm_description   = "Detects high volume of SSM Run Command executions"
  metric_name         = "SSMRunCommandExecutions"
  namespace           = "Security/SSM"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.ssm_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Suspicious AWS Systems Manager Activity",
                alert_description_template="High volume of Run Command executions from {principalId}.",
                investigation_steps=[
                    "Review SSM Run Command history for the principal",
                    "Check which instances were targeted",
                    "Examine command documents executed",
                    "Review command outputs in S3 or CloudWatch",
                    "Verify principal authorisation for SSM access",
                    "Check for unusual execution times or patterns",
                ],
                containment_actions=[
                    "Disable compromised IAM principal immediately",
                    "Revoke SSM access policies from suspicious accounts",
                    "Review and terminate suspicious SSM sessions",
                    "Audit all instances targeted by suspicious commands",
                    "Enable AWS Systems Manager Session Manager logging",
                    "Implement least-privilege IAM policies for SSM",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on legitimate administrative activity and maintenance windows",
            detection_coverage="65% - catches high-volume usage but may miss targeted attacks",
            evasion_considerations="Attackers may limit command frequency or use legitimate documents",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled with SSM API logging",
                "CloudWatch Logs integration",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1072-aws-ssm-unusual-document",
            name="AWS SSM Unusual Document Execution",
            description="Detect execution of unusual or custom SSM documents outside maintenance windows.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.documentName, requestParameters.parameters
| filter eventName = "SendCommand"
| filter eventSource = "ssm.amazonaws.com"
| filter requestParameters.documentName not like /AWS-UpdateSSMAgent|AWS-GatherSoftwareInventory|AWS-ConfigureAWSPackage/
| stats count(*) as executions by requestParameters.documentName, userIdentity.principalId
| sort executions desc""",
                terraform_template="""# Detect unusual SSM document executions

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "aws_sns_topic" "ssm_document_alerts" {
  name         = "ssm-unusual-document-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "SSM Unusual Document Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_document_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for custom/unusual document execution
resource "aws_cloudwatch_log_metric_filter" "unusual_documents" {
  name           = "ssm-unusual-documents"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"SendCommand\" && $.requestParameters.documentName = \"AWS-RunPowerShellScript\" || $.requestParameters.documentName = \"AWS-RunShellScript\" }"

  metric_transformation {
    name      = "SSMUnusualDocuments"
    namespace = "Security/SSM"
    value     = "1"
  }
}

# Alarm for unusual document execution
resource "aws_cloudwatch_metric_alarm" "unusual_documents" {
  alarm_name          = "SSMUnusualDocuments"
  alarm_description   = "Detects execution of unusual SSM documents"
  metric_name         = "SSMUnusualDocuments"
  namespace           = "Security/SSM"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.ssm_document_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Unusual SSM Document Execution",
                alert_description_template="Execution of unusual SSM document {documentName} by {principalId}.",
                investigation_steps=[
                    "Review SSM document content and parameters",
                    "Check document creation/modification history",
                    "Verify principal authorisation",
                    "Review command outputs",
                    "Check for similar executions across environment",
                ],
                containment_actions=[
                    "Disable suspicious SSM documents",
                    "Revoke document execution permissions",
                    "Review and update SSM access policies",
                    "Audit all instances where document was executed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate custom documents and maintenance windows",
            detection_coverage="70% - catches unusual document execution patterns",
            evasion_considerations="Attackers may use legitimate document names",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "SSM document inventory"],
        ),
        DetectionStrategy(
            strategy_id="t1072-gcp-deployment-manager",
            name="GCP Deployment Manager Suspicious Activity",
            description="Detect suspicious GCP Deployment Manager deployments outside normal patterns.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="deploymentmanager.googleapis.com/Deployment"
protoPayload.methodName=~"deploymentmanager.deployments.(insert|update|patch)"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect suspicious Deployment Manager activity

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
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Log metric for Deployment Manager operations
resource "google_logging_metric" "deployment_manager_ops" {
  name   = "deployment-manager-operations"
  filter = <<-EOT
    resource.type="deploymentmanager.googleapis.com/Deployment"
    protoPayload.methodName=~"deploymentmanager.deployments.(insert|update|patch)"
    severity="NOTICE"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal performing deployment"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }

  project = var.project_id
}

# Alert policy for suspicious deployments
resource "google_monitoring_alert_policy" "deployment_manager_activity" {
  display_name = "Suspicious Deployment Manager Activity"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "High deployment frequency"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.deployment_manager_ops.name}\" AND resource.type=\"deploymentmanager.googleapis.com/Deployment\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious Deployment Manager Activity",
                alert_description_template="Unusual Deployment Manager operations detected from {principal}.",
                investigation_steps=[
                    "Review Deployment Manager configuration files",
                    "Check deployment template content",
                    "Verify principal authorisation for deployments",
                    "Review resources created/modified by deployment",
                    "Check deployment timing against maintenance windows",
                    "Audit similar deployments across projects",
                ],
                containment_actions=[
                    "Delete suspicious deployments immediately",
                    "Revoke Deployment Manager permissions from compromised principals",
                    "Review and rollback unauthorised resource changes",
                    "Enable organisation policy constraints on deployments",
                    "Implement approval workflows for deployments",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate deployment pipelines and maintenance windows",
            detection_coverage="65% - catches unusual deployment patterns",
            evasion_considerations="Attackers may deploy slowly or during maintenance windows",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled", "Deployment Manager API auditing"],
        ),
        DetectionStrategy(
            strategy_id="t1072-gcp-compute-startup",
            name="GCP Compute Instance Startup Script Modification",
            description="Detect unauthorised modifications to instance startup scripts for deployment-based execution.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.setMetadata"
protoPayload.request.metadata.items.key="startup-script"''',
                gcp_terraform_template="""# GCP: Detect startup script modifications

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Log metric for startup script modifications
resource "google_logging_metric" "startup_script_mods" {
  name   = "startup-script-modifications"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="v1.compute.instances.setMetadata"
    protoPayload.request.metadata.items.key="startup-script"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }

  project = var.project_id
}

# Alert policy for startup script changes
resource "google_monitoring_alert_policy" "startup_script_changes" {
  display_name = "Startup Script Modifications Detected"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "Startup script modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.startup_script_mods.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
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
}""",
                alert_severity="high",
                alert_title="GCP: Instance Startup Script Modified",
                alert_description_template="Startup script modified on instance {instanceName} by {principal}.",
                investigation_steps=[
                    "Review startup script content for malicious code",
                    "Check instance metadata change history",
                    "Verify principal authorisation",
                    "Review instance network activity",
                    "Check for similar modifications across fleet",
                ],
                containment_actions=[
                    "Restore original startup script",
                    "Reboot instance with clean configuration",
                    "Revoke metadata modification permissions",
                    "Enable organisation policy on metadata changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised automation principals",
            detection_coverage="75% - highly reliable for startup script changes",
            evasion_considerations="Attackers may use other metadata keys or deployment methods",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Logging enabled", "Compute API audit logs"],
        ),
    ],
    recommended_order=[
        "t1072-aws-ssm-session",
        "t1072-aws-ssm-unusual-document",
        "t1072-gcp-deployment-manager",
        "t1072-gcp-compute-startup",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+25% improvement for Execution and Lateral Movement tactics",
)
