"""
T1057 - Process Discovery

Adversaries enumerate running processes to identify security tools,
understand the application landscape, and locate targets for further exploitation.
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
    technique_id="T1057",
    technique_name="Process Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1057/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate running processes on systems to gather information "
            "about security software, running applications, and potential targets. "
            "In cloud environments, this occurs on EC2 instances, container workloads, "
            "and virtual machines where attackers execute commands like ps, tasklist, "
            "or API calls to enumerate processes."
        ),
        attacker_goal="Enumerate processes to identify security tools and valuable targets",
        why_technique=[
            "Identifies security software and defensive tools",
            "Locates processes for injection or termination",
            "Detects sandbox and analysis environments",
            "Finds high-value applications and services",
            "Maps system privileges and capabilities",
            "Required before process injection attacks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "Process discovery itself has low direct impact but is a critical "
            "reconnaissance step. It indicates active threat actor presence and "
            "typically precedes defence evasion, privilege escalation, or process "
            "injection attacks. Early detection provides opportunity for containment."
        ),
        business_impact=[
            "Indicates active compromise of cloud workloads",
            "Reveals security tool mapping by attackers",
            "Precursor to defence evasion attempts",
            "Early warning for process injection attacks",
            "Container breakout risk indicator",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1562.001", "T1055", "T1489"],
        often_follows=["T1078.004", "T1078.001", "T1611"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 Process Enumeration via SSM/Session Manager
        DetectionStrategy(
            strategy_id="t1057-aws-ssm",
            name="AWS SSM Process Enumeration Detection",
            description="Detect process enumeration commands executed via Systems Manager.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, requestParameters.documentName, requestParameters.parameters
| filter eventSource = "ssm.amazonaws.com"
| filter eventName = "SendCommand"
| filter requestParameters.documentName = "AWS-RunShellScript" or requestParameters.documentName = "AWS-RunPowerShellScript"
| filter requestParameters.parameters like /tasklist|Get-Process|ps aux|ps -ef|top|htop/
| stats count(*) as cmd_count by userIdentity.arn, bin(1h)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect process enumeration via SSM

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

  # Step 2: Metric filter for process enumeration commands
  ProcessEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ssm.amazonaws.com" && $.eventName = "SendCommand" && ($.requestParameters.parameters like "*tasklist*" || $.requestParameters.parameters like "*ps aux*" || $.requestParameters.parameters like "*Get-Process*") }'
      MetricTransformations:
        - MetricName: ProcessEnumeration
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: CloudWatch alarm
  ProcessEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ProcessEnumeration
      MetricName: ProcessEnumeration
      Namespace: Security
      Statistic: Sum
      Period: 1800
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
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect process enumeration via SSM

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "process-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for process enumeration
resource "aws_cloudwatch_log_metric_filter" "process_enum" {
  name           = "process-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ssm.amazonaws.com\" && $.eventName = \"SendCommand\" && ($.requestParameters.parameters like \"*tasklist*\" || $.requestParameters.parameters like \"*ps aux*\" || $.requestParameters.parameters like \"*Get-Process*\") }"

  metric_transformation {
    name      = "ProcessEnumeration"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "process_enum" {
  alarm_name          = "ProcessEnumeration"
  metric_name         = "ProcessEnumeration"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 1800
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
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
                alert_title="Process Enumeration Detected on EC2",
                alert_description_template="Process enumeration command executed via SSM by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who executed the command",
                    "Review the complete command and parameters",
                    "Check if this is authorised administrative activity",
                    "Review recent activity from this identity",
                    "Look for follow-on defence evasion or privilege escalation",
                ],
                containment_actions=[
                    "Review SSM session logs for suspicious activity",
                    "Check for unauthorised access",
                    "Monitor for process injection or termination",
                    "Isolate instance if compromise suspected",
                    "Audit security tool status on affected instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised administrative accounts and monitoring tools",
            detection_coverage="75% - API-level, does not require endpoint agent",
            evasion_considerations="Direct SSH access bypasses this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch", "SSM logging enabled"],
        ),
        # Strategy 2: AWS - ECS Task Exec Process Enumeration
        DetectionStrategy(
            strategy_id="t1057-aws-ecs",
            name="AWS ECS Container Process Enumeration",
            description="Detect process enumeration within ECS containers via ExecuteCommand.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, requestParameters.task, requestParameters.command
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "ExecuteCommand"
| filter requestParameters.command like /ps|top|\\/proc/
| stats count(*) as exec_count by userIdentity.arn, requestParameters.cluster, bin(1h)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect container process enumeration in ECS

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

  # Step 2: Metric filter for ECS ExecuteCommand with process enumeration
  ContainerEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ecs.amazonaws.com" && $.eventName = "ExecuteCommand" && ($.requestParameters.command like "*ps*" || $.requestParameters.command like "*/proc*") }'
      MetricTransformations:
        - MetricName: ContainerProcessEnum
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: CloudWatch alarm
  ContainerEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ContainerProcessEnumeration
      MetricName: ContainerProcessEnum
      Namespace: Security
      Statistic: Sum
      Period: 1800
      Threshold: 3
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
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect container process enumeration in ECS

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "container-process-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for ECS process enumeration
resource "aws_cloudwatch_log_metric_filter" "container_enum" {
  name           = "container-process-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ecs.amazonaws.com\" && $.eventName = \"ExecuteCommand\" && ($.requestParameters.command like \"*ps*\" || $.requestParameters.command like \"*/proc*\") }"

  metric_transformation {
    name      = "ContainerProcessEnum"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "container_enum" {
  alarm_name          = "ContainerProcessEnumeration"
  metric_name         = "ContainerProcessEnum"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 1800
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
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
                alert_title="Container Process Enumeration Detected",
                alert_description_template="Process enumeration in ECS container by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who executed the command in the container",
                    "Review the complete command executed",
                    "Check container's expected behaviour",
                    "Look for container escape attempts",
                    "Review task definition for misconfigurations",
                ],
                containment_actions=[
                    "Review ECS exec session logs",
                    "Check for privilege escalation attempts",
                    "Monitor for container breakout activity",
                    "Consider stopping compromised task",
                    "Review container security posture",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised debugging sessions",
            detection_coverage="85% - API-level detection, does not require additional agents",
            evasion_considerations="Direct container access without CloudTrail logging bypasses detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$3-5",
            prerequisites=[
                "CloudTrail logging to CloudWatch",
                "ECS ExecuteCommand audit logging",
            ],
        ),
        # Strategy 3: GCP - Compute Instance Process Enumeration
        DetectionStrategy(
            strategy_id="t1057-gcp-compute",
            name="GCP Compute Process Enumeration Detection",
            description="Detect process enumeration on GCP Compute instances via OS Login or SSH.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.request.cmdline=~"(ps aux|ps -ef|top|htop|/proc/)"
OR textPayload=~"(ps aux|ps -ef|top|htop)"''',
                gcp_terraform_template="""# GCP: Detect process enumeration on Compute instances

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for process enumeration
resource "google_logging_metric" "process_enum" {
  project = var.project_id
  name   = "process-enumeration"
  filter = <<-EOT
    protoPayload.request.cmdline=~"(ps aux|ps -ef|top|htop|/proc/)"
    OR textPayload=~"(ps aux|ps -ef|top|htop)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for process enumeration
resource "google_monitoring_alert_policy" "process_enum" {
  project      = var.project_id
  display_name = "Process Enumeration Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious process enumeration"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.process_enum.name}\""
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
                alert_severity="medium",
                alert_title="GCP: Process Enumeration Detected",
                alert_description_template="Process enumeration commands executed on Compute instance.",
                investigation_steps=[
                    "Identify which instance and user executed the command",
                    "Review OS Login or SSH session logs",
                    "Check if this is authorised administrative activity",
                    "Look for follow-on suspicious activity",
                    "Review instance's expected workload",
                ],
                containment_actions=[
                    "Review instance access logs",
                    "Check for privilege escalation attempts",
                    "Monitor for defence evasion activities",
                    "Consider isolating compromised instance",
                    "Audit firewall rules and network exposure",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised monitoring tools and administrative users",
            detection_coverage="70% - requires Ops Agent with process monitoring enabled",
            evasion_considerations="Commands not logged by Cloud Audit Logs will bypass detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="45 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "OS Login or SSH logging configured",
            ],
        ),
        # Strategy 4: GCP - GKE Container Process Enumeration
        DetectionStrategy(
            strategy_id="t1057-gcp-gke",
            name="GCP GKE Container Process Enumeration",
            description="Detect process enumeration within GKE containers via kubectl exec.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_cluster"
protoPayload.methodName="io.k8s.core.v1.pods.exec"
protoPayload.request.command=~"(ps|top|/proc/)"''',
                gcp_terraform_template="""# GCP: Detect GKE container process enumeration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for kubectl exec process enumeration
resource "google_logging_metric" "gke_process_enum" {
  project = var.project_id
  name   = "gke-process-enumeration"
  filter = <<-EOT
    resource.type="k8s_cluster"
    protoPayload.methodName="io.k8s.core.v1.pods.exec"
    protoPayload.request.command=~"(ps|top|/proc/)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for GKE process enumeration
resource "google_monitoring_alert_policy" "gke_process_enum" {
  project      = var.project_id
  display_name = "GKE Process Enumeration Detected"
  combiner     = "OR"

  conditions {
    display_name = "Container process enumeration"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gke_process_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
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
                alert_severity="medium",
                alert_title="GKE: Container Process Enumeration",
                alert_description_template="Process enumeration executed in GKE pod via kubectl exec.",
                investigation_steps=[
                    "Identify who executed kubectl exec",
                    "Review the specific pod and namespace",
                    "Check if this is authorised debugging",
                    "Look for container escape attempts",
                    "Review pod security context and permissions",
                ],
                containment_actions=[
                    "Review Kubernetes audit logs",
                    "Check for privilege escalation in pod",
                    "Monitor for container breakout activity",
                    "Consider restricting exec permissions",
                    "Audit RBAC policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised DevOps users and debugging sessions",
            detection_coverage="80% - API-level, does not require endpoint agent",
            evasion_considerations="Direct container access bypasses Kubernetes audit logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="45 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=["GKE Audit Logs enabled", "Cloud Logging configured"],
        ),
        # Azure Strategy: Process Discovery
        DetectionStrategy(
            strategy_id="t1057-azure",
            name="Azure Process Discovery Detection",
            description=(
                "Azure detection for Process Discovery. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Process Discovery Detection
// Technique: T1057
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc""",
                azure_terraform_template="""# Azure Detection for Process Discovery
# MITRE ATT&CK: T1057

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
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
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

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "process-discovery-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "process-discovery-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Process Discovery Detection
// Technique: T1057
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects Process Discovery (T1057) activity in Azure environment"
  display_name = "Process Discovery Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1057"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Process Discovery Detected",
                alert_description_template=(
                    "Process Discovery activity detected. "
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
            detection_coverage="30% - only monitors Azure cloud operations, cannot detect endpoint process enumeration",
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
        "t1057-aws-ssm",
        "t1057-aws-ecs",
        "t1057-gcp-compute",
        "t1057-gcp-gke",
    ],
    total_effort_hours=2.5,
    coverage_improvement="+12% improvement for Discovery tactic",
)
