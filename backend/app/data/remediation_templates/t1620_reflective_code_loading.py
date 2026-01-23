"""
T1620 - Reflective Code Loading

Adversaries load and execute malicious payloads directly in process memory to avoid
disk-based detection. Includes loading .NET assemblies, shellcode, and position-
independent code without creating files on disk.
Used by FIN7, Lazarus Group, Cobalt Strike.
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
    technique_id="T1620",
    technique_name="Reflective Code Loading",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1620/",
    threat_context=ThreatContext(
        description=(
            "Adversaries employ reflective code loading to conceal malicious payload "
            "execution by allocating and running code directly within a process's memory "
            "rather than creating disk-backed files. This includes loading .NET assemblies "
            "via Assembly.Load(), position-independent shellcode, and anonymous RAM-only "
            "files using VirtualAlloc/VirtualProtect on Windows or mmap/mprotect on Linux."
        ),
        attacker_goal="Execute malicious code in-memory to evade disk-based detection and file system monitoring",
        why_technique=[
            "Avoids disk artifacts and file-based detection",
            "Enables payloads to remain encrypted until execution",
            "Masks activity within legitimate processes",
            "Bypasses file system monitoring solutions",
            "Commonly used by post-exploitation frameworks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Common defense evasion technique used by advanced threat actors and "
            "post-exploitation frameworks. Difficult to detect and mitigate due to "
            "reliance on normal system features."
        ),
        business_impact=[
            "Evasion of endpoint protection",
            "Difficult forensic investigation",
            "Enables persistence mechanisms",
            "Facilitates lateral movement",
        ],
        typical_attack_phase="defense_evasion",
        often_precedes=["T1055", "T1059", "T1070"],
        often_follows=["T1059.001", "T1203", "T1566"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1620-aws-ec2-memory",
            name="EC2 Suspicious Memory Allocation Patterns",
            description="Detect anomalous memory allocation chains on EC2 instances via CloudWatch Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, host, process_name, event_type
| filter event_type = "memory_allocation"
| filter (syscall = "VirtualAlloc" or syscall = "VirtualProtect" or syscall = "CreateThread")
| stats count(*) as alloc_count by host, process_name, bin(5m)
| filter alloc_count > 3
| sort alloc_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect reflective code loading via memory allocation patterns

Parameters:
  SecurityLogGroup:
    Type: String
    Description: CloudWatch Log Group containing process monitoring logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: reflective-loading-alerts
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

  MemoryAllocFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SecurityLogGroup
      FilterPattern: '{ ($.syscall = "VirtualAlloc" || $.syscall = "VirtualProtect" || $.syscall = "mmap") && $.event_type = "memory_allocation" }'
      MetricTransformations:
        - MetricName: SuspiciousMemoryAllocations
          MetricNamespace: Security/DefenceEvasion
          MetricValue: "1"

  MemoryAllocAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ReflectiveCodeLoadingDetected
      AlarmDescription: Detected suspicious memory allocation patterns
      MetricName: SuspiciousMemoryAllocations
      Namespace: Security/DefenceEvasion
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect reflective code loading via memory allocation patterns

variable "security_log_group" {
  type        = string
  description = "CloudWatch Log Group containing process monitoring logs"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "reflective-loading-alerts"
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

resource "aws_cloudwatch_log_metric_filter" "memory_alloc" {
  name           = "suspicious-memory-allocations"
  log_group_name = var.security_log_group
  pattern        = "{ ($.syscall = \"VirtualAlloc\" || $.syscall = \"VirtualProtect\" || $.syscall = \"mmap\") && $.event_type = \"memory_allocation\" }"

  metric_transformation {
    name      = "SuspiciousMemoryAllocations"
    namespace = "Security/DefenceEvasion"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "reflective_loading" {
  alarm_name          = "ReflectiveCodeLoadingDetected"
  alarm_description   = "Detected suspicious memory allocation patterns"
  metric_name         = "SuspiciousMemoryAllocations"
  namespace           = "Security/DefenceEvasion"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Reflective Code Loading Detected",
                alert_description_template="Suspicious memory allocation pattern detected on {host} in process {process_name}.",
                investigation_steps=[
                    "Review process command line and parent process",
                    "Check process for known malicious signatures",
                    "Analyse memory dumps for injected code",
                    "Review network connections from affected process",
                    "Check for related suspicious activity timeline",
                ],
                containment_actions=[
                    "Isolate affected EC2 instance",
                    "Terminate suspicious process",
                    "Capture memory dump for forensics",
                    "Review EDR/AV logs for related alerts",
                    "Check for lateral movement indicators",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate software may use dynamic memory allocation; baseline normal process behaviour",
            detection_coverage="60% - requires process monitoring agents",
            evasion_considerations="Attackers may throttle allocations or use alternative syscalls",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4-6 hours",
            estimated_monthly_cost="$20-50",
            prerequisites=[
                "Process monitoring agent (e.g., Sysmon, osquery) forwarding to CloudWatch"
            ],
        ),
        DetectionStrategy(
            strategy_id="t1620-aws-dotnet-assembly",
            name="EC2 .NET Assembly Reflective Loading",
            description="Detect PowerShell and .NET reflective assembly loading on EC2.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, host, process_name, command_line, event_data
| filter event_id = 7
| filter (event_data like /Assembly\\.Load/ or event_data like /Reflection\\.Assembly/ or command_line like /FromBase64String/)
| stats count(*) as load_count by host, process_name, bin(5m)
| filter load_count > 2
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect .NET reflective assembly loading

Parameters:
  SecurityLogGroup:
    Type: String
    Description: CloudWatch Log Group with PowerShell/Sysmon logs
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: dotnet-assembly-loading-alerts
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

  AssemblyLoadFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SecurityLogGroup
      FilterPattern: '[timestamp, host, event_id=7, *assembly="*Assembly.Load*"]'
      MetricTransformations:
        - MetricName: ReflectiveAssemblyLoads
          MetricNamespace: Security/DefenceEvasion
          MetricValue: "1"

  AssemblyLoadAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DotNetReflectiveLoading
      AlarmDescription: Detected .NET reflective assembly loading
      MetricName: ReflectiveAssemblyLoads
      Namespace: Security/DefenceEvasion
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect .NET reflective assembly loading

variable "security_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "dotnet-assembly-loading-alerts"
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

resource "aws_cloudwatch_log_metric_filter" "assembly_load" {
  name           = "reflective-assembly-loads"
  log_group_name = var.security_log_group
  pattern        = "[timestamp, host, event_id=7, *assembly=\"*Assembly.Load*\"]"

  metric_transformation {
    name      = "ReflectiveAssemblyLoads"
    namespace = "Security/DefenceEvasion"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "dotnet_loading" {
  alarm_name          = "DotNetReflectiveLoading"
  alarm_description   = "Detected .NET reflective assembly loading"
  metric_name         = "ReflectiveAssemblyLoads"
  namespace           = "Security/DefenceEvasion"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title=".NET Reflective Assembly Loading",
                alert_description_template="Detected .NET Assembly.Load() execution on {host}.",
                investigation_steps=[
                    "Review PowerShell script block logging",
                    "Check for Base64-encoded payloads",
                    "Analyse parent process chain",
                    "Review loaded assembly contents if available",
                    "Check for known malware frameworks (e.g., Cobalt Strike)",
                ],
                containment_actions=[
                    "Terminate PowerShell/suspicious process",
                    "Isolate affected system",
                    "Enable constrained language mode for PowerShell",
                    "Review and block malicious scripts",
                    "Check for persistence mechanisms",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate admin scripts may use Assembly.Load; whitelist known tools",
            detection_coverage="70% - effective for .NET-based loading",
            evasion_considerations="Obfuscation and encoding may bypass pattern matching",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["PowerShell logging and Sysmon forwarding to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1620-gcp-gce-memory",
            name="GCE Suspicious Memory Operations",
            description="Detect suspicious memory operations on GCE instances via Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(jsonPayload.syscall="mmap" OR jsonPayload.syscall="mprotect")
jsonPayload.flags=~".*RWX.*"
jsonPayload.event_type="memory_operation"''',
                gcp_terraform_template="""# GCP: Detect reflective code loading via memory operations

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "suspicious_memory" {
  project = var.project_id
  name   = "suspicious-memory-operations"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.syscall="mmap" OR jsonPayload.syscall="mprotect")
    jsonPayload.flags=~".*RWX.*"
    jsonPayload.event_type="memory_operation"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "GCE instance ID"
    }
  }
  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

resource "google_monitoring_alert_policy" "reflective_loading" {
  project      = var.project_id
  display_name = "Reflective Code Loading Detected"
  combiner     = "OR"
  conditions {
    display_name = "High RWX memory allocations"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_memory.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
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
                alert_title="GCP: Reflective Code Loading Detected",
                alert_description_template="Suspicious RWX memory operations detected on GCE instance.",
                investigation_steps=[
                    "Review process details and command line",
                    "Check for anonymous file mappings",
                    "Analyse process memory for malicious code",
                    "Review Cloud Audit Logs for related activity",
                    "Check for lateral movement indicators",
                ],
                containment_actions=[
                    "Isolate affected GCE instance",
                    "Terminate suspicious process",
                    "Create disk snapshot for forensics",
                    "Review VPC flow logs for exfiltration",
                    "Check for compromised service accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Some legitimate applications use RWX memory; baseline normal behaviour",
            detection_coverage="60% - requires OS-level monitoring",
            evasion_considerations="Attackers may use alternative protection flags or split operations",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4-6 hours",
            estimated_monthly_cost="$25-60",
            prerequisites=["OS-level monitoring agent forwarding to Cloud Logging"],
        ),
        DetectionStrategy(
            strategy_id="t1620-gcp-container-memory",
            name="GKE Container Memory Injection Detection",
            description="Detect in-memory code execution within GKE containers.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_container"
(jsonPayload.syscall="mmap" OR jsonPayload.syscall="execve")
jsonPayload.flags=~".*ANONYMOUS.*"
jsonPayload.event_type="container_memory_operation"''',
                gcp_terraform_template="""# GCP: Detect reflective loading in GKE containers

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Container Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "container_memory_injection" {
  project = var.project_id
  name   = "container-memory-injection"
  filter = <<-EOT
    resource.type="k8s_container"
    (jsonPayload.syscall="mmap" OR jsonPayload.syscall="execve")
    jsonPayload.flags=~".*ANONYMOUS.*"
    jsonPayload.event_type="container_memory_operation"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "container_name"
      value_type  = "STRING"
      description = "Container name"
    }
    labels {
      key         = "namespace_name"
      value_type  = "STRING"
      description = "Kubernetes namespace"
    }
  }
  label_extractors = {
    "container_name" = "EXTRACT(resource.labels.container_name)"
    "namespace_name" = "EXTRACT(resource.labels.namespace_name)"
  }
}

resource "google_monitoring_alert_policy" "container_injection" {
  project      = var.project_id
  display_name = "GKE Container Memory Injection"
  combiner     = "OR"
  conditions {
    display_name = "Anonymous memory execution in container"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.container_memory_injection.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.namespace_name", "metric.label.container_name"]
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
}""",
                alert_severity="critical",
                alert_title="GKE: Container Memory Injection Detected",
                alert_description_template="In-memory code execution detected in container {container_name} in namespace {namespace_name}.",
                investigation_steps=[
                    "Review container image and runtime behaviour",
                    "Check for container escape attempts",
                    "Analyse container process tree",
                    "Review pod security context and policies",
                    "Check for compromised secrets or service accounts",
                ],
                containment_actions=[
                    "Terminate affected pod immediately",
                    "Isolate namespace if widespread",
                    "Review and harden pod security policies",
                    "Scan container images for vulnerabilities",
                    "Rotate compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Container memory injection is rarely legitimate; investigate all alerts",
            detection_coverage="65% - effective for containerised workloads",
            evasion_considerations="Sophisticated attackers may use container-native evasion techniques",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-5 hours",
            estimated_monthly_cost="$30-70",
            prerequisites=["GKE with runtime security monitoring enabled"],
        ),
        # Azure Strategy: Reflective Code Loading
        DetectionStrategy(
            strategy_id="t1620-azure",
            name="Azure Reflective Code Loading Detection",
            description=(
                "Azure detection for Reflective Code Loading. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Reflective Code Loading
// MITRE ATT&CK: T1620
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources""",
                azure_terraform_template="""# Azure Detection for Reflective Code Loading
# MITRE ATT&CK: T1620

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

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "reflective-code-loading-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "reflective-code-loading-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Reflective Code Loading
// MITRE ATT&CK: T1620
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources
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

  description = "Detects Reflective Code Loading (T1620) activity in Azure environment"
  display_name = "Reflective Code Loading Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1620"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Reflective Code Loading Detected",
                alert_description_template=(
                    "Reflective Code Loading activity detected. "
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
        "t1620-aws-dotnet-assembly",
        "t1620-gcp-container-memory",
        "t1620-aws-ec2-memory",
        "t1620-gcp-gce-memory",
    ],
    total_effort_hours=14.0,
    coverage_improvement="+25% improvement for Defence Evasion tactic",
)
