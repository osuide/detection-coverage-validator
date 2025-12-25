"""
T1047 - Windows Management Instrumentation

Adversaries abuse Windows Management Instrumentation (WMI) to execute malicious commands,
gather system information, and perform lateral movement across Windows environments.
Used by APT29, APT32, APT41, Lazarus Group, FIN7, FIN8, Volt Typhoon, and ransomware groups.
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
    technique_id="T1047",
    technique_name="Windows Management Instrumentation",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1047/",
    threat_context=ThreatContext(
        description=(
            "Windows Management Instrumentation (WMI) is a legitimate Windows administration "
            "framework that adversaries exploit for command execution, reconnaissance, and "
            "lateral movement. In cloud environments, attackers abuse WMI on Windows EC2 instances, "
            "Azure VMs, and GCP Windows instances to execute payloads, delete shadow copies, "
            "discover system information, and move laterally across hybrid infrastructure."
        ),
        attacker_goal="Execute commands and gather intelligence using built-in Windows management tools",
        why_technique=[
            "Pre-installed on all Windows systems, no additional tools needed",
            "Enables remote code execution across Windows networks",
            "Bypasses application whitelisting as a legitimate system component",
            "Facilitates 'living off the land' tactics",
            "Historically used wmic.exe, now PowerShell and COM APIs",
            "Critical for ransomware shadow copy deletion",
            "Supports both local and remote system management",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "WMI abuse is a high-severity technique enabling execution, reconnaissance, and "
            "lateral movement. The January 2024 deprecation of wmic.exe has shifted adversary "
            "tactics to PowerShell-based WMI exploitation, requiring updated detection strategies. "
            "Ransomware groups extensively use WMI for shadow copy deletion, preventing system "
            "recovery. In hybrid cloud environments, WMI enables attackers to move from on-premises "
            "to cloud-hosted Windows instances."
        ),
        business_impact=[
            "Ransomware deployment with shadow copy deletion preventing recovery",
            "Lateral movement across Windows environments",
            "Discovery of security tools and system configurations",
            "Remote command execution without malware deployment",
            "Credential theft and privilege escalation",
            "Data destruction and system recovery inhibition",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1003", "T1078", "T1021", "T1490"],
        often_follows=["T1078.004", "T1190", "T1133", "T1078.001"],
    ),
    detection_strategies=[
        # Strategy 1: AWS GuardDuty Runtime Monitoring for WMI Execution
        DetectionStrategy(
            strategy_id="t1047-guardduty-wmi",
            name="AWS GuardDuty Runtime Monitoring for WMI Abuse",
            description=(
                "AWS GuardDuty Runtime Monitoring detects suspicious WMI activity on Windows "
                "EC2 instances, including wmic.exe execution, PowerShell-based WMI commands, "
                "and COM API abuse patterns."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/ReverseShell",
                    "CredentialAccess:Runtime/MemoryDumpCreated",
                    "Impact:Runtime/MaliciousCommand",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for WMI abuse detection on Windows EC2 instances

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable GuardDuty with Runtime Monitoring
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: RUNTIME_MONITORING
          Status: ENABLED

  # Step 2: Create SNS topic for WMI alerts
  WMIAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: WMI Abuse Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route WMI-related findings to alerts
  WMIExecutionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1047-WMI-Execution
      Description: Alert on WMI command execution attempts
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Execution:Runtime"
            - prefix: "Impact:Runtime"
            - prefix: "CredentialAccess:Runtime"
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref WMIAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref WMIAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref WMIAlertTopic""",
                terraform_template="""# GuardDuty Runtime Monitoring for WMI abuse detection

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable GuardDuty with Runtime Monitoring
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"
}

# Step 2: Create SNS topic for WMI alerts
resource "aws_sns_topic" "wmi_alerts" {
  name         = "wmi-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "WMI Abuse Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.wmi_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route WMI-related findings to alerts
resource "aws_cloudwatch_event_rule" "wmi_execution" {
  name        = "guardduty-wmi-execution"
  description = "Alert on WMI command execution attempts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Execution:Runtime" },
        { prefix = "Impact:Runtime" },
        { prefix = "CredentialAccess:Runtime" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.wmi_execution.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.wmi_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.wmi_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.wmi_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: WMI Execution Detected",
                alert_description_template=(
                    "Suspicious WMI activity detected on Windows instance {instance_id}. "
                    "Finding: {finding_type}. Process: {process_name}. "
                    "This may indicate lateral movement or malicious command execution."
                ),
                investigation_steps=[
                    "Review GuardDuty finding details and process execution chain",
                    "Check CloudTrail for API calls from the instance's IAM role",
                    "Examine running processes using SSM Session Manager or PowerShell",
                    "Review Windows Event Logs (EventID 4688, 4648, Sysmon Event 1, 19, 20, 21)",
                    "Check for shadow copy deletion or anti-forensics activities",
                    "Investigate network connections for lateral movement indicators",
                    "Review recent user logons and authentication events",
                ],
                containment_actions=[
                    "Isolate the instance by modifying security groups to block all traffic",
                    "Create a forensic snapshot of the instance for analysis",
                    "Rotate all credentials that may have been exposed on the instance",
                    "Revoke the instance IAM role session credentials",
                    "Check for persistence mechanisms (WMI event subscriptions, scheduled tasks)",
                    "Terminate the instance if compromise is confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Baseline legitimate administrative WMI usage; exclude authorised management tools and patch deployment systems",
            detection_coverage="70% - detects runtime WMI execution patterns on Windows instances",
            evasion_considerations="Obfuscated PowerShell commands, COM API usage, or custom WMI namespaces may evade basic detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per Windows instance per month for Runtime Monitoring",
            prerequisites=[
                "GuardDuty enabled",
                "SSM Agent on Windows EC2 instances for Runtime Monitoring",
            ],
        ),
        # Strategy 2: CloudWatch Logs - WMI Command Detection
        DetectionStrategy(
            strategy_id="t1047-cloudwatch-wmi",
            name="Detect WMI Commands via CloudWatch Logs",
            description=(
                "Monitor CloudWatch Logs for WMI-related commands including wmic.exe, "
                "PowerShell Get-WmiObject, Invoke-WmiMethod, and shadow copy deletion commands."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, commandLine, processName
| filter @message like /wmic.exe|Get-WmiObject|Invoke-WmiMethod|gwmi|iwmi|Win32_Shadowcopy.*Delete|shadowcopy.*delete/i
| filter @message not like /Microsoft.*Update|SCCM|authorised_management/
| stats count() as wmi_executions by instanceId, processName, bin(5m)
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect WMI command execution on Windows instances

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing Windows instance logs
  SNSTopicArn:
    Type: String
    Description: SNS topic ARN for alerts

Resources:
  # Step 1: Create metric filter for WMI command execution
  WMICommandFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process="*wmic.exe*" || process="*powershell*Get-WmiObject*" || process="*powershell*Invoke-WmiMethod*" || command="*shadowcopy*delete*"]'
      MetricTransformations:
        - MetricName: WMICommandExecution
          MetricNamespace: Security/T1047
          MetricValue: "1"

  # Step 2: Create alarm for WMI execution
  WMIExecutionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1047-WMI-Execution
      AlarmDescription: WMI command execution detected
      MetricName: WMICommandExecution
      Namespace: Security/T1047
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Create filter for shadow copy deletion (critical indicator)
  ShadowCopyDeletionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, command="*shadowcopy*delete*" || command="*vssadmin*delete*shadows*"]'
      MetricTransformations:
        - MetricName: ShadowCopyDeletion
          MetricNamespace: Security/T1047
          MetricValue: "1"''',
                terraform_template="""# Detect WMI command execution on Windows instances

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing Windows instance logs"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "wmi-execution-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for WMI command execution
resource "aws_cloudwatch_log_metric_filter" "wmi_commands" {
  name           = "wmi-command-execution"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process=\"*wmic.exe*\" || process=\"*powershell*Get-WmiObject*\" || process=\"*powershell*Invoke-WmiMethod*\" || command=\"*shadowcopy*delete*\"]"

  metric_transformation {
    name      = "WMICommandExecution"
    namespace = "Security/T1047"
    value     = "1"
  }
}

# Step 2: Create alarm for WMI execution
resource "aws_cloudwatch_metric_alarm" "wmi_execution" {
  alarm_name          = "T1047-WMI-Execution"
  alarm_description   = "WMI command execution detected"
  metric_name         = "WMICommandExecution"
  namespace           = "Security/T1047"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}

# Step 3: Create filter for shadow copy deletion (critical ransomware indicator)
resource "aws_cloudwatch_log_metric_filter" "shadow_copy_deletion" {
  name           = "shadow-copy-deletion"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, command=\"*shadowcopy*delete*\" || command=\"*vssadmin*delete*shadows*\"]"

  metric_transformation {
    name      = "ShadowCopyDeletion"
    namespace = "Security/T1047"
    value     = "1"
  }
}""",
                alert_severity="high",
                alert_title="WMI Command Execution Detected",
                alert_description_template=(
                    "WMI command detected on instance {instance_id}. "
                    "Process: {process_name}. Command: {command_line}. "
                    "Investigate for potential lateral movement or ransomware activity."
                ),
                investigation_steps=[
                    "Identify the exact WMI command and its parameters",
                    "Check if wmic.exe or PowerShell WMI cmdlets were used",
                    "Review parent process and execution context",
                    "Search for shadow copy deletion commands (ransomware indicator)",
                    "Check for lateral movement via WMI to other instances",
                    "Review Windows Security Event Log (EventID 4688 for process creation)",
                    "Examine Sysmon logs for WMI EventID 19, 20, 21 (WMI event consumers)",
                ],
                containment_actions=[
                    "Immediately isolate the instance from the network",
                    "If shadow copy deletion detected, assume ransomware and initiate incident response",
                    "Kill suspicious WMI processes if still running",
                    "Disable WMI service temporarily if compromise confirmed",
                    "Check for and remove WMI event subscriptions used for persistence",
                    "Rotate credentials for all accounts that authenticated to the instance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised systems management tools (SCCM, patch management), whitelist known administrative automation",
            detection_coverage="75% - catches wmic.exe and PowerShell WMI cmdlet usage",
            evasion_considerations="COM API usage, obfuscated PowerShell, or custom WMI namespaces may bypass pattern matching",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15 depending on log volume",
            prerequisites=[
                "CloudWatch Logs Agent installed on Windows instances",
                "Windows Event Forwarding or Sysmon logging enabled",
            ],
        ),
        # Strategy 3: Remote WMI Detection via VPC Flow Logs
        DetectionStrategy(
            strategy_id="t1047-remote-wmi",
            name="Detect Remote WMI Connections",
            description=(
                "Monitor network traffic for WMI remote access patterns using port 135 (DCOM) "
                "and ports 5985/5986 (WinRM over HTTP/HTTPS)."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol, action
| filter dstPort in [135, 5985, 5986] and protocol = 6 and action = "ACCEPT"
| stats count() as connections by srcAddr, dstAddr, dstPort, bin(10m)
| filter connections > 5
| sort connections desc""",
                terraform_template="""# Detect remote WMI connections via VPC Flow Logs

variable "vpc_flow_log_group" {
  type        = string
  description = "VPC Flow Logs log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "remote-wmi-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for WMI ports (135, 5985, 5986)
resource "aws_cloudwatch_log_metric_filter" "remote_wmi" {
  name           = "remote-wmi-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport IN (135,5985,5986), protocol=\"6\", packets, bytes, start, end, action=\"ACCEPT\", ...]"

  metric_transformation {
    name          = "RemoteWMIConnections"
    namespace     = "Security/T1047"
    value         = "1"
    default_value = 0
  }
}

# Step 2: Create alarm for excessive remote WMI activity
resource "aws_cloudwatch_metric_alarm" "remote_wmi_alert" {
  alarm_name          = "T1047-Remote-WMI-Activity"
  alarm_description   = "Detects remote WMI connection attempts indicating lateral movement"
  metric_name         = "RemoteWMIConnections"
  namespace           = "Security/T1047"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

# Step 3: Create dedicated filter for DCOM port 135 (primary WMI remote access)
resource "aws_cloudwatch_log_metric_filter" "dcom_wmi" {
  name           = "dcom-wmi-port-135"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport=\"135\", protocol=\"6\", packets, bytes, start, end, action=\"ACCEPT\", ...]"

  metric_transformation {
    name          = "DCOMWMIConnections"
    namespace     = "Security/T1047"
    value         = "1"
    default_value = 0
  }
}""",
                alert_severity="high",
                alert_title="Remote WMI Connection Detected",
                alert_description_template=(
                    "Remote WMI connection detected from {srcAddr} to {dstAddr} on port {dstPort}. "
                    "{connections} connections in 10 minutes. May indicate lateral movement."
                ),
                investigation_steps=[
                    "Identify source and destination instances involved in WMI connections",
                    "Verify if remote WMI access is authorised for these systems",
                    "Check for corresponding authentication events on both systems",
                    "Review what commands were executed via remote WMI",
                    "Investigate if credentials were passed or harvested",
                    "Look for subsequent lateral movement to additional instances",
                    "Check if this matches known administrative patterns or is anomalous",
                ],
                containment_actions=[
                    "Block WMI ports (135, 5985, 5986) via security groups if not required",
                    "Isolate both source and destination instances for investigation",
                    "Implement network segmentation to limit lateral movement",
                    "Enable Windows Firewall rules to restrict WMI to authorised sources",
                    "Review and restrict IAM instance profile permissions",
                    "Consider implementing AWS Systems Manager Session Manager instead of remote WMI",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate remote administration patterns; exclude known management servers and domain controllers",
            detection_coverage="65% - detects network-level WMI remote access",
            evasion_considerations="Encrypted WinRM traffic or tunnelled WMI connections may be harder to distinguish from legitimate traffic",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20 depending on VPC Flow Logs volume",
            prerequisites=[
                "VPC Flow Logs enabled",
                "Windows instances configured for network logging",
            ],
        ),
        # Strategy 4: GCP Cloud Logging for WMI on Windows VMs
        DetectionStrategy(
            strategy_id="t1047-gcp-wmi",
            name="GCP: Detect WMI Execution on Windows GCE Instances",
            description=(
                "Monitor GCP Cloud Logging for WMI command execution on Windows "
                "Compute Engine instances."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(jsonPayload.message=~"wmic[.]exe|Get-WmiObject|Invoke-WmiMethod|gwmi|iwmi"
OR protoPayload.request.commandLine=~"wmic|Get-WmiObject|Invoke-WmiMethod"
OR jsonPayload.message=~"shadowcopy.*delete|vssadmin.*delete.*shadows")
NOT jsonPayload.message=~"Microsoft.*Update|SCCM"''',
                gcp_terraform_template="""# GCP: Detect WMI execution on Windows GCE instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts - WMI"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for WMI execution
resource "google_logging_metric" "wmi_execution" {
  project = var.project_id
  name    = "wmi-command-execution"
  filter  = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.message=~"wmic[.]exe|Get-WmiObject|Invoke-WmiMethod|gwmi|iwmi"
    OR protoPayload.request.commandLine=~"wmic|Get-WmiObject|Invoke-WmiMethod"
    OR jsonPayload.message=~"shadowcopy.*delete|vssadmin.*delete.*shadows")
    NOT jsonPayload.message=~"Microsoft.*Update|SCCM"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where WMI execution was detected"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy for WMI execution
resource "google_monitoring_alert_policy" "wmi_alert" {
  project      = var.project_id
  display_name = "T1047: WMI Execution Detected"
  combiner     = "OR"
  conditions {
    display_name = "WMI command execution activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.wmi_execution.name}\" resource.type=\"gce_instance\""
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
  documentation {
    content   = "WMI command execution detected on Windows GCE instance. Investigate for lateral movement or ransomware activity."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: WMI Execution Detected",
                alert_description_template=(
                    "WMI command execution detected on GCE instance {instance_id}. "
                    "Command: {command_line}. Investigate immediately for potential compromise."
                ),
                investigation_steps=[
                    "Review the Cloud Logging entry for complete command details",
                    "Check instance's service account permissions and recent API activity",
                    "Examine Windows Event Logs via Cloud Logging or direct access",
                    "Look for shadow copy deletion indicating ransomware",
                    "Review network connections for lateral movement",
                    "Check VPC Flow Logs for WMI-related port activity (135, 5985, 5986)",
                    "Investigate authentication events and user sessions",
                ],
                containment_actions=[
                    "Stop the GCE instance to prevent further lateral movement",
                    "Create a disk snapshot for forensic analysis",
                    "Revoke the instance's service account credentials",
                    "Update firewall rules to isolate the instance",
                    "If ransomware suspected, check for shadow copy deletion and initiate backup recovery",
                    "Review and remove any WMI persistence mechanisms",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised management tools, scheduled system maintenance, and patch deployment systems",
            detection_coverage="70% - detects common WMI command patterns",
            evasion_considerations="Obfuscated commands, COM API usage, or custom WMI providers may evade pattern matching",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$15-30 depending on logging volume",
            prerequisites=[
                "Cloud Logging API enabled",
                "Ops Agent or legacy logging agent installed on Windows GCE instances",
            ],
        ),
        # Strategy 5: WMI Event Subscription Detection
        DetectionStrategy(
            strategy_id="t1047-wmi-persistence",
            name="Detect WMI Event Subscription for Persistence",
            description=(
                "Monitor for creation of WMI event subscriptions (WMI Event Consumers, Filters, "
                "and Bindings) which adversaries use for persistence and execution."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, eventID
| filter eventID in [19, 20, 21] or @message like /Win32.*EventConsumer|Win32.*EventFilter|Win32.*FilterToConsumerBinding/
| stats count() as wmi_events by instanceId, eventID, bin(1h)
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect WMI event subscriptions used for persistence

Parameters:
  SysmonLogGroup:
    Type: String
    Description: CloudWatch log group containing Sysmon logs
  SNSTopicArn:
    Type: String
    Description: SNS topic ARN for alerts

Resources:
  # Step 1: Create metric filter for WMI event consumer creation (Sysmon Event 19)
  WMIEventConsumerFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SysmonLogGroup
      FilterPattern: '[time, instance, eventid="19" || eventid="20" || eventid="21", ...]'
      MetricTransformations:
        - MetricName: WMIEventSubscription
          MetricNamespace: Security/T1047
          MetricValue: "1"

  # Step 2: Create alarm for WMI persistence
  WMIPersistenceAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1047-WMI-Persistence
      AlarmDescription: WMI event subscription detected - potential persistence mechanism
      MetricName: WMIEventSubscription
      Namespace: Security/T1047
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor for malicious WMI namespaces
  MaliciousNamespaceFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SysmonLogGroup
      FilterPattern: '[time, instance, msg="*__EventConsumer*" || msg="*CommandLineEventConsumer*" || msg="*ActiveScriptEventConsumer*"]'
      MetricTransformations:
        - MetricName: MaliciousWMINamespace
          MetricNamespace: Security/T1047
          MetricValue: "1"''',
                terraform_template="""# Detect WMI event subscriptions for persistence

variable "sysmon_log_group" {
  type        = string
  description = "CloudWatch log group containing Sysmon logs"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "wmi-persistence-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for WMI event subscription (Sysmon Events 19, 20, 21)
resource "aws_cloudwatch_log_metric_filter" "wmi_event_subscription" {
  name           = "wmi-event-subscription"
  log_group_name = var.sysmon_log_group
  pattern        = "[time, instance, eventid=\"19\" || eventid=\"20\" || eventid=\"21\", ...]"

  metric_transformation {
    name      = "WMIEventSubscription"
    namespace = "Security/T1047"
    value     = "1"
  }
}

# Step 2: Create alarm for WMI persistence mechanisms
resource "aws_cloudwatch_metric_alarm" "wmi_persistence" {
  alarm_name          = "T1047-WMI-Persistence"
  alarm_description   = "WMI event subscription detected - potential persistence mechanism"
  metric_name         = "WMIEventSubscription"
  namespace           = "Security/T1047"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor for malicious WMI consumer types
resource "aws_cloudwatch_log_metric_filter" "malicious_wmi_namespace" {
  name           = "malicious-wmi-namespace"
  log_group_name = var.sysmon_log_group
  pattern        = "[time, instance, msg=\"*__EventConsumer*\" || msg=\"*CommandLineEventConsumer*\" || msg=\"*ActiveScriptEventConsumer*\"]"

  metric_transformation {
    name      = "MaliciousWMINamespace"
    namespace = "Security/T1047"
    value     = "1"
  }
}""",
                alert_severity="critical",
                alert_title="WMI Persistence Mechanism Detected",
                alert_description_template=(
                    "WMI event subscription created on instance {instance_id}. "
                    "Sysmon EventID: {event_id}. This is a common persistence technique. "
                    "Immediate investigation required."
                ),
                investigation_steps=[
                    "Enumerate all WMI event subscriptions using PowerShell: Get-WmiObject -Namespace root\\subscription -Class __EventFilter",
                    "Check for CommandLineEventConsumer or ActiveScriptEventConsumer (common in attacks)",
                    "Review the consumer action and filter query for malicious intent",
                    "Identify when the subscription was created and by which user/process",
                    "Check Sysmon Event 19 (WMIEventConsumer), Event 20 (WMIEventConsumerToFilter), Event 21 (WMIEventFilter)",
                    "Correlate with other security events around the same timeframe",
                    "Search for similar subscriptions across all Windows instances",
                ],
                containment_actions=[
                    "Remove malicious WMI event subscriptions immediately using PowerShell",
                    "Delete associated EventFilter, EventConsumer, and FilterToConsumerBinding",
                    "Check for and remove any files or scripts referenced by the consumer",
                    "Reboot the instance to clear any in-memory WMI components",
                    "Audit all WMI subscriptions across the environment",
                    "Implement WMI auditing and monitoring on all Windows instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="WMI persistence is rarely used legitimately; investigate all detections carefully",
            detection_coverage="85% - Sysmon provides comprehensive WMI event subscription monitoring",
            evasion_considerations="Attackers may use temporary WMI subscriptions or delete them after use; requires continuous monitoring",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30 depending on log volume",
            prerequisites=[
                "Sysmon installed on Windows instances with WMI event monitoring enabled (Events 19, 20, 21)",
                "CloudWatch Logs Agent configured to forward Sysmon logs",
            ],
        ),
    ],
    recommended_order=[
        "t1047-guardduty-wmi",
        "t1047-cloudwatch-wmi",
        "t1047-wmi-persistence",
        "t1047-remote-wmi",
        "t1047-gcp-wmi",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+25% improvement for Execution tactic",
)
