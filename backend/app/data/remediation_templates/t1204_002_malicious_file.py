"""
T1204.002 - User Execution: Malicious File

Adversaries leverage social engineering to manipulate users into opening malicious
files, leading to code execution. Common vectors include documents with macros,
executables, and archive files delivered via phishing or shared directories.
Used by APT28, APT29, Lazarus Group, FIN7, Sandworm Team.
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
    technique_id="T1204.002",
    technique_name="User Execution: Malicious File",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1204/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage social engineering to manipulate users into opening "
            "malicious files such as .doc, .pdf, .exe, .lnk, .scr, .iso, and others. "
            "Files often contain embedded macros, malicious scripts, or executables that "
            "run when opened. Commonly delivered via spearphishing attachments or placed "
            "in shared directories."
        ),
        attacker_goal="Execute malicious code by tricking users into opening weaponised files",
        why_technique=[
            "Bypasses technical controls via user action",
            "Leverages social engineering effectiveness",
            "Can bypass email filters with obfuscation",
            "Users often trust familiar file types",
            "Effective initial access vector",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Primary execution technique for initial access. User interaction makes it "
            "difficult to prevent technically. Successful execution enables full code "
            "execution and system compromise."
        ),
        business_impact=[
            "Initial code execution on endpoints",
            "Credential theft via malware",
            "Data exfiltration risk",
            "Ransomware deployment",
            "Lateral movement enabler",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1059.001", "T1547.001", "T1055", "T1105"],
        often_follows=["T1566.001", "T1566.002"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1204-002-aws-suspicious-downloads",
            name="AWS Suspicious File Download Execution",
            description="Detect file downloads followed by suspicious child process execution on EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.instanceId
| filter eventName = "RunInstances" OR eventName = "StartInstances"
| join (
    fields @timestamp, processName, commandLine
    | filter processName in ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe"]
    | filter commandLine like /Downloads|Temp|AppData/
  ) on instanceId
| stats count(*) as executions by instanceId, processName
| filter executions > 3
| sort executions desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious file execution patterns

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: CloudWatch log group for EC2 process monitoring
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Suspicious File Execution Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for suspicious process execution
  SuspiciousProcessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      # Match suspicious process execution from user directories
      FilterPattern: '[timestamp, process=powershell.exe|cmd.exe|wscript.exe|cscript.exe|regsvr32.exe|rundll32.exe, path=*Downloads*|*Temp*|*AppData*]'
      MetricTransformations:
        - MetricName: SuspiciousFileExecution
          MetricNamespace: Security/UserExecution
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for high-frequency suspicious executions
  SuspiciousExecutionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighSuspiciousFileExecution
      AlarmDescription: Detect multiple suspicious process executions from user directories
      MetricName: SuspiciousFileExecution
      Namespace: Security/UserExecution
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# AWS: Detect suspicious file execution patterns

variable "cloudwatch_log_group" {
  description = "CloudWatch log group for EC2 process monitoring"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "suspicious_execution_alerts" {
  name         = "suspicious-file-execution-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Suspicious File Execution Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.suspicious_execution_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious process execution
resource "aws_cloudwatch_log_metric_filter" "suspicious_processes" {
  name           = "suspicious-file-execution"
  log_group_name = var.cloudwatch_log_group
  # Match suspicious process execution from user directories
  pattern = "[timestamp, process=powershell.exe|cmd.exe|wscript.exe|cscript.exe|regsvr32.exe|rundll32.exe, path=*Downloads*|*Temp*|*AppData*]"

  metric_transformation {
    name      = "SuspiciousFileExecution"
    namespace = "Security/UserExecution"
    value     = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for high-frequency suspicious executions
resource "aws_cloudwatch_metric_alarm" "suspicious_execution" {
  alarm_name          = "HighSuspiciousFileExecution"
  alarm_description   = "Detect multiple suspicious process executions from user directories"
  metric_name         = "SuspiciousFileExecution"
  namespace           = "Security/UserExecution"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.suspicious_execution_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.suspicious_execution_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.suspicious_execution_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Suspicious File Execution Detected",
                alert_description_template="Multiple suspicious processes executed from user directories on instance {instanceId}.",
                investigation_steps=[
                    "Review process execution timeline and parent-child relationships",
                    "Examine file download history and source locations",
                    "Check for macro-enabled documents or suspicious archives",
                    "Analyse process command-line arguments for malicious indicators",
                    "Review network connections initiated by suspicious processes",
                    "Check for persistence mechanisms created",
                ],
                containment_actions=[
                    "Isolate affected instance from network",
                    "Terminate suspicious processes",
                    "Quarantine malicious files",
                    "Review email security controls and attachment filters",
                    "Enhance endpoint protection policies",
                    "Conduct user security awareness training",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate software installations may trigger alerts. Tune by excluding known software deployment paths and authorised installers.",
            detection_coverage="60% - catches common execution patterns from user directories",
            evasion_considerations="Adversaries may execute from non-standard paths or use living-off-the-land binaries",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-40",
            prerequisites=[
                "CloudWatch agent with process monitoring enabled on EC2 instances"
            ],
        ),
        DetectionStrategy(
            strategy_id="t1204-002-aws-office-macro",
            name="AWS Office Document Macro Execution",
            description="Detect Microsoft Office applications spawning suspicious child processes indicating macro execution.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, parentProcess, childProcess, commandLine, userName
| filter parentProcess in ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"]
| filter childProcess in ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe"]
| stats count(*) as spawns by userName, parentProcess, childProcess
| sort spawns desc""",
                terraform_template="""# AWS: Detect Office macro execution via process monitoring

variable "process_log_group" {
  description = "CloudWatch log group containing process creation logs"
  type        = string
}

variable "alert_email" {
  description = "Email for macro execution alerts"
  type        = string
}

# Step 1: Create SNS topic for macro execution alerts
resource "aws_sns_topic" "macro_execution_alerts" {
  name         = "office-macro-execution-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Office Macro Execution Alerts"
}

resource "aws_sns_topic_subscription" "macro_alerts_email" {
  topic_arn = aws_sns_topic.macro_execution_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for Office child processes
resource "aws_cloudwatch_log_metric_filter" "office_child_processes" {
  name           = "office-suspicious-child-processes"
  log_group_name = var.process_log_group
  # Match Office apps spawning scripting engines
  pattern = "[timestamp, parent=*WINWORD.EXE*|*EXCEL.EXE*|*POWERPNT.EXE*, child=*powershell.exe*|*cmd.exe*|*wscript.exe*|*cscript.exe*|*mshta.exe*]"

  metric_transformation {
    name      = "OfficeMacroExecution"
    namespace = "Security/UserExecution"
    value     = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for Office macro execution
resource "aws_cloudwatch_metric_alarm" "office_macro_execution" {
  alarm_name          = "OfficeMacroExecution"
  alarm_description   = "Detect Office applications spawning suspicious child processes"
  metric_name         = "OfficeMacroExecution"
  namespace           = "Security/UserExecution"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.macro_execution_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.macro_execution_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.macro_execution_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Office Macro Execution Detected",
                alert_description_template="Office application {parentProcess} spawned suspicious process {childProcess} for user {userName}.",
                investigation_steps=[
                    "Identify the Office document that triggered execution",
                    "Review document metadata and macros",
                    "Examine child process command-line for malicious indicators",
                    "Check email source and sender reputation",
                    "Review file hash against threat intelligence",
                    "Analyse network activity from spawned processes",
                ],
                containment_actions=[
                    "Quarantine malicious document",
                    "Kill spawned processes",
                    "Block sender email address",
                    "Disable macros via Group Policy",
                    "Scan endpoint for additional compromise indicators",
                    "Review email gateway rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Very few legitimate scenarios require Office spawning scripting engines. Exclude known automation scripts if necessary.",
            detection_coverage="85% - highly effective for macro-based attacks",
            evasion_considerations="Adversaries may use alternative execution methods or exploit vulnerabilities instead of macros",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "Process creation logging enabled via Sysmon or Windows Event Logs"
            ],
        ),
        DetectionStrategy(
            strategy_id="t1204-002-gcp-file-execution",
            name="GCP Suspicious File Execution Monitoring",
            description="Detect suspicious file downloads and executions on GCP Compute Engine instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.start"
OR (
  jsonPayload.process.executable=~"(bash|sh|python|perl|osascript)"
  AND jsonPayload.process.args=~"(Downloads|tmp|var/tmp)"
)""",
                gcp_terraform_template="""# GCP: Detect suspicious file execution on Compute Engine

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email_alerts" {
  display_name = "Security Alerts Email"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for suspicious file execution
resource "google_logging_metric" "suspicious_file_execution" {
  name    = "suspicious-file-execution"
  project = var.project_id
  # Match process execution from temporary or download directories
  filter = <<-EOT
    resource.type="gce_instance"
    (
      jsonPayload.process.executable=~"(bash|sh|python|perl|curl)"
      AND jsonPayload.process.args=~"(Downloads|tmp|/var/tmp)"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    display_name = "Suspicious File Executions"
  }
}

# Step 3: Create alert policy for suspicious executions
resource "google_monitoring_alert_policy" "suspicious_execution_alert" {
  project      = var.project_id
  display_name = "Suspicious File Execution Detected"
  combiner     = "OR"

  conditions {
    display_name = "High rate of suspicious executions"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_file_execution.name}\" AND resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious File Execution",
                alert_description_template="Suspicious script execution detected from temporary directories on GCP instance.",
                investigation_steps=[
                    "Review instance audit logs for recent file downloads",
                    "Examine script content and execution arguments",
                    "Check network egress for data exfiltration",
                    "Review IAM permissions and service account activity",
                    "Analyse VPC flow logs for suspicious connections",
                ],
                containment_actions=[
                    "Stop affected instance",
                    "Create forensic disk snapshot",
                    "Remove malicious files",
                    "Review and tighten firewall rules",
                    "Rotate service account credentials",
                    "Enhance OS login security policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate automation scripts and software deployment paths. Adjust threshold based on instance usage patterns.",
            detection_coverage="65% - catches common execution patterns",
            evasion_considerations="Adversaries may use alternate directories or compiled binaries to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$20-35",
            prerequisites=[
                "Cloud Logging API enabled",
                "OS Config agent for process monitoring",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1204-002-aws-lnk-execution",
            name="AWS Shortcut File (.lnk) Execution Detection",
            description="Detect execution of Windows shortcut files that may contain malicious commands.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, processName, commandLine, parentProcess
| filter processName = "cmd.exe" OR processName = "powershell.exe"
| filter commandLine like /\\.lnk/
| filter parentProcess = "explorer.exe"
| stats count(*) as executions by commandLine, userName
| sort executions desc""",
                terraform_template="""# AWS: Detect malicious .lnk file execution

variable "security_log_group" {
  description = "CloudWatch log group for Windows security events"
  type        = string
}

variable "alert_email" {
  description = "Email for .lnk execution alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "lnk_execution_alerts" {
  name         = "lnk-file-execution-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "LNK File Execution Alerts"
}

resource "aws_sns_topic_subscription" "lnk_alerts_email" {
  topic_arn = aws_sns_topic.lnk_execution_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for .lnk executions
resource "aws_cloudwatch_log_metric_filter" "lnk_executions" {
  name           = "suspicious-lnk-execution"
  log_group_name = var.security_log_group
  # Match cmd.exe or powershell.exe with .lnk in command line
  pattern = "[timestamp, process=cmd.exe|powershell.exe, ..., commandline=*.lnk*]"

  metric_transformation {
    name      = "LnkFileExecution"
    namespace = "Security/UserExecution"
    value     = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for .lnk executions
resource "aws_cloudwatch_metric_alarm" "lnk_execution_detected" {
  alarm_name          = "SuspiciousLnkExecution"
  alarm_description   = "Detect execution of shortcut files with embedded commands"
  metric_name         = "LnkFileExecution"
  namespace           = "Security/UserExecution"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.lnk_execution_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.lnk_execution_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.lnk_execution_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Malicious Shortcut File Execution",
                alert_description_template="Suspicious .lnk file executed: {commandLine}",
                investigation_steps=[
                    "Examine .lnk file properties and embedded command",
                    "Identify file source (email, download, removable media)",
                    "Review process tree for child processes",
                    "Check for network connections or file downloads",
                    "Analyse .lnk file hash against threat intelligence",
                ],
                containment_actions=[
                    "Delete malicious .lnk file",
                    "Terminate spawned processes",
                    "Block file hash across endpoints",
                    "Review email attachment filtering",
                    "Scan for similar files on network shares",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate .lnk files rarely execute via cmd.exe or PowerShell. Review exceptions carefully.",
            detection_coverage="75% - effective for .lnk-based attacks",
            evasion_considerations="Adversaries may use different file formats or direct executable invocation",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["Windows process creation logging enabled"],
        ),
        # Azure Strategy: User Execution: Malicious File
        DetectionStrategy(
            strategy_id="t1204002-azure",
            name="Azure User Execution: Malicious File Detection",
            description=(
                "Azure detection for User Execution: Malicious File. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Azure Defender for Endpoint - Malicious File Execution Detection
// MITRE ATT&CK: T1204.002 - User Execution: Malicious File
let lookback = 24h;
// Detect Defender for Endpoint alerts for malicious file execution
SecurityAlert
| where TimeGenerated > ago(lookback)
| where ProductName in ("Microsoft Defender for Endpoint", "Microsoft Defender Advanced Threat Protection")
| where AlertName has_any (
    "Malicious file detected",
    "Suspicious file execution",
    "Malware detected",
    "Suspicious Office child process",
    "Macro execution",
    "Suspicious script execution",
    "Document with embedded script",
    "Suspicious download",
    "Executable from email"
)
| extend
    AlertDetails = parse_json(ExtendedProperties),
    Entities = parse_json(Entities)
| extend
    FileName = tostring(AlertDetails.["File Name"]),
    FilePath = tostring(AlertDetails.["File Path"]),
    FileHash = tostring(AlertDetails.["SHA256"]),
    DeviceName = tostring(AlertDetails.["Device Name"]),
    UserName = tostring(AlertDetails.["User Name"]),
    ProcessName = tostring(AlertDetails.["Process Name"])
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    FileName,
    FilePath,
    FileHash,
    DeviceName,
    UserName,
    ProcessName,
    Description,
    RemediationSteps
| order by TimeGenerated desc""",
                sentinel_rule_query="""// Sentinel Analytics Rule: Malicious File Execution Detection
// MITRE ATT&CK: T1204.002 - User Execution: Malicious File
// Detects Office documents spawning suspicious processes or script execution
let lookback = 24h;
// Defender alerts for file-based attacks
let FileAlerts = SecurityAlert
| where TimeGenerated > ago(lookback)
| where ProductName has "Defender"
| where AlertName has_any (
    "Malicious",
    "Suspicious file",
    "Macro",
    "Script execution",
    "Office"
)
| extend
    DeviceName = tostring(parse_json(ExtendedProperties).["Device Name"]),
    UserName = tostring(parse_json(ExtendedProperties).["User Name"]),
    FileName = tostring(parse_json(ExtendedProperties).["File Name"])
| summarize
    AlertCount = count(),
    Alerts = make_set(AlertName, 5),
    Files = make_set(FileName, 10)
    by DeviceName, UserName;
// Device events showing Office child processes (if DeviceProcessEvents available)
let OfficeChildProcesses = DeviceProcessEvents
| where TimeGenerated > ago(lookback)
| where InitiatingProcessFileName has_any (
    "WINWORD.EXE",
    "EXCEL.EXE",
    "POWERPNT.EXE",
    "OUTLOOK.EXE"
)
| where FileName has_any (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe"
)
| summarize
    ProcessCount = count(),
    ChildProcesses = make_set(FileName, 5)
    by DeviceName, AccountName;
// Combine alerts and process data
FileAlerts
| join kind=leftouter (OfficeChildProcesses) on DeviceName
| extend
    TotalIndicators = AlertCount + coalesce(ProcessCount, 0),
    RiskScore = AlertCount * 15 + coalesce(ProcessCount, 0) * 10
| where RiskScore > 10
| project
    DeviceName,
    UserName,
    AlertCount,
    Alerts,
    Files,
    ProcessCount,
    ChildProcesses,
    RiskScore
| order by RiskScore desc""",
                azure_terraform_template="""# Azure Detection for User Execution: Malicious File
# MITRE ATT&CK: T1204.002

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
  name                = "user-execution--malicious-file-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "user-execution--malicious-file-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: User Execution: Malicious File
// MITRE ATT&CK: T1204.002
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

  description = "Detects User Execution: Malicious File (T1204.002) activity in Azure environment"
  display_name = "User Execution: Malicious File Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1204.002"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: User Execution: Malicious File Detected",
                alert_description_template=(
                    "User Execution: Malicious File activity detected. "
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
        "t1204-002-aws-office-macro",
        "t1204-002-aws-suspicious-downloads",
        "t1204-002-gcp-file-execution",
        "t1204-002-aws-lnk-execution",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+25% improvement for Execution tactic",
)
