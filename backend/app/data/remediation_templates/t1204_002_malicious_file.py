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
  display_name = "Suspicious File Execution Detected"
  project      = var.project_id
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
